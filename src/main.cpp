// Passiver WLAN-Intrusion-Detector - Waveshare ESP32-C6-LCD-1.47
// Arduino-Core 3.x (pioarduino). Rein passiv: Promiscuous-RX, Kanal-Hopping.
// Callback schreibt nur Zähler + Ringpuffer; Auswertung im loop().

#include <Arduino.h>
#include <atomic>
#include <string.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <LovyanGFX.hpp>
#include <Preferences.h>
#include "config.h"

// Defaults für ältere private config.h ohne die neuen Schalter
#ifndef DEAUTH_MIN_WINDOW_MS
#define DEAUTH_MIN_WINDOW_MS 1000
#endif
#ifndef DEAUTH_MINE_MIN_FRAMES
#define DEAUTH_MINE_MIN_FRAMES 8
#endif
#ifndef DEAUTH_TOTAL_MIN_FRAMES
#define DEAUTH_TOTAL_MIN_FRAMES 20
#endif
#ifndef RSSI_SPOOF_DELTA_DB
#define RSSI_SPOOF_DELTA_DB 10
#endif
#ifndef DEAUTH_SPOOF_MIN_FRAMES
#define DEAUTH_SPOOF_MIN_FRAMES 3
#endif
#ifndef DEAUTH_FROM_AP_IS_WARN
#define DEAUTH_FROM_AP_IS_WARN 1
#endif
#ifndef CHECK_TSF
#define CHECK_TSF 1
#endif
#ifndef TSF_JUMP_US
#define TSF_JUMP_US 3000
#endif
#ifndef TSF_JUMPS_FOR_ALARM
#define TSF_JUMPS_FOR_ALARM 3
#endif
#ifndef TSF_JUMP_WINDOW_MS
#define TSF_JUMP_WINDOW_MS 10000
#endif
#ifndef CHECK_IE_HASH
#define CHECK_IE_HASH 1
#endif
#ifndef EVIDENCE_SIZE
#define EVIDENCE_SIZE 16
#endif
#ifndef EVIDENCE_NVS
#define EVIDENCE_NVS 1
#endif
#ifndef BUTTON_LONG_MS
#define BUTTON_LONG_MS 3000
#endif
#include "font_dejavu_13.h"   // Latin-1 (Umlaute), generiert mit tools/gen_gfxfont.py
#include "font_dejavu_19.h"
#include "font_dejavu_b30.h"

#if NTFY_ENABLE
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#endif

// ---------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------
class LGFX : public lgfx::LGFX_Device {
    lgfx::Panel_ST7789 _panel;
    lgfx::Bus_SPI      _bus;
    lgfx::Light_PWM    _light;
public:
    LGFX() {
        {
            auto c = _bus.config();
            c.spi_host    = SPI2_HOST;
            c.spi_mode    = 0;
            c.freq_write  = LCD_SPI_HZ;
            c.freq_read   = 16000000;
            c.spi_3wire   = true;
            c.use_lock    = true;
            c.dma_channel = SPI_DMA_CH_AUTO;
            c.pin_sclk    = PIN_LCD_SCLK;
            c.pin_mosi    = PIN_LCD_MOSI;
            c.pin_miso    = -1;
            c.pin_dc      = PIN_LCD_DC;
            _bus.config(c);
            _panel.setBus(&_bus);
        }
        {
            auto c = _panel.config();
            c.pin_cs          = PIN_LCD_CS;
            c.pin_rst         = PIN_LCD_RST;
            c.pin_busy        = -1;
            c.panel_width     = LCD_WIDTH;
            c.panel_height    = LCD_HEIGHT;
            c.offset_x        = LCD_OFFSET_X;
            c.offset_y        = LCD_OFFSET_Y;
            c.offset_rotation = 0;
            c.readable        = false;
            c.invert          = true;
            c.rgb_order       = false;
            c.dlen_16bit      = false;
            c.bus_shared      = false;
            _panel.config(c);
        }
        {
            auto c = _light.config();
            c.pin_bl      = PIN_LCD_BL;
            c.invert      = false;
            c.freq        = 44100;
            c.pwm_channel = 7;
            _light.config(c);
            _panel.setLight(&_light);
        }
        setPanel(&_panel);
    }
};

static LGFX        lcd;
static LGFX_Sprite fb(&lcd);
static bool        fbOk = false;

// ---------------------------------------------------------------------
// Shared state Callback -> Loop
// ---------------------------------------------------------------------
enum : uint8_t { EV_SSID_MATCH = 1, EV_WHITELISTED = 2, EV_HAS_RSN = 4, EV_HAS_WPA1 = 8 };

struct ApEvent {
    uint8_t  bssid[6];
    uint8_t  subtype;     // 8 = Beacon, 5 = Probe Response
    uint8_t  rxChannel;   // rx_ctrl.channel (kann Nachbarkanal-Bleed sein)
    uint8_t  dsChannel;   // DS Parameter Set IE, 0 = fehlt
    uint8_t  flags;
    int8_t   rssi;
    uint32_t tsfLo;       // Beacon-Timestamp (TSF des Senders), untere 32 Bit
    uint32_t rxTs;        // rx_ctrl.timestamp: lokaler TSF beim Empfang, µs
    uint32_t ieHash;      // FNV-1a über IE-Struktur, ohne volatile Inhalte (TIM, BSS Load, HT/HE Operation)
};

// Deauth/Disassoc gegen eigene BSSID, als Beweismittel. Zähler reichen nicht,
// wer gesendet hat entscheidet alles.
struct DeauthEvent {
    uint8_t  a1[6], a2[6];   // DA, SA
    uint16_t reason;
    int8_t   rssi;
    uint8_t  ch;
    uint8_t  subtype;        // 0x0C Deauth, 0x0A Disassoc
};

static constexpr uint8_t RING_SIZE = 32;   // Zweierpotenz
static ApEvent               ring[RING_SIZE];
static volatile uint8_t      ringHead = 0;  // Producer (WiFi-Task)
static volatile uint8_t      ringTail = 0;  // Consumer (loop)
static std::atomic<uint32_t> ringDrops{0};

static constexpr uint8_t DRING_SIZE = 16;  // Zweierpotenz
static DeauthEvent           dring[DRING_SIZE];
static volatile uint8_t      dringHead = 0;
static volatile uint8_t      dringTail = 0;
static std::atomic<uint32_t> dringDrops{0};

static std::atomic<uint32_t> cntDeauthTotal{0};
static std::atomic<uint32_t> cntDeauthMine{0};
static std::atomic<uint32_t> cntMgmtTotal{0};

static size_t targetSsidLen = 0;

static int whitelistIndex(const uint8_t* mac) {
    for (size_t i = 0; i < WHITELIST_COUNT; i++)
        if (memcmp(WHITELIST[i].bssid, mac, 6) == 0) return (int)i;
    return -1;
}

static inline uint32_t fnv1a(uint32_t h, const uint8_t* d, size_t n) {
    for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}

// Läuft im WiFi-Task (kein ISR), Payload nur während des Callbacks gültig.
static void promiscCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* p = pkt->payload;
    int len = (int)pkt->rx_ctrl.sig_len - 4;     // FCS abziehen
    if (len < 24) return;

    const uint8_t fc0 = p[0];
    if ((fc0 & 0x0C) != 0x00) return;             // Type != Management
    const uint8_t subtype = fc0 >> 4;
    const uint8_t* a1 = p + 4;
    const uint8_t* a2 = p + 10;
    const uint8_t* a3 = p + 16;

    cntMgmtTotal.fetch_add(1, std::memory_order_relaxed);

    if (subtype == 0x0C || subtype == 0x0A) {     // Deauth / Disassoc
        cntDeauthTotal.fetch_add(1, std::memory_order_relaxed);
        if (whitelistIndex(a1) >= 0 || whitelistIndex(a2) >= 0 || whitelistIndex(a3) >= 0) {
            cntDeauthMine.fetch_add(1, std::memory_order_relaxed);
            const uint8_t head = dringHead;
            const uint8_t next = (head + 1) & (DRING_SIZE - 1);
            if (next == dringTail) { dringDrops.fetch_add(1, std::memory_order_relaxed); return; }
            DeauthEvent& d = dring[head];
            memcpy(d.a1, a1, 6);
            memcpy(d.a2, a2, 6);
            d.reason  = (len >= 26) ? (uint16_t)(p[24] | (p[25] << 8)) : 0;
            d.rssi    = pkt->rx_ctrl.rssi;
            d.ch      = pkt->rx_ctrl.channel;
            d.subtype = subtype;
            dringHead = next;
        }
        return;
    }
    if (subtype != 0x08 && subtype != 0x05) return;   // nur Beacon / Probe Resp

    const uint8_t* body = p + 24;
    int blen = len - 24;
    if (blen < 12) return;                        // TS(8)+Interval(2)+Cap(2)

    const uint8_t* ie = body + 12;
    int rem = blen - 12;
    uint8_t flags = 0, ds = 0;
    uint32_t h = fnv1a(2166136261u, body + 8, 4);   // Beacon-Intervall + Capability
    while (rem >= 2) {
        const uint8_t id = ie[0], l = ie[1];
        if (l + 2 > rem) break;
        switch (id) {
            case 0:   // SSID
                if (l == targetSsidLen && memcmp(ie + 2, TARGET_SSID, l) == 0) flags |= EV_SSID_MATCH;
                break;
            case 3:   // DS Parameter Set
                if (l >= 1) ds = ie[2];
                break;
            case 48:  // RSN
                flags |= EV_HAS_RSN;
                break;
            case 221: // Vendor: WPA1 = 00:50:F2:01
                if (l >= 4 && ie[2] == 0x00 && ie[3] == 0x50 && ie[4] == 0xF2 && ie[5] == 0x01)
                    flags |= EV_HAS_WPA1;
                break;
            default: break;
        }
        // IE-Fingerprint: Reihenfolge und Längen immer, Inhalt nur wo er statisch ist.
        h = fnv1a(h, ie, 2);
        if (id == 5 || id == 11 || id == 61) {
            // TIM, BSS Load, HT Operation: ändern sich im Betrieb
        } else if (id == 221) {
            h = fnv1a(h, ie + 2, l < 4 ? l : 4);           // nur OUI + Typ
        } else if (id == 255 && l >= 1 && ie[2] == 36) {
            // HE Operation: BSS Color kann wechseln
        } else {
            h = fnv1a(h, ie + 2, l);
        }
        ie  += 2 + l;
        rem -= 2 + l;
    }
    if (whitelistIndex(a3) >= 0) flags |= EV_WHITELISTED;
    if (!(flags & (EV_SSID_MATCH | EV_WHITELISTED))) return;   // fremde Netze ignorieren

    const uint8_t head = ringHead;
    const uint8_t next = (head + 1) & (RING_SIZE - 1);
    if (next == ringTail) { ringDrops.fetch_add(1, std::memory_order_relaxed); return; }
    ApEvent& e = ring[head];
    memcpy(e.bssid, a3, 6);
    e.subtype   = subtype;
    e.rxChannel = pkt->rx_ctrl.channel;
    e.dsChannel = ds;
    e.flags     = flags;
    e.rssi      = pkt->rx_ctrl.rssi;
    e.tsfLo     = (uint32_t)body[0] | ((uint32_t)body[1] << 8) | ((uint32_t)body[2] << 16) | ((uint32_t)body[3] << 24);
    e.rxTs      = pkt->rx_ctrl.timestamp;
    e.ieHash    = h;
    ringHead    = next;
}

// ---------------------------------------------------------------------
// Auswertung
// ---------------------------------------------------------------------
enum Level : uint8_t { LVL_OK = 0, LVL_WARN = 1, LVL_ALARM = 2 };

struct ChanStat {
    uint32_t total = 0, mine = 0, airtimeMs = 0;
    float    lastRateTotal = 0, lastRateMine = 0;
};
static ChanStat chan[CH_MAX + 1];

static uint8_t  curCh = CH_MIN;
static uint32_t hopStart = 0;
static uint32_t curDwell = DWELL_FOREIGN_MS;
static bool     stickyUsed = false;

static bool     alarmLatched = false;
static uint32_t alarmSince = 0, alarmLastCond = 0;
static char     alarmReason[24] = "", alarmDetail[40] = "";

static uint32_t warnLast = 0;
static char     warnReason[24] = "", warnDetail[40] = "";

static uint32_t lastOwnBeaconMs = 0;
static bool     ownBeaconSeen = false;
static uint8_t  lastOwnBeaconCh = 0;

static float    dispDeauthRate = 0;      // schlechtester Kanal, letztes Fenster
static uint8_t  dispDeauthCh = 0;
static float    dispDeauthMine = 0;
static char     twinBssid[18] = "-";
static int8_t   twinRssi = 0;
static uint8_t  twinCh = 0;

static uint32_t lastNtfyMs = 0;
static bool     ntfyPending = false;
static uint32_t alarmCount = 0;

static Preferences prefs;

// Fingerprint je Whitelist-Eintrag (Regel 2b, Regel 6)
struct Fingerprint {
    uint32_t ieHash    = 0;      // 0 = noch nicht gelernt
    uint8_t  ieMiss    = 0;      // Abweichungen in Folge
    bool     tsfValid  = false;
    uint32_t tsfOffset = 0;      // tsfLo - rxTs, muss bis auf Drift konstant sein
    uint8_t  jumps     = 0;
    uint32_t jumpWin   = 0;
    bool     rssiValid = false;
    int16_t  rssiEma4  = 0;      // Beacon-RSSI, EMA, Faktor 4
};
static Fingerprint fp[WHITELIST_COUNT > 0 ? WHITELIST_COUNT : 1];

// Beweis-Log: letzte Deauths gegen eigene BSSID, chronologisch
enum : uint8_t { CLS_FROM_AP = 0, CLS_SPOOFED = 1, CLS_OTHER = 2 };
struct __attribute__((packed)) Evidence {
    uint32_t ms;
    uint8_t  sa[6], da[6];
    uint16_t reason;
    int8_t   rssi;
    uint8_t  ch;
    uint8_t  cls;        // Bit 0..1 Klasse, Bit 7 = Disassoc
};
static Evidence evLog[EVIDENCE_SIZE];
static uint8_t  evHead = 0, evCount = 0;
static bool     evDirty = false;
static uint32_t lastEvDump = 0;
// Klassen-Zähler im laufenden Deauth-Fenster
static uint32_t winFromAp = 0, winSpoof = 0, winOther = 0;
static int8_t   lastSpoofRssi = 0, lastSpoofApRssi = 0;
static uint16_t lastReason = 0;

static void macToStr(const uint8_t* m, char* out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static const char* clsName(uint8_t cls) {
    switch (cls & 3) {
        case CLS_FROM_AP: return "AP";
        case CLS_SPOOFED: return "SPOOF";
        default:          return "fremd";
    }
}

static void dumpEvidence(const char* head) {
    char sa[18], da[18];
    Serial.printf("%s (%u Einträge, drop %lu):\n", head, evCount, (unsigned long)dringDrops.load());
    for (uint8_t i = 0; i < evCount; i++) {
        const Evidence& e = evLog[(evHead + EVIDENCE_SIZE - evCount + i) % EVIDENCE_SIZE];
        macToStr(e.sa, sa); macToStr(e.da, da);
        Serial.printf("  [%lu] %s ch%u SA=%s DA=%s reason=%u %ddBm %s\n", (unsigned long)e.ms,
                      (e.cls & 0x80) ? "Disassoc" : "Deauth", e.ch, sa, da, e.reason, e.rssi, clsName(e.cls));
    }
}

#if EVIDENCE_NVS
static void saveEvidence(const char* reason, const char* detail) {
    if (!evDirty) return;
    prefs.putBytes("ev", evLog, sizeof evLog);
    prefs.putUChar("evh", evHead);
    prefs.putUChar("evn", evCount);
    prefs.putString("evr", reason);
    prefs.putString("evd", detail);
    prefs.putUInt("evu", millis() / 1000);
    evDirty = false;
}

static void printSavedEvidence() {
    if (!prefs.isKey("evr")) return;
    Serial.printf("Letzter Alarm vor Reset: %s | %s (Uptime damals %lu s)\n",
                  prefs.getString("evr").c_str(), prefs.getString("evd").c_str(),
                  (unsigned long)prefs.getUInt("evu"));
    if (prefs.getBytesLength("ev") == sizeof evLog) {
        prefs.getBytes("ev", evLog, sizeof evLog);
        evHead  = prefs.getUChar("evh");
        evCount = prefs.getUChar("evn");
        dumpEvidence("Beweis-Log davon");
        evHead = evCount = 0;           // RAM-Log frisch starten
        memset(evLog, 0, sizeof evLog);
    }
}
#endif

static void pushEvidence(const DeauthEvent& d, uint8_t cls) {
    Evidence& e = evLog[evHead];
    e.ms = millis();
    memcpy(e.sa, d.a2, 6);
    memcpy(e.da, d.a1, 6);
    e.reason = d.reason;
    e.rssi   = d.rssi;
    e.ch     = d.ch;
    e.cls    = cls | (d.subtype == 0x0A ? 0x80 : 0);
    evHead = (evHead + 1) % EVIDENCE_SIZE;
    if (evCount < EVIDENCE_SIZE) evCount++;
    evDirty = true;
}

// Heimkanal = erwarteter Kanal einer Whitelist-BSSID oder zuletzt gesehener
// AP-Kanal - aber nur solange der AP kürzlich gesehen wurde. Sonst wird
// gesweept (Boot, Autokanal-Wechsel, AP weg).
static bool isHomeChannel(uint8_t ch) {
    if (!ownBeaconSeen || millis() - lastOwnBeaconMs >= AP_LOST_RESWEEP_MS) return false;
    for (size_t i = 0; i < WHITELIST_COUNT; i++)
        if (WHITELIST[i].expectedChannel == ch) return true;
    return lastOwnBeaconCh == ch;
}

// Beweis-Log seriell ausgeben und sichern, höchstens alle 10 s (Twin-Alarm
// feuert pro Beacon, NVS soll nicht pro Beacon beschrieben werden).
static void secureEvidence(const char* reason, const char* detail) {
    const uint32_t now = millis();
    if (lastEvDump && now - lastEvDump < 10000) return;
    lastEvDump = now;
    if (evCount) dumpEvidence("Beweis-Log");
#if EVIDENCE_NVS
    saveEvidence(reason, detail);
#endif
}

static void raiseAlarm(const char* reason, const char* detail) {
    const uint32_t now = millis();
    const bool fresh = !alarmLatched;
    const bool changed = fresh || strcmp(alarmReason, reason) != 0;
    alarmLatched = true;
    alarmLastCond = now;
    if (fresh) alarmSince = now;
    if (changed) alarmCount++;
    strlcpy(alarmReason, reason, sizeof alarmReason);
    strlcpy(alarmDetail, detail, sizeof alarmDetail);
    if (changed) Serial.printf("[%lu] ALARM #%lu %s | %s\n", (unsigned long)now, (unsigned long)alarmCount, reason, detail);
    secureEvidence(reason, detail);
#if NTFY_ENABLE
    if (fresh) ntfyPending = true;
#endif
}

static void raiseWarn(const char* reason, const char* detail) {
    const uint32_t now = millis();
    if (now - warnLast > 5000 || strcmp(warnReason, reason) != 0)
        Serial.printf("[%lu] WARN  %s | %s\n", (unsigned long)now, reason, detail);
    warnLast = now;
    strlcpy(warnReason, reason, sizeof warnReason);
    strlcpy(warnDetail, detail, sizeof warnDetail);
}

static void evaluateDeauth(uint8_t ch, ChanStat& cs) {
    // Kein Early-Trigger mehr unter DEAUTH_MIN_WINDOW_MS: 5 Frames in 330 ms
    // sind "15/s", aber eben nur 5 Frames. Rate und absolute Anzahl müssen passen.
    const bool windowFull = cs.airtimeMs >= RATE_WINDOW_MS;
    const bool early = cs.airtimeMs >= DEAUTH_MIN_WINDOW_MS &&
                       (cs.total >= DEAUTH_TOTAL_MIN_FRAMES || cs.mine >= DEAUTH_MINE_MIN_FRAMES);
    if (!windowFull && !early) return;
    if (cs.airtimeMs == 0) return;

    cs.lastRateTotal = cs.total * 1000.0f / cs.airtimeMs;
    cs.lastRateMine  = cs.mine  * 1000.0f / cs.airtimeMs;

    if (cs.lastRateTotal >= dispDeauthRate || dispDeauthCh == ch || dispDeauthCh == 0) {
        dispDeauthRate = cs.lastRateTotal;
        dispDeauthMine = cs.lastRateMine;
        dispDeauthCh   = ch;
    }

    char d[40];
    if (cs.lastRateMine > DEAUTH_MINE_PER_S && cs.mine >= DEAUTH_MINE_MIN_FRAMES) {
        // Wer hat gesendet? Alles vom AP mit passendem RSSI ist ein Client in
        // der Reconnect-Schleife oder Band-Steering, kein Angriff.
        bool anyRssi = false;
        for (size_t i = 0; i < WHITELIST_COUNT; i++) if (fp[i].rssiValid) anyRssi = true;
        const bool onlyAp = anyRssi && winSpoof == 0 && winOther == 0 && winFromAp > 0;
        snprintf(d, sizeof d, "%.0f/s ch%u AP%lu sp%lu fr%lu r%u", cs.lastRateMine, ch,
                 (unsigned long)winFromAp, (unsigned long)winSpoof, (unsigned long)winOther, lastReason);
        if (onlyAp && DEAUTH_FROM_AP_IS_WARN) raiseWarn("DEAUTH vom AP", d);
        else                                   raiseAlarm("DEAUTH eig. BSSID", d);
    } else if (cs.lastRateTotal > DEAUTH_TOTAL_PER_S && cs.total >= DEAUTH_TOTAL_MIN_FRAMES) {
        snprintf(d, sizeof d, "%.0f/s gesamt ch%u", cs.lastRateTotal, ch);
        raiseAlarm("DEAUTH-Flut", d);
    }
    cs.total = cs.mine = cs.airtimeMs = 0;
    winFromAp = winSpoof = winOther = 0;
}

// Deauth-Ring auswerten: klassifizieren, ins Beweis-Log, Regel 6.
static void processDeauths() {
    static uint32_t logWin = 0; static uint8_t logN = 0;
    char sa[18], da[18], d[40];
    while (dringTail != dringHead) {
        const DeauthEvent e = dring[dringTail];
        dringTail = (dringTail + 1) & (DRING_SIZE - 1);
        lastReason = e.reason;

        uint8_t cls = CLS_OTHER;
        const int idx = whitelistIndex(e.a2);          // SA = eigene BSSID?
        if (idx >= 0) {
            const Fingerprint& f = fp[idx];
            if (f.rssiValid) {
                const int apRssi = f.rssiEma4 / 4;
                const int delta  = e.rssi - apRssi;
                if (delta > RSSI_SPOOF_DELTA_DB || delta < -RSSI_SPOOF_DELTA_DB) {
                    cls = CLS_SPOOFED;
                    lastSpoofRssi = e.rssi; lastSpoofApRssi = (int8_t)apRssi;
                } else cls = CLS_FROM_AP;
            } else cls = CLS_FROM_AP;                   // noch kein Beacon-RSSI, nicht bewertbar
        }
        if (cls == CLS_FROM_AP) winFromAp++; else if (cls == CLS_SPOOFED) winSpoof++; else winOther++;
        pushEvidence(e, cls);

        // Serial, höchstens 10 Zeilen pro Sekunde
        const uint32_t now = millis();
        if (now - logWin > 1000) { logWin = now; logN = 0; }
        if (logN < 10) {
            logN++;
            macToStr(e.a2, sa); macToStr(e.a1, da);
            Serial.printf("[%lu] %s ch%u SA=%s DA=%s reason=%u %ddBm %s\n", (unsigned long)now,
                          e.subtype == 0x0A ? "Disassoc" : "Deauth", e.ch, sa, da, e.reason, e.rssi, clsName(cls));
        }
        // Regel 6: Frames mit SA = AP, aber RSSI passt nicht zu den Beacons
        if (winSpoof >= DEAUTH_SPOOF_MIN_FRAMES) {
            snprintf(d, sizeof d, "%lu Fr. %ddBm, AP %ddBm", (unsigned long)winSpoof, lastSpoofRssi, lastSpoofApRssi);
            raiseAlarm("DEAUTH gespooft", d);
        }
    }
}

// Regel 2b: geklonte BSSID. Beacon-RSSI mitführen (Regel 6), IE-Hash gegen
// gelernten Wert, TSF-Offset auf Sprünge prüfen.
static void checkFingerprint(int idx, const ApEvent& e) {
    Fingerprint& f = fp[idx];
    const char* label = WHITELIST[idx].label;
    char d[40];

    if (!f.rssiValid) { f.rssiEma4 = e.rssi * 4; f.rssiValid = true; }
    else               f.rssiEma4 += (e.rssi * 4 - f.rssiEma4) / 8;

#if CHECK_IE_HASH
    if (f.ieHash == 0) {
        f.ieHash = e.ieHash;
        char key[8]; snprintf(key, sizeof key, "ie%d", idx);
        prefs.putUInt(key, f.ieHash);
        Serial.printf("IE-Hash %s gelernt: %08lX (BOOT 3 s halten zum Neulernen)\n", label, (unsigned long)f.ieHash);
    } else if (e.ieHash != f.ieHash) {
        // zwei in Folge, damit ein einzelner kaputter Beacon nicht reicht
        if (++f.ieMiss >= 2) {
            snprintf(d, sizeof d, "%s IE %08lX statt %08lX", label, (unsigned long)e.ieHash, (unsigned long)f.ieHash);
            raiseAlarm("BSSID GEKLONT (IE)", d);
        }
    } else f.ieMiss = 0;
#endif

#if CHECK_TSF
    const uint32_t off = e.tsfLo - e.rxTs;
    if (f.tsfValid) {
        const int32_t dev = (int32_t)(off - f.tsfOffset);
        if (dev > TSF_JUMP_US || dev < -TSF_JUMP_US) {
            const uint32_t now = millis();
            if (now - f.jumpWin > TSF_JUMP_WINDOW_MS) { f.jumpWin = now; f.jumps = 0; }
            f.jumps++;
            Serial.printf("[%lu] TSF-Sprung %s %+ld us (%u in %lus)\n", (unsigned long)now, label,
                          (long)dev, f.jumps, (unsigned long)(TSF_JUMP_WINDOW_MS / 1000));
            if (f.jumps >= TSF_JUMPS_FOR_ALARM) {
                snprintf(d, sizeof d, "%s %u TSF-Sprünge in %lus", label, f.jumps, (unsigned long)(TSF_JUMP_WINDOW_MS / 1000));
                raiseAlarm("BSSID GEKLONT (TSF)", d);
            } else {
                snprintf(d, sizeof d, "%s %+ld us (AP-Neustart?)", label, (long)dev);
                raiseWarn("TSF-Sprung", d);
            }
        }
    }
    f.tsfOffset = off;
    f.tsfValid  = true;
#endif
}

static void processEvents() {
    char mac[18], d[40];
    while (ringTail != ringHead) {
        const ApEvent e = ring[ringTail];          // Kopie, dann freigeben
        ringTail = (ringTail + 1) & (RING_SIZE - 1);

        const uint8_t effCh = e.dsChannel ? e.dsChannel : e.rxChannel;
        const bool wl   = e.flags & EV_WHITELISTED;
        const bool mine = e.flags & EV_SSID_MATCH;
        const bool secure = (e.flags & EV_HAS_RSN) || (TREAT_WPA1_AS_SECURE && (e.flags & EV_HAS_WPA1));
        macToStr(e.bssid, mac);

#if LOG_SSID_MATCHES
        if (mine && e.subtype == 8) {
            static uint32_t lastLog = 0;
            if (millis() - lastLog > 2000) {
                lastLog = millis();
                Serial.printf("SSID-Match: %s ch%u rssi%d RSN=%d WL=%d\n", mac, effCh, e.rssi,
                              (e.flags & EV_HAS_RSN) ? 1 : 0, wl ? 1 : 0);
            }
        }
#endif
        // Regel 2: Evil Twin
        if (mine && !wl) {
            strlcpy(twinBssid, mac, sizeof twinBssid);
            twinRssi = e.rssi;
            twinCh   = effCh;
            snprintf(d, sizeof d, "%s ch%u %ddBm", mac, effCh, e.rssi);   // 17+1+4+... -> 2 Zeilen
            raiseAlarm("EVIL TWIN", d);
            continue;
        }
        // Regel 3: offen / ohne RSN
        if ((mine || wl) && !secure) {
            snprintf(d, sizeof d, "%s ch%u", mac, effCh);
            raiseAlarm(wl ? "BSSID ohne RSN" : "SSID offen", d);
        }
        if (wl) {
            const int idx = whitelistIndex(e.bssid);
            if (e.subtype == 8) {
                lastOwnBeaconMs = millis();
                ownBeaconSeen   = true;
                lastOwnBeaconCh = effCh;
                if (idx >= 0) checkFingerprint(idx, e);
            }
            // Regel 4: Kanalabweichung
#if CHECK_CHANNEL
            if (idx >= 0 && WHITELIST[idx].expectedChannel != 0 &&
                e.dsChannel != 0 && e.dsChannel != WHITELIST[idx].expectedChannel) {
                snprintf(d, sizeof d, "%s ch%u statt %u", WHITELIST[idx].label, e.dsChannel,
                         WHITELIST[idx].expectedChannel);
                raiseWarn("KANAL abweichend", d);
            }
#endif
        }
    }
}

static uint32_t lastFlush = 0;
static bool     deauthThisDwell = false;

// Zähler dem aktuellen Kanal gutschreiben und bewerten - läuft alle
// DEAUTH_EVAL_MS, unabhängig vom Hop (sonst wäre die Regel beim Parken blind).
static void flushCounters(uint32_t now) {
    const uint32_t t = cntDeauthTotal.exchange(0);
    const uint32_t m = cntDeauthMine.exchange(0);
    ChanStat& cs = chan[curCh];
    cs.total     += t;
    cs.mine      += m;
    cs.airtimeMs += now - lastFlush;
    lastFlush = now;
    if (t) deauthThisDwell = true;
    evaluateDeauth(curCh, cs);
}

static void hopChannel() {
    const uint32_t now = millis();
    if (now - lastFlush >= DEAUTH_EVAL_MS) flushCounters(now);
    // Parken vorzeitig abbrechen, wenn der AP auf diesem Kanal verstummt ist
    if (curDwell == DWELL_HOME_MS && !isHomeChannel(curCh)) curDwell = DWELL_FOREIGN_MS;
    if (now - hopStart < curDwell) return;
    flushCounters(now);

    // Heimkanal verloren (Autokanal gewechselt / AP weg) -> Parken abbrechen passiert
    // automatisch: isHomeChannel() liefert dann false und curDwell wird kurz.
#if STICKY_ON_DEAUTH
    if (deauthThisDwell && !stickyUsed && !isHomeChannel(curCh)) {
        stickyUsed = true;               // auf dem Fremdkanal bleiben, Flut sauber vermessen
        deauthThisDwell = false;
        hopStart   = now;
        curDwell   = STICKY_DWELL_MS;
        return;
    }
#endif
    stickyUsed = false;
    deauthThisDwell = false;
    curCh = (curCh >= CH_MAX) ? CH_MIN : curCh + 1;
    esp_wifi_set_channel(curCh, WIFI_SECOND_CHAN_NONE);
    cntDeauthTotal.exchange(0);          // Frames aus der Umschaltphase verwerfen
    cntDeauthMine.exchange(0);
    hopStart = lastFlush = millis();
    curDwell = isHomeChannel(curCh) ? DWELL_HOME_MS : DWELL_FOREIGN_MS;
}

static void checkBeaconTimeout() {
    const uint32_t now = millis();
    if (now < STARTUP_GRACE_MS) return;
    const uint32_t ref = ownBeaconSeen ? lastOwnBeaconMs : 0;
    if (now - ref > BEACON_TIMEOUT_MS) {
        char d[40];
        snprintf(d, sizeof d, "seit %lus kein Beacon", (unsigned long)((now - ref) / 1000));
        raiseWarn("AP STILL", d);
    }
}

static Level currentLevel() {
    const uint32_t now = millis();
    if (alarmLatched) {
        const bool holdOver = now - alarmSince > ALARM_HOLD_MS;
        const bool condGone = now - alarmLastCond > ALARM_HOLD_MS;
        if (!ALARM_REQUIRE_ACK && holdOver && condGone) {
            alarmLatched = false;
            Serial.println("ALARM auto-clear");
        }
    }
    if (alarmLatched) return LVL_ALARM;
    if (now - warnLast < WARN_HOLD_MS && warnLast != 0) return LVL_WARN;
    return LVL_OK;
}

// ---------------------------------------------------------------------
// Taster
// ---------------------------------------------------------------------
// Gelernte Fingerprints verwerfen (nach Router-Update oder Konfigänderung)
static void relearnFingerprints() {
    for (size_t i = 0; i < WHITELIST_COUNT; i++) {
        fp[i] = Fingerprint();
        char key[8]; snprintf(key, sizeof key, "ie%u", (unsigned)i);
        prefs.remove(key);
    }
    Serial.println("Fingerprints gelöscht, lerne neu");
    raiseWarn("FINGERPRINT NEU", "IE-Hash und TSF werden neu gelernt");
}

static void pollButton() {
    static bool     stable = true, lastRaw = true;
    static uint32_t lastChange = 0, pressedAt = 0;
    static bool     longDone = false;
    const bool raw = digitalRead(PIN_BUTTON);
    const uint32_t now = millis();
    if (raw != lastRaw) { lastRaw = raw; lastChange = now; }
    if (now - lastChange > BUTTON_DEBOUNCE_MS && raw != stable) {
        stable = raw;
        if (!stable) {                       // Flanke: gedrückt
            pressedAt = now; longDone = false;
            if (alarmLatched) Serial.println("ALARM quittiert");
            alarmLatched = false;
            warnLast = 0;
            dispDeauthRate = dispDeauthMine = 0;
            dispDeauthCh = 0;
            strlcpy(twinBssid, "-", sizeof twinBssid);
            twinCh = 0;
        }
    }
    if (!stable && !longDone && now - pressedAt >= BUTTON_LONG_MS) {   // lang gehalten
        longDone = true;
        relearnFingerprints();
    }
}

// ---------------------------------------------------------------------
// Anzeige
// ---------------------------------------------------------------------
static inline void ledWrite(uint8_t r, uint8_t g, uint8_t b) {
#if LED_SWAP_RG
    rgbLedWrite(PIN_RGB_LED, g, r, b);
#else
    rgbLedWrite(PIN_RGB_LED, r, g, b);
#endif
}

// Gamma, damit der lineare Ramp-down visuell linear wirkt (WS2812 ist bei <10 % schon hell)
static uint8_t gammaLed(uint8_t v) {
    const uint32_t x = v;
    return (uint8_t)((x * x * x + 32512) / 65025);   // v^3 / 255^2
}

static void updateLed(Level lvl) {
    static uint32_t lastUpd = 0;
    static Level    lastLvl = LVL_OK;
    static uint32_t phase0 = 0;
    const uint32_t now = millis();
    if (now - lastUpd < LED_UPDATE_MS) return;
    lastUpd = now;
    if (lvl != lastLvl) { lastLvl = lvl; phase0 = now; }   // Muster bei Statuswechsel neu starten
    const uint32_t t = now - phase0;

    switch (lvl) {
        case LVL_OK: {
            const uint32_t p = t % LED_OK_PERIOD_MS;
            uint8_t v = LED_OK_MIN;
            if (p < LED_OK_RAMP_MS)
                v = LED_OK_MAX - (uint32_t)(LED_OK_MAX - LED_OK_MIN) * p / LED_OK_RAMP_MS;
            ledWrite(0, gammaLed(v), 0);
            break;
        }
        case LVL_WARN: {
            const uint32_t half = 1000 / (2 * LED_WARN_HZ);
            const bool on = (t / half) & 1;
            ledWrite(on ? LED_WARN_LEVEL : 0, on ? LED_WARN_LEVEL * 55 / 100 : 0, 0);
            break;
        }
        case LVL_ALARM: {
            const bool red = (t / LED_ALARM_STROBE_MS) & 1;
            ledWrite(red ? 255 : 0, 0, red ? 0 : 255);
            break;
        }
    }
}

static void fmtUptime(char* out, size_t n) {
    uint32_t s = millis() / 1000;
    const uint32_t d = s / 86400; s %= 86400;
    const uint32_t h = s / 3600;  s %= 3600;
    const uint32_t m = s / 60;    s %= 60;
    if (d) snprintf(out, n, "%lud %02lu:%02lu:%02lu", (unsigned long)d, (unsigned long)h, (unsigned long)m, (unsigned long)s);
    else   snprintf(out, n, "%02lu:%02lu:%02lu", (unsigned long)h, (unsigned long)m, (unsigned long)s);
}

static void draw(Level lvl, bool blinkOn) {
    LovyanGFX& g = fbOk ? static_cast<LovyanGFX&>(fb) : static_cast<LovyanGFX&>(lcd);
    uint16_t bg, fg = TFT_WHITE;
    const char* title;
    const char* reason = "";
    const char* detail = "";
    switch (lvl) {
        case LVL_OK:    bg = g.color565(0, 110, 30);  title = "OK";    break;
        case LVL_WARN:  bg = g.color565(200, 150, 0); title = "WARN";  fg = TFT_BLACK; reason = warnReason; detail = warnDetail; break;
        default:        bg = blinkOn ? g.color565(210, 0, 0) : g.color565(70, 0, 0); title = "ALARM"; reason = alarmReason; detail = alarmDetail; break;
    }
    // Querformat: 320 x 172
    const int W = LCD_HEIGHT, H = LCD_WIDTH;
    g.fillScreen(bg);
    g.setTextColor(fg, bg);
    char line[64];

    // Kopfzeile: Titel links (Font4 x1.5 = 39 px), Uptime rechts
    g.setFont(&DejaVuL1B_30);
    g.setTextDatum(textdatum_t::top_left);
    g.drawString(title, 6, 4);
    g.setFont(&DejaVuL1_13);
    g.setTextDatum(textdatum_t::top_right);
    char up[24]; fmtUptime(up, sizeof up);
    snprintf(line, sizeof line, "%s%s", ntfyPending ? "ntfy  " : "", up);
    g.drawString(line, W - 6, 6);
    if (alarmCount) snprintf(line, sizeof line, "drop %lu  #%lu", (unsigned long)ringDrops.load(), (unsigned long)alarmCount);
    else            snprintf(line, sizeof line, "drop %lu", (unsigned long)ringDrops.load());
    g.drawString(line, W - 6, 24);

    // Grund (Font4, 26 px) + Detail (Font2)
    g.setTextDatum(textdatum_t::top_left);
    g.setFont(&DejaVuL1_19);
    g.drawString(reason[0] ? reason : "Netz unauffällig", 6, 48);
    g.setFont(&DejaVuL1_13);
    g.drawString(detail, 6, 78);

    // Trennlinie
    g.drawFastHLine(6, 98, W - 12, fg);

    // Statuszeilen (Font2, 16 px, 3 Zeilen)
    const int lh = 18;
    int y = 104;
    snprintf(line, sizeof line, "Deauth/s %.1f (ch%u)   eigene %.1f", dispDeauthRate, dispDeauthCh, dispDeauthMine);
    g.drawString(line, 6, y); y += lh;

    if (twinCh) snprintf(line, sizeof line, "Twin %s  ch%u  %d dBm", twinBssid, twinCh, twinRssi);
    else        snprintf(line, sizeof line, "Twin %s", twinBssid);
    g.drawString(line, 6, y); y += lh;

    if (ownBeaconSeen)
        snprintf(line, sizeof line, "Scan ch%u   AP ch%u, vor %lu s", curCh, lastOwnBeaconCh,
                 (unsigned long)((millis() - lastOwnBeaconMs) / 1000));
    else
        snprintf(line, sizeof line, "Scan ch%u   AP nicht gesehen", curCh);
    g.drawString(line, 6, y);

    // Kanalbalken unten: 13 Segmente, aktueller Kanal hell, Heimkanal markiert
    {
        const int bx = 6, by = H - 12, bw = (W - 12) / 13, bh = 8;
        for (int c = CH_MIN; c <= CH_MAX; c++) {
            const int x = bx + (c - CH_MIN) * bw;
            const bool cur = (c == curCh), home = (c == lastOwnBeaconCh && ownBeaconSeen);
            if (cur)       g.fillRect(x, by, bw - 2, bh, fg);
            else if (home) g.drawRect(x, by, bw - 2, bh, fg);
            else           g.drawFastHLine(x, by + bh - 1, bw - 2, fg);
        }
    }
    if (fbOk) fb.pushSprite(0, 0);
}

// ---------------------------------------------------------------------
// WiFi / Promiscuous
// ---------------------------------------------------------------------
static void startSniffer() {
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t f = {};
    f.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&f);
    esp_wifi_set_promiscuous_rx_cb(&promiscCb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(curCh, WIFI_SECOND_CHAN_NONE);
    cntDeauthTotal.exchange(0);
    cntDeauthMine.exchange(0);
    hopStart = lastFlush = millis();
    curDwell = DWELL_FOREIGN_MS;
}

#if NTFY_ENABLE
static void sendNtfy() {
    ntfyPending = false;
    const uint32_t now = millis();
    if (lastNtfyMs && now - lastNtfyMs < NTFY_MIN_INTERVAL_MS) { Serial.println("ntfy: rate-limited"); return; }
    lastNtfyMs = now;

    esp_wifi_set_promiscuous(false);
    WiFi.begin(TARGET_SSID, WIFI_PASS);
    const uint32_t t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < NTFY_CONNECT_TIMEOUT_MS) delay(50);

    if (WiFi.status() == WL_CONNECTED) {
        char body[96];
        snprintf(body, sizeof body, "%s\n%s", alarmReason, alarmDetail);
        HTTPClient http;
        int code = -1;
        if (strncmp(NTFY_URL, "https", 5) == 0) {
            WiFiClientSecure cl; cl.setInsecure();
            if (http.begin(cl, NTFY_URL)) {
                http.addHeader("Title", NTFY_TITLE);
                http.addHeader("Priority", "urgent");
                http.addHeader("Tags", "rotating_light");
                code = http.POST((uint8_t*)body, strlen(body));
                http.end();
            }
        } else {
            WiFiClient cl;
            if (http.begin(cl, NTFY_URL)) {
                http.addHeader("Title", NTFY_TITLE);
                http.addHeader("Priority", "urgent");
                code = http.POST((uint8_t*)body, strlen(body));
                http.end();
            }
        }
        Serial.printf("ntfy: HTTP %d\n", code);
    } else {
        Serial.println("ntfy: WLAN-Connect fehlgeschlagen (AP unter Beschuss?)");
    }
    WiFi.disconnect(false, false);
    delay(100);
    startSniffer();
}
#endif

// ---------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(300);
    pinMode(PIN_BUTTON, INPUT_PULLUP);
    targetSsidLen = strlen(TARGET_SSID);

    lcd.init();
    lcd.setRotation(LCD_ROTATION);
    lcd.setBrightness(LCD_BRIGHTNESS);
    fb.setColorDepth(16);
    fbOk = fb.createSprite(lcd.width(), lcd.height()) != nullptr;   // 320x172x2 = 110 KB
    if (!fbOk) Serial.println("Sprite-Alloc fehlgeschlagen, zeichne direkt");
    lcd.fillScreen(TFT_BLACK);
    lcd.setTextColor(TFT_WHITE);
    lcd.setFont(&DejaVuL1_13);
    lcd.drawString("WLAN-IDS startet …", 4, 4);

    prefs.begin("ids", false);
#if CHECK_IE_HASH
    for (size_t i = 0; i < WHITELIST_COUNT; i++) {
        char key[8]; snprintf(key, sizeof key, "ie%u", (unsigned)i);
        fp[i].ieHash = prefs.getUInt(key, 0);
        if (fp[i].ieHash) Serial.printf("IE-Hash %s aus NVS: %08lX\n", WHITELIST[i].label, (unsigned long)fp[i].ieHash);
    }
#endif
#if EVIDENCE_NVS
    printSavedEvidence();
#endif

    WiFi.persistent(false);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.disconnect(false, false);

    wifi_country_t country = {};
    memcpy(country.cc, "DE", 3);
    country.schan        = CH_MIN;
    country.nchan        = CH_MAX - CH_MIN + 1;
    country.max_tx_power = 20;
    country.policy       = WIFI_COUNTRY_POLICY_MANUAL;
    esp_wifi_set_country(&country);
    esp_wifi_set_ps(WIFI_PS_NONE);

    startSniffer();
    Serial.printf("Sniffer aktiv. SSID=\"%s\" Whitelist=%u\n", TARGET_SSID, (unsigned)WHITELIST_COUNT);
}

void loop() {
    static uint32_t lastDraw = 0;
    static bool blink = false;
    static uint32_t lastBlink = 0;

    processDeauths();          // vor der Bewertung, damit die Klassen-Zähler stimmen
    hopChannel();
    processEvents();
    checkBeaconTimeout();
    pollButton();

    const uint32_t now = millis();
    if (now - lastBlink >= BLINK_MS) { lastBlink = now; blink = !blink; }

    const Level lvl = currentLevel();
    if (now - lastDraw >= REDRAW_MS) {
        lastDraw = now;
        draw(lvl, blink);
    }
    updateLed(lvl);

#if NTFY_ENABLE
    if (ntfyPending) sendNtfy();
#endif
    delay(2);
}
