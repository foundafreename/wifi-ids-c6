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
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <esp_timer.h>
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
#ifndef TIMEZONE
#define TIMEZONE "CET-1CEST,M3.5.0,M10.5.0/3"
#endif
#ifndef LED_WARN_PERIOD_MS
#define LED_WARN_PERIOD_MS 800
#endif
#ifndef LED_WARN_RAMP_MS
#define LED_WARN_RAMP_MS 640
#endif
#ifndef LED_ALARM_PERIOD_MS
#define LED_ALARM_PERIOD_MS 300
#endif
#ifndef LED_ALARM_RAMP_MS
#define LED_ALARM_RAMP_MS 240
#endif
#ifndef LED_GAMMA
#define LED_GAMMA 2.2f
#endif
#ifndef LED_TICK_MS
#define LED_TICK_MS 4
#endif
#ifndef BUTTON_DOUBLE_MS
#define BUTTON_DOUBLE_MS 350
#endif
#define IE_HASH_VERSION 2   // hochzählen, wenn sich ändert, was in den Hash eingeht
#include "font_fira_r13.h"    // Fira Sans, Latin-1, generiert mit tools/gen_gfxfont.py
#include "font_fira_r16.h"
#include "font_fira_s14.h"
#include "font_fira_s22.h"
#include "font_fira_b30.h"
#include "font_fira_b46.h"    // nur Ziffern und Satzzeichen, fuer die grosse Uhr (quer)
#include "font_fira_b56.h"    // dito, hochkant

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
    uint32_t ieHash;      // FNV-1a über Identitäts-IEs (Whitelist, siehe promiscCb)
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

// Client-Ereignisse (An-/Abmeldung), für die Pi-Bridge als EV-Zeilen
enum : uint8_t { CE_AUTH = 1, CE_ASSOC_REQ, CE_JOIN, CE_JOIN_FAIL, CE_LEAVE, CE_KICK };
struct ClientEvent {
    uint8_t  mac[6];
    uint8_t  kind;
    uint8_t  subtype;
    int8_t   rssi;
    uint16_t code;       // Reason bzw. Status
};
static constexpr uint8_t CRING_SIZE = 16;
static ClientEvent           cring[CRING_SIZE];
static volatile uint8_t      cringHead = 0, cringTail = 0;
static std::atomic<uint32_t> cringDrops{0};

static void pushClient(const uint8_t* mac, uint8_t kind, uint8_t subtype, int8_t rssi, uint16_t code) {
    const uint8_t head = cringHead;
    const uint8_t next = (head + 1) & (CRING_SIZE - 1);
    if (next == cringTail) { cringDrops.fetch_add(1, std::memory_order_relaxed); return; }
    ClientEvent& c = cring[head];
    memcpy(c.mac, mac, 6);
    c.kind = kind; c.subtype = subtype; c.rssi = rssi; c.code = code;
    cringHead = next;
}

// Regel-6-Kalibrierung: RSSI von Unicast-Management-Frames des eigenen AP
static std::atomic<uint32_t> uniRssiSum{0};   // Summe der Beträge (RSSI ist negativ)
static std::atomic<uint32_t> uniRssiN{0};
static std::atomic<int8_t>   uniRssiLast{0};

// Debug: nach IE-Alarm einmal die IE-Liste des nächsten eigenen Beacons
// sichern (id, len, bei Vendor OUI+Typ), damit man sieht, was sich ändert.
static volatile bool ieDumpWanted = false;
static volatile bool ieDumpReady  = false;
static uint8_t       ieDump[160];
static uint8_t       ieDumpLen = 0;

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

    const bool a1Mine = whitelistIndex(a1) >= 0;
    const bool a2Mine = whitelistIndex(a2) >= 0;

    if (subtype == 0x0C || subtype == 0x0A) {     // Deauth / Disassoc
        cntDeauthTotal.fetch_add(1, std::memory_order_relaxed);
        const uint16_t reason = (len >= 26) ? (uint16_t)(p[24] | (p[25] << 8)) : 0;
        if (a1Mine || a2Mine || whitelistIndex(a3) >= 0) {
            cntDeauthMine.fetch_add(1, std::memory_order_relaxed);
            const uint8_t head = dringHead;
            const uint8_t next = (head + 1) & (DRING_SIZE - 1);
            if (next == dringTail) { dringDrops.fetch_add(1, std::memory_order_relaxed); return; }
            DeauthEvent& d = dring[head];
            memcpy(d.a1, a1, 6);
            memcpy(d.a2, a2, 6);
            d.reason  = reason;
            d.rssi    = pkt->rx_ctrl.rssi;
            d.ch      = pkt->rx_ctrl.channel;
            d.subtype = subtype;
            dringHead = next;
            // Client-Sicht: Client verabschiedet sich selbst, oder AP wirft ihn raus
            // (Reason 7 ist die Antwort auf Frames eines unbekannten Clients, kein Rauswurf)
            if (!a2Mine && a1Mine)                            pushClient(a2, CE_LEAVE, subtype, pkt->rx_ctrl.rssi, reason);
            else if (a2Mine && !a1Mine && reason != 7 && !(a1[0] & 1)) pushClient(a1, CE_KICK, subtype, pkt->rx_ctrl.rssi, reason);
        }
        return;
    }
    // Kalibrierung für Regel 6: Unicast-Management vom eigenen AP (Auth 0x0B,
    // Assoc Resp 0x01, Reassoc Resp 0x03, Action 0x0D) muss mit Beacon-RSSI
    // ankommen. Tut es das nicht, ist die RSSI-Regel am Standort unbrauchbar.
    if ((subtype == 0x0B || subtype == 0x01 || subtype == 0x03 || subtype == 0x0D) && a2Mine) {
        uniRssiSum.fetch_add((uint32_t)(int32_t)(-pkt->rx_ctrl.rssi), std::memory_order_relaxed);
        uniRssiN.fetch_add(1, std::memory_order_relaxed);
        uniRssiLast.store(pkt->rx_ctrl.rssi, std::memory_order_relaxed);
        // Assoc/Reassoc Response: Status-Code bei Body-Offset 2
        if ((subtype == 0x01 || subtype == 0x03) && len >= 30) {
            const uint16_t status = (uint16_t)(p[26] | (p[27] << 8));
            pushClient(a1, status == 0 ? CE_JOIN : CE_JOIN_FAIL, subtype, pkt->rx_ctrl.rssi, status);
        }
        return;
    }
    // Client meldet sich an: Auth / Assoc Req / Reassoc Req an unsere BSSID
    if ((subtype == 0x0B || subtype == 0x00 || subtype == 0x02) && a1Mine && !a2Mine) {
        pushClient(a2, subtype == 0x0B ? CE_AUTH : CE_ASSOC_REQ, subtype, pkt->rx_ctrl.rssi, 0);
        return;
    }
    if (subtype != 0x08 && subtype != 0x05) return;   // nur Beacon / Probe Resp

    const uint8_t* body = p + 24;
    int blen = len - 24;
    if (blen < 12) return;                        // TS(8)+Interval(2)+Cap(2)

    const uint8_t* ie = body + 12;
    int rem = blen - 12;
    uint8_t flags = 0, ds = 0;
    uint32_t h = fnv1a(2166136261u, body + 8, 2);   // Beacon-Intervall. Capability nicht: Short-Slot-Bit kippt mit Legacy-Clients
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
        // IE-Fingerprint, Whitelist: nur IEs, die die Identität des APs
        // beschreiben und sich im Betrieb nicht ändern. Alles andere (TIM,
        // ERP-Protection, BSS Load, HT/HE Operation, CSA, BSS Color) kippt
        // mit Clients oder Nachbarn und bleibt draußen.
        switch (id) {
            case 0:   // SSID
            case 1:   // Supported Rates
            case 3:   // DS Parameter
            case 7:   // Country
            case 45:  // HT Capabilities
            case 48:  // RSN
            case 50:  // Extended Supported Rates
            case 127: // Extended Capabilities
                h = fnv1a(h, ie, 2 + l);
                break;
            case 221: // Vendor: nur OUI + Typ, Länge/Inhalt nicht (WPS, AVM-IEs variieren)
                h = fnv1a(h, ie, 1);
                h = fnv1a(h, ie + 2, l < 4 ? l : 4);
                break;
            case 255: // Extension: nur HE Capabilities (35)
                if (l >= 1 && ie[2] == 35) h = fnv1a(h, ie, 2 + l);
                break;
            default: break;
        }
        ie  += 2 + l;
        rem -= 2 + l;
    }
    if (whitelistIndex(a3) >= 0) flags |= EV_WHITELISTED;
    if (!(flags & (EV_SSID_MATCH | EV_WHITELISTED))) return;   // fremde Netze ignorieren

    if (ieDumpWanted && !ieDumpReady && subtype == 0x08 && (flags & EV_WHITELISTED)) {
        uint8_t n = 0;
        const uint8_t* q = body + 12; int r = blen - 12;
        while (r >= 2 && n + 6 <= sizeof ieDump) {
            const uint8_t id = q[0], l = q[1];
            if (l + 2 > r) break;
            ieDump[n++] = id; ieDump[n++] = l;
            if (id == 221 || id == 255) {                 // OUI+Typ bzw. Ext-ID
                const uint8_t k = (id == 221) ? 4 : 1;
                for (uint8_t i = 0; i < k; i++) ieDump[n++] = (i < l) ? q[2 + i] : 0;
            }
            q += 2 + l; r -= 2 + l;
        }
        ieDumpLen = n;
        ieDumpWanted = false;
        ieDumpReady  = true;
    }

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
static time_t   alarmSinceT = 0, alarmLastT = 0;   // Wallclock, 0 = unbekannt
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

// Wallclock kommt von außen (Serial "T<unix>", z. B. von der Pi-Bridge).
// Ohne gesetzte Zeit bleibt alles bei Uptime.
static bool timeValid() { return time(nullptr) > 1700000000; }
static void fmtClock(char* out, size_t n, time_t t) {
    struct tm tmv; localtime_r(&t, &tmv);
    strftime(out, n, "%H:%M:%S", &tmv);
}
static void fmtClockShort(char* out, size_t n, time_t t) {
    struct tm tmv; localtime_r(&t, &tmv);
    strftime(out, n, "%H:%M", &tmv);
}
// Uptime-Millisekunden in Wallclock, wenn der Boot-Zeitpunkt bekannt ist
static void fmtStamp(char* out, size_t n, uint32_t ms, time_t bootEpoch) {
    if (bootEpoch) fmtClock(out, n, bootEpoch + (time_t)(ms / 1000));
    else           snprintf(out, n, "%lu", (unsigned long)ms);
}
static time_t bootEpochNow() { return timeValid() ? time(nullptr) - (time_t)(millis() / 1000) : 0; }

static const char* clsName(uint8_t cls) {
    switch (cls & 3) {
        case CLS_FROM_AP: return "AP";
        case CLS_SPOOFED: return "SPOOF";
        default:          return "fremd";
    }
}

static void dumpEvidenceBuf(const char* head, const Evidence* log, uint8_t head_, uint8_t count, time_t bootEpoch) {
    char sa[18], da[18], ts[16];
    Serial.printf("%s (%u Einträge, drop %lu):\n", head, count, (unsigned long)dringDrops.load());
    for (uint8_t i = 0; i < count; i++) {
        const Evidence& e = log[(head_ + EVIDENCE_SIZE - count + i) % EVIDENCE_SIZE];
        macToStr(e.sa, sa); macToStr(e.da, da); fmtStamp(ts, sizeof ts, e.ms, bootEpoch);
        Serial.printf("  [%s] %s ch%u SA=%s DA=%s reason=%u %ddBm %s\n", ts,
                      (e.cls & 0x80) ? "Disassoc" : "Deauth", e.ch, sa, da, e.reason, e.rssi, clsName(e.cls));
    }
}

static void dumpEvidence(const char* head) { dumpEvidenceBuf(head, evLog, evHead, evCount, bootEpochNow()); }

#if EVIDENCE_NVS
static void saveEvidence(const char* reason, const char* detail) {
    if (!evDirty) return;
    prefs.putBytes("ev", evLog, sizeof evLog);
    prefs.putUChar("evh", evHead);
    prefs.putUChar("evn", evCount);
    prefs.putString("evr", reason);
    prefs.putString("evd", detail);
    prefs.putUInt("evu", millis() / 1000);
    prefs.putUInt("evb", (uint32_t)bootEpochNow());
    evDirty = false;
}

// Gesicherten Dump ausgeben, ohne das RAM-Log anzufassen. Beim Boot und auf
// Serial-Kommando 'd', weil der USB-Port nach einem Reset erst neu enumeriert
// und die Boot-Ausgabe am Host meist verloren geht.
static void printSavedEvidence() {
    if (!prefs.isKey("evr")) { Serial.println("NVS: kein gesicherter Alarm"); return; }
    Serial.printf("Letzter gesicherter Alarm: %s | %s (Uptime damals %lu s)\n",
                  prefs.getString("evr").c_str(), prefs.getString("evd").c_str(),
                  (unsigned long)prefs.getUInt("evu"));
    if (prefs.getBytesLength("ev") == sizeof evLog) {
        static Evidence saved[EVIDENCE_SIZE];
        prefs.getBytes("ev", saved, sizeof saved);
        dumpEvidenceBuf("Beweis-Log (NVS)", saved, prefs.getUChar("evh"), prefs.getUChar("evn"), (time_t)prefs.getUInt("evb", 0));
    }
}
#else
static void printSavedEvidence() {}
#endif
#if 0
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
    // Zähler: Episoden, nicht Reason-Wechsel. Sonst zählt "eig. BSSID" / "gespooft"
    // im Wechsel pro Frame hoch (1454 in einer Nacht).
    const bool episode = fresh || now - alarmLastCond > ALARM_HOLD_MS;
    alarmLatched = true;
    alarmLastCond = now;
    if (fresh) { alarmSince = now; alarmSinceT = timeValid() ? time(nullptr) : 0; }
    if (timeValid()) alarmLastT = time(nullptr);
    if (episode) alarmCount++;
    strlcpy(alarmReason, reason, sizeof alarmReason);
    strlcpy(alarmDetail, detail, sizeof alarmDetail);
    if (changed) {
        Serial.printf("[%lu] ALARM #%lu %s | %s\n", (unsigned long)now, (unsigned long)alarmCount, reason, detail);
        Serial.printf("EV ALARM|%s|%s\n", reason, detail);
    }
    secureEvidence(reason, detail);
#if NTFY_ENABLE
    if (fresh) ntfyPending = true;
#endif
}

static void raiseWarn(const char* reason, const char* detail) {
    const uint32_t now = millis();
    if (now - warnLast > 5000 || strcmp(warnReason, reason) != 0)
    {
        Serial.printf("[%lu] WARN  %s | %s\n", (unsigned long)now, reason, detail);
        Serial.printf("EV WARN|%s|%s\n", reason, detail);
    }
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
        if (f.ieMiss < 255) f.ieMiss++;
        if (f.ieMiss == 2) {
            snprintf(d, sizeof d, "%s %08lX/%08lX", label, (unsigned long)e.ieHash, (unsigned long)f.ieHash);
            raiseAlarm("BSSID GEKLONT (IE)", d);
            ieDumpWanted = true;      // nächsten Beacon dieser BSSID seriell zerlegen
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
// Beacon-RSSI gegen Unicast-Management-RSSI des eigenen AP. Liegen beide
// zusammen, ist Regel 6 am Standort gültig.
static void printCalib() {
    const uint32_t n = uniRssiN.load();
    for (size_t i = 0; i < WHITELIST_COUNT; i++)
        if (fp[i].rssiValid)
            Serial.printf("Kalibrierung %s: Beacon %d dBm", WHITELIST[i].label, fp[i].rssiEma4 / 4);
    if (n) Serial.printf(", Unicast-Mgmt vom AP %lu Frames, Mittel %ld dBm, zuletzt %d dBm\n",
                         (unsigned long)n, -(long)(uniRssiSum.load() / n), (int)uniRssiLast.load());
    else   Serial.println(", noch kein Unicast-Mgmt vom AP gesehen (Auth/Assoc/Action)");
    if (WHITELIST_COUNT > 0 && fp[0].rssiValid)
        Serial.printf("EV CALIB|%d|%lu|%ld\n", fp[0].rssiEma4 / 4, (unsigned long)n, n ? -(long)(uniRssiSum.load() / n) : 0L);
}

static void relearnFingerprints();

// Client-Ereignisse ausgeben. Auth/Assoc-Request nur seriell (Rauschen beim
// Roaming), JOIN/LEAVE/KICK als EV-Zeile für die Bridge, pro MAC entprellt.
static void processClients() {
    static uint8_t  lastMac[6] = {0};
    static uint8_t  lastKind = 0;
    static uint32_t lastMs = 0;
    char mac[18];
    while (cringTail != cringHead) {
        const ClientEvent c = cring[cringTail];
        cringTail = (cringTail + 1) & (CRING_SIZE - 1);
        macToStr(c.mac, mac);
        const uint32_t now = millis();
        const bool dup = (c.kind == lastKind && memcmp(c.mac, lastMac, 6) == 0 && now - lastMs < 5000);
        memcpy(lastMac, c.mac, 6); lastKind = c.kind; lastMs = now;
        if (dup) continue;
        switch (c.kind) {
            case CE_AUTH:      Serial.printf("[%lu] Auth %s %ddBm\n", (unsigned long)now, mac, c.rssi); break;
            case CE_ASSOC_REQ: Serial.printf("[%lu] AssocReq %s %ddBm\n", (unsigned long)now, mac, c.rssi); break;
            case CE_JOIN:      Serial.printf("[%lu] JOIN %s %ddBm\nEV JOIN|%s|%d\n", (unsigned long)now, mac, c.rssi, mac, c.rssi); break;
            case CE_JOIN_FAIL: Serial.printf("[%lu] Assoc abgelehnt %s status=%u\nEV JOINFAIL|%s|%u\n", (unsigned long)now, mac, c.code, mac, c.code); break;
            case CE_LEAVE:     Serial.printf("[%lu] LEAVE %s reason=%u\nEV LEAVE|%s|%u\n", (unsigned long)now, mac, c.code, mac, c.code); break;
            case CE_KICK:      Serial.printf("[%lu] KICK %s reason=%u %ddBm\nEV KICK|%s|%u|%d\n", (unsigned long)now, mac, c.code, c.rssi, mac, c.code, c.rssi); break;
            default: break;
        }
    }
}

// Serial-Kommandos. Einzelzeichen sofort (d, r, h), "T<unix>\n" zeilenweise.
static void pollSerial() {
    static char buf[24];
    static uint8_t n = 0;
    while (Serial.available()) {
        const char c = (char)Serial.read();
        if (n == 0 && (c == 'd' || c == 'r' || c == 'h' || c == '?')) {
            if (c == 'd')      { printSavedEvidence(); dumpEvidence("Beweis-Log (RAM)"); printCalib(); }
            else if (c == 'r') relearnFingerprints();
            else Serial.println("d = Beweis-Log, r = Fingerprints neu lernen, T<unix> = Zeit setzen");
            continue;
        }
        if (c == '\n' || c == '\r') {
            buf[n] = 0;
            if (n > 1 && buf[0] == 'T') {
                const time_t t = (time_t)strtoul(buf + 1, nullptr, 10);
                if (t > 1700000000) {
                    struct timeval tv = { .tv_sec = t, .tv_usec = 0 };
                    settimeofday(&tv, nullptr);
                    char ts[16]; fmtClock(ts, sizeof ts, t);
                    Serial.printf("Zeit gesetzt: %s\nEV TIME|%lu\n", ts, (unsigned long)t);
                } else Serial.println("T: ungültig");
            }
            n = 0;
            continue;
        }
        if (n < sizeof buf - 1) buf[n++] = c; else n = 0;
    }
}

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

static void applyRotation(uint8_t rot);
static uint8_t dispRotation = LCD_ROTATION;

static void ackAlarm() {
    if (alarmLatched) { Serial.println("ALARM quittiert"); Serial.println("EV ACK"); }
    alarmLatched = false;
    warnLast = 0;
    dispDeauthRate = dispDeauthMine = 0;
    dispDeauthCh = 0;
    strlcpy(twinBssid, "-", sizeof twinBssid);
    twinCh = 0;
}

// BOOT: 1x = quittieren (nach BUTTON_DOUBLE_MS ohne zweiten Druck),
// 2x = Display um 90 Grad drehen, halten = Fingerprints neu lernen
static void pollButton() {
    static bool     stable = true, lastRaw = true;
    static uint32_t lastChange = 0, pressedAt = 0, releasedAt = 0;
    static bool     longDone = false;
    static uint8_t  clicks = 0;
    const bool raw = digitalRead(PIN_BUTTON);
    const uint32_t now = millis();
    if (raw != lastRaw) { lastRaw = raw; lastChange = now; }
    if (now - lastChange > BUTTON_DEBOUNCE_MS && raw != stable) {
        stable = raw;
        if (!stable) { pressedAt = now; longDone = false; }
        else if (!longDone) {
            releasedAt = now;
            clicks++;
            if (clicks >= 2) {
                clicks = 0;
                applyRotation((dispRotation + 1) & 3);
            }
        }
    }
    if (!stable && !longDone && now - pressedAt >= BUTTON_LONG_MS) {   // lang gehalten
        longDone = true; clicks = 0;
        relearnFingerprints();
    }
    if (clicks == 1 && stable && now - releasedAt > BUTTON_DOUBLE_MS) {  // Einzelklick steht fest
        clicks = 0;
        ackAlarm();
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

// Eine Hüllkurve für alle Stufen: sofort auf Max, dann Ramp-down über
// LED_*_RAMP_MS, Rest der Periode dunkel. Läuft im esp_timer alle LED_TICK_MS,
// unabhängig vom loop(), damit der 25-ms-Display-Push keine Stufen frisst.
// 16-Bit-Rechnung plus zeitliches Dithering: die WS2812 kann nur 8 Bit, am
// Rampenende sind das die Werte 3, 2, 1, 0 mit riesigen relativen Sprüngen.
// Der Fehler zwischen Soll (16 Bit) und Ist (8 Bit) wird in den nächsten
// Tick mitgenommen, die LED wechselt dann schnell zwischen n und n+1.
static volatile Level ledLevel = LVL_OK;
static esp_timer_handle_t ledTimer = nullptr;

struct LedPattern { uint8_t r, g, b; uint16_t periodMs, rampMs; uint16_t minLevel; };
static const LedPattern LED_PAT[3] = {
    { 0,   255, 0,   LED_OK_PERIOD_MS,    LED_OK_RAMP_MS,    LED_OK_MIN * 257u },
    { 255, 140, 0,   LED_WARN_PERIOD_MS,  LED_WARN_RAMP_MS,  0 },
    { 255, 0,   0,   LED_ALARM_PERIOD_MS, LED_ALARM_RAMP_MS, 0 },
};

// Gamma 2,2 auf 16 Bit, Eingang 0..65535
static uint16_t gamma16(uint16_t v) {
    const float x = v / 65535.0f;
    return (uint16_t)(powf(x, LED_GAMMA) * 65535.0f + 0.5f);
}

static void ledTick(void*) {
    static Level    lastLvl = LVL_OK;
    static int64_t  phase0 = 0;
    static int32_t  err[3] = {0, 0, 0};
    const int64_t nowUs = esp_timer_get_time();
    const Level lvl = ledLevel;
    if (lvl != lastLvl) { lastLvl = lvl; phase0 = nowUs; err[0] = err[1] = err[2] = 0; }
    const LedPattern& pat = LED_PAT[lvl];
    const uint32_t t = (uint32_t)((nowUs - phase0) / 1000) % pat.periodMs;

    // Hüllkurve linear in 16 Bit, dann Gamma
    uint32_t lin = pat.minLevel;
    if (t < pat.rampMs) lin = 65535u - (uint32_t)(65535u - pat.minLevel) * t / pat.rampMs;
    const uint32_t env = gamma16((uint16_t)lin);

    uint8_t out[3];
    const uint8_t col[3] = { pat.r, pat.g, pat.b };
    for (int i = 0; i < 3; i++) {
        const int32_t want = (int32_t)(env * col[i] / 255) + err[i];   // 16-Bit-Soll inkl. Restfehler
        int32_t q = (want + 128) / 257;                                 // auf 8 Bit runden
        if (q < 0) q = 0; if (q > 255) q = 255;
        err[i] = want - q * 257;
        if (err[i] > 257) err[i] = 257; if (err[i] < -257) err[i] = -257;
        out[i] = (uint8_t)q;
    }
    ledWrite(out[0], out[1], out[2]);
}

static void startLed() {
    const esp_timer_create_args_t a = { .callback = &ledTick, .arg = nullptr,
                                        .dispatch_method = ESP_TIMER_TASK, .name = "led", .skip_unhandled_events = true };
    esp_timer_create(&a, &ledTimer);
    esp_timer_start_periodic(ledTimer, (uint64_t)LED_TICK_MS * 1000);
}

static void updateLed(Level lvl) { ledLevel = lvl; }

static void fmtUptime(char* out, size_t n) {
    uint32_t s = millis() / 1000;
    const uint32_t d = s / 86400; s %= 86400;
    const uint32_t h = s / 3600;  s %= 3600;
    const uint32_t m = s / 60;    s %= 60;
    if (d) snprintf(out, n, "%lud %02lu:%02lu:%02lu", (unsigned long)d, (unsigned long)h, (unsigned long)m, (unsigned long)s);
    else   snprintf(out, n, "%02lu:%02lu:%02lu", (unsigned long)h, (unsigned long)m, (unsigned long)s);
}

// Ein Satz Klartext je Alarm-/Warngrund, wird je nach Breite umgebrochen
static const char* explain(const char* reason) {
    struct Ex { const char* key; const char* text; };
    static const Ex tab[] = {
        { "DEAUTH eig. BSSID",   "Jemand wirft Geräte aus deinem WLAN. Wer: siehe Serial. WPA3-Geräte sind immun." },
        { "DEAUTH gespooft",     "Deauths mit deiner BSSID, aber falscher Signalstärke. Nicht vom Router: Angriff." },
        { "DEAUTH-Flut",         "Deauth-Flut gegen ein fremdes Netz. Nicht dein WLAN, aber jemand in Reichweite." },
        { "DEAUTH vom AP",       "Dein Router selbst trennt Geräte. Meist ein Gerät in der Reconnect-Schleife." },
        { "EVIL TWIN",           "Fremder AP sendet deine SSID. Nicht verbinden, Passwort nirgends eingeben." },
        { "BSSID GEKLONT (IE)",  "Beacon mit deiner BSSID, anderer Aufbau. Zweiter Sender oder Router-Update. BOOT 3 s." },
        { "BSSID GEKLONT (TSF)", "Zwei Uhren hinter deiner BSSID. Ein zweites Gerät imitiert deinen Router." },
        { "BSSID ohne RSN",      "Dein Router sendet ohne Verschlüsselung. Router-Einstellungen prüfen." },
        { "SSID offen",          "Deine SSID wird unverschlüsselt gesendet. Fremder AP oder Router falsch konfiguriert." },
        { "KANAL abweichend",    "Router auf anderem Kanal als erwartet. Autokanal oder Einstellung geändert." },
        { "AP STILL",            "Kein Beacon vom Router. Router aus, Kanal gewechselt oder gestört." },
        { "TSF-Sprung",          "Die Uhr deines Routers ist gesprungen. Einmal: Neustart. Mehrfach: Klon." },
        { "FINGERPRINT NEU",     "Fingerprints gelöscht. Werden beim nächsten Beacon neu gelernt." },
    };
    for (const Ex& e : tab) if (strcmp(e.key, reason) == 0) return e.text;
    return "";
}

// ---------------------------------------------------------------------
// Renderer. Farben und Formen nach dem Entwurf: Ground schwarz, Glaskarte,
// Ring als Pegel, Status-Pill, Kanalpunkte. Beide Orientierungen.
// ---------------------------------------------------------------------
static constexpr uint32_t C_GROUND = 0x000000, C_TRACK = 0x2a2a32, C_TXT1 = 0xf2f2f5,
                          C_TXT2 = 0xc8c8d0, C_TXT3 = 0x9a9aa6, C_TXT4 = 0x6e6e7a,
                          C_OK = 0x30d158, C_WARN = 0xffb340, C_ALARM = 0xff453a;

static uint32_t stateColor(Level lvl) { return lvl == LVL_ALARM ? C_ALARM : lvl == LVL_WARN ? C_WARN : C_OK; }

// Hüllkurve der LED für das Display (gleiche Phase, gleiche Form)
static float envelope(Level lvl) {
    const LedPattern& pat = LED_PAT[lvl];
    const uint32_t t = (uint32_t)(esp_timer_get_time() / 1000) % pat.periodMs;
    if (t >= pat.rampMs) return 0.0f;
    const float x = 1.0f - (float)t / pat.rampMs;
    return powf(x, LED_GAMMA);
}

// Superellipse n=4 (Squircle), gefuellt, mit Alpha ueber dem Ground
static void fillSquircle(LovyanGFX& g, int x, int y, int w, int h, int r, uint8_t alpha, uint32_t color) {
    if (r * 2 > h) r = h / 2;
    if (r * 2 > w) r = w / 2;
    for (int row = 0; row < h; row++) {
        int inset = 0;
        const int dy = (row < r) ? (r - row) : (row >= h - r) ? (row - (h - r) + 1) : 0;
        if (dy > 0) {
            const float t = (float)dy / r;                 // 0..1
            const float f = powf(1.0f - powf(t, 4.0f), 0.25f);
            inset = r - (int)(f * r + 0.5f);
        }
        g.fillRectAlpha(x + inset, y + row, w - 2 * inset, 1, alpha, color);
    }
    g.fillRectAlpha(x + r, y, w - 2 * r, 1, 30, 0xffffff);   // Highlight oben
}

static void pill(LovyanGFX& g, int x, int y, int h, const char* text, uint32_t accent, uint8_t tintAlpha, float dot) {
    g.setFont(&FiraS14);
    const int tw = g.textWidth(text);
    const int w = 6 + 8 + 6 + tw + 9;
    g.fillRectAlpha(x, y, w, h, tintAlpha, accent);
    g.fillSmoothCircle(x + 6 + 4, y + h / 2, 4, g.color888((uint8_t)(((accent >> 16) & 0xff) * dot), (uint8_t)(((accent >> 8) & 0xff) * dot), (uint8_t)((accent & 0xff) * dot)));
    g.setTextDatum(textdatum_t::middle_left);
    g.setTextColor(accent == C_OK ? C_TXT1 : accent);
    g.drawString(text, x + 6 + 8 + 6, y + h / 2);
}

static void drawRing(LovyanGFX& g, int cx, int cy, int r, int sw, float frac, uint32_t accent, float bright) {
    g.fillArc(cx, cy, r - sw, r, 0, 360, C_TRACK);
    if (frac > 0.005f) {
        const uint32_t c = g.color888((uint8_t)(((accent >> 16) & 0xff) * bright), (uint8_t)(((accent >> 8) & 0xff) * bright), (uint8_t)((accent & 0xff) * bright));
        if (frac > 0.995f) g.fillArc(cx, cy, r - sw, r, 0, 360, c);
        else               g.fillArc(cx, cy, r - sw, r, 270, 270 + frac * 360.0f, c);
    }
}

// Woerter in Zeilen der Breite maxW umbrechen, hoechstens maxLines
static int wrapText(LovyanGFX& g, const char* text, int maxW, char lines[][64], int maxLines) {
    int n = 0; char cur[64] = ""; char word[48];
    const char* p = text;
    while (*p && n < maxLines) {
        while (*p == ' ') p++;
        int wl = 0; while (*p && *p != ' ' && wl < 47) word[wl++] = *p++;
        word[wl] = 0;
        if (!wl) break;
        char test[64]; snprintf(test, sizeof test, "%s%s%s", cur, cur[0] ? " " : "", word);
        if (g.textWidth(test) <= maxW || !cur[0]) strlcpy(cur, test, sizeof cur);
        else { strlcpy(lines[n++], cur, 64); strlcpy(cur, word, sizeof cur); }
    }
    if (cur[0] && n < maxLines) strlcpy(lines[n++], cur, 64);
    return n;
}

static void dots(LovyanGFX& g, int x0, int x1, int y, uint32_t accent) {
    const float step = (float)(x1 - x0) / (CH_MAX - CH_MIN);
    for (int c = CH_MIN; c <= CH_MAX; c++) {
        const int x = x0 + (int)((c - CH_MIN) * step + 0.5f);
        const bool home = ownBeaconSeen && c == lastOwnBeaconCh;
        if (home)            g.fillSmoothCircle(x, y, 4, accent);
        else if (c == curCh) g.fillSmoothCircle(x, y, 3, C_TXT1);
        else                 g.fillSmoothCircle(x, y, 3, C_TRACK);
    }
}

static const char* WDAY[7]  = { "Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag" };
static const char* MONTH[12] = { "Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember" };

static float ringShown = 0;   // geglaetteter Pegel

static void draw(Level lvl) {
    LovyanGFX& g = fbOk ? static_cast<LovyanGFX&>(fb) : static_cast<LovyanGFX&>(lcd);
    const int W = g.width(), H = g.height();
    const bool portrait = H > W;
    const uint32_t accent = stateColor(lvl);
    const float env = envelope(lvl);
    const float bright = (lvl == LVL_ALARM) ? 0.35f + 0.65f * env : 1.0f;
    const char* reason = lvl == LVL_ALARM ? alarmReason : lvl == LVL_WARN ? warnReason : "";
    const char* detail = lvl == LVL_ALARM ? alarmDetail : lvl == LVL_WARN ? warnDetail : "";

    // Pegel: eigene Deauth-Rate relativ zur Alarmschwelle, geglaettet
    const float target = (lvl == LVL_ALARM) ? 1.0f : fminf(dispDeauthMine / (float)DEAUTH_MINE_PER_S, 1.0f);
    ringShown += (target - ringShown) * 0.25f;

    g.fillScreen(C_GROUND);
    char line[64], ts[16];
    const int m = 6;

    // Kopf: Pill links, Uhr rechts
    pill(g, m, 6, 22, lvl == LVL_ALARM ? "ALARM" : lvl == LVL_WARN ? "WARNUNG" : "AKTIV", accent,
         lvl == LVL_ALARM ? 46 : lvl == LVL_WARN ? 36 : 15, lvl == LVL_ALARM ? bright : 1.0f);
    const bool haveTime = timeValid();
    if (haveTime) fmtClock(ts, sizeof ts, time(nullptr)); else fmtUptime(ts, sizeof ts);
    g.setFont(&FiraR16);
    g.setTextColor(C_TXT1);
    g.setTextDatum(textdatum_t::middle_right);
    g.drawString(ts, W - m, 17);
    if (lvl != LVL_OK) {
        char a[8], b[8];
        if (lvl == LVL_ALARM && alarmSinceT) { fmtClockShort(a, sizeof a, alarmSinceT); fmtClockShort(b, sizeof b, alarmLastT); snprintf(line, sizeof line, "%s bis %s · #%lu", a, b, (unsigned long)alarmCount); }
        else if (lvl == LVL_ALARM)          snprintf(line, sizeof line, "seit %lu s · #%lu", (unsigned long)((millis() - alarmSince) / 1000), (unsigned long)alarmCount);
        else                                snprintf(line, sizeof line, "vor %lu s", (unsigned long)((millis() - warnLast) / 1000));
        g.setFont(&FiraR13);
        g.setTextColor(C_TXT3);
        g.setTextDatum(textdatum_t::middle_right);
        if (portrait) g.drawString(line, W - m, 36);
        else          g.drawString(line, W - m - g.textWidth(ts, &FiraR16) - 10, 17);
    }

    // Ring
    int rcx, rcy, rr, sw;
    if (!portrait) { rcx = 50; rcy = 92; rr = 40; sw = 8; }
    else           { rcx = W / 2; rcy = lvl == LVL_OK ? 102 : 96; rr = lvl == LVL_OK ? 52 : 46; sw = 9; }
    drawRing(g, rcx, rcy, rr, sw, lvl == LVL_OK ? ringShown : fmaxf(ringShown, 0.02f), accent, bright);
    snprintf(line, sizeof line, lvl == LVL_ALARM && dispDeauthMine >= 10 ? "%.0f" : "%.1f", dispDeauthMine);
    for (char* c = line; *c; c++) if (*c == '.') *c = ',';
    g.setFont(&FiraB30);
    g.setTextColor(C_TXT1);
    g.setTextDatum(textdatum_t::middle_center);
    g.drawString(line, rcx, rcy - 7);
    g.setFont(&FiraR13);
    g.setTextColor(C_TXT3);
    g.drawString("Deauth/s", rcx, rcy + 15);

    if (lvl == LVL_OK) {
        char last[8] = "";
        if (alarmLastT) fmtClockShort(last, sizeof last, alarmLastT);
        if (haveTime) {
            const time_t t = time(nullptr); struct tm tmv; localtime_r(&t, &tmv);
            strftime(ts, sizeof ts, "%H:%M", &tmv);
            snprintf(line, sizeof line, "%s, %d. %s", WDAY[tmv.tm_wday], tmv.tm_mday, MONTH[tmv.tm_mon]);
            g.setTextColor(C_TXT1);
            if (!portrait) { g.setFont(&FiraB46); g.setTextDatum(textdatum_t::middle_right);  g.drawString(ts, W - m, 84); }
            else           { g.setFont(&FiraB56); g.setTextDatum(textdatum_t::middle_center); g.drawString(ts, W / 2, 196); }
            g.setFont(&FiraR13);
            g.setTextColor(C_TXT3);
            if (!portrait) g.drawString(line, W - m, 116); else g.drawString(line, W / 2, 234);
        } else {
            g.setFont(&FiraR16);
            g.setTextColor(C_TXT3);
            g.setTextDatum(portrait ? textdatum_t::middle_center : textdatum_t::middle_right);
            g.drawString("keine Uhrzeit", portrait ? W / 2 : W - m, portrait ? 196 : 90);
        }
        g.setFont(&FiraR13);
        g.setTextColor(C_TXT4);
        if (!portrait) {
            g.setTextDatum(textdatum_t::middle_left);
            if (ownBeaconSeen) snprintf(line, sizeof line, "Netz unauffällig · AP ch%u vor %lu s", lastOwnBeaconCh, (unsigned long)((millis() - lastOwnBeaconMs) / 1000));
            else               snprintf(line, sizeof line, "Netz unauffällig · AP nicht gesehen");
            g.drawString(line, m, 140);
            if (last[0]) { snprintf(line, sizeof line, "letzter Alarm %s", last); g.setTextDatum(textdatum_t::middle_right); g.drawString(line, W - m, 140); }
        } else {
            g.setTextDatum(textdatum_t::middle_center);
            g.drawString("Netz unauffällig", W / 2, 262);
            if (ownBeaconSeen) snprintf(line, sizeof line, "AP ch%u vor %lu s", lastOwnBeaconCh, (unsigned long)((millis() - lastOwnBeaconMs) / 1000));
            else               snprintf(line, sizeof line, "AP nicht gesehen");
            g.drawString(line, W / 2, 279);
            if (last[0]) { snprintf(line, sizeof line, "letzter Alarm %s", last); g.drawString(line, W / 2, 296); }
        }
    } else {
        // Glaskarte
        int cx, cy, cw, ch;
        if (!portrait) { cx = 100; cy = 42; cw = W - 100 - m; ch = 86; }
        else           { cx = m; cy = 148; cw = W - 2 * m; ch = 90; }
        fillSquircle(g, cx, cy, cw, ch, 12, lvl == LVL_ALARM ? 40 : 26, accent);
        g.setTextDatum(textdatum_t::middle_left);
        g.setFont(&FiraS22);
        g.setTextColor(C_TXT1);
        g.drawString(reason, cx + 10, cy + 20);
        g.setFont(&FiraR16);
        g.setTextColor(C_TXT2);
        g.drawString(detail, cx + 10, cy + 47);
        g.setFont(&FiraR13);
        g.setTextColor(C_TXT3);
        if (twinCh) snprintf(line, sizeof line, "Twin ch%u %d dBm", twinCh, twinRssi);
        else if (ownBeaconSeen) snprintf(line, sizeof line, "AP ch%u vor %lu s · Twin nein", lastOwnBeaconCh, (unsigned long)((millis() - lastOwnBeaconMs) / 1000));
        else snprintf(line, sizeof line, "AP nicht gesehen");
        g.drawString(line, cx + 10, cy + 70);
        // Erklaerung, umgebrochen
        char lines[3][64];
        g.setFont(&FiraR16);
        const int n = wrapText(g, explain(reason), W - 2 * m, lines, portrait ? 3 : 2);
        int y = portrait ? 254 : 140;
        for (int i = 0; i < n; i++) {
            g.setTextColor(i == 0 ? C_TXT1 : C_TXT3);
            g.drawString(lines[i], m, y);
            y += 19;
        }
    }

    dots(g, m + 4, W - m - 4, H - 8, accent);
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
// Display drehen, Sprite neu anlegen (0/2 hochkant, 1/3 quer), in NVS merken
static void applyRotation(uint8_t rot) {
    dispRotation = rot & 3;
    lcd.setRotation(dispRotation);
    if (fbOk) fb.deleteSprite();
    fbOk = fb.createSprite(lcd.width(), lcd.height()) != nullptr;   // 320x172x2 = 110 KB
    if (!fbOk) Serial.println("Sprite-Alloc fehlgeschlagen, zeichne direkt");
    prefs.putUChar("rot", dispRotation);
    Serial.printf("Rotation %u (%ux%u)\n", dispRotation, lcd.width(), lcd.height());
}

void setup() {
    Serial.begin(115200);
#if ARDUINO_USB_CDC_ON_BOOT
    Serial.setTxTimeoutMs(10);     // ohne Host am USB nicht blockieren
#endif
    delay(300);
    pinMode(PIN_BUTTON, INPUT_PULLUP);
    targetSsidLen = strlen(TARGET_SSID);

    lcd.init();
    lcd.setBrightness(LCD_BRIGHTNESS);
    fb.setColorDepth(16);
    prefs.begin("ids", false);
    applyRotation(prefs.getUChar("rot", LCD_ROTATION));
    lcd.fillScreen(TFT_BLACK);
    lcd.setTextColor(TFT_WHITE);
    lcd.setFont(&FiraR16);
    lcd.drawString("WLAN-IDS startet", 6, 6);

#if CHECK_IE_HASH
    // Hash-Algorithmus geändert -> alte Werte wegwerfen, sonst Alarm beim ersten Beacon
    if (prefs.getUChar("iev", 0) != IE_HASH_VERSION) {
        for (size_t i = 0; i < WHITELIST_COUNT; i++) {
            char key[8]; snprintf(key, sizeof key, "ie%u", (unsigned)i);
            prefs.remove(key);
        }
        prefs.putUChar("iev", IE_HASH_VERSION);
    }
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

    startLed();
    startSniffer();
    setenv("TZ", TIMEZONE, 1);
    tzset();
    Serial.printf("Sniffer aktiv. SSID=\"%s\" Whitelist=%u\n", TARGET_SSID, (unsigned)WHITELIST_COUNT);
    Serial.println("EV BOOT");
}

void loop() {
    static uint32_t lastDraw = 0;

    processDeauths();          // vor der Bewertung, damit die Klassen-Zähler stimmen
    hopChannel();
    processEvents();
    checkBeaconTimeout();
    if (ieDumpReady) {
        Serial.print("IE-Liste (id:len):");
        for (uint8_t i = 0; i + 1 < ieDumpLen;) {
            const uint8_t id = ieDump[i], l = ieDump[i + 1];
            i += 2;
            if (id == 221 && i + 4 <= ieDumpLen) {
                Serial.printf(" 221:%u[%02X%02X%02X:%u]", l, ieDump[i], ieDump[i + 1], ieDump[i + 2], ieDump[i + 3]);
                i += 4;
            } else if (id == 255 && i + 1 <= ieDumpLen) {
                Serial.printf(" 255.%u:%u", ieDump[i], l);
                i += 1;
            } else Serial.printf(" %u:%u", id, l);
        }
        Serial.println();
        ieDumpReady = false;
    }
    pollButton();
    pollSerial();
    processClients();
    {
        static uint32_t lastCalib = 0;
        if (millis() - lastCalib > 60000) { lastCalib = millis(); printCalib(); }
    }

    const uint32_t now = millis();

    const Level lvl = currentLevel();
    if (now - lastDraw >= REDRAW_MS) {
        lastDraw = now;
        draw(lvl);
    }
    updateLed(lvl);

#if NTFY_ENABLE
    if (ntfyPending) sendNtfy();
#endif
    delay(2);
}
