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
#include "config.h"
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
    uint8_t bssid[6];
    uint8_t subtype;     // 8 = Beacon, 5 = Probe Response
    uint8_t rxChannel;   // rx_ctrl.channel (kann Nachbarkanal-Bleed sein)
    uint8_t dsChannel;   // DS Parameter Set IE, 0 = fehlt
    uint8_t flags;
    int8_t  rssi;
};

static constexpr uint8_t RING_SIZE = 32;   // Zweierpotenz
static ApEvent               ring[RING_SIZE];
static volatile uint8_t      ringHead = 0;  // Producer (WiFi-Task)
static volatile uint8_t      ringTail = 0;  // Consumer (loop)
static std::atomic<uint32_t> ringDrops{0};

static std::atomic<uint32_t> cntDeauthTotal{0};
static std::atomic<uint32_t> cntDeauthMine{0};
static std::atomic<uint32_t> cntMgmtTotal{0};

static size_t targetSsidLen = 0;

static int whitelistIndex(const uint8_t* mac) {
    for (size_t i = 0; i < WHITELIST_COUNT; i++)
        if (memcmp(WHITELIST[i].bssid, mac, 6) == 0) return (int)i;
    return -1;
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
        if (whitelistIndex(a1) >= 0 || whitelistIndex(a2) >= 0 || whitelistIndex(a3) >= 0)
            cntDeauthMine.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (subtype != 0x08 && subtype != 0x05) return;   // nur Beacon / Probe Resp

    const uint8_t* body = p + 24;
    int blen = len - 24;
    if (blen < 12) return;                        // TS(8)+Interval(2)+Cap(2)

    const uint8_t* ie = body + 12;
    int rem = blen - 12;
    uint8_t flags = 0, ds = 0;
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

static void macToStr(const uint8_t* m, char* out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
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

static void raiseAlarm(const char* reason, const char* detail) {
    const uint32_t now = millis();
    const bool fresh = !alarmLatched;
    alarmLatched = true;
    alarmLastCond = now;
    if (fresh) alarmSince = now;
    strlcpy(alarmReason, reason, sizeof alarmReason);
    strlcpy(alarmDetail, detail, sizeof alarmDetail);
    Serial.printf("[%lu] ALARM %s | %s\n", (unsigned long)now, reason, detail);
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
    const bool windowFull = cs.airtimeMs >= RATE_WINDOW_MS;
    const bool early = cs.total >= DEAUTH_TOTAL_PER_S || cs.mine >= DEAUTH_MINE_PER_S;
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
    if (cs.lastRateMine > DEAUTH_MINE_PER_S) {
        snprintf(d, sizeof d, "%.0f/s eig. BSSID ch%u", cs.lastRateMine, ch);
        raiseAlarm("DEAUTH eig. BSSID", d);
    } else if (cs.lastRateTotal > DEAUTH_TOTAL_PER_S) {
        snprintf(d, sizeof d, "%.0f/s gesamt ch%u", cs.lastRateTotal, ch);
        raiseAlarm("DEAUTH-Flut", d);
    }
    cs.total = cs.mine = cs.airtimeMs = 0;
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
            if (e.subtype == 8) {
                lastOwnBeaconMs = millis();
                ownBeaconSeen   = true;
                lastOwnBeaconCh = effCh;
            }
            // Regel 4: Kanalabweichung
#if CHECK_CHANNEL
            const int idx = whitelistIndex(e.bssid);
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
static void pollButton() {
    static bool     stable = true, lastRaw = true;
    static uint32_t lastChange = 0;
    const bool raw = digitalRead(PIN_BUTTON);
    const uint32_t now = millis();
    if (raw != lastRaw) { lastRaw = raw; lastChange = now; }
    if (now - lastChange > BUTTON_DEBOUNCE_MS && raw != stable) {
        stable = raw;
        if (!stable) {                       // Flanke: gedrückt
            if (alarmLatched) Serial.println("ALARM quittiert");
            alarmLatched = false;
            warnLast = 0;
            dispDeauthRate = dispDeauthMine = 0;
            dispDeauthCh = 0;
            strlcpy(twinBssid, "-", sizeof twinBssid);
        }
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
    snprintf(line, sizeof line, "drop %lu", (unsigned long)ringDrops.load());
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
