#pragma once
#include <stdint.h>

// =====================================================================
// Eigenes Netz
// =====================================================================
#define TARGET_SSID        "MeinWLAN"            // exakt wie im Beacon (case-sensitiv)

// Whitelist: alle legitimen BSSIDs, die TARGET_SSID ausstrahlen dürfen.
// FritzBox 7510: 2,4-GHz-BSSID. Mesh-Repeater/Powerline-WLAN mit gleicher
// SSID müssen hier ebenfalls rein, sonst Evil-Twin-Alarm.
// expectedChannel = 0 -> Kanal nicht prüfen (FritzBox-Autokanal).
struct ApEntry {
    uint8_t     bssid[6];
    uint8_t     expectedChannel;
    const char* label;
};

static const ApEntry WHITELIST[] = {
    { {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, "FritzBox 2.4G" },   // <- deine BSSID; expectedChannel 0 = Autokanal
};
#define WHITELIST_COUNT (sizeof(WHITELIST) / sizeof(WHITELIST[0]))

// Beim Erststart: Whitelist leer lassen -> jedes Beacon mit TARGET_SSID
// wird seriell geloggt, BSSID + Kanal daraus abschreiben.
#define LOG_SSID_MATCHES   1

// =====================================================================
// Erkennungsregeln
// =====================================================================
// Regel 1: Deauth/Disassoc-Rate, bezogen auf *Airtime auf dem jeweiligen
// Kanal* (nicht Wanduhr). ">" Schwelle -> ALARM.
#define DEAUTH_TOTAL_PER_S   20     // alle BSSIDs
#define DEAUTH_MINE_PER_S    5      // addr1/2/3 in Whitelist
#define RATE_WINDOW_MS       1000   // Airtime-Fenster je Kanal
// Ohne Mindestfenster reichen 5 Frames in 330 ms für "15/s". Ein Router, der
// beim Rekey 5 Clients auf einmal kickt, sieht dann aus wie ein Angriff.
#define DEAUTH_MIN_WINDOW_MS 1000   // erst ab so viel Airtime bewerten
#define DEAUTH_MINE_MIN_FRAMES  8   // und mindestens so viele Frames gegen eigene BSSID
#define DEAUTH_TOTAL_MIN_FRAMES 20  // bzw. gesamt

// Regel 6: RSSI-Plausibilität. Ein Deauth mit SA = eigene BSSID muss ungefähr
// so laut ankommen wie die Beacons dieser BSSID. Weicht er stärker ab, hat ihn
// jemand anderes gesendet. Das Board gehört dafür nah an den Router.
#define RSSI_SPOOF_DELTA_DB  10
#define DEAUTH_SPOOF_MIN_FRAMES 3   // so viele gespoofte Frames im Fenster -> ALARM
// Sind alle Deauths plausibel vom AP (RSSI passt, keine fremden Sender), ist
// das meist ein Client in der Reconnect-Schleife, kein Angriff. 1 = nur WARN.
#define DEAUTH_FROM_AP_IS_WARN 1

// Regel 2b: geklonte BSSID. Zwei Sender mit gleicher BSSID haben zwei
// TSF-Zähler; der Offset Beacon-TSF minus Empfangszeit springt dann hin und
// her. Dazu ein Hash über die IE-Struktur des Beacons: ein hostapd-Twin
// reproduziert das IE-Set einer FritzBox nicht.
#define CHECK_TSF            1
#define TSF_JUMP_US          3000   // Toleranz: Drift 40 ppm x 22 s Sweep = 0,9 ms, plus Latenz
#define TSF_JUMPS_FOR_ALARM  3      // so viele Sprünge in TSF_JUMP_WINDOW_MS -> ALARM, einzelner Sprung = WARN (AP-Neustart)
#define TSF_JUMP_WINDOW_MS   10000
#define CHECK_IE_HASH        1      // Hash beim ersten Beacon lernen, in NVS merken; Abweichung -> ALARM
                                    // Nach Router-Update/Konfigänderung: BOOT 3 s halten, dann neu lernen

// Beweis-Log: die letzten Deauths gegen eigene BSSID (SA, DA, Reason, RSSI,
// Kanal). Wird bei ALARM seriell ausgegeben und in NVS gesichert, beim
// nächsten Boot wieder ausgegeben. Sonst ist nach einem Reset nichts mehr da.
#define EVIDENCE_SIZE        16
#define EVIDENCE_NVS         1

// Regel 3: WPA1-only (Vendor-IE 00:50:F2:01 ohne RSN-IE) als sicher werten?
#define TREAT_WPA1_AS_SECURE 0

// Regel 4: Kanalabweichung bekannter BSSID -> WARN (0 = global aus)
#define CHECK_CHANNEL        1

// Regel 5: kein Beacon einer Whitelist-BSSID seit X ms -> WARN
#define BEACON_TIMEOUT_MS    30000
#define STARTUP_GRACE_MS     20000  // nach Boot erst mal Ruhe

// =====================================================================
// Kanal-Hopping (Country DE: 1–13)
// =====================================================================
#define CH_MIN               1
#define CH_MAX               13
// Trade-off Deauth-Burst (100–500 ms, nur auf Heimkanal relevant) vs. Twin auf
// Fremdkanal. P(Burst gesehen) ≈ (Burst + HOME) / Zyklus, Zyklus = HOME + 12·FOREIGN.
//   HOME   400 / FOREIGN 150: Zyklus 2,2 s, Heimanteil 18 %, Burst-P 23–41 %, Twin-Latenz ≤ 2 s
//   HOME  5000 / FOREIGN 150: Zyklus 6,8 s, Heimanteil 74 %, Burst-P 75–81 %, Twin-Latenz ≤ 7 s
//   HOME 20000 / FOREIGN 150: Zyklus 21,8 s, Heimanteil 92 %, Burst-P 92–94 %, Twin-Latenz ≤ 22 s
//   HOME 0xFFFFFFFF: nur Heimkanal (Sweep nur initial / bei AP-Verlust), Twin nur auf Heimkanal
#define DWELL_FOREIGN_MS     150    // >= Beacon-Intervall 102,4 ms -> 1 Beacon pro Besuch garantiert
#define DWELL_HOME_MS        20000  // Parkzeit auf Heimkanal (expectedChannel bzw. zuletzt gesehener AP-Kanal)
#define DEAUTH_EVAL_MS       250    // Zähler-Flush/Bewertung während des Parkens
#define STICKY_ON_DEAUTH     1      // Deauth auf Fremdkanal gesehen -> Dwell einmalig verlängern
#define STICKY_DWELL_MS      600
#define AP_LOST_RESWEEP_MS   10000  // kein eigenes Beacon seit X ms -> Heimkanal vergessen, sweepen

// =====================================================================
// Alarm-/Warn-Latch
// =====================================================================
#define ALARM_HOLD_MS        30000  // Mindest-Anzeigedauer ALARM
#define ALARM_REQUIRE_ACK    1      // 1: bleibt bis BOOT-Taster; 0: fällt nach HOLD ab, wenn Ursache weg
#define WARN_HOLD_MS         15000
#define BUTTON_DEBOUNCE_MS   40
#define BUTTON_LONG_MS       3000   // BOOT so lange halten: Fingerprints (IE-Hash, TSF) neu lernen
#define BUTTON_DOUBLE_MS     350    // zwei Klicks innerhalb dieser Zeit: Display um 90 Grad drehen

// =====================================================================
// Uhrzeit: kommt per Serial ("T<unix>\n", z. B. von tools/pi-bridge), kein
// NTP, keine WLAN-Verbindung. Ohne gesetzte Zeit zeigt das Display Uptime.
// =====================================================================
#define TIMEZONE             "CET-1CEST,M3.5.0,M10.5.0/3"   // POSIX-TZ, Deutschland

// =====================================================================
// Pins (Waveshare ESP32-C6-LCD-1.47)
// =====================================================================
#define PIN_LCD_MOSI         6
#define PIN_LCD_SCLK         7
#define PIN_LCD_CS           14
#define PIN_LCD_DC           15
#define PIN_LCD_RST          21
#define PIN_LCD_BL           22
#define PIN_RGB_LED          8
#define PIN_BUTTON           9      // BOOT, active-low

// =====================================================================
// Anzeige / LED
// =====================================================================
#define LCD_WIDTH            172
#define LCD_HEIGHT           320
#define LCD_OFFSET_X         34     // ST7789 172x320 ist im 240er-RAM zentriert
#define LCD_OFFSET_Y         0
#define LCD_SPI_HZ           40000000
#define LCD_BRIGHTNESS       180    // 0..255
#define LCD_ROTATION         1      // Startwert: 1/3 quer, 0/2 hochkant. Doppelklick BOOT dreht weiter, Stand liegt im NVS
#define REDRAW_MS            50     // 20 fps, Ring und Alarm-Puls laufen mit der LED-Hüllkurve
// LED-Muster: alle Stufen dieselbe Hüllkurve (sofort Max, Ramp-down, Rest dunkel),
// nur Farbe und Tempo unterscheiden sich. Läuft im Timer, 16 Bit mit Dithering.
#define LED_OK_MIN           4      // OK: Sockel, damit die LED nie ganz aus ist
#define LED_OK_PERIOD_MS     2000
#define LED_OK_RAMP_MS       1600
#define LED_WARN_PERIOD_MS   800    // amber
#define LED_WARN_RAMP_MS     640
#define LED_ALARM_PERIOD_MS  300    // rot, schnell
#define LED_ALARM_RAMP_MS    240
#define LED_GAMMA            2.2f
#define LED_TICK_MS          4
#define LED_SWAP_RG          1      // 1: LED erwartet RGB statt GRB (Waveshare-Board: Gruen kam als Rot)

// =====================================================================
// Optional: ntfy-Push bei ALARM (unterbricht den Scan für ~5–15 s)
// =====================================================================
#define NTFY_ENABLE          0
#define WIFI_PASS            "geheim"
#define NTFY_URL             "https://ntfy.sh/mein-topic"   // http:// oder https:// (ohne Zertifikatsprüfung)
#define NTFY_TITLE           "WLAN-IDS"
#define NTFY_CONNECT_TIMEOUT_MS 10000
#define NTFY_MIN_INTERVAL_MS 120000 // Rate-Limit zwischen zwei Pushes
