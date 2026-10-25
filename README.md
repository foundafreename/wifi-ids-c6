# wifi-ids-c6

Passiver WLAN-Wächter für das 2,4-GHz-Heimnetz auf einem Waveshare ESP32-C6-LCD-1.47. Hört nur zu, sendet nichts (außer optional ein ntfy-Push). Ampel auf dem Display, RGB-LED spiegelt den Status, BOOT-Taster quittiert.

Gebaut für eine FritzBox, läuft aber mit jedem AP – nur SSID und BSSID eintragen.

UI und Serial-Log sind auf Deutsch. Alle Strings liegen in `src/main.cpp` (`raiseAlarm`/`raiseWarn`-Aufrufe und `draw()`), übersetzen ist ein Fünf-Minuten-Job – PRs willkommen.

## Was es erkennt

| | Regel | Stufe |
|---|---|---|
| 1 | Deauth/Disassoc-Flut (> 20/s gesamt oder > 5/s gegen deine BSSID) | ALARM |
| 2 | Evil Twin – deine SSID von einer fremden BSSID | ALARM |
| 3 | Deine SSID/BSSID ohne RSN-IE (offen) | ALARM |
| 4 | Dein AP auf anderem Kanal als erwartet | WARN |
| 5 | Kein Beacon vom eigenen AP seit 30 s | WARN |

Schwellen in `src/config.h`.

## Flashen (ohne Toolchain)

Fertiges Image unter Releases: `wifi-ids-c6-factory.bin`, komplett (Bootloader + Partitionen + App), Offset `0x0`.

- Browser: https://espressif.github.io/esptool-js/ → Connect → Datei wählen, Offset `0x0` → Program
- CLI: `esptool.py --chip esp32c6 write_flash 0x0 wifi-ids-c6-factory.bin`

Das Release-Image hat Platzhalter-SSID drin. Zum Anpassen musst du bauen:

## Bauen

PlatformIO + pioarduino (Arduino-Core 3.x). `platformio.ini` zieht alles selbst.

1. `src/config.h`: `TARGET_SSID`, `WHITELIST[]` (BSSID + Kanal, 0 = Autokanal)
2. `pio run -t upload && pio device monitor`

BSSID nicht zur Hand? Whitelist leer lassen, flashen, im Serial-Log steht `SSID-Match: <BSSID> chN …`. Oder FritzBox → WLAN → Funkkanal, ganz unten in der Tabelle.

Mesh-Repeater mit gleicher SSID müssen mit in die Whitelist, sonst Dauer-Twin-Alarm.

## Wie es intern läuft

- Promiscuous-RX, nur Management-Frames. Callback zählt Deauths und schiebt Beacons/Probe-Responses mit Treffer in einen Ringpuffer. Auswertung im `loop()`.
- Kanal-Hopping als Park-und-Sweep: 20 s auf dem Heimkanal, dann 13 × 150 ms über alle anderen. Deauth-Raten sind Airtime-bezogen pro Kanal, nicht Wanduhr – sonst würde eine Flut durch das Hopping um Faktor 13 verdünnt. Trade-off-Tabelle in `config.h`.
- Kanal des Senders kommt aus der DS-Parameter-IE, nicht aus `rx_ctrl.channel` (Nachbarkanal-Bleed).
- Display 320×172 quer über LovyanGFX, Framebuffer als Sprite. Fonts sind eigene GFXfonts mit Latin-1 (`tools/gen_gfxfont.py`), die mitgelieferten können kein ä.
- LED: grün pulsend = OK, gelb 4 Hz = WARN, rot/blau-Strobe = ALARM. Board will RGB statt GRB, deshalb `LED_SWAP_RG`.

## Was man wissen sollte

- Ein Gerät, ein Kanal. Kurze Deauth-Bursts auf dem Heimkanal werden mit ~92 % gesehen, ein Twin auf einem Fremdkanal mit bis zu 22 s Verzögerung. Beides vollständig gibt's nur mit zwei Boards.
- WPA3/PMF macht Deauth-Angriffe wirkungslos, sichtbar sind sie trotzdem. Bei WPA2+WPA3-Mischbetrieb sind die WPA2-Clients weiterhin kickbar.
- ntfy (`NTFY_ENABLE 1`): bucht sich bei ALARM kurz ins WLAN ein, postet, geht zurück in den Sniff-Modus. 5–15 s blind. Läuft der AP gerade unter Beschuss, scheitert das erwartbar.
- Partitionstabelle `huge_app` (3 MB App, kein OTA), damit ntfy mit TLS noch reinpasst.

## Hardware

Waveshare ESP32-C6-LCD-1.47. ST7789 172×320 an SPI2 (MOSI 6, SCLK 7, CS 14, DC 15, RST 21, BL 22), WS2812 an GPIO 8, BOOT an GPIO 9.

MIT.
