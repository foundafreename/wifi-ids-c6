# wifi-ids-c6

Passive Wi-Fi watchdog for your 2.4 GHz home network, running on a Waveshare ESP32-C6-LCD-1.47. It only listens, never transmits (except an optional ntfy push). Traffic-light display, RGB LED mirrors the state, BOOT button acknowledges alarms.

Built around a FritzBox, works with any AP. Just put in your SSID and BSSID.

The UI and serial log are in German. All strings live in `src/main.cpp` (the `raiseAlarm`/`raiseWarn` calls and `draw()`), so translating takes five minutes. PRs welcome.

Deutsche Version weiter unten.

## What it detects

| | Rule | Level |
|---|---|---|
| 1 | Deauth/disassoc flood (more than 20/s total, or more than 5/s against your BSSID) | ALARM |
| 2 | Evil twin: your SSID from a BSSID that is not whitelisted | ALARM |
| 3 | Your SSID or BSSID without an RSN IE (open network) | ALARM |
| 4 | Your AP on a different channel than expected | WARN |
| 5 | No beacon from your AP for 30 s | WARN |

Thresholds are in `src/config.h`.

## Flashing (no toolchain)

Grab `wifi-ids-c6-factory.bin` from Releases. It is a complete image (bootloader, partition table, app), flash at offset `0x0`.

- Browser: https://espressif.github.io/esptool-js/ , Connect, pick the file, offset `0x0`, Program
- CLI: `esptool.py --chip esp32c6 write_flash 0x0 wifi-ids-c6-factory.bin`

The release image ships with a placeholder SSID. To use it on your network you have to build it yourself:

## Building

PlatformIO with pioarduino (Arduino core 3.x). `platformio.ini` pulls everything in.

1. Edit `src/config.h`: `TARGET_SSID`, `WHITELIST[]` (BSSID plus channel, 0 means auto channel)
2. `pio run -t upload && pio device monitor`

Don't know your BSSID? Leave the whitelist empty, flash, and read it off the serial log (`SSID-Match: <BSSID> chN ...`). On a FritzBox it's also under WLAN, Funkkanal, bottom table.

Mesh repeaters broadcasting the same SSID have to go into the whitelist too, or you'll get a permanent evil-twin alarm.

## How it works

- Promiscuous RX, management frames only. The callback counts deauths and pushes matching beacons/probe responses into a ring buffer. Everything else happens in `loop()`.
- Channel hopping is park-and-sweep: 20 s on the home channel, then 13 x 150 ms across the rest. Deauth rates are computed per channel against airtime, not wall clock, otherwise hopping would dilute a flood by a factor of 13. The trade-off table is in `config.h`.
- The sender's channel comes from the DS Parameter IE, not from `rx_ctrl.channel` (adjacent-channel bleed).
- Display is 320x172 landscape via LovyanGFX, framebuffer as a sprite. Fonts are custom GFX fonts with Latin-1 (`tools/gen_gfxfont.py`), the bundled ones can't do umlauts.
- LED: pulsing green is OK, yellow at 4 Hz is WARN, red/blue strobe is ALARM. The board wants RGB instead of GRB, hence `LED_SWAP_RG`.

## Things to know

- One radio, one channel. Short deauth bursts on the home channel are caught with about 92 % probability; a twin on a foreign channel can take up to 22 s to show up. You only get both fully with two boards.
- WPA3/PMF makes deauth attacks useless, but they still show up. In WPA2+WPA3 mixed mode the WPA2 clients can still be kicked.
- ntfy (`NTFY_ENABLE 1`): on ALARM it briefly joins the Wi-Fi, posts, and goes back to sniffing. Blind for 5 to 15 s. If the AP is under attack right then, the connect will fail, as you'd expect.
- Partition table is `huge_app` (3 MB app, no OTA) so ntfy with TLS still fits.

## Hardware

Waveshare ESP32-C6-LCD-1.47. ST7789 172x320 on SPI2 (MOSI 6, SCLK 7, CS 14, DC 15, RST 21, BL 22), WS2812 on GPIO 8, BOOT on GPIO 9.

MIT.

---

# Deutsch

Passiver WLAN-Wächter für das 2,4-GHz-Heimnetz auf einem Waveshare ESP32-C6-LCD-1.47. Hört nur zu, sendet nichts (außer optional ein ntfy-Push). Ampel auf dem Display, RGB-LED spiegelt den Status, BOOT-Taster quittiert.

Gebaut für eine FritzBox, läuft aber mit jedem AP. Nur SSID und BSSID eintragen.

## Was es erkennt

| | Regel | Stufe |
|---|---|---|
| 1 | Deauth/Disassoc-Flut (mehr als 20/s gesamt oder mehr als 5/s gegen deine BSSID) | ALARM |
| 2 | Evil Twin, deine SSID von einer fremden BSSID | ALARM |
| 3 | Deine SSID/BSSID ohne RSN-IE (offen) | ALARM |
| 4 | Dein AP auf anderem Kanal als erwartet | WARN |
| 5 | Kein Beacon vom eigenen AP seit 30 s | WARN |

Schwellen in `src/config.h`.

## Flashen (ohne Toolchain)

Fertiges Image unter Releases: `wifi-ids-c6-factory.bin`, komplett (Bootloader, Partitionen, App), Offset `0x0`.

- Browser: https://espressif.github.io/esptool-js/ , Connect, Datei wählen, Offset `0x0`, Program
- CLI: `esptool.py --chip esp32c6 write_flash 0x0 wifi-ids-c6-factory.bin`

Das Release-Image hat eine Platzhalter-SSID drin. Für dein Netz musst du selbst bauen:

## Bauen

PlatformIO mit pioarduino (Arduino-Core 3.x). `platformio.ini` zieht alles selbst.

1. `src/config.h`: `TARGET_SSID`, `WHITELIST[]` (BSSID und Kanal, 0 = Autokanal)
2. `pio run -t upload && pio device monitor`

BSSID nicht zur Hand? Whitelist leer lassen, flashen, im Serial-Log steht `SSID-Match: <BSSID> chN ...`. Bei der FritzBox auch unter WLAN, Funkkanal, ganz unten in der Tabelle.

Mesh-Repeater mit gleicher SSID müssen mit in die Whitelist, sonst Dauer-Twin-Alarm.

## Wie es intern läuft

- Promiscuous-RX, nur Management-Frames. Der Callback zählt Deauths und schiebt passende Beacons/Probe-Responses in einen Ringpuffer. Der Rest passiert im `loop()`.
- Kanal-Hopping als Park-und-Sweep: 20 s auf dem Heimkanal, dann 13 x 150 ms über alle anderen. Deauth-Raten werden pro Kanal auf Airtime bezogen, nicht auf die Wanduhr, sonst würde das Hopping eine Flut um Faktor 13 verdünnen. Trade-off-Tabelle in `config.h`.
- Der Kanal des Senders kommt aus der DS-Parameter-IE, nicht aus `rx_ctrl.channel` (Nachbarkanal-Bleed).
- Display 320x172 quer über LovyanGFX, Framebuffer als Sprite. Fonts sind eigene GFXfonts mit Latin-1 (`tools/gen_gfxfont.py`), die mitgelieferten können kein ä.
- LED: grün pulsend ist OK, gelb 4 Hz ist WARN, rot/blau-Strobe ist ALARM. Das Board will RGB statt GRB, deshalb `LED_SWAP_RG`.

## Was man wissen sollte

- Ein Gerät, ein Kanal. Kurze Deauth-Bursts auf dem Heimkanal werden mit etwa 92 % gesehen, ein Twin auf einem Fremdkanal mit bis zu 22 s Verzögerung. Beides vollständig gibt es nur mit zwei Boards.
- WPA3/PMF macht Deauth-Angriffe wirkungslos, sichtbar sind sie trotzdem. Bei WPA2+WPA3-Mischbetrieb sind die WPA2-Clients weiterhin kickbar.
- ntfy (`NTFY_ENABLE 1`): bucht sich bei ALARM kurz ins WLAN ein, postet, geht zurück in den Sniff-Modus. 5 bis 15 s blind. Läuft der AP gerade unter Beschuss, scheitert das erwartbar.
- Partitionstabelle `huge_app` (3 MB App, kein OTA), damit ntfy mit TLS noch reinpasst.

## Hardware

Waveshare ESP32-C6-LCD-1.47. ST7789 172x320 an SPI2 (MOSI 6, SCLK 7, CS 14, DC 15, RST 21, BL 22), WS2812 an GPIO 8, BOOT an GPIO 9.

MIT.
