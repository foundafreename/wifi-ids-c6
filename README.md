# wifi-ids-c6

Passive Wi-Fi watchdog for your 2.4 GHz home network, running on a Waveshare ESP32-C6-LCD-1.47. It only listens, never transmits (except an optional ntfy push). Traffic-light display, RGB LED mirrors the state, BOOT button acknowledges alarms.

Built around a FritzBox, works with any AP. Just put in your SSID and BSSID.

The UI and serial log are in German. All strings live in `src/main.cpp` (the `raiseAlarm`/`raiseWarn` calls and `draw()`), so translating takes five minutes. PRs welcome.

Deutsche Version weiter unten.

## What it detects

| | Rule | Level |
|---|---|---|
| 1 | Deauth/disassoc flood (more than 20/s total, or more than 5/s against your BSSID, measured over at least 1 s and at least 8 frames) | ALARM |
| 1b | Same, but every frame comes from your AP and the RSSI matches its beacons. Usually a client stuck in a reconnect loop, not an attack | WARN |
| 2 | Evil twin: your SSID from a BSSID that is not whitelisted | ALARM |
| 2b | Cloned BSSID: beacons with your BSSID whose TSF offset jumps around (two radios, two clocks), or whose IE set differs from the one learned at first boot | ALARM |
| 3 | Your SSID or BSSID without an RSN IE (open network) | ALARM |
| 4 | Your AP on a different channel than expected | WARN |
| 5 | No beacon from your AP for 30 s | WARN |
| 6 | Deauth with your BSSID as sender but an RSSI that is off by more than 10 dB from your AP's beacons. Somebody else sent that | ALARM |

Thresholds are in `src/config.h`.

BOOT button: one click acknowledges an alarm, double click rotates the display, holding it for 3 s relearns the fingerprints.

Every deauth against your BSSID goes into an evidence log (sender, receiver, reason code, RSSI, channel). On ALARM the log is printed to serial and written to NVS, and printed again after the next boot. So a reset no longer eats the evidence.

Rule 6 and the RSSI part of 1b assume the board sits close to the router, so your AP's own frames are clearly louder than anything from outside. On a desk next to the FritzBox you see about -25 dBm; a spoofed frame from the neighbour's flat arrives 20 dB weaker.

Rule 2b learns the IE hash from the first beacon it sees and keeps it in NVS. After a router firmware update or a config change it will complain. Hold BOOT for 3 s to relearn. A single TSF jump is only a WARN (AP rebooted); three jumps within 10 s is an alarm.

## Flashing (no toolchain)

Grab `wifi-ids-c6-factory.bin` from Releases. It is a complete image (bootloader, partition table, app), flash at offset `0x0`.

- Browser: https://espressif.github.io/esptool-js/ , Connect, pick the file, offset `0x0`, Program
- CLI: `esptool.py --chip esp32c6 write_flash 0x0 wifi-ids-c6-factory.bin`

The release image ships with a placeholder SSID. To use it on your network you have to build it yourself:

## Building

PlatformIO with pioarduino (Arduino core 3.x). `platformio.ini` pulls everything in.

1. Edit `src/config.h`: `TARGET_SSID`, `WHITELIST[]` (BSSID plus channel, 0 means auto channel)
2. `pio run -t upload && pio device monitor`

Serial goes over the USB-C port (USB-Serial-JTAG), `platformio.ini` sets `ARDUINO_USB_CDC_ON_BOOT=1` for that. Without it everything is printed to UART0 and you see nothing.

Don't know your BSSID? Leave the whitelist empty, flash, and read it off the serial log (`SSID-Match: <BSSID> chN ...`). On a FritzBox it's also under WLAN, Funkkanal, bottom table.

Mesh repeaters broadcasting the same SSID have to go into the whitelist too, or you'll get a permanent evil-twin alarm.

## How it works

- Promiscuous RX, management frames only. The callback counts deauths, pushes matching beacons/probe responses into a ring buffer and deauths against your BSSID into a second one. Everything else happens in `loop()`.
- TSF check: each beacon carries the AP's 64 bit microsecond clock, `rx_ctrl.timestamp` gives the board's own. Their difference drifts by a few ppm at most. A second transmitter using the same BSSID has a different clock, so the difference jumps back and forth.
- IE hash: FNV-1a over the identity IEs only (SSID, rates, DS, country, HT and HE capabilities, RSN, extended capabilities, vendor IEs by OUI and type). Everything that moves in normal operation stays out: TIM, ERP protection bit, BSS load, HT/HE operation, CSA, BSS color, capability bits. First attempt hashed everything except a short blacklist and fired after two minutes. If it still fires, the serial log prints the IE list of the next beacon so you can see what changed.
- Channel hopping is park-and-sweep: 20 s on the home channel, then 13 x 150 ms across the rest. Deauth rates are computed per channel against airtime, not wall clock, otherwise hopping would dilute a flood by a factor of 13. The trade-off table is in `config.h`.
- The sender's channel comes from the DS Parameter IE, not from `rx_ctrl.channel` (adjacent-channel bleed).
- Display 320x172 via LovyanGFX, framebuffer as a sprite, 20 fps. Black ground, a status pill, the deauth rate as a ring against the alarm threshold, a translucent card with reason and detail, the explanation wrapped underneath, 13 channel dots at the bottom (home channel in the state colour, the scan cursor hops along). In the OK state the right half is a clock. Portrait works too: double-click BOOT rotates by 90 degrees, the setting survives a reboot. Fonts are Fira Sans as GFX fonts with Latin-1 (`tools/gen_gfxfont.py`), the bundled ones can't do umlauts.
- LED: one envelope for every state, full on then a ramp down, the rest of the period dark. Green every 2 s is OK, amber every 0.8 s is WARN, red every 0.3 s is ALARM. Runs on an esp_timer at 250 Hz with 16 bit math and temporal dithering, so the tail of the ramp doesn't step. The board wants RGB instead of GRB, hence `LED_SWAP_RG`.

## Things to know

- One radio, one channel. Short deauth bursts on the home channel are caught with about 92 % probability; a twin on a foreign channel can take up to 22 s to show up. You only get both fully with two boards.
- Everything here is passive. There is no "connect to the suspicious AP and check the WAN IP" test on purpose: joining a twin with your real PSK hands the attacker a handshake to crack offline, and a bridged twin shows your real WAN IP anyway. The TSF and IE checks give you a second factor without sending a byte.
- The RSSI rule can be fooled by an attacker standing next to your router. That is a different problem.
- WPA3/PMF makes deauth attacks useless, but they still show up. In WPA2+WPA3 mixed mode the WPA2 clients can still be kicked.
- Wall clock: the board has no NTP and never joins the Wi-Fi. It takes the time over USB serial (`T<unix>\n`), see `tools/pi-bridge`. With the time set, the display shows the clock, an alarm shows first and last occurrence, and the evidence log carries real timestamps. Without it you get uptime.
- Serial commands: `d` dumps the evidence log (NVS and RAM) plus the RSSI calibration, `r` relearns the fingerprints, `T<unix>` sets the time. Lines starting with `EV ` are machine readable (ALARM, WARN, JOIN, LEAVE, KICK, BOOT, ACK, TIME, CALIB) for the bridge.
- Push notifications: run `tools/pi-bridge` on a Pi with the board on USB. It pushes alarms, warnings, new devices and devices leaving via signal-cli, ntfy or Telegram, and keeps a device list. The board itself holds no credentials.
- The built-in ntfy (`NTFY_ENABLE 1`) still exists but needs the Wi-Fi password in the firmware and goes blind for 5 to 15 s per push. The bridge is the better way.
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
| 1 | Deauth/Disassoc-Flut (mehr als 20/s gesamt oder mehr als 5/s gegen deine BSSID, gemessen über mindestens 1 s und mindestens 8 Frames) | ALARM |
| 1b | Dasselbe, aber alle Frames kommen vom eigenen AP und der RSSI passt zu seinen Beacons. Meist ein Client in der Reconnect-Schleife, kein Angriff | WARN |
| 2 | Evil Twin, deine SSID von einer fremden BSSID | ALARM |
| 2b | Geklonte BSSID: Beacons mit deiner BSSID, deren TSF-Offset springt (zwei Radios, zwei Uhren) oder deren IE-Set vom beim ersten Boot gelernten abweicht | ALARM |
| 3 | Deine SSID/BSSID ohne RSN-IE (offen) | ALARM |
| 4 | Dein AP auf anderem Kanal als erwartet | WARN |
| 5 | Kein Beacon vom eigenen AP seit 30 s | WARN |
| 6 | Deauth mit deiner BSSID als Sender, aber RSSI mehr als 10 dB neben den Beacons deines APs. Das hat jemand anderes gesendet | ALARM |

Schwellen in `src/config.h`.

BOOT-Taster: einmal drücken quittiert einen Alarm, Doppelklick dreht das Display, 3 s halten lernt die Fingerprints neu.

Jeder Deauth gegen die eigene BSSID landet in einem Beweis-Log (Sender, Empfänger, Reason-Code, RSSI, Kanal). Bei ALARM wird es seriell ausgegeben und in den NVS geschrieben, beim nächsten Boot noch einmal ausgegeben. Ein Reset frisst die Beweise damit nicht mehr.

Regel 6 und der RSSI-Teil von 1b setzen voraus, dass das Board nah am Router steht, damit dessen eigene Frames deutlich lauter sind als alles von draußen. Neben der FritzBox sind das etwa -25 dBm, ein gespooftes Frame aus der Nachbarwohnung kommt 20 dB leiser an.

Regel 2b lernt den IE-Hash vom ersten Beacon und merkt ihn sich im NVS. Nach einem Router-Update oder einer Konfigänderung meckert sie. BOOT 3 s halten, dann wird neu gelernt. Ein einzelner TSF-Sprung ist nur WARN (AP neu gestartet), drei Sprünge in 10 s sind Alarm.

## Flashen (ohne Toolchain)

Fertiges Image unter Releases: `wifi-ids-c6-factory.bin`, komplett (Bootloader, Partitionen, App), Offset `0x0`.

- Browser: https://espressif.github.io/esptool-js/ , Connect, Datei wählen, Offset `0x0`, Program
- CLI: `esptool.py --chip esp32c6 write_flash 0x0 wifi-ids-c6-factory.bin`

Das Release-Image hat eine Platzhalter-SSID drin. Für dein Netz musst du selbst bauen:

## Bauen

PlatformIO mit pioarduino (Arduino-Core 3.x). `platformio.ini` zieht alles selbst.

1. `src/config.h`: `TARGET_SSID`, `WHITELIST[]` (BSSID und Kanal, 0 = Autokanal)
2. `pio run -t upload && pio device monitor`

Serial läuft über die USB-C-Buchse (USB-Serial-JTAG), dafür setzt `platformio.ini` `ARDUINO_USB_CDC_ON_BOOT=1`. Ohne das landet alles auf UART0 und man sieht nichts.

BSSID nicht zur Hand? Whitelist leer lassen, flashen, im Serial-Log steht `SSID-Match: <BSSID> chN ...`. Bei der FritzBox auch unter WLAN, Funkkanal, ganz unten in der Tabelle.

Mesh-Repeater mit gleicher SSID müssen mit in die Whitelist, sonst Dauer-Twin-Alarm.

## Wie es intern läuft

- Promiscuous-RX, nur Management-Frames. Der Callback zählt Deauths, schiebt passende Beacons/Probe-Responses in einen Ringpuffer und Deauths gegen die eigene BSSID in einen zweiten. Der Rest passiert im `loop()`.
- TSF-Prüfung: Jedes Beacon trägt die 64-bit-Mikrosekunden-Uhr des APs, `rx_ctrl.timestamp` liefert die des Boards. Die Differenz driftet um ein paar ppm, mehr nicht. Ein zweiter Sender mit derselben BSSID hat eine andere Uhr, dann springt die Differenz hin und her.
- IE-Hash: FNV-1a nur über die Identitäts-IEs (SSID, Raten, DS, Country, HT- und HE-Capabilities, RSN, Extended Capabilities, Vendor-IEs nach OUI und Typ). Alles, was sich im Betrieb bewegt, bleibt draußen: TIM, ERP-Protection-Bit, BSS Load, HT/HE Operation, CSA, BSS Color, Capability-Bits. Der erste Versuch hat alles bis auf eine kurze Blacklist gehasht und nach zwei Minuten Alarm geschlagen. Falls es trotzdem feuert, steht im Serial-Log die IE-Liste des nächsten Beacons, dann sieht man, was sich geändert hat.
- Kanal-Hopping als Park-und-Sweep: 20 s auf dem Heimkanal, dann 13 x 150 ms über alle anderen. Deauth-Raten werden pro Kanal auf Airtime bezogen, nicht auf die Wanduhr, sonst würde das Hopping eine Flut um Faktor 13 verdünnen. Trade-off-Tabelle in `config.h`.
- Der Kanal des Senders kommt aus der DS-Parameter-IE, nicht aus `rx_ctrl.channel` (Nachbarkanal-Bleed).
- Display 320x172 über LovyanGFX, Framebuffer als Sprite, 20 fps. Schwarzer Grund, Status-Pill, die Deauth-Rate als Ring gegen die Alarmschwelle, eine halbtransparente Karte mit Grund und Detail, die Erklärung darunter umgebrochen, unten 13 Kanalpunkte (Heimkanal in Zustandsfarbe, der Scan-Cursor hüpft entlang). Im OK-Zustand ist die rechte Hälfte eine Uhr. Hochkant geht auch: Doppelklick auf BOOT dreht um 90 Grad, die Einstellung überlebt den Neustart. Fonts sind Fira Sans als GFXfonts mit Latin-1 (`tools/gen_gfxfont.py`), die mitgelieferten können kein ä.
- LED: eine Hüllkurve für alle Stufen, sofort an, dann Rampe runter, Rest der Periode dunkel. Grün alle 2 s ist OK, amber alle 0,8 s ist WARN, rot alle 0,3 s ist ALARM. Läuft im esp_timer mit 250 Hz, 16 Bit und zeitlichem Dithering, damit das Rampenende nicht stuft. Das Board will RGB statt GRB, deshalb `LED_SWAP_RG`.

## Was man wissen sollte

- Ein Gerät, ein Kanal. Kurze Deauth-Bursts auf dem Heimkanal werden mit etwa 92 % gesehen, ein Twin auf einem Fremdkanal mit bis zu 22 s Verzögerung. Beides vollständig gibt es nur mit zwei Boards.
- Alles hier ist passiv. Einen "mit dem verdächtigen AP verbinden und WAN-IP prüfen"-Test gibt es absichtlich nicht: Wer sich mit dem echten PSK bei einem Twin einbucht, schenkt dem Angreifer einen Handshake zum Offline-Cracken, und ein gebridgter Twin zeigt sowieso die echte WAN-IP. TSF und IE-Hash sind der zweite Faktor, ohne ein Byte zu senden.
- Die RSSI-Regel lässt sich von einem Angreifer direkt neben dem Router austricksen. Das ist dann ein anderes Problem.
- WPA3/PMF macht Deauth-Angriffe wirkungslos, sichtbar sind sie trotzdem. Bei WPA2+WPA3-Mischbetrieb sind die WPA2-Clients weiterhin kickbar.
- Uhrzeit: Das Board hat kein NTP und geht nie ins WLAN. Die Zeit kommt über USB-Serial (`T<unix>\n`), siehe `tools/pi-bridge`. Mit gesetzter Zeit zeigt das Display die Uhr, ein Alarm erstes und letztes Auftreten, und das Beweis-Log echte Zeitstempel. Ohne Zeit gibt es Uptime.
- Serial-Kommandos: `d` gibt das Beweis-Log (NVS und RAM) plus die RSSI-Kalibrierung aus, `r` lernt die Fingerprints neu, `T<unix>` setzt die Zeit. Zeilen mit `EV ` am Anfang sind maschinenlesbar (ALARM, WARN, JOIN, LEAVE, KICK, BOOT, ACK, TIME, CALIB) für die Bridge.
- Push: `tools/pi-bridge` auf einem Pi laufen lassen, an dem das Board per USB hängt. Pusht Alarme, Warnungen, neue Geräte und Abmeldungen per signal-cli, ntfy oder Telegram und führt eine Geräteliste. Das Board selbst kennt keine Zugangsdaten.
- Das eingebaute ntfy (`NTFY_ENABLE 1`) gibt es noch, braucht aber das WLAN-Passwort in der Firmware und ist pro Push 5 bis 15 s blind. Die Bridge ist der bessere Weg.
- Partitionstabelle `huge_app` (3 MB App, kein OTA), damit ntfy mit TLS noch reinpasst.

## Hardware

Waveshare ESP32-C6-LCD-1.47. ST7789 172x320 an SPI2 (MOSI 6, SCLK 7, CS 14, DC 15, RST 21, BL 22), WS2812 an GPIO 8, BOOT an GPIO 9.

MIT.
