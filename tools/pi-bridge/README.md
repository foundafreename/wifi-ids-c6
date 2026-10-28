# pi-bridge

Small Python service for a Raspberry Pi (or any Linux box) that has the board on USB. The board stays passive and holds no credentials; the Pi does the rest:

- sends the wall clock to the board (`T<unix>\n`) on boot and every hour, so the display and the evidence log show real time
- logs every serial line to a daily rotating file (evidence survives a reset of the board)
- parses `EV ...` lines and pushes alarms, warnings, new devices, and devices leaving via signal-cli, ntfy, or a Telegram bot
- keeps `devices.json` with first/last seen per MAC, optionally resolves names via the FritzBox TR-064 API

## Install

```
sudo mkdir -p /opt/wifi-ids-bridge && sudo chown pi /opt/wifi-ids-bridge
cp wifi_ids_bridge.py bridge.example.json wifi-ids-bridge.service /opt/wifi-ids-bridge/
cd /opt/wifi-ids-bridge && cp bridge.example.json bridge.json
pip3 install pyserial            # plus: fritzconnection if you want device names
sudo usermod -aG dialout pi
```

Edit `bridge.json`, then:

```
python3 wifi_ids_bridge.py --test-push     # one test message
sudo cp wifi-ids-bridge.service /etc/systemd/system/
sudo systemctl enable --now wifi-ids-bridge
journalctl -u wifi-ids-bridge -f
```

The port is `/dev/ttyACM0` on most Pis. If it moves around, use the `/dev/serial/by-id/...` path instead.

## Push backends

- **signal**: install signal-cli, link the Pi as a second device (`signal-cli link -n pi`, scan the QR in the Signal app), then `account` is your own number and `to` can be your own number ("Note to Self") or anyone else.
- **ntfy**: topic URL, optional token. Get the ntfy app on the phone.
- **telegram**: bot token from BotFather, your chat id.

## What gets pushed

| EV line from the board | Push |
|---|---|
| `EV ALARM\|reason\|detail` | always |
| `EV WARN\|reason\|detail` | at most once per 10 min per reason |
| `EV JOIN\|mac\|rssi` | only when the MAC has never been seen (new device) |
| `EV LEAVE\|mac\|reason` | client said goodbye, at most once per 5 min per MAC |
| `EV KICK\|mac\|reason\|rssi` | router threw the client out (reason other than 7) |

`EV BOOT`, `EV TIME`, `EV ACK`, `EV CALIB` go to the log only. Join/leave detection is passive: the board sees Auth/Assoc on the home channel, which it watches 92 % of the time. A device that joins during the 2 s sweep is caught on its next reconnect.

## Note on resets

Opening the port on Linux normally toggles DTR/RTS, which the ESP32-C6 USB-Serial-JTAG interprets as a reset request. The bridge sets both lines high before opening, which means "do nothing". If your board still reboots when the bridge starts, the log will show `EV BOOT` and the time is re-sent right after, so nothing is lost.

---

# Deutsch

Kleiner Python-Dienst für einen Raspberry Pi (oder irgendein Linux), an dem das Board per USB hängt. Das Board bleibt passiv und kennt keine Zugangsdaten, der Pi macht den Rest:

- schickt dem Board die Uhrzeit (`T<unix>\n`), beim Boot und stündlich. Display und Beweis-Log zeigen dann echte Zeit.
- schreibt jede serielle Zeile in ein täglich rotierendes Logfile (die Beweise überleben einen Reset des Boards)
- wertet `EV ...`-Zeilen aus und pusht Alarme, Warnungen, neue Geräte und Abmeldungen per signal-cli, ntfy oder Telegram-Bot
- führt `devices.json` mit first/last seen je MAC, optional mit Namen aus der FritzBox (TR-064)

Installation und Backends siehe oben, die Befehle sind dieselben. Für Signal: signal-cli installieren, Pi als Zweitgerät koppeln (`signal-cli link -n pi`, QR-Code in der Signal-App scannen), `account` ist die eigene Nummer, `to` die eigene ("Notiz an mich") oder eine andere.

Was gepusht wird: ALARM immer, WARN höchstens alle 10 min je Grund, JOIN nur bei unbekannter MAC, LEAVE/KICK höchstens alle 5 min je MAC. An-/Abmeldungen werden passiv auf dem Heimkanal gesehen (92 % der Zeit); wer in den 2 s Sweep reinrutscht, wird beim nächsten Reconnect erwischt.
