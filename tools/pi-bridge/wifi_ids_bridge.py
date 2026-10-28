#!/usr/bin/env python3
"""Serial-Bridge für wifi-ids-c6.

Hängt am USB-Port des Boards und macht drei Dinge:
  1. Zeit setzen: "T<unix>\\n" beim Boot des Boards und alle SYNC_INTERVAL Sekunden
  2. Alles mitschreiben (rotierendes Logfile), inklusive Beweis-Log
  3. EV-Zeilen auswerten und pushen: Alarm, Warnung, neues Gerät, Gerät weg

Push-Backends: signal-cli, ntfy, telegram. Konfiguration in bridge.json.
Das Board braucht dafür keine Zugangsdaten, alles liegt auf dem Pi.
"""

import json
import logging
import logging.handlers
import os
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

try:
    import serial
except ImportError:
    sys.exit("pyserial fehlt: pip install pyserial")

HERE = Path(__file__).resolve().parent
CFG_PATH = Path(os.environ.get("BRIDGE_CONFIG", HERE / "bridge.json"))

DEFAULTS = {
    "port": "/dev/ttyACM0",
    "baud": 115200,
    "log_dir": str(HERE / "log"),
    "log_keep_days": 30,
    "sync_interval_s": 3600,
    "devices_file": str(HERE / "devices.json"),
    "notify": {
        "backend": "none",              # none | signal | ntfy | telegram
        "events": ["ALARM", "WARN", "NEWDEVICE", "LEAVE", "KICK"],
        "warn_min_interval_s": 600,     # WARN pro Grund höchstens alle 10 min
        "leave_min_interval_s": 300,    # LEAVE/KICK pro MAC höchstens alle 5 min
        "signal": {"cli": "signal-cli", "account": "+49...", "to": ["+49..."]},
        "ntfy": {"url": "https://ntfy.sh/mein-topic", "token": ""},
        "telegram": {"bot_token": "", "chat_id": ""},
    },
    "fritzbox": {                       # optional: Gerätenamen nachschlagen
        "enabled": False,
        "address": "192.168.178.1",
        "user": "",
        "password": "",
    },
}


def deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_config():
    if CFG_PATH.exists():
        with open(CFG_PATH) as f:
            return deep_merge(DEFAULTS, json.load(f))
    return dict(DEFAULTS)


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------
class Notifier:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.backend = cfg.get("backend", "none")
        self.last = {}              # key -> letzter Push (für Rate-Limits)

    def allowed(self, key, min_interval):
        now = time.time()
        if now - self.last.get(key, 0) < min_interval:
            return False
        self.last[key] = now
        return True

    def send(self, text):
        self.log.info("PUSH %s: %s", self.backend, text.replace("\n", " / "))
        try:
            if self.backend == "signal":
                self._signal(text)
            elif self.backend == "ntfy":
                self._ntfy(text)
            elif self.backend == "telegram":
                self._telegram(text)
        except Exception as e:  # Push darf die Bridge nie umwerfen
            self.log.error("Push fehlgeschlagen: %s", e)

    def _signal(self, text):
        c = self.cfg["signal"]
        cmd = [c["cli"], "-a", c["account"], "send", "-m", text] + list(c["to"])
        subprocess.run(cmd, check=True, timeout=60, capture_output=True)

    def _ntfy(self, text):
        c = self.cfg["ntfy"]
        title, _, body = text.partition("\n")
        req = urllib.request.Request(c["url"], data=body.encode() or title.encode(), method="POST")
        req.add_header("Title", title.encode("ascii", "ignore").decode())
        req.add_header("Priority", "high")
        if c.get("token"):
            req.add_header("Authorization", "Bearer " + c["token"])
        urllib.request.urlopen(req, timeout=15).read()

    def _telegram(self, text):
        c = self.cfg["telegram"]
        url = f"https://api.telegram.org/bot{c['bot_token']}/sendMessage"
        data = json.dumps({"chat_id": c["chat_id"], "text": text}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15).read()


# ---------------------------------------------------------------------------
# Gerätenamen (optional, FritzBox TR-064)
# ---------------------------------------------------------------------------
class NameLookup:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.fc = None
        if cfg.get("enabled"):
            try:
                from fritzconnection.lib.fritzhosts import FritzHosts
                self.fc = FritzHosts(address=cfg["address"], user=cfg["user"], password=cfg["password"])
            except Exception as e:
                log.error("FritzBox-Lookup aus: %s", e)

    def name(self, mac):
        if not self.fc:
            return ""
        try:
            info = self.fc.get_specific_host_entry(mac)
            return info.get("NewHostName", "") or ""
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------
class Bridge:
    def __init__(self, cfg):
        self.cfg = cfg
        Path(cfg["log_dir"]).mkdir(parents=True, exist_ok=True)
        self.log = logging.getLogger("bridge")
        self.log.setLevel(logging.INFO)
        fh = logging.handlers.TimedRotatingFileHandler(
            Path(cfg["log_dir"]) / "wifi-ids.log", when="midnight", backupCount=cfg["log_keep_days"])
        fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        self.log.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        self.log.addHandler(sh)

        self.notifier = Notifier(cfg["notify"], self.log)
        self.names = NameLookup(cfg["fritzbox"], self.log)
        self.events = set(cfg["notify"]["events"])
        self.devices_path = Path(cfg["devices_file"])
        self.devices = self._load_devices()
        self.ser = None
        self.last_sync = 0

    # -- Geräteliste --------------------------------------------------------
    def _load_devices(self):
        if self.devices_path.exists():
            with open(self.devices_path) as f:
                return json.load(f)
        return {}

    def _save_devices(self):
        tmp = self.devices_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self.devices, f, indent=1, sort_keys=True)
        tmp.replace(self.devices_path)

    def _touch_device(self, mac, rssi=None):
        now = datetime.now().isoformat(timespec="seconds")
        new = mac not in self.devices
        d = self.devices.setdefault(mac, {"first_seen": now, "name": ""})
        d["last_seen"] = now
        if rssi is not None:
            d["last_rssi"] = rssi
        if not d.get("name"):
            d["name"] = self.names.name(mac)
        self._save_devices()
        return new, d

    def label(self, mac):
        d = self.devices.get(mac, {})
        return f"{d['name']} ({mac})" if d.get("name") else mac

    # -- Serial --------------------------------------------------------------
    def open(self):
        # DTR/RTS vor dem Öffnen auf 1 setzen: beide 1 = kein Reset auf dem
        # USB-Serial-JTAG des C6. pyserial würde sonst beim Öffnen toggeln.
        s = serial.Serial()
        s.port = self.cfg["port"]
        s.baudrate = self.cfg["baud"]
        s.timeout = 1
        s.dtr = True
        s.rts = True
        s.open()
        self.ser = s
        self.log.info("Port %s offen", s.port)

    def send_time(self):
        t = int(time.time())
        self.ser.write(f"T{t}\n".encode())
        self.last_sync = time.time()
        self.log.info("Zeit gesendet: %d", t)

    def run(self):
        while True:
            try:
                self.open()
                time.sleep(0.5)
                self.send_time()
                self._read_loop()
            except (serial.SerialException, OSError) as e:
                self.log.error("Serial: %s, neuer Versuch in 5 s", e)
                time.sleep(5)

    def _read_loop(self):
        while True:
            raw = self.ser.readline()
            if time.time() - self.last_sync > self.cfg["sync_interval_s"]:
                self.send_time()
            if not raw:
                continue
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                continue
            self.log.info("%s", line)
            if line.startswith("EV "):
                self.handle_event(line[3:])

    # -- Ereignisse ----------------------------------------------------------
    def handle_event(self, ev):
        parts = ev.split("|")
        kind, args = parts[0], parts[1:]
        n = self.cfg["notify"]
        ts = datetime.now().strftime("%H:%M:%S")

        if kind == "BOOT":
            self.send_time()
            return
        if kind == "ALARM" and "ALARM" in self.events:
            reason, detail = (args + ["", ""])[:2]
            self.notifier.send(f"WLAN-IDS ALARM {ts}\n{reason}\n{detail}")
        elif kind == "WARN" and "WARN" in self.events:
            reason, detail = (args + ["", ""])[:2]
            if self.notifier.allowed("warn:" + reason, n["warn_min_interval_s"]):
                self.notifier.send(f"WLAN-IDS Warnung {ts}\n{reason}\n{detail}")
        elif kind == "JOIN":
            mac, rssi = (args + ["", ""])[:2]
            new, d = self._touch_device(mac, int(rssi) if rssi.lstrip("-").isdigit() else None)
            if new and "NEWDEVICE" in self.events:
                self.notifier.send(f"WLAN-IDS: neues Gerät {ts}\n{self.label(mac)} {rssi} dBm")
        elif kind in ("LEAVE", "KICK") and kind in self.events:
            mac, code = (args + ["", ""])[:2]
            self._touch_device(mac)
            if self.notifier.allowed(f"{kind}:{mac}", n["leave_min_interval_s"]):
                what = "abgemeldet" if kind == "LEAVE" else "vom Router getrennt"
                self.notifier.send(f"WLAN-IDS: Gerät {what} {ts}\n{self.label(mac)} reason {code}")
        # ACK, TIME, CALIB, JOINFAIL: nur Log


def main():
    cfg = load_config()
    if "--test-push" in sys.argv:
        Bridge(cfg).notifier.send("WLAN-IDS Test\nBridge läuft.")
        return
    Bridge(cfg).run()


if __name__ == "__main__":
    main()
