import re
import time
import subprocess
import shlex
import threading


def _run(cmd):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    except (FileNotFoundError, OSError):
        class _D:
            stdout = ""
            stderr = ""
            returncode = 1
        return _D()


def _parse_scan_results(output):
    results = []
    lines = output.strip().splitlines()
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        bssid, freq, signal, flags, ssid = parts[0], parts[1], parts[2], parts[3], parts[4]
        results.append({"bssid": bssid.lower(), "freq": freq,
                         "signal": signal, "ssid": ssid})
    return results


class RogueAPWatcher:

    def __init__(self, iface, get_ssid, get_own_bssid, on_detect, debug,
                 poll_interval=10):
        self.iface = iface
        self.get_ssid = get_ssid
        self.get_own_bssid = get_own_bssid
        self.on_detect = on_detect
        self.debug = debug
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        while not self._stop.wait(self.poll_interval):
            try:
                self._check_once()
            except Exception as e:
                self.debug("warn", f"Rogue-AP check failed: {e}")

    def _check_once(self):
        _run(["hostapd_cli", "-i", self.iface, "scan"])
        time.sleep(2)
        res = _run(["hostapd_cli", "-i", self.iface, "scan_results"])
        if res.returncode != 0 or not res.stdout.strip():
            return

        my_ssid = self.get_ssid()
        my_bssid = (self.get_own_bssid() or "").lower()
        results = _parse_scan_results(res.stdout)

        impostors = [r for r in results
                     if r["ssid"] == my_ssid and r["bssid"] != my_bssid]
        if impostors:
            for imp in impostors:
                self.debug("critical",
                           f"ROGUE AP / EVIL TWIN DETECTED: another device "
                           f"({imp['bssid']}) is broadcasting SSID "
                           f"'{my_ssid}' — signal={imp['signal']} "
                           f"freq={imp['freq']}. Shutting down this AP.")
            self.on_detect(impostors)
