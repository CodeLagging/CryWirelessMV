

import os
import re
import sys
import json
import time
import shlex
import select
import termios
import tty
import threading
import subprocess
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path

from scapy.all import (
    sniff, wrpcap, PcapWriter, RadioTap, Dot11, Dot11Deauth, Dot11Disas,
    Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon, Dot11Auth, Dot11AssoReq,
    Dot11Elt, EAPOL
)

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
              124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]

FILTER_MODES = ["all", "deauth", "probe_flood", "disassoc_flood",
                 "ap_flood", "auth_flood", "malformed", "handshake"]

LOCK_TARGETS = {
    "1": "deauth",
    "2": "probe_flood",
    "3": "disassoc_flood",
    "4": "ap_flood",
    "5": "auth_flood",
    "6": "all",
}


class Scanner:

    class RawKeyReader:

        def __init__(self):
            self.fd = sys.stdin.fileno()
            self.old_settings = None

        def __enter__(self):
            try:
                self.old_settings = termios.tcgetattr(self.fd)
                tty.setcbreak(self.fd)
            except termios.error:
                self.old_settings = None
            return self

        def __exit__(self, *a):
            if self.old_settings:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)

        def getch(self, timeout=0.2):
            r, _, _ = select.select([sys.stdin], [], [], timeout)
            if r:
                return sys.stdin.read(1)
            return None

        def prompt_line(self, msg, hide=False):
            if self.old_settings:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)
            try:
                if hide:
                    import getpass
                    val = getpass.getpass(msg)
                else:
                    val = input(msg)
            finally:
                try:
                    tty.setcbreak(self.fd)





                    termios.tcflush(self.fd, termios.TCIFLUSH)
                except termios.error:
                    pass
            return val

    @staticmethod
    def _ch_to_freq(ch: int) -> int:
        if ch == 14:
            return 2484
        if ch <= 13:
            return 2407 + ch * 5
        return 5000 + ch * 5

    @staticmethod
    def _run(cmd, check=False, capture=True):
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        return subprocess.run(cmd, capture_output=capture, text=True, check=check)

    @classmethod
    def _which(cls, name):
        return cls._run(["which", name]).stdout.strip() or None

    def __init__(self, iface, savepath="./wifi_scans"):
        self.orig_iface_arg = iface
        self.savepath_base = Path(savepath)
        self.mon_iface = None
        self.base_iface = None

        self.filter_idx = 0

        self.paused = True
        self.raw_mode = False
        self.saving = False
        self.lock_mode = False
        self.running = False

        self.session_dir = None
        self.txt_fh = None
        self.json_fh = None
        self.pcap_writer = None

        self.current_channel = None
        self.hopping = False
        self._hop_thread = None
        self._hop_stop = threading.Event()

        self._sniff_thread = None
        self._stop_sniff = threading.Event()







        self.probe_hist = defaultdict(deque)
        self.deauth_hist = defaultdict(deque)
        self.disassoc_hist = defaultdict(deque)
        self.auth_hist = defaultdict(deque)
        self.eapol_pairs = defaultdict(list)
        self.handshake_done = set()







        self.beacon_ssid_hist = defaultdict(deque)
        self.SSID_FLOOD_WINDOW = 5.0
        self.SSID_FLOOD_DISTINCT = 5

        self._flood_last_alert = defaultdict(float)
        self._flood_first_seen = {}



        self.SUSTAIN_SECONDS = 4





        self.BASELINE_WINDOW = 30.0
        self.FLOOD_MULTIPLIER = 3.0
        self.PER_SECOND_FLOOR = 3
        self.ALERT_COOLDOWN = 4.0

        self._kr = None
        self._lock = threading.Lock()

        self._status_len = 0
        self._status_active = False





    def _resolve_iface_name(self, arg):
        arg = str(arg).strip()
        if arg.isdigit():
            out = self._run(["iw", "dev"]).stdout
            names = re.findall(r"Interface\s+(\S+)", out)
            if not names:
                raise RuntimeError("No wireless interfaces found via `iw dev`.")
            i = int(arg)
            if i < 0 or i >= len(names):
                raise RuntimeError(f"Interface index {i} out of range: {names}")
            return names[i]


        return arg

    def _enable_monitor_mode(self, iface):
        if self._which("nmcli"):
            try:
                self._run(["nmcli", "device", "set", iface, "managed", "no"])
            except Exception:
                pass
        try:
            self._run(["pkill", "-f", f"wpa_supplicant.*{iface}"])
        except Exception:
            pass
        self._run(["ip", "link", "set", iface, "down"])
        res = self._run(["iw", "dev", iface, "set", "type", "monitor"])
        self._run(["ip", "link", "set", iface, "up"])
        check = self._run(["iw", "dev", iface, "info"])
        if "type monitor" not in check.stdout:
            raise RuntimeError(
                f"Failed to put {iface} into monitor mode. "
                f"iw error: {res.stderr.strip()}"
            )
        return iface

    def _disable_monitor_mode(self):
        if not self.mon_iface:
            return
        try:
            self._run(["ip", "link", "set", self.mon_iface, "down"])
            self._run(["iw", "dev", self.mon_iface, "set", "type", "managed"])
            self._run(["ip", "link", "set", self.mon_iface, "up"])
            if self._which("nmcli"):
                self._run(["nmcli", "device", "set", self.mon_iface, "managed", "yes"])
        except Exception:
            pass

    def _setup(self):
        self.base_iface = self._resolve_iface_name(self.orig_iface_arg)
        print(f"[*] Using base interface: {self.base_iface}")
        info = self._run(["iw", "dev", self.base_iface, "info"]).stdout
        if "type monitor" in info:
            self.mon_iface = self.base_iface
            print(f"[*] {self.base_iface} already in monitor mode.")
        else:
            print("[*] Enabling monitor mode...")
            self.mon_iface = self._enable_monitor_mode(self.base_iface)
            print(f"[+] Monitor mode active on: {self.mon_iface}")







    def set_channel(self, ch):
        self.stop_hop()
        ok = self._run(["iw", "dev", self.mon_iface, "set", "channel", str(ch)])
        if ok.returncode != 0:
            freq = self._ch_to_freq(ch)
            self._run(["iw", "dev", self.mon_iface, "set", "freq", str(freq)])
        self.current_channel = ch
        self._log_event(f"[channel] switched to {ch}")

    def start_hop(self, band=None, interval=0.35):
        self.stop_hop()
        chans = CHANNELS_24 + CHANNELS_5 if band is None else (
            CHANNELS_24 if band == "2.4" else CHANNELS_5)
        self._hop_stop.clear()
        self.hopping = True

        def loop():
            i = 0
            while not self._hop_stop.is_set():
                ch = chans[i % len(chans)]
                self._run(["iw", "dev", self.mon_iface, "set", "channel", str(ch)])
                self.current_channel = ch
                i += 1
                time.sleep(interval)
        self._hop_thread = threading.Thread(target=loop, daemon=True)
        self._hop_thread.start()
        self._log_event(f"[channel] hopping started ({band or 'all'})")

    def stop_hop(self):
        if self._hop_thread is not None:
            self._hop_stop.set()
            self._hop_thread.join(timeout=1)
            self._hop_thread = None
        self.hopping = False





    def _open_session_files(self):
        self.savepath_base.mkdir(parents=True, exist_ok=True)
        name = datetime.now().strftime("%m_%d_%H-%M")
        self.session_dir = self.savepath_base / f"{datetime.now().strftime('%Y_%m_%d_%H-%M-%S')}_{name}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.txt_fh = open(self.session_dir / "scan.txt", "a", buffering=1)
        self.json_fh = open(self.session_dir / "scan.json", "a", buffering=1)
        self.pcap_writer = PcapWriter(str(self.session_dir / "scan.pcap"),
                                       append=True, sync=True)
        self.txt_fh.write(f"=== Session started {datetime.now().isoformat()} ===\n")
        print(f"[+] Saving to: {self.session_dir}")

    def _close_session_files(self):
        for fh in (self.txt_fh, self.json_fh):
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
        self.txt_fh = None
        self.json_fh = None
        self.pcap_writer = None
        self.session_dir = None

    def _status(self, text):
        pad = " " * max(0, self._status_len - len(text))
        sys.stdout.write("\r" + text + pad)
        sys.stdout.flush()
        self._status_len = len(text)
        self._status_active = True

    def _newline_if_status(self):
        if self._status_active:
            print()
            self._status_active = False
            self._status_len = 0

    def _log_event(self, text, data=None, pkt=None):
        self._newline_if_status()
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        print(line)
        if self.saving and self.session_dir:
            with self._lock:
                if self.txt_fh:
                    self.txt_fh.write(line + "\n")
                if self.json_fh and data is not None:
                    rec = {"time": ts, "text": text, **data}
                    self.json_fh.write(json.dumps(rec) + "\n")
                if self.pcap_writer and pkt is not None:
                    try:
                        self.pcap_writer.write(pkt)
                    except Exception:
                        pass





    def _reopen_logs(self):
        if self.session_dir and self.txt_fh:
            try:
                self.txt_fh.close()
            except Exception:
                pass
            self.txt_fh = open(self.session_dir / "scan.txt", "w", buffering=1)
            self.txt_fh.write(f"=== Logs cleared {datetime.now().isoformat()} ===\n")
        if self.session_dir and self.json_fh:
            try:
                self.json_fh.close()
            except Exception:
                pass
            self.json_fh = open(self.session_dir / "scan.json", "w", buffering=1)

    def clear_logs(self):
        with self._lock:
            self._reopen_logs()
            for d in (self.probe_hist, self.deauth_hist, self.disassoc_hist,
                      self.auth_hist, self.beacon_ssid_hist):
                d.clear()
            self.eapol_pairs.clear()
            self.handshake_done.clear()
            self._flood_last_alert.clear()
            self._flood_first_seen.clear()





    def _src_info(self, pkt):
        mac = pkt.addr2 if pkt.haslayer(Dot11) else None
        rssi = None
        if pkt.haslayer(RadioTap):
            rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)
        return mac or "??:??:??:??:??:??", rssi, self.current_channel

    def _avg_other_rate(self, hist, exclude_mac, now):
        cutoff = now - self.BASELINE_WINDOW
        rates = []
        for m, dq in hist.items():
            if m == exclude_mac:
                continue
            pts = [t for t in dq if t >= cutoff]
            if len(pts) < 2:
                continue
            duration = max(1.0, now - pts[0])
            rates.append(len(pts) / duration)
        if not rates:
            return 0.0
        return sum(rates) / len(rates)

    def _flood_check(self, hist, mac, kind):
        now = time.time()
        prev_last = hist[mac][-1] if hist[mac] else None
        hist[mac].append(now)
        keep_from = now - (self.SUSTAIN_SECONDS + 2)
        while hist[mac] and hist[mac][0] < keep_from:
            hist[mac].popleft()

        key = (kind, mac)
        if prev_last is None or (now - prev_last) > self.SUSTAIN_SECONDS:
            self._flood_first_seen[key] = now
        first_seen = self._flood_first_seen.setdefault(key, now)
        window_start = now - self.SUSTAIN_SECONDS
        recent = [t for t in hist[mac] if t >= window_start]
        total = len(recent)


        if now - first_seen < self.SUSTAIN_SECONDS:
            return False, total





        avg_rate = self._avg_other_rate(hist, mac, now)
        threshold = max(self.PER_SECOND_FLOOR, avg_rate * self.FLOOD_MULTIPLIER)

        buckets = defaultdict(int)
        for t in recent:
            buckets[int(t)] += 1
        oldest_second = int(window_start)
        seconds_to_check = [int(now) - i for i in range(1, self.SUSTAIN_SECONDS)]
        if oldest_second not in seconds_to_check:
            seconds_to_check.append(oldest_second)
        sustained = all(buckets.get(s, 0) >= threshold for s in seconds_to_check)

        if sustained and now - self._flood_last_alert[key] > self.ALERT_COOLDOWN:
            self._flood_last_alert[key] = now
            return True, total
        return False, total

    @staticmethod
    def _get_ssid(pkt):
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if getattr(elt, "ID", None) == 0:
                    raw = elt.info
                    if not raw:
                        return "<hidden>"
                    try:
                        return raw.decode(errors="replace")
                    except Exception:
                        return str(raw)
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        except Exception:
            pass
        return None

    def _ssid_flood_check(self, mac, ssid, now):
        if ssid is None:
            return False, 0
        hist = self.beacon_ssid_hist[mac]
        hist.append((now, ssid))
        cutoff = now - self.SSID_FLOOD_WINDOW
        while hist and hist[0][0] < cutoff:
            hist.popleft()
        distinct = {s for _, s in hist}
        if len(distinct) >= self.SSID_FLOOD_DISTINCT:
            key = ("ap_flood", mac)
            if now - self._flood_last_alert[key] > self.ALERT_COOLDOWN:
                self._flood_last_alert[key] = now
                return True, len(distinct)
        return False, len(distinct)

    def _is_malformed(self, pkt):
        reasons = []
        try:
            raw = bytes(pkt)
            if len(raw) < 10:
                reasons.append("frame too short")
            if pkt.haslayer(Dot11):
                d = pkt[Dot11]
                if d.type is None or d.subtype is None:
                    reasons.append("missing type/subtype")
                if d.type == 0 and d.subtype not in range(0, 16):
                    reasons.append("invalid mgmt subtype")
                if d.addr1 and not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", d.addr1):
                    reasons.append("malformed addr1")
            if pkt.haslayer(RadioTap):
                flags = getattr(pkt[RadioTap], "Flags", None)
                try:
                    if flags is not None and "BADFCS" in str(flags).upper():
                        reasons.append("bad FCS")
                except Exception:
                    pass
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    try:
                        if elt.len is not None and elt.len > 255:
                            reasons.append("oversized information element")
                    except Exception:
                        reasons.append("corrupt information element")
                    elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        except Exception as e:
            reasons.append(f"parse exception: {e}")
        return reasons

    def _handle_eapol(self, pkt):
        mac1, mac2 = pkt.addr1, pkt.addr2
        pair = tuple(sorted([mac1 or "", mac2 or ""]))
        now = time.time()
        self.eapol_pairs[pair].append(now)
        cutoff = now - 10
        self.eapol_pairs[pair] = [t for t in self.eapol_pairs[pair] if t >= cutoff]
        if pair not in self.handshake_done and len(self.eapol_pairs[pair]) >= 4:
            recent = [t for t in self.eapol_pairs[pair] if now - t < 10]
            if len(recent) >= 4:
                self.handshake_done.add(pair)
                return True
        return False





    def _current_filter(self):
        return FILTER_MODES[self.filter_idx]

    def _packet_callback(self, pkt):
        if self.paused and not self.raw_mode:
            return
        if not pkt.haslayer(Dot11):
            return

        if self.raw_mode:
            mac, rssi, ch = self._src_info(pkt)
            self._log_event(
                f"[RAW] {pkt.summary()} | src={mac} rssi={rssi} ch={ch}",
                data={"kind": "raw", "mac": mac, "rssi": rssi, "channel": ch,
                      "summary": pkt.summary()},
                pkt=pkt,
            )
            return

        fmode = self._current_filter()
        mac, rssi, ch = self._src_info(pkt)

        def report(kind, msg, extra=None):
            data = {"kind": kind, "mac": mac, "rssi": rssi, "channel": ch}
            if extra:
                data.update(extra)
            self._log_event(msg, data=data, pkt=pkt)

        if pkt.haslayer(Dot11Deauth):
            hit, count = self._flood_check(self.deauth_hist, mac, "deauth")
            if fmode in ("all", "deauth") and hit:
                report("deauth_flood",
                       f"[!] DEAUTH FLOOD from {mac} (rssi={rssi} ch={ch}, "
                       f"{count} in {self.SUSTAIN_SECONDS}s)", {"count": count})
            elif fmode == "deauth":
                report("deauth", f"[deauth] frame from {mac} (rssi={rssi} ch={ch})")

        if pkt.haslayer(Dot11Disas):
            hit, count = self._flood_check(self.disassoc_hist, mac, "disassoc")
            if fmode in ("all", "disassoc_flood") and hit:
                report("disassoc_flood",
                       f"[!] DISASSOC FLOOD from {mac} (rssi={rssi} ch={ch}, "
                       f"{count} in {self.SUSTAIN_SECONDS}s)", {"count": count})
            elif fmode == "disassoc_flood":
                report("disassoc", f"[disassoc] frame from {mac} (rssi={rssi} ch={ch})")

        if pkt.haslayer(Dot11ProbeReq):
            hit, count = self._flood_check(self.probe_hist, mac, "probe")
            if fmode in ("all", "probe_flood") and hit:
                report("probe_flood",
                       f"[!] PROBE FLOOD from {mac} (rssi={rssi} ch={ch}, "
                       f"{count} in {self.SUSTAIN_SECONDS}s)", {"count": count})

        if pkt.haslayer(Dot11Beacon):
            ssid = self._get_ssid(pkt)
            hit, distinct_count = self._ssid_flood_check(mac, ssid, time.time())
            if fmode in ("all", "ap_flood") and hit:
                report("ap_flood",
                       f"[!] AP FLOOD from {mac} (rssi={rssi} ch={ch}) — "
                       f"{distinct_count} different SSIDs in "
                       f"{self.SSID_FLOOD_WINDOW}s, real APs never do this "
                       f"(possible rogue/fake AP or beacon-flood tool)",
                       {"distinct_ssids": distinct_count})

        if pkt.haslayer(Dot11Auth):
            hit, count = self._flood_check(self.auth_hist, mac, "auth")
            if fmode in ("all", "auth_flood") and hit:
                report("auth_flood",
                       f"[!] AUTH FLOOD from {mac} (rssi={rssi} ch={ch}, "
                       f"{count} in {self.SUSTAIN_SECONDS}s)", {"count": count})

        if pkt.haslayer(EAPOL):
            done = self._handle_eapol(pkt)
            if fmode in ("handshake", "all") and done:
                report("handshake_captured",
                       f"[+] HANDSHAKE CAPTURED involving {mac} (ch={ch})")

        if fmode == "malformed":
            reasons = self._is_malformed(pkt)
            if reasons:
                report("malformed",
                       f"[!] MALFORMED frame from {mac} (rssi={rssi} ch={ch}): "
                       f"{'; '.join(reasons)}", {"reasons": reasons})





    def _start_sniff(self):
        self._stop_sniff.clear()

        def loop():
            while not self._stop_sniff.is_set():
                try:
                    sniff(iface=self.mon_iface, prn=self._packet_callback,
                          store=False, timeout=1)
                except Exception as e:
                    self._log_event(f"[!] sniff error: {e}")
                    time.sleep(1)
        self._sniff_thread = threading.Thread(target=loop, daemon=True)
        self._sniff_thread.start()

    def _stop_sniffing(self):
        self._stop_sniff.set()
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2)





    def lock_and_follow(self, kr: "Scanner.RawKeyReader", choice=None, band=None):
        print("\n  Lock & Follow target:")
        for k, v in LOCK_TARGETS.items():
            print(f"    {k}) {v}")
        target_kind = LOCK_TARGETS.get(choice, "all") if choice else "all"
        if band is None:
            band = kr.prompt_line("  Band 2.4 or 5: ").strip()
        band = "2.4" if band.startswith("2") else "5"
        chans = CHANNELS_24 if band == "2.4" else CHANNELS_5

        self.lock_mode = True
        self._log_event(f"[lock] engaged target={target_kind} band={band}")
        print("  [LOCK] engaged — all other keys disabled. Press L again to stop.\n")

        last_seen = {"t": 0.0, "ch": None, "mac": None}
        gap_hist = deque(maxlen=20)
        chan_scores = defaultdict(float)
        search_interval = 0.35
        min_search_interval = 0.08
        max_search_interval = 0.6
        dwell_timeout_default = 2.0

        idx = 0

        def matches(kind):
            if target_kind == "all":
                return kind in ("deauth_flood", "probe_flood", "disassoc_flood",
                                 "ap_flood", "auth_flood", "deauth", "disassoc")
            return kind == target_kind or kind == target_kind.replace("_flood", "")


        orig_cb = self._packet_callback

        def lock_cb(pkt):
            orig_cb(pkt)
            if not pkt.haslayer(Dot11):
                return
            kind = None
            if pkt.haslayer(Dot11Deauth):
                kind = "deauth_flood"
            elif pkt.haslayer(Dot11Disas):
                kind = "disassoc_flood"
            elif pkt.haslayer(Dot11ProbeReq):
                kind = "probe_flood"
            elif pkt.haslayer(Dot11Beacon):
                kind = "ap_flood"
            elif pkt.haslayer(Dot11Auth):
                kind = "auth_flood"
            if kind and matches(kind):
                now = time.time()
                if last_seen["t"]:
                    gap_hist.append(now - last_seen["t"])
                last_seen["t"] = now
                last_seen["ch"] = self.current_channel
                last_seen["mac"] = pkt.addr2
                chan_scores[self.current_channel] += 1.0

        self._packet_callback = lock_cb

        try:
            while self.lock_mode:
                now = time.time()
                if last_seen["t"] and (now - last_seen["t"]) < dwell_timeout_default:

                    if self.current_channel != last_seen["ch"] and last_seen["ch"]:
                        self.set_channel(last_seen["ch"])
                    time.sleep(0.15)
                    continue

                if last_seen["t"] == 0:

                    ch = chans[idx % len(chans)]
                    idx += 1
                    self.set_channel(ch)
                    time.sleep(search_interval)
                    continue



                if gap_hist:
                    avg_gap = sum(gap_hist) / len(gap_hist)
                    search_interval = max(min_search_interval,
                                           min(max_search_interval, avg_gap / 4))
                else:
                    search_interval = min_search_interval

                ranked = sorted(chans, key=lambda c: -chan_scores.get(c, 0))
                ch = ranked[idx % len(ranked)]
                idx += 1
                self.set_channel(ch)
                if idx % len(ranked) == 0:
                    self._log_event(
                        f"[lock] signal lost, sweeping (interval={search_interval:.2f}s)"
                    )
                time.sleep(search_interval)
        finally:
            self._packet_callback = orig_cb
            self._log_event("[lock] disengaged")





    def _print_help(self):
        self._newline_if_status()
        print("\n--- Wi-Fi Scan Module ---")
        print(f"iface(monitor)={self.mon_iface}  channel={self.current_channel}  "
              f"filter={self._current_filter()}")
        print("Keys: [F]ilter [P]ause [R]aw [C]lear logs [E]channel [S]ave "
              "[L]ock&Follow [Q]uit\n")

    def _handle_key(self, key, kr):
        if key is None:
            return
        key = key.lower()

        if self.lock_mode:
            if key == "l":
                self.lock_mode = False
            elif key == "q":
                self.lock_mode = False
                self.running = False
            return

        if key == "q":
            self.running = False

        elif key == "f":
            self.filter_idx = (self.filter_idx + 1) % len(FILTER_MODES)
            self._status(f"  [filter] -> {self._current_filter()}")

        elif key == "p":
            self.paused = not self.paused
            self._status(f"  [pause] -> {'PAUSED' if self.paused else 'RUNNING'}")

        elif key == "r":
            self.raw_mode = not self.raw_mode
            self._status(f"  [raw] -> {'ON (overrides filter)' if self.raw_mode else 'OFF'}")

        elif key == "c":
            self.clear_logs()
            self._status("  [clear] -> logs cleared")

        elif key == "e":
            self._newline_if_status()
            val = kr.prompt_line("  Channel number (or 'h' to hop): ").strip().lower()
            if val == "h":
                b = kr.prompt_line("  Band 2.4 or 5 (blank=both): ").strip()
                band = "2.4" if b.startswith("2") else ("5" if b.startswith("5") else None)
                self.start_hop(band)
                self._status(f"  [channel] -> hopping ({band or 'all'})")
            else:
                try:
                    self.set_channel(int(val))
                    self._status(f"  [channel] -> {val}")
                except ValueError:
                    self._status("  [!] invalid channel")

        elif key == "s":
            self.saving = not self.saving
            if self.saving and not self.session_dir:
                self._newline_if_status()
                self._open_session_files()
            self._status(f"  [save] -> {'ON' if self.saving else 'OFF'} "
                         f"({self.session_dir if self.session_dir else 'no folder yet'})")

        elif key == "l":
            self._newline_if_status()
            choice = kr.prompt_line("  Select target [1-6]: ").strip()
            band = kr.prompt_line("  Band 2.4 or 5: ").strip()
            threading.Thread(target=self.lock_and_follow, args=(kr, choice, band),
                              daemon=True).start()

        elif key == "?":
            self._print_help()

    def run(self):
        if os.geteuid() != 0:
            print("[!] This needs root (monitor mode / channel control). "
                  "Re-run with sudo.")
            return

        try:
            self._setup()
            self._start_sniff()
            self.running = True
            self._print_help()

            with self.RawKeyReader() as kr:
                self._kr = kr
                while self.running:
                    key = kr.getch(timeout=0.2)
                    if key:
                        self._handle_key(key, kr)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        print("\n[*] Shutting down...")
        self.lock_mode = False
        self.stop_hop()
        self._stop_sniffing()
        self._close_session_files()
        self._disable_monitor_mode()
        print("[*] Done.")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Defensive Wi-Fi scan module (Scanner)")
    p.add_argument("iface", help="interface name (e.g. wlan0) or index number")
    p.add_argument("-o", "--savepath", default="./wifi_scans",
                    help="base directory for saved sessions")
    args = p.parse_args()
    Scanner(iface=args.iface, savepath=args.savepath).run()