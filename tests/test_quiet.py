import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from core.WIFI.quiet_device import (
    _ALL_5,
    _ALL_24,
    _BCAST,
    _build_beacon,
    _quiet_ie,
    _resolve_channels,
)


def test_resolve_channels_all():
    chans = _resolve_channels("all")
    assert 1 in chans
    assert 13 in chans
    assert 36 in chans
    assert 165 in chans

def test_resolve_channels_none_means_all():
    chans = _resolve_channels(None)
    assert len(chans) == len(_ALL_24) + len(_ALL_5)

def test_resolve_channels_int():
    assert _resolve_channels(6) == [6]

def test_resolve_channels_list():
    assert _resolve_channels([1, 6, 11]) == [1, 6, 11]

def test_quiet_ie_is_dot11elt_with_id_40():
    ie = _quiet_ie()
    assert isinstance(ie, Dot11Elt)
    assert ie.ID == 40
    assert len(ie.info) == 6

def test_build_beacon_produces_parseable_packet():
    raw = _build_beacon("aa:bb:cc:dd:ee:ff", "MyNet", 6)
    assert isinstance(raw, (bytes, bytearray))
    pkt = RadioTap(raw)
    assert pkt.haslayer(Dot11Beacon)
    assert pkt[Dot11].addr2 == "aa:bb:cc:dd:ee:ff"
    assert pkt[Dot11].addr3 == "aa:bb:cc:dd:ee:ff"

def test_build_beacon_ssid_matches():
    raw = _build_beacon("aa:bb:cc:dd:ee:ff", "TestSSID", 11)
    pkt = RadioTap(raw)
    elt = pkt.getlayer(Dot11Elt)
    ssid_found = None
    while elt is not None:
        if elt.ID == 0:
            ssid_found = elt.info
            break
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    assert ssid_found == b"TestSSID"

def test_build_beacon_includes_channel():
    raw = _build_beacon("aa:bb:cc:dd:ee:ff", "Net", 11)
    pkt = RadioTap(raw)
    elt = pkt.getlayer(Dot11Elt)
    ds_channel = None
    while elt is not None:
        if elt.ID == 3:
            ds_channel = elt.info[0]
            break
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    assert ds_channel == 11

def test_build_beacon_includes_quiet_ie():
    raw = _build_beacon("aa:bb:cc:dd:ee:ff", "Net", 6)
    pkt = RadioTap(raw)
    elt = pkt.getlayer(Dot11Elt)
    has_quiet = False
    while elt is not None:
        if elt.ID == 40:
            has_quiet = True
            break
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    assert has_quiet, "Quiet IE (ID 40) missing from beacon"

def test_broadcast_mac_constant():
    assert _BCAST == "ff:ff:ff:ff:ff:ff"