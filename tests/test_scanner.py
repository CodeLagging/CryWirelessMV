import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.WIFI.scanner import CHANNELS_5, CHANNELS_24, FILTER_MODES, Scanner


def test_ch_to_freq_2_4ghz():
    assert Scanner._ch_to_freq(1) == 2412
    assert Scanner._ch_to_freq(6) == 2437
    assert Scanner._ch_to_freq(11) == 2462
    assert Scanner._ch_to_freq(13) == 2472

def test_ch_to_freq_channel_14():
    assert Scanner._ch_to_freq(14) == 2484

def test_ch_to_freq_5ghz():
    assert Scanner._ch_to_freq(36) == 5180
    assert Scanner._ch_to_freq(149) == 5745
    assert Scanner._ch_to_freq(165) == 5825

def test_channels_lists_are_sane():
    assert CHANNELS_24 == list(range(1, 14))
    assert 36 in CHANNELS_5
    assert 165 in CHANNELS_5
    assert 1 not in CHANNELS_5

def test_filter_modes_are_strings():
    assert all(isinstance(m, str) for m in FILTER_MODES)
    assert "all" in FILTER_MODES
    assert "deauth" in FILTER_MODES
    assert "handshake" in FILTER_MODES

def test_get_ssid_returns_none_for_empty_packet():
    from scapy.all import Dot11
    pkt = Dot11(type=0, subtype=8)
    # No Dot11Elt layer, so _get_ssid should return None
    assert Scanner._get_ssid(pkt) is None

def test_get_ssid_parses_ssid_from_beacon():
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt
    pkt = (Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                 addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")
           / Dot11Beacon()
           / Dot11Elt(ID=0, info=b"TestNetwork"))
    assert Scanner._get_ssid(pkt) == "TestNetwork"

def test_get_ssid_handles_hidden_ssid():
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt
    pkt = (Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                 addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")
           / Dot11Beacon()
           / Dot11Elt(ID=0, info=b""))
    assert Scanner._get_ssid(pkt) == "<hidden>"