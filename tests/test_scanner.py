import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.WIFI.scanner import CHANNELS_5, CHANNELS_24, FILTER_MODES, Scanner


class _FakeRun:
    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


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


# --- _resolve_iface_name ---------------------------------------------------

def _scanner(tmp_path):
    return Scanner("wlan0", savepath=str(tmp_path))


def test_resolve_iface_name_passthrough(tmp_path):
    s = _scanner(tmp_path)
    assert s._resolve_iface_name("wlan1") == "wlan1"
    assert s._resolve_iface_name("  wlan0  ") == "wlan0"  # stripped


def test_resolve_iface_name_by_index(tmp_path, monkeypatch):
    s = _scanner(tmp_path)
    monkeypatch.setattr(Scanner, "_run",
                        lambda *a, **k: _FakeRun("Interface wlan0\nInterface wlan1\n"))
    assert s._resolve_iface_name("0") == "wlan0"
    assert s._resolve_iface_name("1") == "wlan1"


def test_resolve_iface_name_index_out_of_range(tmp_path, monkeypatch):
    s = _scanner(tmp_path)
    monkeypatch.setattr(Scanner, "_run",
                        lambda *a, **k: _FakeRun("Interface wlan0\n"))
    with pytest.raises(RuntimeError):
        s._resolve_iface_name("5")


def test_resolve_iface_name_no_interfaces(tmp_path, monkeypatch):
    s = _scanner(tmp_path)
    monkeypatch.setattr(Scanner, "_run", lambda *a, **k: _FakeRun(""))
    with pytest.raises(RuntimeError):
        s._resolve_iface_name("0")