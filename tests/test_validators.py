import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validators import (
    is_valid_channel,
    is_valid_iface,
    is_valid_ip_range,
    is_valid_mac,
    is_valid_ssid,
    validate_iface,
    validate_mac,
)

# --- validate_iface --------------------------------------------------------

@pytest.mark.parametrize("name", ["wlan0", "eth0", "wlan0mon", "br-lan", "ap_0", "a"])
def test_validate_iface_accepts_valid(name):
    assert validate_iface(name) == name


@pytest.mark.parametrize("name", [
    "",                     # empty
    "wlan0; rm -rf /",      # shell injection
    "wlan 0",               # space
    "eth0|nc",              # pipe
    "a" * 16,               # too long (>15)
    "wlan$0",               # special char
    "../etc",               # path traversal chars
])
def test_validate_iface_rejects_invalid(name):
    with pytest.raises(ValueError):
        validate_iface(name)


def test_is_valid_iface_matches_validate():
    assert is_valid_iface("wlan0") is True
    assert is_valid_iface("bad name") is False
    assert is_valid_iface("") is False


# --- validate_mac ----------------------------------------------------------

def test_validate_mac_colon_form():
    assert validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_validate_mac_dash_form_normalized_to_colons():
    assert validate_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize("mac", [
    "",
    "AA:BB:CC:DD:EE",        # 5 octets
    "AA:BB:CC:DD:EE:FF:00",  # 7 octets
    "ZZ:BB:CC:DD:EE:FF",     # non-hex
    "aabbccddeeff",          # no separators
])
def test_validate_mac_rejects_invalid(mac):
    with pytest.raises(ValueError):
        validate_mac(mac)


def test_is_valid_mac():
    assert is_valid_mac("00:11:22:33:44:55") is True
    assert is_valid_mac("nope") is False


# --- is_valid_channel ------------------------------------------------------

@pytest.mark.parametrize("ch", [1, 6, 11, 14, 36, 149, 165, "6", "36"])
def test_is_valid_channel_accepts(ch):
    assert is_valid_channel(ch) is True


@pytest.mark.parametrize("ch", [0, 15, 31, 200, -1, "abc", None])
def test_is_valid_channel_rejects(ch):
    assert is_valid_channel(ch) is False


def test_is_valid_channel_truncates_floats():
    assert is_valid_channel(6.0) is True       # int(6.0) == 6
    assert is_valid_channel(200.0) is False


# --- is_valid_ip_range -----------------------------------------------------

@pytest.mark.parametrize("cidr", ["192.168.0.0/24", "10.0.0.0/8", "192.168.1.5/24"])
def test_is_valid_ip_range_accepts(cidr):
    assert is_valid_ip_range(cidr) is True


@pytest.mark.parametrize("cidr", ["not-a-network", "999.0.0.0/24", "fe80::/64", ""])
def test_is_valid_ip_range_rejects(cidr):
    assert is_valid_ip_range(cidr) is False


# --- is_valid_ssid ---------------------------------------------------------

def test_is_valid_ssid_length_boundaries():
    assert is_valid_ssid("") is True
    assert is_valid_ssid("A" * 32) is True
    assert is_valid_ssid("A" * 33) is False


def test_is_valid_ssid_counts_utf8_bytes_not_chars():
    # "é" is 2 bytes in UTF-8, so 16 of them = 32 bytes (ok), 17 = 34 (too long)
    assert is_valid_ssid("é" * 16) is True
    assert is_valid_ssid("é" * 17) is False


def test_is_valid_ssid_none():
    assert is_valid_ssid(None) is False
