"""Tests that settings are validated/sanitized at load time, not just on `set`.

A hand-edited or corrupt settings.json must not pass malformed values through to
hostapd/dnsmasq/iptables command construction.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC.settings import DEFAULTS, load_settings


def _write(tmp_path, data):
    (tmp_path / "settings.json").write_text(json.dumps(data))


def test_missing_file_returns_defaults(tmp_path):
    s = load_settings(tmp_path)
    assert s["channel"] == DEFAULTS["channel"]
    assert s["ip_range"] == DEFAULTS["ip_range"]


def test_malformed_json_falls_back_to_defaults(tmp_path):
    (tmp_path / "settings.json").write_text("{ this is not json ")
    s = load_settings(tmp_path)
    assert s["ssid"] == DEFAULTS["ssid"]  # no crash, defaults used


def test_unknown_keys_are_ignored(tmp_path):
    _write(tmp_path, {"ssid": "MyAP", "evil_injected_key": "rm -rf /"})
    s = load_settings(tmp_path)
    assert s["ssid"] == "MyAP"
    assert "evil_injected_key" not in s


def test_bad_channel_is_sanitized_on_load(tmp_path):
    _write(tmp_path, {"band": "2.4", "channel": 99})   # invalid for 2.4GHz
    s = load_settings(tmp_path)
    assert s["channel"] == 6                            # corrected, not 99


def test_bad_ip_range_is_sanitized_on_load(tmp_path):
    _write(tmp_path, {"ip_range": "not-a-network"})
    s = load_settings(tmp_path)
    assert s["ip_range"] == str(DEFAULTS["ip_range"])   # reset to a valid CIDR


def test_oversized_ssid_security_coupling_on_load(tmp_path):
    # open security must blank the PSK even if the file sets one
    _write(tmp_path, {"security": "open", "psk": "leftover-secret"})
    s = load_settings(tmp_path)
    assert s["psk"] == ""


def test_non_integer_mtu_is_sanitized_on_load(tmp_path):
    _write(tmp_path, {"mtu": "garbage"})
    s = load_settings(tmp_path)
    assert s["mtu"] == 0                                # reset to auto
