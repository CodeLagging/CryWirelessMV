"""Behaviour tests for the pure helpers in the Bluetooth scanner (no DBus/hardware)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.BT_HCI.bluetooth import bluetooth


@pytest.fixture
def bt():
    # __init__ only checks platform + sets status; no DBus connection happens here.
    return bluetooth()


class _Variant:
    """Stand-in for a dbus_next Variant, which exposes `.value`."""
    def __init__(self, value):
        self.value = value


# --- root / sudo detection -------------------------------------------------

def test_is_root_true_when_euid_zero(bt, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert bt._is_root() is True


def test_is_root_false_when_not_zero(bt, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert bt._is_root() is False


def test_running_under_sudo_requires_root_and_sudo_uid(bt, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    assert bt._running_under_sudo() is True
    monkeypatch.delenv("SUDO_UID", raising=False)
    assert bt._running_under_sudo() is False


def test_restore_ownership_is_noop_without_sudo(bt, monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)   # not root
    called = []
    monkeypatch.setattr(os, "chown", lambda *a: called.append(a))
    bt._restore_sudo_user_ownership(tmp_path / "x")
    assert called == []                                 # never chowns


def test_restore_ownership_chowns_under_sudo(bt, monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    f = tmp_path / "capture.hc22000"
    f.write_text("x")
    called = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: called.append((str(p), u, g)))
    bt._restore_sudo_user_ownership(f)
    assert called == [(str(f), 1000, 1000)]


# --- _unwrap (dbus Variant flattening) -------------------------------------

def test_unwrap_scalar_and_nested_variant(bt):
    assert bt._unwrap(_Variant(_Variant(42))) == 42


def test_unwrap_dict_and_list(bt):
    out = bt._unwrap({_Variant("k"): _Variant([_Variant(1), _Variant(2)])})
    assert out == {"k": [1, 2]}


def test_unwrap_bytes_passthrough(bt):
    assert bt._unwrap(_Variant(bytearray(b"\x01\x02"))) == b"\x01\x02"


# --- class-name decoding ---------------------------------------------------

def test_major_class_unknown(bt):
    assert bt._major_class_name(0xFFFF) == "Unknown"


def test_peripheral_minor_bit_logic(bt):
    assert bt._minor_class_name(5, 0x10) == "Keyboard"
    assert bt._minor_class_name(5, 0x20) == "Pointing Device"
    assert bt._minor_class_name(5, 0x30) == "Combo Keyboard/Pointing Device"


def test_imaging_minor_bit_logic(bt):
    assert "Camera" in bt._minor_class_name(6, 0x08)
    assert "Printer" in bt._minor_class_name(6, 0x20)


# --- _parse_int ------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (5, 5),
    ("0x1a", 26),
    ("42", 42),
    ("nope", None),
    (None, None),
])
def test_parse_int(bt, value, expected):
    assert bt._parse_int(value) == expected


# --- COMPANY_IDS -----------------------------------------------------------

def test_company_ids_is_populated_int_to_str(bt):
    assert isinstance(bt.COMPANY_IDS, dict)
    assert bt.COMPANY_IDS
    cid, name = next(iter(bt.COMPANY_IDS.items()))
    assert isinstance(cid, int) and isinstance(name, str)
    assert bt.COMPANY_IDS[cid] == name
