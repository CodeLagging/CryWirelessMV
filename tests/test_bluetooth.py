"""Tests for the DeviceRecord display-name fallback logic."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.BT_HCI.bluetooth import DeviceRecord


def test_title_prefers_alias():
    d = DeviceRecord(path="/org/bluez/hci0/dev_X", address="AA:BB", name="Nm", alias="Al")
    assert d.title() == "Al"


def test_title_falls_back_to_name():
    d = DeviceRecord(path="/org/bluez/hci0/dev_X", address="AA:BB", name="Nm")
    assert d.title() == "Nm"


def test_title_falls_back_to_address():
    d = DeviceRecord(path="/org/bluez/hci0/dev_X", address="AA:BB:CC:DD:EE:FF")
    assert d.title() == "AA:BB:CC:DD:EE:FF"


def test_title_falls_back_to_path_basename():
    d = DeviceRecord(path="/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
    assert d.title() == "dev_AA_BB_CC_DD_EE_FF"


def test_title_skips_empty_strings_in_order():
    # empty alias + empty name should skip to address
    d = DeviceRecord(path="/x/y", alias="", name="", address="00:11:22:33:44:55")
    assert d.title() == "00:11:22:33:44:55"
