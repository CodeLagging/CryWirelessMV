import os
import sys

import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

def test_ble_module_imports():
    try:
        from core.BT_HCI import ble_module
        assert ble_module is not None
    except ImportError as e:
        pytest.fail(f"Failed to import core.BT_HCI.ble_module: {e}")

def test_ble_module_has_class():
    try:
        from core.BT_HCI import ble_module
    except ImportError:
        pytest.skip("BLE module not available")
    classes = [name for name in dir(ble_module) if name.startswith("Ble")]
    assert len(classes) > 0, "No Ble* class found in ble_module"

def test_bluetooth_module_imports():
    try:
        from core.BT_HCI import bluetooth
        assert bluetooth is not None
    except ImportError:
        pytest.skip("Bluetooth module not available")

def test_ble_module_instantiation():
    try:
        from core.BT_HCI.ble_module import BleModule
    except ImportError:
        pytest.skip("BleModule class not found")
    try:
        instance = BleModule()
        assert instance is not None
    except (ImportError, RuntimeError, OSError) as e:
        pytest.fail(f"BleModule() crashed on init: {e}")