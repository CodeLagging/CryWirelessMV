"""Tests for the extracted Bluetooth lookup tables (Task 06 / Task 09)."""
from core.BT_HCI.ble_constants import BluetoothConstants


def test_company_ids_has_known_vendors():
    assert BluetoothConstants.COMPANY_IDS[0x004C] == "Apple"
    assert BluetoothConstants.COMPANY_IDS[0x00E0] == "Google"
    assert BluetoothConstants.COMPANY_IDS[0x0075] == "Samsung"


def test_uuid_names_cover_common_profiles():
    hid = "00001124-0000-1000-8000-00805f9b34fb"
    battery = "0000180f-0000-1000-8000-00805f9b34fb"
    heart = "0000180d-0000-1000-8000-00805f9b34fb"
    assert BluetoothConstants.UUID_NAMES[hid] == "Human Interface Device"
    assert BluetoothConstants.UUID_NAMES[battery] == "Battery Service"
    assert BluetoothConstants.UUID_NAMES[heart] == "Heart Rate"


def test_major_class_names_cover_every_known_major():
    expected = {
        0: "Miscellaneous",
        1: "Computer",
        2: "Phone",
        3: "LAN/Network Access",
        4: "Audio/Video",
        5: "Peripheral",
        6: "Imaging",
        7: "Wearable",
        8: "Toy",
        9: "Health",
        31: "Uncategorized",
    }
    assert BluetoothConstants.MAJOR_CLASS_NAMES == expected


def test_minor_class_names_are_dict_of_dicts():
    assert isinstance(BluetoothConstants.MINOR_CLASS_NAMES, dict)
    for major, mapping in BluetoothConstants.MINOR_CLASS_NAMES.items():
        assert isinstance(major, int)
        assert isinstance(mapping, dict)
        for minor, label in mapping.items():
            assert isinstance(minor, int)
            assert isinstance(label, str)


def test_service_class_names_bitmap():
    assert BluetoothConstants.SERVICE_CLASS_NAMES[13] == "Limited Discoverable Mode"
    assert BluetoothConstants.SERVICE_CLASS_NAMES[21] == "Audio"
    assert BluetoothConstants.SERVICE_CLASS_NAMES[22] == "Telephony"


def test_bluetooth_class_reexports_constants():
    """The scanner should still expose the same tables for backwards compat."""
    from core.BT_HCI.bluetooth import bluetooth

    assert bluetooth.COMPANY_IDS is BluetoothConstants.COMPANY_IDS
    assert bluetooth.UUID_NAMES is BluetoothConstants.UUID_NAMES
    assert bluetooth.MAJOR_CLASS_NAMES is BluetoothConstants.MAJOR_CLASS_NAMES
    assert bluetooth.MINOR_CLASS_NAMES is BluetoothConstants.MINOR_CLASS_NAMES
    assert bluetooth.SERVICE_CLASS_NAMES is BluetoothConstants.SERVICE_CLASS_NAMES