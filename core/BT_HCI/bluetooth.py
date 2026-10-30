from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.BT_HCI.ble_constants import BluetoothConstants


@dataclass
class DeviceRecord:
    path: str
    name: str = ""
    alias: str = ""
    address: str = ""
    address_type: str = ""
    class_code: int | None = None
    major: str = "Unknown"
    minor: str = "Unknown"
    services: list[str] = field(default_factory=list)
    uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[Any, Any] = field(default_factory=dict)
    service_data: dict[str, Any] = field(default_factory=dict)
    appearance: Any = ""
    paired: bool = False
    trusted: bool = False
    connected: bool = False
    blocked: bool = False
    legacy_pairing: bool = False
    wake_allowed: bool = False
    icon: str = ""
    modalias: str = ""
    adapter: str = ""
    battery: int | None = None
    vendor: str = "Unknown"
    rssi: int | None = None
    tx_power: int | None = None
    first_seen: str = ""
    last_seen: str = ""
    times_seen: int = 0
    discoverable: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def title(self) -> str:
        return self.alias or self.name or self.address or self.path.rsplit("/", 1)[-1]


class bluetooth:

    BLUEZ = "org.bluez"
    OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
    PROPERTIES = "org.freedesktop.DBus.Properties"
    ADAPTER = "org.bluez.Adapter1"
    DEVICE = "org.bluez.Device1"
    BATTERY = "org.bluez.Battery1"

    # Re-exported from BluetoothConstants so external callers/tests can use them.
    COMPANY_IDS = BluetoothConstants.COMPANY_IDS
    UUID_NAMES = BluetoothConstants.UUID_NAMES
    MAJOR_CLASS_NAMES = BluetoothConstants.MAJOR_CLASS_NAMES
    MINOR_CLASS_NAMES = BluetoothConstants.MINOR_CLASS_NAMES
    SERVICE_CLASS_NAMES = BluetoothConstants.SERVICE_CLASS_NAMES

    def __init__(self) -> None:
        if sys.platform != "linux":
            raise RuntimeError("This Bluetooth scanner is Linux-only and requires BlueZ.")

        self.bt_classes: dict[str, Any] = {}
        self.devices: dict[str, DeviceRecord] = {}
        self.device_order: list[str] = []
        self.adapter_path: str | None = None
        self.bus: Any = None
        self.adapter: Any = None
        self.adapter_props: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._previous_sigint_handler: Any = None
        self._sigint_handler_installed = False
        self._dirty = True
        self._last_draw = 0.0
        self._scanning = False
        self._status = ""
        self._status_persistent = ""
        self._use_rich = False
        self._console: Any = None
        self._dbus_import_error: Exception | None = None
        self.load_bt_classes()
        self._setup_rich()

    def run(self) -> None:
        self._warn_if_not_root()
        self._require_dbus_next()
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            while True:
                try:
                    self._loop.run_until_complete(self._scan_session())
                except RuntimeError:
                    if self._status:
                        print(self._status)
                    break

                choice = self.select_device()
                if choice == "rescan":
                    continue
                if choice == "exit":
                    break

                selected = choice
                while selected is not None:
                    action = self.show_device_details(selected)
                    if action == "back":
                        selected = self.select_device()
                        if selected in ("rescan", "exit"):
                            if selected == "rescan":
                                break
                            return
                    elif action == "copy":
                        self.copy_details(selected)
                    elif action == "rescan":
                        break
                    elif action == "exit":
                        return

                if selected == "rescan" or action == "rescan":
                    continue
                break
        finally:
            try:
                self._loop.run_until_complete(self.stop_scan())
            except (OSError, RuntimeError):
                pass
            self._loop.close()
            asyncio.set_event_loop(None)

    async def _scan_session(self) -> None:
        self._stop_event = asyncio.Event()
        self._install_signal_handler()
        self.clear()
        print("Scanning Bluetooth Devices...")
        print("Press Ctrl+C to stop scanning.\n")

        await self.start_scan()
        try:
            while not self._stop_event.is_set():
                if self._dirty and time.monotonic() - self._last_draw >= 0.45:
                    self.refresh_screen()
                await asyncio.sleep(0.1)
        finally:
            await self.stop_scan()
            self._restore_signal_handler()
            self.refresh_screen(force=True)
            print()

    def _warn_if_not_root(self) -> None:
        if not self._is_root():
            self._status_persistent = (
                "Warning: not running as root. BlueZ discovery may show fewer details "
                "or fail on some systems. Run your script with sudo if needed."
            )

    def _is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _running_under_sudo(self) -> bool:
        return self._is_root() and bool(os.environ.get("SUDO_UID"))

    def _user_writable_path(self, filename: str) -> Path:
        return Path.cwd() / filename

    def _restore_sudo_user_ownership(self, path: Path) -> None:
        if not self._running_under_sudo():
            return
        try:
            uid = int(os.environ["SUDO_UID"])
            gid = int(os.environ.get("SUDO_GID", uid))
            os.chown(path, uid, gid)
        except (KeyError, ValueError, OSError) as exc:
            print(f"[!] Could not restore ownership of {path}: {exc}")

    async def start_scan(self) -> None:
        await self._connect_bluez()
        if self.adapter is None:
            raise RuntimeError("No Bluetooth adapter exposing org.bluez.Adapter1 was found.")
        await self._ensure_adapter_ready()

        self._scanning = True
        self._status = ""
        try:
            if hasattr(self.adapter, "call_set_discovery_filter"):
                from dbus_next import Variant

                await self.adapter.call_set_discovery_filter(
                    {
                        "Transport": Variant("s", "auto"),
                        "DuplicateData": Variant("b", True),
                        "RSSI": Variant("n", -127),
                    }
                )
        except (AttributeError, ValueError) as exc:
            print(f"[!] Could not set discovery filter: {exc}")

        try:
            await self.adapter.call_start_discovery()
        except (OSError, RuntimeError) as exc:
            self._scanning = False
            self._status = (
                "Unable to start discovery. Make sure Bluetooth is unblocked and BlueZ is running: "
                f"{exc}"
            )
            raise

    async def stop_scan(self) -> None:
        if not self._scanning or self.adapter is None:
            return
        try:
            await self.adapter.call_stop_discovery()
        except (OSError, RuntimeError) as exc:
            print(f"[!] Could not cleanly stop discovery: {exc}")
        finally:
            self._scanning = False

    def refresh_screen(self, force: bool = False) -> None:
        if not force and not self._dirty:
            return
        self.clear()
        self.show_device_list()
        self._dirty = False
        self._last_draw = time.monotonic()

    def clear(self) -> None:
        print("\033[2J\033[H", end="")

    def load_bt_classes(self) -> None:
        self.bt_classes = {
            "major": self.MAJOR_CLASS_NAMES,
            "minor": self.MINOR_CLASS_NAMES,
            "services": self.SERVICE_CLASS_NAMES,
            "oui": {
                "00:0A:95": "Apple",
                "00:0F:00": "Broadcom",
                "00:1A:7D": "Intel",
                "00:1B:FB": "Intel",
                "00:1C:BF": "Intel",
                "00:1D:4F": "Intel",
                "00:22:7D": "Intel",
                "00:24:6C": "Intel",
                "00:26:37": "Intel",
                "00:28:F8": "Intel",
                "00:2A:6A": "Intel",
                "00:2B:67": "Intel",
                "00:2C:44": "Intel",
                "00:2F:B5": "Intel",
                "00:3E:1A": "Intel",
                "00:5A:CD": "Intel",
                "00:7C:35": "Intel",
                "08:00:27": "VirtualBox",
                "10:00:00": "Microsoft",
                "14:02:EC": "Microsoft",
                "2C:54:2D": "Samsung",
                "3C:52:82": "Samsung",
                "44:6D:57": "Samsung",
                "70:4F:57": "Samsung",
                "74:DA:38": "Samsung",
                "7C:7D:3D": "Samsung",
                "84:16:F9": "Samsung",
                "90:68:C3": "Samsung",
                "A4:34:D9": "Samsung",
                "B4:FB:E4": "Samsung",
                "C0:EE:FB": "Samsung",
                "D8:3A:DD": "Samsung",
                "E8:2A:EA": "Samsung",
                "F4:0F:24": "Google",
            },
        }

    def decode_class(self, class_code: int | None) -> tuple[str, str, list[str]]:
        if class_code is None:
            return "Unknown", "Unknown", []

        major_key = (class_code >> 8) & 0x1F
        minor_key = (class_code >> 2) & 0x3F
        service_mask = class_code & 0xFFE000

        major = self._major_class_name(major_key)
        minor = self._minor_class_name(major_key, minor_key)
        services = self.decode_services(service_mask)
        return major or "Unknown", minor or "Unknown", services

    def decode_services(self, service_mask: int | list[Any] | None) -> list[str]:
        if isinstance(service_mask, list):
            return [str(item) for item in service_mask if item]
        if not isinstance(service_mask, int):
            return []

        labels: list[str] = []
        for bit, label in self.SERVICE_CLASS_NAMES.items():
            if service_mask & (1 << bit):
                labels.append(label)
        return labels

    def decode_uuids(self, uuids: list[str]) -> list[str]:
        decoded: list[str] = []
        for uuid in uuids:
            normalized = uuid.lower()
            short = normalized[4:8].upper() if normalized.startswith("0000") else self._short_uuid(uuid)
            name = self.UUID_NAMES.get(normalized)
            decoded.append(f"{short} {name}" if name else short)
        return decoded

    def lookup_vendor(self, device: DeviceRecord) -> str:
        for key in device.manufacturer_data:
            company_id = self._parse_int(key)
            if company_id in self.COMPANY_IDS:
                return self.COMPANY_IDS[company_id]

        modalias_match = re.search(r"v([0-9A-Fa-f]{4})", device.modalias or "")
        if modalias_match:
            company_id = int(modalias_match.group(1), 16)
            if company_id in self.COMPANY_IDS:
                return self.COMPANY_IDS[company_id]

        address_type = str(getattr(device, "address_type", "") or "").lower()
        if address_type == "random":
            return "Unknown"

        oui = (device.address or "").upper().replace("-", ":")[:8]
        oui_map = self._mapping_at(self.bt_classes, ("oui", "ouis", "vendors"))
        if isinstance(oui_map, dict):
            vendor = oui_map.get(oui) or oui_map.get(oui.replace(":", ""))
            if vendor:
                return self._label(vendor)
        return "Unknown"

    def copy_details(self, device: DeviceRecord) -> None:
        report = self._format_device_details(device)
        try:
            import pyperclip

            pyperclip.copy(report)
            print("\nCopied details to clipboard.")
        except ImportError:
            try:
                filename = f"bluetooth-device-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
                path = self._user_writable_path(filename)
                path.write_text(report, encoding="utf-8")
                self._restore_sudo_user_ownership(path)
                print(f"\npyperclip unavailable; saved details to {path}.")
            except OSError:
                print("\npyperclip unavailable; unable to save details to a fallback file.")
        input("\nPress Enter to continue...")

    def show_device_list(self) -> None:
        print("Scanning Bluetooth Devices...")
        print("Press Ctrl+C to stop scanning.\n")
        if self._status_persistent:
            print(f"{self._status_persistent}\n")
        if self._status:
            print(f"{self._status}\n")

        for index, device in enumerate(self._ordered_devices(), 1):
            name = self._fit(device.title(), 38)
            rssi = f"{device.rssi} dBm" if device.rssi is not None else "N/A"
            category = f"{device.major} / {device.minor}"
            print(f"[{index}] {name:<38} RSSI: {rssi}")
            print(f"     {self._fit(category, 38):<38} MAC : {device.address or 'Unknown'}\n")

    def show_device_details(self, device: DeviceRecord) -> str:
        while True:
            self.clear()
            print(self._format_device_details(device))
            print("\nPress:\n")
            print("Y - Back")
            print("C - Copy Details")
            print("S - Rescan")
            print("N - Exit\n")
            choice = input("> ").strip().lower()
            if choice == "y":
                return "back"
            if choice == "c":
                return "copy"
            if choice == "s":
                return "rescan"
            if choice == "n":
                return "exit"

    def select_device(self) -> DeviceRecord | str:
        while True:
            ordered = self._ordered_devices()
            print(f"Found {len(ordered)} devices.\n")
            print("Select a device by:\n")
            print("- Number")
            print("- Device name\n")
            print("Type S to rescan or N to exit.\n")
            choice = input("> ").strip()
            if not choice:
                self.clear()
                continue
            lowered = choice.lower()
            if lowered == "s":
                return "rescan"
            if lowered == "n":
                return "exit"
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(ordered):
                    return ordered[index]
            matches = [
                device
                for device in ordered
                if lowered in {device.name.lower(), device.alias.lower(), device.title().lower()}
            ]
            if len(matches) == 1:
                return matches[0]
            partial = [
                device
                for device in ordered
                if lowered and lowered in device.title().lower()
            ]
            if len(partial) == 1:
                return partial[0]
            self.clear()
            print("No unique match. Try a number or exact device name.\n")

    def rescan(self) -> None:
        self.run()

    async def _connect_bluez(self) -> None:
        self._require_dbus_next()
        from dbus_next.aio import MessageBus
        from dbus_next.constants import BusType

        try:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            introspection = await self.bus.introspect(self.BLUEZ, "/")
            obj = self.bus.get_proxy_object(self.BLUEZ, "/", introspection)
            manager = obj.get_interface(self.OBJECT_MANAGER)
            objects = await manager.call_get_managed_objects()
            self._ingest_managed_objects(objects)
            self.adapter_path = self._find_adapter(objects)
            if self.adapter_path is None:
                raise RuntimeError("No powered Bluetooth adapter found through BlueZ.")
            adapter_intro = await self.bus.introspect(self.BLUEZ, self.adapter_path)
            adapter_obj = self.bus.get_proxy_object(self.BLUEZ, self.adapter_path, adapter_intro)
            self.adapter = adapter_obj.get_interface(self.ADAPTER)
            self.adapter_props = adapter_obj.get_interface(self.PROPERTIES)
            self.adapter_props.on_properties_changed(self._handle_adapter_properties_changed)
            await self._add_signal_matches()
            self.bus.add_message_handler(self._message_handler)
        except (OSError, RuntimeError) as exc:
            self._status = f"BlueZ connection error: {exc}"
            raise

    async def _add_signal_matches(self) -> None:
        if self.bus is None:
            return

        from dbus_next.message import Message

        rules = [
            (
                "type='signal',sender='org.bluez',"
                "interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',"
                "arg0='org.bluez.Device1'"
            ),
            (
                "type='signal',sender='org.bluez',"
                "interface='org.freedesktop.DBus.ObjectManager',member='InterfacesAdded'"
            ),
        ]
        for rule in rules:
            try:
                await self.bus.call(
                    Message(
                        destination="org.freedesktop.DBus",
                        path="/org/freedesktop/DBus",
                        interface="org.freedesktop.DBus",
                        member="AddMatch",
                        signature="s",
                        body=[rule],
                    )
                )
            except (OSError, ValueError) as exc:
                print(f"[!] Could not add D-Bus match rule ({rule}): {exc}")

    async def _ensure_adapter_ready(self) -> None:
        if self.adapter_props is None:
            return

        from dbus_next import Variant

        try:
            powered = await self.adapter_props.call_get(self.ADAPTER, "Powered")
            if not bool(self._unwrap(powered)):
                await self.adapter_props.call_set(self.ADAPTER, "Powered", Variant("b", True))
                await asyncio.sleep(1.0)
        except (OSError, ValueError, RuntimeError) as exc:
            self._status = f"Could not power Bluetooth adapter automatically: {exc}"

    def _message_handler(self, message: Any) -> None:
        if message.message_type.name != "SIGNAL":
            return
        if message.interface == self.PROPERTIES and message.member == "PropertiesChanged":
            interface, changed, _invalidated = message.body
            if interface in {self.DEVICE, self.BATTERY, self.ADAPTER}:
                path = message.path
                self._handle_properties_changed(path, interface, changed)
        elif message.interface == self.OBJECT_MANAGER and message.member == "InterfacesAdded":
            path, interfaces = message.body
            self._handle_interfaces_added(path, interfaces)
        elif message.interface == self.OBJECT_MANAGER and message.member == "InterfacesRemoved":
            self._handle_interfaces_removed(path, interfaces)

    def _handle_interfaces_removed(self, path: str, interfaces: dict[str, Any]) -> None:
        props = self._unwrap(interfaces)
        if self.DEVICE in props:
            self.devices.pop(path, None)
            if path in self.device_order:
                self.device_order.remove(path)
        self._dirty = True

    def _handle_adapter_properties_changed(
        self,
        interface: str,
        changed: dict[str, Any],
        _invalidated: list[str],
    ) -> None:
        self._handle_properties_changed(self.adapter_path or "", interface, changed)

    def _handle_interfaces_added(self, path: str, interfaces: dict[str, Any]) -> None:
        props = self._unwrap(interfaces)
        if self.DEVICE in props:
            self._upsert_device(path, props[self.DEVICE])
        if self.BATTERY in props:
            self._apply_battery(path, props[self.BATTERY])

    def _handle_properties_changed(self, path: str, interface: str, changed: dict[str, Any]) -> None:
        props = self._unwrap(changed)
        if interface == self.DEVICE:
            self._upsert_device(path, props)
        elif interface == self.BATTERY:
            self._apply_battery(path, props)
        elif interface == self.ADAPTER and path == self.adapter_path:
            self._dirty = True

    def _ingest_managed_objects(self, objects: dict[str, Any]) -> None:
        for path, interfaces in self._unwrap(objects).items():
            if self.DEVICE in interfaces:
                self._upsert_device(path, interfaces[self.DEVICE])
            if self.BATTERY in interfaces:
                self._apply_battery(path, interfaces[self.BATTERY])

    def _find_adapter(self, objects: dict[str, Any]) -> str | None:
        unwrapped = self._unwrap(objects)
        for path, interfaces in unwrapped.items():
            if self.ADAPTER in interfaces and interfaces[self.ADAPTER].get("Powered", True):
                return path
        for path, interfaces in unwrapped.items():
            if self.ADAPTER in interfaces:
                return path
        return None

    def _upsert_device(self, path: str, props: dict[str, Any]) -> None:
        props = self._unwrap(props)
        now = datetime.now().strftime("%H:%M:%S")
        is_new = path not in self.devices
        device = self.devices.get(path) or DeviceRecord(path=path)
        if is_new:
            device.first_seen = now
            self.device_order.append(path)

        device.last_seen = now
        device.times_seen += 1
        device.raw.update(props)

        field_map: dict[str, Callable[[Any], None]] = {
            "Name": lambda value: setattr(device, "name", str(value)),
            "Alias": lambda value: setattr(device, "alias", str(value)),
            "Address": lambda value: setattr(device, "address", str(value)),
            "AddressType": lambda value: setattr(device, "address_type", str(value)),
            "Class": lambda value: setattr(device, "class_code", int(value)),
            "UUIDs": lambda value: setattr(device, "uuids", list(value or [])),
            "ManufacturerData": lambda value: setattr(device, "manufacturer_data", dict(value or {})),
            "ServiceData": lambda value: setattr(device, "service_data", dict(value or {})),
            "Appearance": lambda value: setattr(device, "appearance", value),
            "Paired": lambda value: setattr(device, "paired", bool(value)),
            "Trusted": lambda value: setattr(device, "trusted", bool(value)),
            "Connected": lambda value: setattr(device, "connected", bool(value)),
            "Blocked": lambda value: setattr(device, "blocked", bool(value)),
            "LegacyPairing": lambda value: setattr(device, "legacy_pairing", bool(value)),
            "WakeAllowed": lambda value: setattr(device, "wake_allowed", bool(value)),
            "Icon": lambda value: setattr(device, "icon", str(value)),
            "Modalias": lambda value: setattr(device, "modalias", str(value)),
            "Adapter": lambda value: setattr(device, "adapter", str(value)),
            "RSSI": lambda value: setattr(device, "rssi", int(value)),
            "TxPower": lambda value: setattr(device, "tx_power", int(value)),
        }
        for prop, setter in field_map.items():
            if prop in props and props[prop] is not None:
                try:
                    setter(props[prop])
                except (ValueError, TypeError, AttributeError) as exc:
                    print(f"[!] Could not apply property {prop}={props[prop]!r}: {exc}")

        device.major, device.minor, device.services = self.decode_class(device.class_code)
        device.vendor = self.lookup_vendor(device)
        self.devices[path] = device
        self._dirty = True

    def _apply_battery(self, path: str, props: dict[str, Any]) -> None:
        props = self._unwrap(props)
        device_path = path
        if self.BATTERY not in props and "/service" in path:
            device_path = path.split("/service", 1)[0]
        device = self.devices.get(device_path)
        if device is None:
            return
        percentage = props.get("Percentage")
        if percentage is not None:
            try:
                device.battery = int(percentage)
                self._dirty = True
            except (ValueError, TypeError) as exc:
                print(f"[!] Could not parse battery percentage {percentage!r}: {exc}")

    def _format_device_details(self, device: DeviceRecord) -> str:
        title = device.title()
        class_hex = f"0x{device.class_code:06X}" if device.class_code is not None else "N/A"
        class_dec = str(device.class_code) if device.class_code is not None else "N/A"
        rssi = f"{device.rssi} dBm" if device.rssi is not None else "N/A"
        tx_power = f"{device.tx_power} dBm" if device.tx_power is not None else "N/A"
        battery = f"{device.battery}%" if device.battery is not None else "N/A"
        appearance = str(device.appearance) if device.appearance not in (None, "") else "N/A"
        address_type = device.address_type or "N/A"

        lines = [title, ""]
        rows = [
            ("Address", device.address or "Unknown", "Vendor", device.vendor or "Unknown"),
            ("Alias", device.alias or "N/A", "RSSI", rssi),
            ("Name", device.name or "N/A", "TX Power", tx_power),
            ("Major Class", device.major, "Minor Class", device.minor),
            ("Class (Hex)", class_hex, "Class (Dec)", class_dec),
            ("Paired", self._yesno(device.paired), "Connected", self._yesno(device.connected)),
            ("Trusted", self._yesno(device.trusted), "Blocked", self._yesno(device.blocked)),
            ("LegacyPairing", self._yesno(device.legacy_pairing), "WakeAllowed", self._yesno(device.wake_allowed)),
            ("First Seen", device.first_seen or "N/A", "Last Seen", device.last_seen or "N/A"),
            ("Times Seen", str(device.times_seen), "Battery", battery),
            ("Appearance", appearance, "Address Type", address_type),
            ("Icon", device.icon or "N/A", "Modalias", device.modalias or "N/A"),
            ("Adapter", device.adapter or "N/A", "Path", device.path),
        ]
        for left_key, left_value, right_key, right_value in rows:
            lines.append(self._detail_row(left_key, left_value, right_key, right_value))

        lines.extend(self._section_columns("Services", device.services))
        lines.extend(self._section_columns("UUIDs", self.decode_uuids(device.uuids)))
        lines.extend(
            self._section_columns("Manufacturer Data", self._format_mapping(device.manufacturer_data))
        )
        lines.extend(self._section_columns("Service Data", self._format_mapping(device.service_data)))

        extra = self._extra_properties(device)
        if extra:
            lines.extend(self._section_columns("Other BlueZ Properties", extra))
        return "\n".join(lines)

    def _section(self, title: str, values: list[Any]) -> list[str]:
        lines = ["", title]
        if values:
            lines.extend(str(value) for value in values)
        else:
            lines.append("N/A")
        return lines

    def _section_columns(self, title: str, values: list[Any]) -> list[str]:
        lines = ["", title]
        if not values:
            lines.append("N/A")
            return lines

        width = shutil.get_terminal_size((120, 24)).columns
        column_count = 3 if width >= 132 and len(values) > 2 else 2 if width >= 84 else 1
        gap = 4
        column_width = max(20, (width - gap * (column_count - 1)) // column_count)
        cells = [self._fit(str(value), column_width) for value in values]

        for row_start in range(0, len(cells), column_count):
            row = cells[row_start: row_start + column_count]
            padded = [cell.ljust(column_width) for cell in row]
            lines.append((" " * gap).join(padded).rstrip())
        return lines

    def _format_mapping(self, mapping: dict[Any, Any]) -> list[str]:
        if not mapping:
            return []
        lines: list[str] = []
        for key, value in mapping.items():
            company = ""
            company_id = self._parse_int(key)
            if company_id in self.COMPANY_IDS:
                company = f" ({self.COMPANY_IDS[company_id]})"
            lines.append(f"{key}{company}: {self._compact_value(value)}")
        return lines

    def _extra_properties(self, device: DeviceRecord) -> list[str]:
        known = {
            "Name", "Alias", "Address", "AddressType", "Class", "UUIDs", "ManufacturerData",
            "ServiceData", "Appearance", "Paired", "Trusted", "Connected", "Blocked",
            "LegacyPairing", "WakeAllowed", "Icon", "Modalias", "Adapter", "RSSI", "TxPower",
        }
        return [
            f"{key}: {self._format_value(value)}"
            for key, value in sorted(device.raw.items())
            if key not in known
        ]

    def _detail_row(self, lk: str, lv: Any, rk: str, rv: Any) -> str:
        width = shutil.get_terminal_size((100, 24)).columns
        value_width = max(16, min(36, (width - 34) // 2))
        return (
            f"{lk:<14} {self._fit(str(lv), value_width):<{value_width}}"
            f"  {rk:<14} {self._fit(str(rv), value_width):<{value_width}}"
        )

    def _ordered_devices(self) -> list[DeviceRecord]:
        return [self.devices[path] for path in self.device_order if path in self.devices]

    def _install_signal_handler(self) -> None:
        if self._loop is None or self._stop_event is None:
            return
        try:
            self._loop.add_signal_handler(signal.SIGINT, self._stop_event.set)
            self._sigint_handler_installed = True
        except (NotImplementedError, RuntimeError):
            self._previous_sigint_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self._signal_handler_fallback)
            self._sigint_handler_installed = True

    def _restore_signal_handler(self) -> None:
        if not self._sigint_handler_installed:
            return
        if self._loop is not None:
            try:
                self._loop.remove_signal_handler(signal.SIGINT)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
        if self._previous_sigint_handler is not None:
            try:
                signal.signal(signal.SIGINT, self._previous_sigint_handler)
            except (OSError, ValueError, RuntimeError):
                pass
            self._previous_sigint_handler = None
        self._sigint_handler_installed = False

    def _signal_handler_fallback(self, _sig: int, _frame: Any) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    def _require_dbus_next(self) -> None:
        if self._dbus_import_error:
            raise RuntimeError(
                "dbus-next is required. Install it with: python -m pip install dbus-next"
            ) from self._dbus_import_error
        try:
            __import__("dbus_next")
        except ImportError as exc:
            self._dbus_import_error = exc
            raise RuntimeError(
                "dbus-next is required. Install it with: python -m pip install dbus-next"
            ) from exc

    def _setup_rich(self) -> None:
        try:
            from rich.console import Console

            self._console = Console()
            self._use_rich = True
        except ImportError:
            self._console = None
            self._use_rich = False

    def _unwrap(self, value: Any) -> Any:
        if hasattr(value, "value"):
            return self._unwrap(value.value)
        if isinstance(value, dict):
            return {self._unwrap(key): self._unwrap(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, bytes, bytearray)):
            if isinstance(value, (bytes, bytearray)):
                return bytes(value)
            return [self._unwrap(item) for item in value]
        return value

    def _major_class_name(self, major: int) -> str:
        return self.MAJOR_CLASS_NAMES.get(major, "Unknown")

    def _minor_class_name(self, major: int, minor: int) -> str:
        if major == 3:
            return self._lan_minor_name(minor)
        if major == 5:
            return self._peripheral_minor_name(minor)
        if major == 6:
            return self._imaging_minor_name(minor)

        mapping = self.MINOR_CLASS_NAMES.get(major)
        if not isinstance(mapping, dict):
            return "Unknown"
        if minor in mapping:
            return mapping[minor]
        return "Unknown"

    def _lan_minor_name(self, minor: int) -> str:
        mapping = self.MINOR_CLASS_NAMES.get(3, {})
        if not isinstance(mapping, dict):
            return "Unknown"
        availability = minor & 0x7
        return mapping.get(availability, "Unknown")

    def _peripheral_minor_name(self, minor: int) -> str:
        if minor & 0x10 and minor & 0x20:
            return "Combo Keyboard/Pointing Device"
        if minor & 0x10:
            return "Keyboard"
        if minor & 0x20:
            return "Pointing Device"
        mapping = self.MINOR_CLASS_NAMES.get(5, {})
        return mapping.get(minor & 0x0F, "Unknown")

    def _imaging_minor_name(self, minor: int) -> str:
        if minor == 0:
            return self.MINOR_CLASS_NAMES.get(6, {}).get(0, "Uncategorized Imaging")

        labels: list[str] = []
        for bit, label in ((4, "Display"), (8, "Camera"), (16, "Scanner"), (32, "Printer")):
            if minor & bit:
                labels.append(label)
        return ", ".join(labels) if labels else "Unknown"

    def _mapping_at(self, data: dict[str, Any], keys: tuple[str, ...]) -> Any:
        for key in keys:
            value = data.get(key)
            if value is not None:
                return value
        return None

    def _label(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in ("name", "label", "description", "title"):
                if key in value:
                    return str(value[key])
        return str(value)

    def _parse_int(self, value: Any) -> int | None:
        if isinstance(value, int):
            return value
        try:
            return int(str(value), 0)
        except (ValueError, TypeError):
            return None

    def _format_value(self, value: Any) -> str:
        value = self._unwrap(value)
        if isinstance(value, bytes):
            return value.hex(" ").upper()
        if isinstance(value, list):
            if all(isinstance(item, int) and 0 <= item <= 255 for item in value):
                return bytes(value).hex(" ").upper()
            return ", ".join(self._format_value(item) for item in value)
        if isinstance(value, dict):
            return json.dumps(value, default=str, ensure_ascii=False)
        return str(value)

    def _compact_value(self, value: Any) -> str:
        formatted = self._format_value(value)
        return " ".join(formatted.split())

    def _short_uuid(self, uuid: str) -> str:
        uuid = str(uuid)
        if len(uuid) <= 13:
            return uuid.upper()
        return f"{uuid[:8].upper()}...{uuid[-4:].upper()}"

    def _fit(self, text: str, width: int) -> str:
        if len(text) <= width:
            return text
        return text[: max(0, width - 1)] + "…"

    def _yesno(self, value: bool) -> str:
        return "Yes" if value else "No"


if __name__ == "__main__":
    bluetooth().run()