"""The DeviceRecord dataclass: one discovered Bluetooth/BLE device's state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
