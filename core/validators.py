"""Centralized input validation.

Every value that reaches a subprocess call, an iptables rule, or a hostapd /
dnsmasq config file passes through here first. Keeping the patterns in one
place means there is a single, auditable definition of what this tool will
accept — nothing downstream has to re-derive "is this a safe interface name".
"""

import ipaddress
import re

# Linux interface names: up to IFNAMSIZ-1 (15) chars, restricted to the set
# that cannot break out of a shell-less argv or an iptables token.
IFACE_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")

# Colon- or dash-separated 48-bit MAC.
MAC_REGEX = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")

# 2.4 GHz channels 1-14, 5 GHz channels 32-177 (superset; regulatory domain
# narrows it further at runtime).
_VALID_2GHZ = set(range(1, 15))
_VALID_5GHZ = set(range(32, 178))


def validate_iface(name: str) -> str:
    """Return `name` if it is a safe interface name, else raise ValueError."""
    if not name or not IFACE_REGEX.match(name):
        raise ValueError(
            f"Invalid interface name: {name!r}. Must match {IFACE_REGEX.pattern}"
        )
    return name


def is_valid_iface(name: str) -> bool:
    return bool(name) and bool(IFACE_REGEX.match(name))


def validate_mac(mac: str) -> str:
    """Return the lowercased MAC if well-formed, else raise ValueError."""
    if not mac or not MAC_REGEX.match(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return mac.lower().replace("-", ":")


def is_valid_mac(mac: str) -> bool:
    return bool(mac) and bool(MAC_REGEX.match(mac))


def is_valid_channel(ch) -> bool:
    """True if `ch` is a WiFi channel in the 2.4 or 5 GHz ranges."""
    try:
        ch = int(ch)
    except (TypeError, ValueError):
        return False
    return ch in _VALID_2GHZ or ch in _VALID_5GHZ


def is_valid_ip_range(cidr: str) -> bool:
    """True if `cidr` parses as an IPv4 network (host bits allowed)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False
    return net.version == 4


def is_valid_ssid(ssid: str) -> bool:
    """802.11 SSID: 0-32 bytes once UTF-8 encoded."""
    if ssid is None:
        return False
    try:
        return len(ssid.encode("utf-8")) <= 32
    except (AttributeError, UnicodeError):
        return False
