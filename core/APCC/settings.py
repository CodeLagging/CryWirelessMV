import json
import secrets
import ipaddress
from pathlib import Path


SECURITY_OPTIONS = ["open", "wpa2", "wpa3", "wpa2/wpa3"]
PMF_OPTIONS = ["disabled", "optional", "required"]
BAND_OPTIONS = ["2.4", "5"]
CIPHER_OPTIONS = ["ccmp", "tkip", "ccmp+tkip"]
RESOURCE_PROFILE_OPTIONS = ["lowest", "low", "normal", "high", "highest", "uncapped"]

DEFAULTS = {
    "ssid": "ScannerAP",
    "hidden": False,
    "security": "wpa2",
    "psk": "changeme123",
    "band": "2.4",
    "channel": 6,
    "country_code": "US",
    "pmf": "optional",
    "sae": False,
    "cipher": "ccmp",
    "tx_power_dbm": 20,
    "max_clients": 10,
    "ip_range": "192.168.50.0/24",
    "dhcp_start": "192.168.50.10",
    "dhcp_end": "192.168.50.200",
    "dhcp_lease_time": "12h",
    "bridge_iface": "",
    "mac_addr": "",
    "beacon_interval": 100,
    "dtim_period": 2,
    "rts_threshold": -1,
    "frag_threshold": -1,
    "ap_isolate": False,
    "short_preamble": True,
    "wmm_enabled": True,
    "disassoc_low_ack": True,
    "resource_profile": "normal",
}



FIELDS = [
    ("ssid", "SSID", "str", None, None),
    ("hidden", "Hidden SSID", "bool", None, None),
    ("security", "Security Type", "choice", SECURITY_OPTIONS, None),
    ("psk", "Pre-Shared Key", "str", None, lambda s: s["security"] == "open"),
    ("band", "Band", "choice", BAND_OPTIONS, None),
    ("channel", "Channel", "int", None, None),
    ("country_code", "Country Code", "str", None, None),
    ("pmf", "802.11w (PMF)", "choice", PMF_OPTIONS, lambda s: s["security"] == "open"),
    ("sae", "SAE (WPA3)", "bool", None,
     lambda s: s["security"] not in ("wpa3", "wpa2/wpa3")),
    ("cipher", "Cipher", "choice", CIPHER_OPTIONS, lambda s: s["security"] == "open"),
    ("tx_power_dbm", "TX Power (dBm)", "int", None, None),
    ("max_clients", "Max Clients", "int", None, None),
    ("ip_range", "AP IP Range (CIDR)", "str", None, None),
    ("dhcp_start", "DHCP Range Start", "str", None, None),
    ("dhcp_end", "DHCP Range End", "str", None, None),
    ("dhcp_lease_time", "DHCP Lease Time", "str", None, None),
    ("bridge_iface", "Bridge/Uplink Interface", "str", None, None),
    ("mac_addr", "AP MAC Override", "str", None, None),
    ("beacon_interval", "Beacon Interval (ms)", "int", None, None),
    ("dtim_period", "DTIM Period", "int", None, None),
    ("rts_threshold", "RTS Threshold (-1=off)", "int", None, None),
    ("frag_threshold", "Fragmentation Threshold (-1=off)", "int", None, None),
    ("ap_isolate", "Client Isolation (block client-to-client)", "bool", None, None),
    ("short_preamble", "Short Preamble", "bool", None, None),
    ("wmm_enabled", "WMM / QoS", "bool", None, None),
    ("disassoc_low_ack", "Disassociate on Low ACK", "bool", None, None),
    ("resource_profile", "Resource Limit Profile", "choice",
     RESOURCE_PROFILE_OPTIONS, None),
]


def load_settings(save_dir: Path) -> dict:
    path = Path(save_dir) / "settings.json"
    settings = dict(DEFAULTS)
    if path.is_file():
        try:
            loaded = json.loads(path.read_text())
            settings.update({k: v for k, v in loaded.items() if k in DEFAULTS})
        except Exception:
            pass
    return settings


def save_settings(save_dir: Path, settings: dict):
    path = Path(save_dir) / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2))


def validate_settings(settings: dict):
    s = dict(settings)
    warnings = []

    def warn(msg):
        warnings.append(msg)


    if s["security"] == "open":
        if s.get("psk"):
            s["psk"] = ""
        s["pmf"] = "disabled"
        s["sae"] = False
    elif s["security"] == "wpa2":
        if s["sae"]:
            warn("SAE is a WPA3 feature — disabled for WPA2-only.")
            s["sae"] = False
        if s["pmf"] == "required":
            warn("PMF required is not compatible with plain WPA2 clients — set to optional.")
            s["pmf"] = "optional"
    elif s["security"] == "wpa3":
        if s["pmf"] != "required":
            warn("WPA3 requires PMF — forced to 'required'.")
            s["pmf"] = "required"
        if not s["sae"]:
            warn("WPA3 requires SAE — enabled automatically.")
            s["sae"] = True
        if s["cipher"] == "tkip":
            warn("TKIP is not allowed under WPA3 — switched to CCMP.")
            s["cipher"] = "ccmp"
    elif s["security"] == "wpa2/wpa3":
        if s["pmf"] == "disabled":
            warn("WPA2/WPA3 transition mode needs PMF optional at minimum — set to optional.")
            s["pmf"] = "optional"
        s["sae"] = True

    if s["security"] != "open" and len(s.get("psk", "")) < 8:
        warn(f"PSK too short ({len(s.get('psk',''))} chars) — reset to default 'changeme123'.")
        s["psk"] = "changeme123"


    try:
        ch = int(s["channel"])
    except (ValueError, TypeError):
        warn("Invalid channel — reset to 6.")
        ch = 6
    if s["band"] == "2.4" and not (1 <= ch <= 14):
        warn(f"Channel {ch} invalid for 2.4GHz — reset to 6.")
        ch = 6
    if s["band"] == "5" and ch not in (
        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
        124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165
    ):
        warn(f"Channel {ch} invalid for 5GHz — reset to 36.")
        ch = 36
    s["channel"] = ch


    try:
        network = ipaddress.ip_network(s["ip_range"], strict=False)
    except Exception:
        warn(f"Invalid IP range '{s['ip_range']}' — reset to default.")
        network = ipaddress.ip_network(DEFAULTS["ip_range"])
        s["ip_range"] = str(network)

    for key in ("dhcp_start", "dhcp_end"):
        try:
            addr = ipaddress.ip_address(s[key])
            if addr not in network:
                raise ValueError
        except Exception:
            warn(f"{key} not valid inside {network} — reset to default.")
            s[key] = DEFAULTS[key]

    try:
        max_c = int(s["max_clients"])
        if max_c < 1:
            raise ValueError
    except (ValueError, TypeError):
        warn("Invalid max_clients — reset to 10.")
        max_c = 10
    s["max_clients"] = max_c

    try:
        tx = int(s["tx_power_dbm"])
    except (ValueError, TypeError):
        warn("Invalid TX power — reset to 20 dBm.")
        tx = 20
    s["tx_power_dbm"] = tx

    try:
        bi = int(s["beacon_interval"])
        if not (15 <= bi <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        warn("Invalid beacon interval — reset to 100ms.")
        bi = 100
    s["beacon_interval"] = bi

    try:
        dtim = int(s["dtim_period"])
        if not (1 <= dtim <= 255):
            raise ValueError
    except (ValueError, TypeError):
        warn("Invalid DTIM period — reset to 2.")
        dtim = 2
    s["dtim_period"] = dtim

    for key, label, default in (
        ("rts_threshold", "RTS threshold", -1),
        ("frag_threshold", "Fragmentation threshold", -1),
    ):
        try:
            val = int(s[key])
            if val != -1 and not (256 <= val <= 2347):
                raise ValueError
        except (ValueError, TypeError):
            warn(f"Invalid {label} — reset to off (-1).")
            val = default
        s[key] = val

    return s, warnings
