import ipaddress
import json
from pathlib import Path

from debugs import debug

SECURITY_OPTIONS = ["open", "wpa2", "wpa3", "wpa2/wpa3"]
PMF_OPTIONS = ["disabled", "optional", "required"]
BAND_OPTIONS = ["2.4", "5"]
CIPHER_OPTIONS = ["ccmp", "tkip", "ccmp+tkip"]
CHANWIDTH_OPTIONS = ["20", "40", "80", "160"]
POWERSAVE_OPTIONS = ["off", "on"]
RESOURCE_PROFILE_OPTIONS = ["lowest", "low", "normal", "high", "highest", "uncapped"]

DEFAULTS = {
    # access point identity
    "ssid": "ScannerAP",
    "hidden": False,
    "utf8_ssid": True,
    # security
    "security": "wpa2",
    "psk": "changeme123",
    "pmf": "optional",
    "sae": False,
    "cipher": "ccmp",
    "wpa_group_rekey": 600,
    "wpa_ptk_rekey": 0,
    "okc": False,
    # radio / PHY
    "band": "2.4",
    "channel": 6,
    "channel_width": "20",
    "country_code": "US",
    "ieee80211d": True,
    "ieee80211h": False,
    "ht_enabled": True,
    "vht_enabled": False,
    "he_enabled": False,
    "short_gi": True,
    "require_ht": False,
    "require_vht": False,
    "power_save": False,
    # tx / timing
    "tx_power_dbm": 20,
    "beacon_interval": 100,
    "dtim_period": 2,
    "short_preamble": True,
    "rts_threshold": -1,
    "frag_threshold": -1,
    # association behaviour
    "max_clients": 10,
    "ap_max_inactivity": 300,
    "ap_isolate": False,
    "wmm_enabled": True,
    "disassoc_low_ack": True,
    "mac_addr": "",
    # dhcp / dns
    "ip_range": "192.168.50.0/24",
    "dhcp_start": "192.168.50.10",
    "dhcp_end": "192.168.50.200",
    "dhcp_lease_time": "12h",
    "dhcp_domain": "",
    "upstream_dns": "",
    "mtu": 0,
    # bridge / nat
    "bridge_iface": "",
    "bridge_gateway": None,
    # misc
    "resource_profile": "normal",
}



def _is_open(s):
    return s["security"] == "open"


FIELDS = [
    # --- Access Point ---
    ("ssid", "SSID", "str", None, None),
    ("hidden", "Hidden SSID", "bool", None, None),
    ("utf8_ssid", "UTF-8 SSID", "bool", None, None),
    ("max_clients", "Max Clients", "int", None, None),
    ("ap_max_inactivity", "Client Idle Timeout (s)", "int", None, None),
    ("ap_isolate", "Client Isolation (block client-to-client)", "bool", None, None),
    ("wmm_enabled", "WMM / QoS", "bool", None, None),
    ("disassoc_low_ack", "Disassociate on Low ACK", "bool", None, None),
    ("mac_addr", "AP MAC Override", "str", None, None),
    # --- Security ---
    ("security", "Security Type", "choice", SECURITY_OPTIONS, None),
    ("psk", "Pre-Shared Key", "str", None, _is_open),
    ("pmf", "802.11w (PMF)", "choice", PMF_OPTIONS, _is_open),
    ("sae", "SAE (WPA3)", "bool", None,
     lambda s: s["security"] not in ("wpa3", "wpa2/wpa3")),
    ("cipher", "Cipher", "choice", CIPHER_OPTIONS, _is_open),
    ("wpa_group_rekey", "Group Rekey (s, 0=off)", "int", None, _is_open),
    ("wpa_ptk_rekey", "Pairwise Rekey (s, 0=off)", "int", None, _is_open),
    ("okc", "Opportunistic Key Caching", "bool", None, _is_open),
    # --- Radio & PHY ---
    ("band", "Band (GHz)", "choice", BAND_OPTIONS, None),
    ("channel", "Channel", "int", None, None),
    ("channel_width", "Channel Width (MHz)", "choice", CHANWIDTH_OPTIONS, None),
    ("country_code", "Regulatory Domain (Country)", "str", None, None),
    ("ieee80211d", "802.11d (Country IE)", "bool", None, None),
    ("ieee80211h", "802.11h (DFS/TPC)", "bool", None, lambda s: s["band"] != "5"),
    ("ht_enabled", "802.11n (HT)", "bool", None, None),
    ("vht_enabled", "802.11ac (VHT)", "bool", None, lambda s: s["band"] != "5"),
    ("he_enabled", "802.11ax (HE / Wi-Fi 6)", "bool", None, None),
    ("short_gi", "Short Guard Interval", "bool", None, lambda s: not s["ht_enabled"]),
    ("require_ht", "Require HT (reject non-n)", "bool", None, lambda s: not s["ht_enabled"]),
    ("require_vht", "Require VHT (reject non-ac)", "bool", None,
     lambda s: not s["vht_enabled"]),
    ("power_save", "Radio Power Save", "bool", None, None),
    # --- TX & Timing ---
    ("tx_power_dbm", "TX Power (dBm)", "int", None, None),
    ("beacon_interval", "Beacon Interval (ms)", "int", None, None),
    ("dtim_period", "DTIM Period", "int", None, None),
    ("short_preamble", "Short Preamble", "bool", None, None),
    ("rts_threshold", "RTS Threshold (-1=off)", "int", None, None),
    ("frag_threshold", "Fragmentation Threshold (-1=off)", "int", None, None),
    # --- DHCP & DNS ---
    ("ip_range", "AP IP Range (CIDR)", "str", None, None),
    ("dhcp_start", "DHCP Range Start", "str", None, None),
    ("dhcp_end", "DHCP Range End", "str", None, None),
    ("dhcp_lease_time", "DHCP Lease Time", "str", None, None),
    ("dhcp_domain", "DHCP Domain Name", "str", None, None),
    ("upstream_dns", "Upstream DNS (blank=uplink)", "str", None, None),
    ("mtu", "Client MTU (0=auto)", "int", None, None),
    # --- Bridge / NAT ---
    ("bridge_iface", "Bridge/Uplink Interface", "str", None, None),
    # --- Misc ---
    ("resource_profile", "Resource Limit Profile", "choice",
     RESOURCE_PROFILE_OPTIONS, None),
]


# Ordered accordion grouping for the TUI control panel. Keys map 1:1 to FIELDS
# (bridge_iface is surfaced in the TUI's Services section instead, so it is not
# listed here). Each category is one collapsible section.
CATEGORIES = [
    ("Access Point", ["ssid", "hidden", "utf8_ssid", "max_clients",
                      "ap_max_inactivity", "ap_isolate", "wmm_enabled",
                      "disassoc_low_ack", "mac_addr"]),
    ("Security", ["security", "psk", "pmf", "sae", "cipher",
                  "wpa_group_rekey", "wpa_ptk_rekey", "okc"]),
    ("Radio & PHY", ["band", "channel", "channel_width", "country_code",
                     "ieee80211d", "ieee80211h", "ht_enabled", "vht_enabled",
                     "he_enabled", "short_gi", "require_ht", "require_vht",
                     "power_save"]),
    ("TX & Timing", ["tx_power_dbm", "beacon_interval", "dtim_period",
                     "short_preamble", "rts_threshold", "frag_threshold"]),
    ("DHCP & DNS", ["ip_range", "dhcp_start", "dhcp_end", "dhcp_lease_time",
                    "dhcp_domain", "upstream_dns", "mtu"]),
    ("Advanced", ["resource_profile"]),
]


def load_settings(save_dir: Path) -> dict:
    path = Path(save_dir) / "settings.json"
    settings = dict(DEFAULTS)
    if path.is_file():
        try:
            loaded = json.loads(path.read_text())
            settings.update({k: v for k, v in loaded.items() if k in DEFAULTS})
        except (OSError, json.JSONDecodeError, AttributeError, TypeError) as e:
            debug("warn", f"Could not load settings from {path}: {e} — using defaults.")
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
    except (ValueError, TypeError) as e:
        warn(f"Invalid IP range '{s['ip_range']}' ({e}) — reset to default.")
        network = ipaddress.ip_network(DEFAULTS["ip_range"])
        s["ip_range"] = str(network)

    for key in ("dhcp_start", "dhcp_end"):
        try:
            addr = ipaddress.ip_address(s[key])
            if addr not in network:
                raise ValueError(f"{addr} not in {network}")
        except (ValueError, TypeError) as e:
            warn(f"{key} not valid inside {network} ({e}) — reset to default.")
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

    try:
        mtu = int(s["mtu"])
        if mtu != 0 and not (576 <= mtu <= 1500):
            raise ValueError
    except (ValueError, TypeError):
        warn("Invalid MTU — reset to 0 (auto-detect from uplink).")
        mtu = 0
    s["mtu"] = mtu

    raw_dns = (s.get("upstream_dns") or "").strip()
    valid_dns = []
    for tok in raw_dns.replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            ipaddress.ip_address(tok)
            valid_dns.append(tok)
        except ValueError:
            warn(f"Ignoring invalid upstream DNS address '{tok}'.")
    s["upstream_dns"] = ",".join(valid_dns)

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

    # Non-negative second counters.
    for key, label, default in (
        ("wpa_group_rekey", "group rekey", 600),
        ("wpa_ptk_rekey", "pairwise rekey", 0),
        ("ap_max_inactivity", "client idle timeout", 300),
    ):
        try:
            val = int(s[key])
            if val < 0:
                raise ValueError
        except (ValueError, TypeError):
            warn(f"Invalid {label} — reset to {default}.")
            val = default
        s[key] = val
    if s["ap_max_inactivity"] == 0:
        warn("Client idle timeout can't be 0 — reset to 300.")
        s["ap_max_inactivity"] = 300

    # Channel width must be valid for the band, and VHT/HE have band limits.
    cw = str(s.get("channel_width", "20"))
    if cw not in CHANWIDTH_OPTIONS:
        warn(f"Invalid channel width '{cw}' — reset to 20.")
        cw = "20"
    if s["band"] == "2.4" and cw not in ("20", "40"):
        warn("2.4GHz supports only 20/40MHz width — reset to 20.")
        cw = "20"
    s["channel_width"] = cw
    if s["band"] != "5":
        if s["vht_enabled"]:
            warn("802.11ac (VHT) is 5GHz-only — disabled.")
            s["vht_enabled"] = False
        if s["ieee80211h"]:
            s["ieee80211h"] = False
    if s["vht_enabled"] and not s["ht_enabled"]:
        warn("VHT requires HT — enabling 802.11n.")
        s["ht_enabled"] = True
    if s["require_vht"] and not s["vht_enabled"]:
        s["require_vht"] = False
    if s["require_ht"] and not s["ht_enabled"]:
        s["require_ht"] = False

    return s, warnings