"""Policy-based routing for the APCC bridge path.

Forces AP-subnet traffic out a specific uplink via a dedicated routing table
(leaving the host's main table untouched), detects the uplink's gateway, and
manages the reverse-path-filter relaxation that asymmetric NAT routing needs.
Pure routing — it calls no firewall or NAT-orchestration code.
"""

from pathlib import Path

from core.APCC.netutil import _run, _run_checked
from core.validators import validate_iface

PBR_TABLE_ID = 200
PBR_RULE_PRIORITY = 10000


def _iface_default_gateway(iface, debug=None):
    validate_iface(iface)
    res = _run(["ip", "route", "show", "table", "all", "default", "dev", iface])
    for line in res.stdout.splitlines():
        parts = line.split()
        if "via" not in parts:
            continue
        try:
            gw = parts[parts.index("via") + 1]
        except IndexError:
            continue
        if ":" in gw:
            continue
        return gw
    if debug:
        debug("warn", f"No default-route gateway found for {iface} — "
                       "it may be a directly-connected/static interface "
                       "with no gateway of its own.")
    return None


def _rp_filter_path(iface):
    return Path(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter")


# Original rp_filter values, captured the first time we loosen an interface so
# teardown can put back exactly what the host had (0/1/2) instead of assuming 1.
_rp_filter_saved: dict = {}


def _set_rp_filter(iface, value, debug):
    try:
        _rp_filter_path(iface).write_text(f"{value}\n")
    except (OSError, ValueError) as e:
        debug("warn", f"Could not set rp_filter for {iface}: {e}")


def _loosen_one_rp_filter(iface, debug):
    if not iface:
        return
    validate_iface(iface)
    path = _rp_filter_path(iface)
    try:
        current = int(path.read_text().strip())
    except (OSError, ValueError):
        current = None
    if iface not in _rp_filter_saved:
        _rp_filter_saved[iface] = current
    # 2 = loose mode; kernel uses max(conf.all, conf.iface), and 2 wins.
    if current != 2:
        _set_rp_filter(iface, 2, debug)


def loosen_rp_filter(ap_iface: str, bridge_iface: str, debug):
    _loosen_one_rp_filter(ap_iface, debug)
    _loosen_one_rp_filter(bridge_iface, debug)


def restore_rp_filter(ap_iface: str, bridge_iface: str, debug):
    for iface in (ap_iface, bridge_iface):
        if not iface or iface not in _rp_filter_saved:
            continue
        original = _rp_filter_saved.pop(iface)
        if original is not None:
            _set_rp_filter(iface, original, debug)


def setup_policy_routing(ap_iface: str, bridge_iface: str, ip_range: str, debug,
                          gateway_override: str | None = None):
    validate_iface(ap_iface)
    validate_iface(bridge_iface)
    gateway = gateway_override or _iface_default_gateway(bridge_iface, debug)
    if not gateway:
        debug("warn", f"Policy routing not set up for {bridge_iface} "
                       "(no gateway found) — falling back to whatever "
                       "the main routing table picks by metric.")
        return False

    teardown_policy_routing(ap_iface, bridge_iface, debug, quiet=True)

    _run(["ip", "route", "flush", "table", str(PBR_TABLE_ID)])
    # Deliver AP-subnet traffic locally WITHIN this table. The `from <subnet>`
    # rule also catches the host's own replies to clients (dnsmasq DNS answers,
    # ICMP echo replies, the redirect server) because those are sourced from the
    # gateway IP, which is inside the subnet. Without this connected route, the
    # table's only entry is the default route, so every gateway->client reply is
    # sent out the uplink instead of back to the client — clients then get a
    # lease but no DNS answers and no gateway ping, i.e. "connected, no internet".
    _run_checked(
        ["ip", "route", "add", ip_range, "dev", ap_iface, "scope", "link",
         "table", str(PBR_TABLE_ID)],
        debug, f"Adding table-{PBR_TABLE_ID} local route for {ip_range} via {ap_iface}")
    route_res = _run_checked(
        ["ip", "route", "add", "default", "via", gateway, "dev", bridge_iface,
         "table", str(PBR_TABLE_ID)], debug, f"Adding table-{PBR_TABLE_ID} route via {bridge_iface}")
    rule_res = _run_checked(
        ["ip", "rule", "add", "from", ip_range, "table", str(PBR_TABLE_ID),
         "priority", str(PBR_RULE_PRIORITY)], debug, "Adding policy-routing ip rule")
    if route_res.returncode != 0 or rule_res.returncode != 0:
        debug("warn", "Policy routing was NOT fully applied — see the failure(s) "
                       "above. Falling back to whatever the main routing table "
                       "picks by metric.")
        return False
    loosen_rp_filter(ap_iface, bridge_iface, debug)

    debug("ok", f"Policy routing: {ip_range} forced out {bridge_iface} "
                 f"via {gateway} (table {PBR_TABLE_ID}) — main table and "
                 "every other interface/rule left untouched.")
    return True


def teardown_policy_routing(ap_iface: str, bridge_iface: str, debug, quiet=False):
    if ap_iface:
        validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    _run(["ip", "rule", "del", "priority", str(PBR_RULE_PRIORITY)])
    _run(["ip", "route", "flush", "table", str(PBR_TABLE_ID)])
    restore_rp_filter(ap_iface, bridge_iface, debug)
    if not quiet:
        debug("info", "Policy routing rule/table removed.")


def detect_gateway(iface: str, debug=None):
    return _iface_default_gateway(iface, debug)
