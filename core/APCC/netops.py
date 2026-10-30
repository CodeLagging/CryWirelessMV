import ipaddress
import json
import re
import shlex
import socket
import subprocess
from datetime import datetime
from pathlib import Path

# --- SECURITY FIX (Task 04): Strict Interface Name Validation ---
IFACE_REGEX = re.compile(r'^[a-zA-Z0-9_-]{1,15}$')

def validate_iface(name: str) -> str:
    """Validate interface names before they are used in subprocess calls."""
    if not name or not IFACE_REGEX.match(name):
        raise ValueError(f"Invalid interface name: {name}. Must match {IFACE_REGEX.pattern}")
    return name


class _DummyResult:
    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 1


def _run(cmd, check=False, capture=True, timeout=8):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True,
                              check=check, timeout=timeout)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return _DummyResult()


def _run_checked(cmd, debug, what):
    res = _run(cmd)
    if res.returncode != 0:
        stderr = (res.stderr or "").strip()
        debug("warn", f"{what} failed (exit {res.returncode})"
                       f"{': ' + stderr if stderr else ''} — command: {' '.join(cmd)}")
    return res


BACKUP_MARKER = "scannerap_backup.json"

DEFAULT_MTU = 1500
MIN_MTU = 576
MSS_OVERHEAD = 40  # IPv4 header (20) + TCP header (20)

# Conservative path MTU used as an always-on TCP MSS floor. Tethered/cellular/
# CGNAT/VPN uplinks routinely carry a real internet path below 1500 AND filter
# the ICMP "fragmentation needed" messages that TCP PMTUD relies on, so
# --clamp-mss-to-pmtu (which only sees the 1500 egress iface) can't catch it.
# The result is the classic "connects + DNS + QUIC/UDP video all work, but TCP
# web pages never load" black hole: QUIC does its own in-band path-MTU probing
# and shrinks itself, while full-size forwarded TCP data segments silently drop.
# 1400 (-> MSS 1360) clears PPPoE, common VPN/tunnel, and most carrier overhead.
PMTU_SAFE_MTU = 1400


def iface_mtu(iface: str) -> int:
    try:
        return int(Path(f"/sys/class/net/{iface}/mtu").read_text().strip())
    except (OSError, ValueError):
        return 0


def resolve_client_mtu(bridge_iface: str, configured=0) -> int:
    """MTU to advertise to clients / clamp traffic to.

    An explicit setting wins; otherwise fall back to the real uplink
    interface MTU, which on cheap links (cellular, PPPoE, telemetry
    modems) is already the reduced value — the number we actually need.
    """
    try:
        configured = int(configured)
    except (TypeError, ValueError):
        configured = 0
    if configured and configured >= MIN_MTU:
        return min(configured, DEFAULT_MTU)
    detected = iface_mtu(bridge_iface) if bridge_iface else 0
    if detected and MIN_MTU <= detected <= DEFAULT_MTU:
        return detected
    return DEFAULT_MTU


def _mss_for(mtu: int) -> int:
    return max(536, min(mtu - MSS_OVERHEAD, DEFAULT_MTU - MSS_OVERHEAD))


def _flush_mss_rules():
    res = _run(["iptables", "-t", "mangle", "-L", "FORWARD", "--line-numbers", "-n"])
    nums = [int(line.split()[0]) for line in res.stdout.splitlines()
            if line.split() and line.split()[0].isdigit() and "TCPMSS" in line]
    for n in sorted(nums, reverse=True):
        _run(["iptables", "-t", "mangle", "-D", "FORWARD", str(n)])


_AP_SVC_TAG = "scannerap_svc"

# Core services a client must always be able to reach on the AP host itself:
# DNS (so names resolve), DHCP (so it gets a lease), and ICMP (ping / PMTU).
# Without these, a host whose INPUT policy is default-DROP (ufw, firewalld,
# most servers) silently drops client DNS and the whole AP looks broken even
# though forwarding is fine.
_AP_SVC_MATCHES = [
    ["-p", "udp", "--dport", "53"],
    ["-p", "tcp", "--dport", "53"],
    ["-p", "udp", "--dport", "67"],
    ["-p", "icmp"],
]


def allow_ap_services(ap_iface: str, debug):
    validate_iface(ap_iface)
    _deny_ap_services(ap_iface)
    for match in _AP_SVC_MATCHES:
        _run(["iptables", "-I", "INPUT", "1", "-i", ap_iface, *match,
              "-m", "comment", "--comment", _AP_SVC_TAG, "-j", "ACCEPT"])
    debug("info", f"Ensured DNS/DHCP/ICMP from {ap_iface} clients are accepted "
                   "(survives a default-deny INPUT policy).")


def _deny_ap_services(ap_iface: str):
    dump = _run(["iptables-save", "-t", "filter"]).stdout
    for line in dump.splitlines():
        if line.startswith("-A INPUT") and _AP_SVC_TAG in line:
            _run(["iptables", *shlex.split(line.replace("-A INPUT", "-D INPUT", 1))])


def ensure_conntrack_headroom(debug, minimum=32768):
    """Raise nf_conntrack_max if it's small. Browsers and apps like Discord
    open many simultaneous connections; a tiny table drops NEW connections
    silently under load while a single steady flow keeps working."""
    path = Path("/proc/sys/net/netfilter/nf_conntrack_max")
    try:
        current = int(path.read_text().strip())
    except (OSError, ValueError):
        return  # module not loaded / not applicable
    if current >= minimum:
        return
    try:
        path.write_text(f"{minimum}\n")
        debug("info", f"Raised nf_conntrack_max {current} -> {minimum} "
                       "(more room for simultaneous client connections).")
    except (OSError, ValueError) as e:
        debug("warn", f"Could not raise nf_conntrack_max (was {current}): {e}")


def _ip6tables_available():
    return _run(["ip6tables", "-L", "-n"]).returncode == 0


def block_ipv6_forwarding(ap_iface: str, debug):
    """We hand clients IPv4 only and don't NAT v6. Drop forwarded IPv6 on the
    AP interface so clients don't half-attempt IPv6 (Happy-Eyeballs stalls) and
    so nothing leaks out un-NATed if the host has v6 forwarding enabled."""
    validate_iface(ap_iface)
    if not _ip6tables_available():
        return
    _unblock_ipv6_forwarding(ap_iface)
    for direction in ("-i", "-o"):
        _run(["ip6tables", "-I", "FORWARD", "1", direction, ap_iface,
              "-m", "comment", "--comment", _AP_SVC_TAG, "-j", "DROP"])
    debug("info", f"IPv6 forwarding on {ap_iface} blocked (clients are IPv4-only "
                   "here; prevents un-NATed v6 leaks and IPv6 connection stalls).")


def _unblock_ipv6_forwarding(ap_iface: str):
    if not _ip6tables_available():
        return
    dump = _run(["ip6tables-save", "-t", "filter"]).stdout
    for line in dump.splitlines():
        if line.startswith("-A FORWARD") and _AP_SVC_TAG in line:
            _run(["ip6tables", *shlex.split(line.replace("-A FORWARD", "-D FORWARD", 1))])


def snapshot_extra_file(save_dir: Path, path: str, debug, restart_unit=None):
    backup_dir = Path(save_dir) / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = backup_dir / BACKUP_MARKER

    manifest = {"timestamp": datetime.now().isoformat(), "ip_forward": None,
                "saved_files": {}, "extra_saved_files": {}, "created_files": [],
                "restart_units": {}}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError, AttributeError) as e:
            debug("warn", f"Could not read backup manifest, starting fresh: {e}")
    manifest.setdefault("saved_files", {})
    manifest.setdefault("extra_saved_files", {})
    manifest.setdefault("created_files", [])
    manifest.setdefault("restart_units", {})

    already_tracked = (path in manifest["saved_files"]
                       or path in manifest["extra_saved_files"]
                       or path in manifest["created_files"])
    if already_tracked:





        if restart_unit and path not in manifest["restart_units"]:
            manifest["restart_units"][path] = restart_unit
            try:
                manifest_path.write_text(json.dumps(manifest, indent=2))
            except (OSError, ValueError) as e:
                debug("warn", f"Could not update backup manifest for {path}: {e}")
        return

    p = Path(path)
    if p.is_file():
        dest_name = f"extra_{len(manifest['extra_saved_files'])}_{p.name}"
        try:
            (backup_dir / dest_name).write_text(p.read_text())
            manifest["extra_saved_files"][path] = dest_name
        except (OSError, ValueError) as e:
            debug("warn", f"Could not snapshot {path}: {e}")
            return
    else:
        manifest["created_files"].append(path)

    if restart_unit:
        manifest["restart_units"][path] = restart_unit

    try:
        manifest_path.write_text(json.dumps(manifest, indent=2))
    except (OSError, ValueError) as e:
        debug("warn", f"Could not update backup manifest for {path}: {e}")


def _restart_units_for(manifest, paths, iface, debug):
    units = {manifest.get("restart_units", {}).get(p) for p in paths}
    units.discard(None)
    for unit in units:
        debug("info", f"Restarting {unit} to apply revert...")
        res = _run(["systemctl", "restart", unit])
        if res.returncode != 0:
            debug("warn", f"Failed to restart {unit}: {res.stderr.strip()}")
            continue
        if iface:



            _run(["nmcli", "device", "set", iface, "managed", "no"])
        debug("ok", f"{unit} restarted.")


def restore_extra_files(save_dir: Path, debug, iface=None):
    backup_dir = Path(save_dir) / "backup"
    manifest_path = backup_dir / BACKUP_MARKER
    if not manifest_path.is_file():
        return []
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError, AttributeError) as e:
        debug("error", f"Could not read backup manifest: {e}")
        return []

    touched = []
    for path, backup_name in manifest.get("extra_saved_files", {}).items():
        backup_file = backup_dir / backup_name
        if backup_file.is_file():
            try:
                Path(path).write_text(backup_file.read_text())
                debug("info", f"Restored {path} to its previous contents.")
                touched.append(path)
            except (OSError, ValueError) as e:
                debug("warn", f"Could not restore {path}: {e}")

    for path in manifest.get("created_files", []):
        try:
            Path(path).unlink()
            debug("info", f"Removed {path} (created by this session).")
            touched.append(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            debug("warn", f"Could not remove {path}: {e}")

    if touched:
        debug("ok", "Runtime config changes reverted.")
        _restart_units_for(manifest, touched, iface, debug)
    return touched


def backup_state(save_dir: Path, debug):
    backup_dir = Path(save_dir) / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)

    iptables_dump = _run(["iptables-save"]).stdout
    (backup_dir / "iptables.rules").write_text(iptables_dump)

    try:
        ip_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except OSError:
        ip_forward = "0"

    manifest = {
        "timestamp": datetime.now().isoformat(),
        "ip_forward": ip_forward,
        "saved_files": {},
    }
    (backup_dir / BACKUP_MARKER).write_text(json.dumps(manifest, indent=2))
    debug("ok", f"Backed up current network config to {backup_dir}")
    return True


def restore_state(save_dir: Path, debug, iface=None):
    backup_dir = Path(save_dir) / "backup"
    manifest_path = backup_dir / BACKUP_MARKER
    if not manifest_path.is_file():
        return []
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError, AttributeError) as e:
        debug("error", f"Could not read backup manifest: {e}")
        return []

    rules_file = backup_dir / "iptables.rules"
    if rules_file.is_file():
        try:
            restore_res = subprocess.run(["iptables-restore"], input=rules_file.read_text(),
                                          text=True, check=False, capture_output=True)
            if restore_res.returncode != 0:
                debug("warn", "iptables-restore reported an error — previous rules "
                               "may not be fully cleared: "
                               f"{(restore_res.stderr or '').strip()}")
        except (OSError, subprocess.SubprocessError) as e:
            debug("error", f"Failed to restore iptables rules: {e}")

    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text(manifest.get("ip_forward") or "0")
    except (OSError, ValueError) as e:
        debug("warn", f"Could not restore ip_forward: {e}")









    teardown_policy_routing(iface, "", debug, quiet=True)

    touched = []
    for path, backup_name in manifest.get("extra_saved_files", {}).items():
        backup_file = backup_dir / backup_name
        if backup_file.is_file():
            try:
                Path(path).write_text(backup_file.read_text())
                touched.append(path)
            except (OSError, ValueError) as e:
                debug("warn", f"Could not restore {path}: {e}")

    for path in manifest.get("created_files", []):
        try:
            Path(path).unlink()
            touched.append(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            debug("warn", f"Could not remove {path}: {e}")

    debug("ok", "Restored previous network configuration.")
    if touched:
        _restart_units_for(manifest, touched, iface, debug)
    return touched


def set_client_timeout(ap_iface: str, mac: str, enabled: bool, debug):
    validate_iface(ap_iface)
    while True:
        res = _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-m", "mac",
                     "--mac-source", mac, "-j", "DROP"])
        if res.returncode != 0:
            break
    if enabled:
        _run_checked(["iptables", "-I", "FORWARD", "1", "-i", ap_iface, "-m", "mac",
                       "--mac-source", mac, "-j", "DROP"], debug, f"Timing out {mac}")


def ip_forward_is_enabled() -> bool:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    except OSError:
        return False


def enable_ip_forward():
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    except (OSError, ValueError) as e:
        print(f"[!] Could not enable ip_forward: {e}")


def disable_ip_forward():
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    except (OSError, ValueError) as e:
        print(f"[!] Could not disable ip_forward: {e}")


def _sysctl_read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _sysctl_write(path, value):
    try:
        Path(path).write_text(f"{value}\n")
        return True
    except (OSError, ValueError) as e:
        print(f"[!] Could not write {path}: {e}")
        return False


def ensure_forwarding(ap_iface: str, bridge_iface: str, debug):
    """Global ip_forward is NOT sufficient on its own. The kernel also gates
    routing on conf.all.forwarding and the per-interface forwarding flag, and
    some systems (NetworkManager, sysctl.d, security hardening) leave one of
    those at 0 — so packets are silently not routed even though our iptables
    rules are perfect. Set and verify all of them."""
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)

    targets = [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv4/conf/all/forwarding",
    ]
    for iface in (ap_iface, bridge_iface):
        if iface:
            targets.append(f"/proc/sys/net/ipv4/conf/{iface}/forwarding")
    stuck = []
    for path in targets:
        if _sysctl_read(path) is None:
            continue  # not applicable on this kernel/iface
        _sysctl_write(path, 1)
        if _sysctl_read(path) != "1":
            stuck.append(path)
    if stuck:
        debug("warn", "IP forwarding could not be enabled (stuck at 0): "
                       + ", ".join(stuck) + " — something on the system is "
                       "forcing it off (check sysctl.d, NetworkManager, or a "
                       "hardening profile). Routing will not work until this is 1.")
    return not stuck


def iptables_backend():
    out = (_run(["iptables", "-V"]).stdout or "").lower()
    if "nf_tables" in out:
        return "nf_tables"
    if "legacy" in out:
        return "legacy"
    return "unknown"


def isolate_ap_iface(ap_iface: str, debug):
    validate_iface(ap_iface)
    deisolate_ap_iface(ap_iface, debug, quiet=True)
    # Clients still get DHCP/DNS from the AP in isolated mode — just no internet.
    allow_ap_services(ap_iface, debug)
    res = _run_checked(["iptables", "-I", "FORWARD", "1", "-i", ap_iface, "-j", "DROP"],
                        debug, f"Isolating {ap_iface}")
    disable_ip_forward()
    if res.returncode == 0:
        debug("info", f"{ap_iface} isolated — forwarding explicitly blocked "
                        "(bridge/NAT is off).")
    return res.returncode == 0


def deisolate_ap_iface(ap_iface: str, debug, quiet=False):
    validate_iface(ap_iface)
    while True:
        res = _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-j", "DROP"])
        if res.returncode != 0:
            break
    if not quiet:
        debug("info", f"{ap_iface} isolation rule removed.")























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
_rp_filter_saved = {}


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


def setup_nat(ap_iface: str, bridge_iface: str, ip_range: str, debug,
              gateway_override: str | None = None, configured_mtu: int = 0):
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    if not bridge_iface:
        debug("info", "No bridge/uplink interface set — NAT not enabled.")
        return False

    ensure_forwarding(ap_iface, bridge_iface, debug)
    teardown_nat(ap_iface, bridge_iface, ip_range, debug, quiet=True)
    deisolate_ap_iface(ap_iface, debug, quiet=True)
    setup_policy_routing(ap_iface, bridge_iface, ip_range, debug,
                         gateway_override=gateway_override)

    allow_ap_services(ap_iface, debug)
    ensure_conntrack_headroom(debug)
    block_ipv6_forwarding(ap_iface, debug)

    # Match the AP-side L3 MTU to the real uplink so oversized client packets
    # are handled at the gateway instead of silently blackholing on a smaller
    # upstream link.
    client_mtu = resolve_client_mtu(bridge_iface, configured_mtu)
    _run_checked(["ip", "link", "set", ap_iface, "mtu", str(client_mtu)],
                 debug, f"Setting AP MTU to {client_mtu}")

    # Disable NIC offloads on both legs. GRO/GSO/TSO (especially on USB Wi-Fi
    # adapters) routinely corrupt or black-hole FORWARDED TCP data segments
    # while the handshake and small/UDP packets still pass — the exact
    # "connects, DNS resolves, but pages never load" signature. Harmless if the
    # driver doesn't support a given knob.
    for nic in (ap_iface, bridge_iface):
        _run(["ethtool", "-K", nic, "gro", "off", "gso", "off", "tso", "off",
              "sg", "off", "tx", "off", "rx", "off"])

    # Scope NAT/forwarding to the AP subnet so the host's own traffic and any
    # other subnets on the uplink are left untouched.
    masq_res = _run_checked(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ip_range,
         "-o", bridge_iface, "-j", "MASQUERADE"],
        debug, f"Adding MASQUERADE for {ip_range} out {bridge_iface}")









    fwd1_res = _run_checked(
        ["iptables", "-I", "FORWARD", "1", "-i", bridge_iface, "-o", ap_iface,
         "-d", ip_range, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        debug, f"Adding FORWARD accept ({bridge_iface} -> {ap_iface}, established)")
    fwd2_res = _run_checked(
        ["iptables", "-I", "FORWARD", "1", "-i", ap_iface, "-o", bridge_iface,
         "-s", ip_range, "-j", "ACCEPT"],
        debug, f"Adding FORWARD accept ({ap_iface} -> {bridge_iface})")
    # Clamp forwarded TCP MSS to the real PATH MTU (discovered via PMTUD), not
    # the interface MTU. An interface may be 1500 while the true internet path
    # is smaller (PPPoE 1492, tunnels, etc.); a fixed MSS from the iface MTU
    # then lets the handshake through but black-holes full-size data. For
    # uplinks that don't do PMTUD, lower the client MTU with the 'mtu' setting
    # (that caps everything, including UDP, from the start).
    _flush_mss_rules()
    _run_checked(
        ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp",
         "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        debug, "Clamping forwarded TCP MSS to path MTU")
    # Always cap MSS hard as well. --clamp-mss-to-pmtu only sees the egress iface
    # MTU (1500), so on an uplink whose true internet path is smaller AND whose
    # ICMP frag-needed is filtered (cellular/CGNAT/VPN — the common tethered-AP
    # case), the clamp leaves MSS at 1460 and full-size TCP data black-holes while
    # the handshake, DNS and QUIC/UDP video all keep working. The floor is the
    # safe path MTU unless the user pinned an even lower MTU via the setting; it
    # runs on 1500 uplinks too, which is exactly where the clamp alone falls short.
    hard = _mss_for(min(client_mtu, PMTU_SAFE_MTU))
    _run_checked(
        ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp",
         "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", str(hard)],
        debug, f"Capping forwarded TCP MSS at {hard} (PMTU black-hole guard)")

    if masq_res.returncode != 0 or fwd1_res.returncode != 0 or fwd2_res.returncode != 0:
        debug("error", f"NAT was NOT fully enabled for {ap_iface} -> {bridge_iface} — "
                        "see the failure(s) above (a common cause is not actually "
                        "running with root/CAP_NET_ADMIN).")
        return False
    _warn_if_forward_blocked(bridge_iface, debug)
    debug("ok", f"NAT enabled: {ap_iface} -> {bridge_iface}")
    verify_nat(ap_iface, bridge_iface, ip_range, debug,
               gateway=gateway_override)
    return True


def _warn_if_forward_blocked(bridge_iface, debug):
    res = _run(["iptables", "-L", "FORWARD", "-n"])
    first_line = res.stdout.splitlines()[0] if res.stdout else ""
    if "policy DROP" in first_line or "policy REJECT" in first_line:
        debug("warn",
              f"FORWARD chain default policy is {first_line.split('policy ')[-1].split(')')[0]} "
              "— something else (commonly Docker, ufw, or firewalld) is "
              "managing this chain. Our ACCEPT rules are inserted at the "
              "top and should still win, but if that other tool reapplies "
              "its own rules afterward (e.g. Docker restarting, `ufw "
              "reload`), it can push ours back down or remove them. If "
              "NAT stops passing traffic again with no changes on this "
              "end, that's the first thing to check.")


def teardown_nat(ap_iface: str, bridge_iface: str, ip_range: str, debug, quiet=False):
    if ap_iface:
        validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    if not bridge_iface:
        return
    teardown_policy_routing(ap_iface, bridge_iface, debug, quiet=True)
    # Delete both the scoped (current) and unscoped (pre-upgrade) rule forms.
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ip_range,
          "-o", bridge_iface, "-j", "MASQUERADE"])
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", bridge_iface,
          "-j", "MASQUERADE"])
    _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-o", bridge_iface,
          "-s", ip_range, "-j", "ACCEPT"])
    _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-o", bridge_iface,
          "-j", "ACCEPT"])
    _run(["iptables", "-D", "FORWARD", "-i", bridge_iface, "-o", ap_iface,
          "-d", ip_range, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    _run(["iptables", "-D", "FORWARD", "-i", bridge_iface, "-o", ap_iface,
          "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    _flush_mss_rules()
    _deny_ap_services(ap_iface)
    _unblock_ipv6_forwarding(ap_iface)
    if not quiet:
        debug("info", f"NAT rules removed for {ap_iface} -> {bridge_iface}")


def fix_rules(ap_iface: str, bridge_iface: str, ip_range: str, debug,
              gateway_override: str | None = None):
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
        ok = setup_nat(ap_iface, bridge_iface, ip_range, debug,
                        gateway_override=gateway_override)
    else:
        ok = isolate_ap_iface(ap_iface, debug)
    if ok:
        debug("ok", "Rules reapplied.")


def reset_rules(ap_iface: str, bridge_iface: str, ip_range: str, debug,
                 gateway_override: str | None = None):
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    teardown_nat(ap_iface, bridge_iface, ip_range, debug, quiet=True)
    deisolate_ap_iface(ap_iface, debug, quiet=True)
    _run(["iptables", "-t", "nat", "-F"])
    _run(["iptables", "-F", "FORWARD"])
    if bridge_iface:
        ok = setup_nat(ap_iface, bridge_iface, ip_range, debug,
                        gateway_override=gateway_override)
    else:
        ok = isolate_ap_iface(ap_iface, debug)
    if ok:
        debug("ok", "Rules hard-reset and reapplied.")


def _forward_policy():
    res = _run(["iptables", "-L", "FORWARD", "-n"])
    line = res.stdout.splitlines()[0] if res.stdout else ""
    if "policy " in line:
        return line.split("policy ", 1)[1].split(")")[0].strip()
    return "unknown"


def detect_host_firewall():
    """Find host firewalls that enforce their own forward policy independently
    of our iptables rules — the most common reason NAT silently fails even
    though our rules look correct. Returns [(name, advice), ...]."""
    findings = []

    ufw = _run(["ufw", "status"])
    if ufw.returncode == 0 and "status: active" in (ufw.stdout or "").lower():
        findings.append(("ufw", ("ufw is active — it defaults to dropping forwarded "
                                 "traffic. Set DEFAULT_FORWARD_POLICY=\"ACCEPT\" in "
                                 "/etc/default/ufw and run 'ufw reload'.")))

    fw = _run(["firewall-cmd", "--state"])
    if fw.returncode == 0 and "running" in (fw.stdout or "").lower():
        findings.append(("firewalld", ("firewalld is running — it owns the forward chain "
                                        "and will drop our forwarded traffic unless the "
                                        "uplink zone permits it (enable masquerade/forward "
                                        "on the zone).")))

    all_rules = _run(["iptables", "-S"]).stdout or ""
    if "-P FORWARD DROP" in all_rules and "DOCKER" in all_rules:
        findings.append(("docker", ("Docker is managing iptables (FORWARD policy DROP and "
                                     "DOCKER chains present). It can reinsert its rules and "
                                     "push ours down whenever the daemon or a container "
                                     "restarts.")))

    nft = _run(["nft", "list", "ruleset"])
    if (nft.returncode == 0
            and re.search(r"hook\s+forward\b", nft.stdout or "")
            and re.search(r"hook\s+forward[^}]*?policy\s+drop", nft.stdout, re.DOTALL)):
        findings.append(("nftables", ("A native nftables chain hooks 'forward' with "
                                      "'policy drop'. nftables evaluates this independently "
                                      "of our iptables rules, so it drops forwarded packets "
                                      "regardless. Allow your AP subnet to forward in that "
                                      "nft ruleset, or disable the conflicting firewall.")))
    return findings


def verify_nat(ap_iface: str, bridge_iface: str, ip_range: str, debug, gateway=None):
    """Post-setup self-check: confirm the system is actually in a state where
    forwarding can work, and surface the exact reason if not."""
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    ok = True
    if _sysctl_read("/proc/sys/net/ipv4/ip_forward") != "1":
        debug("error", "ip_forward is 0 — routing is disabled at the kernel level.")
        ok = False

    fwd_present = _run(["iptables", "-C", "FORWARD", "-i", ap_iface, "-o", bridge_iface,
                        "-s", ip_range, "-j", "ACCEPT"]).returncode == 0
    masq_present = _run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", ip_range,
                         "-o", bridge_iface, "-j", "MASQUERADE"]).returncode == 0
    if not fwd_present:
        debug("warn", "Our FORWARD ACCEPT rule is not present — another tool may have "
                       "flushed or reordered it.")
        ok = False
    if not masq_present:
        debug("warn", "Our MASQUERADE rule is not present.")
        ok = False

    for name, advice in detect_host_firewall():
        debug("warn", f"[{name}] {advice}")
        ok = False

    if ok:
        debug("ok", "NAT self-check passed: forwarding on, rules present, no host "
                     "firewall overriding the forward path.")
    else:
        debug("warn", "NAT self-check found problems above — these are the likely "
                       "reason clients can't reach the internet. Run 'diag' for detail.")
    return ok


def _chain_counters(table, chain):
    args = ["iptables"]
    if table:
        args += ["-t", table]
    args += ["-L", chain, "-v", "-n", "-x"]
    return _run(args).stdout or ""


def report_traffic_counters(ap_iface, bridge_iface, ip_range, debug):
    """Read the live packet counters on the forward/NAT rules and the conntrack
    table so we can see whether REAL client traffic (arriving over the air on
    the AP iface) is actually being forwarded — the host-sourced ping test can't
    show this because locally-generated packets skip the FORWARD chain."""
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    fwd_out = fwd_in = masq = None
    for line in _chain_counters(None, "FORWARD").splitlines():
        p = line.split()
        if len(p) >= 7 and p[0].isdigit():
            pkts, inif, outif = p[0], p[5], p[6]
            if inif == ap_iface and outif == bridge_iface:
                fwd_out = pkts
            elif inif == bridge_iface and outif == ap_iface:
                fwd_in = pkts
    for line in _chain_counters("nat", "POSTROUTING").splitlines():
        p = line.split()
        if len(p) >= 7 and p[0].isdigit() and p[2] == "MASQUERADE" and p[6] == bridge_iface:
            masq = p[0]

    debug("info", f"forward counters: client->net ({ap_iface}->{bridge_iface})="
                   f"{fwd_out if fwd_out is not None else '?'} pkts, "
                   f"net->client ({bridge_iface}->{ap_iface})="
                   f"{fwd_in if fwd_in is not None else '?'} pkts, "
                   f"MASQUERADE={masq if masq is not None else '?'} pkts")

    try:
        prefix = str(ipaddress.ip_network(ip_range, strict=False).network_address)
        prefix = prefix.rsplit(".", 1)[0] + "."
    except (ValueError, TypeError, AttributeError):
        prefix = None
    flows = None
    if prefix:
        text = ""
        try:
            text = Path("/proc/net/nf_conntrack").read_text()
        except OSError:
            text = ""
        if not text.strip():
            # /proc/net/nf_conntrack can be empty/disabled even when tracking
            # works; fall back to the conntrack tool (prints to stdout/stderr).
            ct = _run(["conntrack", "-L"])
            text = (ct.stdout or "") + (ct.stderr or "")
        flows = len(re.findall(r"src=" + re.escape(prefix), text))
    debug("info", f"conntrack flows sourced from {prefix or ip_range}x: "
                   f"{flows if flows is not None else '?'}")
    if fwd_out in ("0", None) and (flows in (0, None)):
        debug("warn", "No forwarded client packets seen yet. Browse something on a "
                       "client (with mobile data OFF so it can't use cellular), then run "
                       "'diag' again: if client->net stays 0, the phone's data isn't "
                       "reaching the AP over the air (driver/RF/power-save) — not a "
                       "routing problem; if it climbs but there's still no internet, the "
                       "break is past the AP.")


def _iface_phy(iface):
    validate_iface(iface)
    try:
        return Path(f"/sys/class/net/{iface}/phy80211/name").read_text().strip()
    except OSError:
        return None


def _first_host(ip_range):
    try:
        net = ipaddress.ip_network(ip_range, strict=False)
        return str(next(net.hosts()))
    except (ValueError, TypeError, StopIteration):
        return None


def tcp_connect_probe(src_ip, host, port, timeout=4):
    """Open a real TCP connection from the AP's LAN IP out through the NAT path,
    to confirm TCP (not just ICMP) survives forwarding + MASQUERADE + the uplink
    — the original 'small packets work, TCP apps fail' symptom lives here."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.bind((src_ip, 0))
        except OSError:
            pass
        rc = s.connect_ex((host, port))
        s.close()
        return rc == 0
    except (OSError, ValueError):
        return False


def dns_probe(server_ip, name="example.com", timeout=3):
    """Send a minimal A-record query straight to a DNS server (our dnsmasq on
    the AP gateway) and report whether it answers — tests the exact path a
    client's DNS takes, without depending on dig/nslookup being installed."""
    txid = b"\x12\x34"
    header = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    packet = header + q + b"\x00\x01\x00\x01"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (server_ip, 53))
        data, _ = s.recvfrom(512)
        s.close()
        ancount = int.from_bytes(data[6:8], "big")
        return ancount > 0
    except (OSError, ValueError):
        return False


def diagnose(ap_iface: str, bridge_iface: str, ip_range: str, debug, gateway=None):
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    debug("info", "=== bridge diagnostics ===")
    debug("info", f"iptables backend: {iptables_backend()}")
    debug("info", f"ip_forward={_sysctl_read('/proc/sys/net/ipv4/ip_forward')} "
                   f"all.forwarding={_sysctl_read('/proc/sys/net/ipv4/conf/all/forwarding')}")
    for iface in (ap_iface, bridge_iface):
        if not iface:
            continue
        fwd = _sysctl_read(f"/proc/sys/net/ipv4/conf/{iface}/forwarding")
        rpf = _sysctl_read(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter")
        off = _run(["ethtool", "-k", iface]).stdout or ""
        on_offloads = [o for o in ("generic-receive-offload", "generic-segmentation-offload",
                                    "tcp-segmentation-offload")
                       if re.search(rf"^{o}: on", off, re.MULTILINE)]
        offtxt = ("offloads ON: " + ", ".join(on_offloads)) if on_offloads else "offloads off"
        debug("info", f"{iface}: forwarding={fwd} rp_filter={rpf}  ({offtxt})")

    # Same-radio AP+STA: a very common reason a Wi-Fi AP "works" but clients
    # drop and traffic stalls, even with perfect host-side rules.
    phy_ap = _iface_phy(ap_iface)
    phy_up = _iface_phy(bridge_iface) if bridge_iface else None
    if phy_ap and phy_up and phy_ap == phy_up:
        debug("warn", f"{ap_iface} (AP) and {bridge_iface} (uplink) are the SAME radio "
                       f"({phy_ap}). Most Wi-Fi chips cannot reliably run an access point "
                       "and a client uplink at the same time — the usual symptom is exactly "
                       "this: clients connect then drop, and traffic doesn't pass. Use a "
                       "separate Wi-Fi adapter or a wired uplink for the bridge.")

    addr = _run(["ip", "-4", "addr", "show", "dev", ap_iface]).stdout or ""
    addrs = re.findall(r"inet (\S+)", addr)
    debug("info" if addrs else "warn",
          f"{ap_iface} IPv4: {', '.join(addrs) if addrs else 'NONE (clients have no gateway to reach)'}")

    debug("info", f"FORWARD policy: {_forward_policy()}")

    if bridge_iface:
        pbr = (_run(["ip", "route", "show", "table", str(PBR_TABLE_ID)]).stdout or "").strip()
        pbr_line = pbr.replace("\n", "  |  ") if pbr else "empty"
        has_local = ip_range.rsplit("/", 1)[0].rsplit(".", 1)[0] in pbr and " dev " + ap_iface in pbr
        debug("info" if has_local else "warn",
              f"policy table {PBR_TABLE_ID}: {pbr_line}"
              + ("" if has_local else f"  — MISSING the local {ap_iface} route; "
                 "gateway->client replies (DNS/ICMP) will be sent out the uplink"))

    ap_gw = _first_host(ip_range)
    if ap_gw:
        dns_ok = dns_probe(ap_gw)
        debug("info" if dns_ok else "warn",
              f"DNS probe to dnsmasq at {ap_gw}: "
              f"{'answered (resolution works for clients)' if dns_ok else 'NO ANSWER — clients cannot resolve names (dnsmasq down, wrong upstream, or port 53 blocked)'}")

    if bridge_iface:
        gw = gateway or _iface_default_gateway(bridge_iface)
        debug("info", f"uplink {bridge_iface} gateway: {gw or 'unknown'}")
        if gw:
            ping = _run(["ping", "-c", "1", "-W", "2", "-I", bridge_iface, gw])
            debug("info" if ping.returncode == 0 else "warn",
                  f"ping gateway {gw} via {bridge_iface}: "
                  f"{'reachable' if ping.returncode == 0 else 'FAILED (uplink may be down)'}")
        # The decisive test: source a packet from the AP's LAN IP so it takes
        # the exact policy-route + MASQUERADE path a client's traffic takes.
        if ap_gw:
            cp = _run(["ping", "-c", "1", "-W", "3", "-I", ap_gw, "8.8.8.8"])
            icmp_ok = cp.returncode == 0
            tcp_ok = tcp_connect_probe(ap_gw, "1.1.1.1", 443)
            debug("ok" if icmp_ok else "warn",
                  f"client-path ICMP (src {ap_gw} -> 8.8.8.8 through NAT): "
                  f"{'works' if icmp_ok else 'FAILED'}")
            debug("ok" if tcp_ok else "warn",
                  f"client-path TCP (src {ap_gw} -> 1.1.1.1:443 through NAT): "
                  f"{'works' if tcp_ok else 'FAILED'}")
            if icmp_ok and tcp_ok:
                debug("ok", "Full egress path works for AP-subnet-sourced traffic (ICMP+TCP). "
                             "If real clients still fail, the break is NOT host routing/NAT — "
                             "it's the client leg: the Wi-Fi data path on the AP radio, or the "
                             "client isn't actually sending via this network (e.g. phone on "
                             "cellular). Watch the forward counters below while a client browses.")
            elif icmp_ok and not tcp_ok:
                debug("warn", "ICMP works but TCP does not through the NAT path — this matches "
                               "the 'small packets pass, apps fail' symptom. Suspect the uplink "
                               "blocking/altering TCP, or an MSS/offload issue on the uplink NIC "
                               "(try: ethtool -K <uplink> tx off gro off).")

    ct_max = _sysctl_read("/proc/sys/net/netfilter/nf_conntrack_max")
    ct_cnt = _sysctl_read("/proc/sys/net/netfilter/nf_conntrack_count")
    debug("info", f"conntrack: count={ct_cnt or '?'} max={ct_max or 'module not loaded'}")

    if bridge_iface:
        report_traffic_counters(ap_iface, bridge_iface, ip_range, debug)
        verify_nat(ap_iface, bridge_iface, ip_range, debug, gateway=gateway)
    else:
        debug("info", "No uplink set — AP is in isolated mode (no internet by design).")
    debug("info", "=== end diagnostics ===")