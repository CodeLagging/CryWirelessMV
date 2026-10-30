"""NAT orchestration, host-config backup/restore, and client MTU resolution.

The firewall primitives live in `firewall.py`, policy routing in `routing.py`,
and diagnostics in `diag.py`. This module wires them into the high-level
setup/teardown/fix/reset flow the AP uses, snapshots and restores the host's
original network configuration, and resolves the MTU advertised to clients.

The firewall / routing / diagnostics entry points that callers historically
reached as ``netops.<name>`` are re-exported here so the split is transparent.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path

from core.APCC.diag import diagnose  # noqa: F401  (re-exported as netops.diagnose)
from core.APCC.firewall import (
    _deny_ap_services,
    _unblock_ipv6_forwarding,
    _warn_if_forward_blocked,
    allow_ap_services,
    block_ipv6_forwarding,
    deisolate_ap_iface,
    ensure_conntrack_headroom,
    ensure_forwarding,
    isolate_ap_iface,
    set_client_timeout,  # noqa: F401  (re-exported as netops.set_client_timeout)
    verify_nat,
)
from core.APCC.netutil import _run, _run_checked
from core.APCC.routing import (
    detect_gateway,  # noqa: F401  (re-exported as netops.detect_gateway)
    setup_policy_routing,
    teardown_policy_routing,
)
from core.validators import validate_iface

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


def snapshot_extra_file(save_dir: Path, path: str, debug, restart_unit=None):
    backup_dir = Path(save_dir) / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = backup_dir / BACKUP_MARKER

    manifest: dict = {"timestamp": datetime.now().isoformat(), "ip_forward": None,
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
