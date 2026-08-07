import subprocess
import shlex
import json
from pathlib import Path
from datetime import datetime


class _DummyResult:
    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 1


def _run(cmd, check=False, capture=True):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True, check=check)
    except (FileNotFoundError, OSError):
        return _DummyResult()


def _run_checked(cmd, debug, what):
    res = _run(cmd)
    if res.returncode != 0:
        stderr = (res.stderr or "").strip()
        debug("warn", f"{what} failed (exit {res.returncode})"
                       f"{': ' + stderr if stderr else ''} — command: {' '.join(cmd)}")
    return res


BACKUP_MARKER = "scannerap_backup.json"


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
        except Exception as e:
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
            except Exception as e:
                debug("warn", f"Could not update backup manifest for {path}: {e}")
        return

    p = Path(path)
    if p.is_file():
        dest_name = f"extra_{len(manifest['extra_saved_files'])}_{p.name}"
        try:
            (backup_dir / dest_name).write_text(p.read_text())
            manifest["extra_saved_files"][path] = dest_name
        except Exception as e:
            debug("warn", f"Could not snapshot {path}: {e}")
            return
    else:
        manifest["created_files"].append(path)

    if restart_unit:
        manifest["restart_units"][path] = restart_unit

    try:
        manifest_path.write_text(json.dumps(manifest, indent=2))
    except Exception as e:
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
    except Exception as e:
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
            except Exception as e:
                debug("warn", f"Could not restore {path}: {e}")

    for path in manifest.get("created_files", []):
        try:
            Path(path).unlink()
            debug("info", f"Removed {path} (created by this session).")
            touched.append(path)
        except FileNotFoundError:
            pass
        except Exception as e:
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
    except Exception:
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
    except Exception as e:
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
        except Exception as e:
            debug("error", f"Failed to restore iptables rules: {e}")

    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text(manifest.get("ip_forward") or "0")
    except Exception:
        pass








    teardown_policy_routing(iface, "", debug, quiet=True)

    touched = []
    for path, backup_name in manifest.get("extra_saved_files", {}).items():
        backup_file = backup_dir / backup_name
        if backup_file.is_file():
            try:
                Path(path).write_text(backup_file.read_text())
                touched.append(path)
            except Exception as e:
                debug("warn", f"Could not restore {path}: {e}")

    for path in manifest.get("created_files", []):
        try:
            Path(path).unlink()
            touched.append(path)
        except FileNotFoundError:
            pass
        except Exception as e:
            debug("warn", f"Could not remove {path}: {e}")

    debug("ok", "Restored previous network configuration.")
    if touched:
        _restart_units_for(manifest, touched, iface, debug)
    return touched


def set_client_timeout(ap_iface: str, mac: str, enabled: bool, debug):
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
    except Exception:
        return False


def enable_ip_forward():
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    except Exception:
        pass


def disable_ip_forward():
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    except Exception:
        pass


def isolate_ap_iface(ap_iface: str, debug):
    deisolate_ap_iface(ap_iface, debug, quiet=True)
    res = _run_checked(["iptables", "-I", "FORWARD", "1", "-i", ap_iface, "-j", "DROP"],
                        debug, f"Isolating {ap_iface}")
    disable_ip_forward()
    if res.returncode == 0:
        debug("info", f"{ap_iface} isolated — forwarding explicitly blocked "
                        "(bridge/NAT is off).")
    return res.returncode == 0


def deisolate_ap_iface(ap_iface: str, debug, quiet=False):
    while True:
        res = _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-j", "DROP"])
        if res.returncode != 0:
            break
    if not quiet:
        debug("info", f"{ap_iface} isolation rule removed.")























PBR_TABLE_ID = 200
PBR_RULE_PRIORITY = 10000


def _iface_default_gateway(iface, debug=None):
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


def _set_rp_filter(iface, value, debug):
    try:
        _rp_filter_path(iface).write_text(f"{value}\n")
    except Exception as e:
        debug("warn", f"Could not set rp_filter for {iface}: {e}")


def loosen_rp_filter(ap_iface: str, bridge_iface: str, debug):
    _set_rp_filter(ap_iface, 2, debug)
    _set_rp_filter(bridge_iface, 2, debug)


def restore_rp_filter(ap_iface: str, bridge_iface: str, debug):
    if ap_iface:
        _set_rp_filter(ap_iface, 1, debug)
    if bridge_iface:
        _set_rp_filter(bridge_iface, 1, debug)


def setup_policy_routing(ap_iface: str, bridge_iface: str, ip_range: str, debug,
                          gateway_override: str = None):
    gateway = gateway_override or _iface_default_gateway(bridge_iface, debug)
    if not gateway:
        debug("warn", f"Policy routing not set up for {bridge_iface} "
                       "(no gateway found) — falling back to whatever "
                       "the main routing table picks by metric.")
        return False

    teardown_policy_routing(ap_iface, bridge_iface, debug, quiet=True)

    _run(["ip", "route", "flush", "table", str(PBR_TABLE_ID)])
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
    _run(["ip", "rule", "del", "priority", str(PBR_RULE_PRIORITY)])
    _run(["ip", "route", "flush", "table", str(PBR_TABLE_ID)])
    restore_rp_filter(ap_iface, bridge_iface, debug)
    if not quiet:
        debug("info", "Policy routing rule/table removed.")


def detect_gateway(iface: str, debug=None):
    return _iface_default_gateway(iface, debug)


def setup_nat(ap_iface: str, bridge_iface: str, ip_range: str, debug,
              gateway_override: str = None):
    if not bridge_iface:
        debug("info", "No bridge/uplink interface set — NAT not enabled.")
        return False

    enable_ip_forward()
    teardown_nat(ap_iface, bridge_iface, ip_range, debug, quiet=True)
    deisolate_ap_iface(ap_iface, debug, quiet=True)
    setup_policy_routing(ap_iface, bridge_iface, ip_range, debug,
                         gateway_override=gateway_override)

    masq_res = _run_checked(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", bridge_iface, "-j", "MASQUERADE"],
        debug, f"Adding MASQUERADE for {bridge_iface}")









    fwd1_res = _run_checked(
        ["iptables", "-I", "FORWARD", "1", "-i", bridge_iface, "-o", ap_iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        debug, f"Adding FORWARD accept ({bridge_iface} -> {ap_iface}, established)")
    fwd2_res = _run_checked(
        ["iptables", "-I", "FORWARD", "1", "-i", ap_iface, "-o", bridge_iface, "-j", "ACCEPT"],
        debug, f"Adding FORWARD accept ({ap_iface} -> {bridge_iface})")
    if masq_res.returncode != 0 or fwd1_res.returncode != 0 or fwd2_res.returncode != 0:
        debug("error", f"NAT was NOT fully enabled for {ap_iface} -> {bridge_iface} — "
                        "see the failure(s) above (a common cause is not actually "
                        "running with root/CAP_NET_ADMIN).")
        return False
    _warn_if_forward_blocked(bridge_iface, debug)
    debug("ok", f"NAT enabled: {ap_iface} -> {bridge_iface}")
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
    if not bridge_iface:
        return
    teardown_policy_routing(ap_iface, bridge_iface, debug, quiet=True)
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", bridge_iface,
          "-j", "MASQUERADE"])
    _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-o", bridge_iface,
          "-j", "ACCEPT"])
    _run(["iptables", "-D", "FORWARD", "-i", bridge_iface, "-o", ap_iface,
          "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    if not quiet:
        debug("info", f"NAT rules removed for {ap_iface} -> {bridge_iface}")


def fix_rules(ap_iface: str, bridge_iface: str, ip_range: str, debug,
              gateway_override: str = None):
    if bridge_iface:
        ok = setup_nat(ap_iface, bridge_iface, ip_range, debug,
                        gateway_override=gateway_override)
    else:
        ok = isolate_ap_iface(ap_iface, debug)
    if ok:
        debug("ok", "Rules reapplied.")


def reset_rules(ap_iface: str, bridge_iface: str, ip_range: str, debug,
                 gateway_override: str = None):
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
