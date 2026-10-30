import ipaddress
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import ClassVar

from core.APCC import confgen, netops, reslimit
from core.APCC import settings as settings_mod
from core.APCC.binpaths import get_bin


class _DummyResult:
    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 1


def _run(cmd, check=False, capture=True, timeout=5):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True,
                              check=check, timeout=timeout)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return _DummyResult()


def _diagnose_port_owners(ports=(53, 67)):
    found = {}
    res = _run(["ss", "-tulpn"])
    if res.returncode != 0:
        return found
    for line in res.stdout.splitlines():
        m = re.search(r":(\d+)\s+[\d.:\[\]*]+\s+users:\(\(\"([^\"]+)\",pid=(\d+)", line)
        if not m:
            continue
        port, name, pid = int(m.group(1)), m.group(2), m.group(3)
        if port not in ports or port in found:
            continue
        cmdline = ""
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_text().replace("\x00", " ").strip()
        except OSError:
            pass
        unit = ""
        try:
            cgroup = Path(f"/proc/{pid}/cgroup").read_text()
            m2 = re.search(r"/([\w@.\-]+\.service)\b", cgroup)
            if m2:
                unit = m2.group(1)
        except (OSError, AttributeError, TypeError):
            pass
        found[port] = {"pid": pid, "name": name, "cmdline": cmdline, "unit": unit}
    return found


def _dnsmasq_conf_path(cmdline):
    m = re.search(r"--conf-file[= ](\S+)", cmdline)
    if m:
        return m.group(1)
    return "/etc/dnsmasq.conf"


def _dnsmasq_conf_dir_files(cmdline):
    m = re.search(r"(?:--conf-dir[= ]|-7[= ])(\S+)", cmdline)
    if not m:
        return []
    parts = m.group(1).split(",")
    conf_dir = parts[0]
    suffixes = parts[1:]
    try:
        entries = sorted(Path(conf_dir).iterdir())
    except OSError:
        return []

    include_only = [s[1:] for s in suffixes if s.startswith("*")]
    if include_only:
        return [str(entry) for entry in entries if entry.is_file()
                and any(entry.name.endswith(suf) for suf in include_only)]

    files = []
    for entry in entries:
        if not entry.is_file():
            continue
        if any(entry.name.endswith(suf) for suf in suffixes):
            continue
        files.append(str(entry))
    return files


class APStateManager:
    """Handles config generation, dnsmasq conflict resolution, and state persistence."""

    DEFAULT_UPSTREAM_DNS: ClassVar[list[str]] = ["1.1.1.1", "8.8.8.8"]

    def __init__(self, iface, save_dir, settings, logger):
        self.iface = iface
        self.save_dir = Path(save_dir)
        self.settings = settings
        self.logger = logger
        self.lease_file = str(self.save_dir / "dnsmasq.leases")
        self.bridge_enabled = False
        self.gateway = None

    def _resolve_upstream_dns(self):
        configured = (self.settings.get("upstream_dns") or "").strip()
        if configured:
            return [p.strip() for p in configured.replace(";", ",").split(",") if p.strip()]
        if self.bridge_enabled and self.settings.get("bridge_iface"):
            return list(self.DEFAULT_UPSTREAM_DNS)
        return []

    def write_configs(self, domain_control, domain_filter):
        corrected, warnings = settings_mod.validate_settings(self.settings)
        self.settings = corrected
        settings_mod.save_settings(self.save_dir, self.settings)
        for w in warnings:
            self.logger.debug("warn", f"[settings] {w}")  # noqa: PLE1205

        hostapd_conf = confgen.generate_hostapd_conf(self.settings, self.iface)
        gateway = self._gateway_for(self.settings["ip_range"])
        self.gateway = gateway
        extra_lines = domain_control.generate_dnsmasq_lines(domain_filter, gateway)
        client_mtu = netops.resolve_client_mtu(self.settings.get("bridge_iface", ""), self.settings.get("mtu", 0))
        dnsmasq_conf, gateway = confgen.generate_dnsmasq_conf(
            self.settings, self.iface, self.lease_file, extra_lines=extra_lines,
            mtu=client_mtu, upstream_dns=self._resolve_upstream_dns())

        conf_dir = self.save_dir / "conf"
        conf_dir.mkdir(parents=True, exist_ok=True)
        hostapd_path = conf_dir / "hostapd.conf"
        dnsmasq_path = conf_dir / "dnsmasq.conf"
        hostapd_path.write_text(hostapd_conf)
        dnsmasq_path.write_text(dnsmasq_conf)
        return hostapd_path, dnsmasq_path, gateway

    @staticmethod
    def _gateway_for(network):
        return str(next(ipaddress.ip_network(network, strict=False).hosts()))

    def start_dnsmasq(self, dnsmasq_path, client_mgr, kr=None, _retries_left=2):
        _run(["pkill", "-f", f"dnsmasq.*{dnsmasq_path.name}"])
        time.sleep(0.3)

        static_hosts_path = self.save_dir / "conf" / "dhcp-hosts"
        lines = [f"{mac},{ip}" for mac, ip in client_mgr.static_ips.items()]
        static_hosts_path.write_text("\n".join(lines) + ("\n" if lines else ""))

        conf_text = dnsmasq_path.read_text()
        if "dhcp-hostsfile" not in conf_text:
            conf_text += f"dhcp-hostsfile={static_hosts_path}\n"
            dnsmasq_path.write_text(conf_text)

        proc = subprocess.Popen(
            [get_bin("dnsmasq"), "--no-daemon", "--conf-file=" + str(dnsmasq_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        reslimit.exclude_pid_from_limits(proc.pid, self.logger.debug)
        time.sleep(0.5)
        
        if proc.poll() is not None:
            out = ""
            try:
                out = proc.stdout.read()
            except (OSError, ValueError):
                pass

            address_in_use = "address already in use" in out.lower()
            owners = _diagnose_port_owners((53, 67)) if address_in_use else {}
            fix_target = None
            for info in owners.values():
                if info["name"] == "dnsmasq" or info["name"].startswith("systemd-resolve"):
                    fix_target = info
                    break

            attempting = fix_target is not None
            self.logger.debug("info" if attempting else "error", "dnsmasq couldn't bind — port 53/67 already in use, adjusting the conflicting service..." if attempting else "dnsmasq failed to start.")

            if address_in_use:
                if owners:
                    seen = {}
                    for port, info in owners.items():
                        key = (info["name"], info["pid"])
                        seen.setdefault(key, []).append(str(port))
                    culprits = ", ".join(f"{name} (pid {pid}, port{'s' if len(ports) > 1 else ''} {'/'.join(ports)})" for (name, pid), ports in seen.items())
                    self.logger.debug("info" if attempting else "error", f"Port 53/67 on {self.iface} is already held by: {culprits}.")
                    for info in owners.values():
                        detail = f"  pid {info['pid']} ({info['name']}): {info['cmdline'] or '<cmdline unavailable>'}"
                        if info["unit"]:
                            detail += f"  [unit: {info['unit']}]"
                        self.logger.debug("info", detail)  # noqa: PLE1205

                    fixed = False
                    if fix_target is not None:
                        info = fix_target
                        unit_lower = info["unit"].lower()
                        if info["name"] == "dnsmasq" and "networkmanager" in unit_lower:
                            self.logger.debug("info", f"Held by {info['unit']}'s own internal dnsmasq (shared/NAT connection on your other interface). Scoping it to specific interfaces instead of the wildcard address (tracked under this session's backup, reverted at exit or via --fix).")  # noqa: PLE1205
                            fixed = self._apply_nm_dnsmasq_fix(info["unit"])
                        elif info["name"] == "dnsmasq":
                            self.logger.debug("info", f"Held by dnsmasq under {info['unit'] or 'no systemd unit'} — scoping its own conf file to specific interfaces instead of the wildcard address (tracked under this session's backup, reverted at exit or via --fix).")  # noqa: PLE1205
                            fixed = self._apply_generic_dnsmasq_fix(info)
                        elif info["name"].startswith("systemd-resolve"):
                            self.logger.debug("info", "Held by systemd-resolved's DNS stub listener. Disabling just that listener (host DNS resolution keeps working — this only drops the network-facing socket; tracked under this session's backup, reverted at exit or via --fix).")  # noqa: PLE1205
                            fixed = self._apply_systemd_resolved_fix(info["unit"])
                    else:
                        for info in owners.values():
                            self.logger.debug("error", f"Don't know how to safely reconfigure '{info['name']}' automatically — stop or reconfigure it manually, or scope it to a specific interface if it supports that, then retry.")  # noqa: PLE1205

                    if fixed and _retries_left > 0:
                        self.logger.debug("info", "Retrying dnsmasq startup...")  # noqa: PLE1205
                        return self.start_dnsmasq(dnsmasq_path, client_mgr, kr=None, _retries_left=_retries_left - 1)
                    elif fixed:
                        self.logger.debug("error", "Still couldn't bind after applying a fix and retrying — giving up rather than retrying indefinitely. Check manually with: sudo ss -tulpn | grep -E ':53|:67'")  # noqa: PLE1205
                else:
                    self.logger.debug("error", f"Port 53/67 already bound on {self.iface}, but the owning process couldn't be identified (ss not available or output unparsable). Check manually with: sudo ss -tulpn | grep -E ':53|:67'")  # noqa: PLE1205

            if out.strip():
                for line in out.strip().splitlines()[-10:]:
                    self.logger.debug("error", f"  dnsmasq: {line}")  # noqa: PLE1205
            return None
        return proc

    def _apply_nm_dnsmasq_fix(self, unit):
        unit = unit or "NetworkManager"
        snippet_dir = Path("/etc/NetworkManager/dnsmasq-shared.d")
        snippet_path = snippet_dir / "bind-interfaces.conf"
        netops.snapshot_extra_file(self.save_dir, str(snippet_path), self.logger.debug, restart_unit=unit)
        try:
            snippet_dir.mkdir(parents=True, exist_ok=True)
            snippet_path.write_text(f"bind-interfaces\nexcept-interface={self.iface}\n")
        except (OSError, ValueError) as e:
            self.logger.debug("error", f"Could not write {snippet_path}: {e}")  # noqa: PLE1205
            return False
        self.logger.debug("info", f"Wrote {snippet_path}. Restarting {unit}...")  # noqa: PLE1205
        return self._restart_unit_and_keep_iface_unmanaged(unit)

    def _apply_generic_dnsmasq_fix(self, info):
        conf_path = _dnsmasq_conf_path(info["cmdline"])
        conf_dir_files = _dnsmasq_conf_dir_files(info["cmdline"])
        all_files = [conf_path] + [f for f in conf_dir_files if f != conf_path]

        for f in all_files:
            netops.snapshot_extra_file(self.save_dir, f, self.logger.debug, restart_unit=info["unit"] or None)

        changed_files = []
        overridden_in = []

        override_re = re.compile(r"^[ \t]*(interface[ \t]*=[ \t]*" + re.escape(self.iface) + r"|listen-address[ \t]*=[ \t]*" + re.escape(self.gateway or "\x00no-gateway-set\x00") + r")[ \t]*$", re.MULTILINE)
        for f in all_files:
            p = Path(f)
            if not p.is_file():
                continue
            try:
                text = p.read_text()
            except (OSError, ValueError) as e:
                self.logger.debug("error", f"Could not read {f}: {e}")  # noqa: PLE1205
                continue
            new_text, n = override_re.subn(lambda m: "#" + m.group(0) + "  # commented out by scannerap: overrode except-interface", text)
            if n:
                try:
                    p.write_text(new_text)
                    changed_files.append(f)
                    overridden_in.append(f)
                except (OSError, ValueError) as e:
                    self.logger.debug("error", f"Could not modify {f}: {e}")  # noqa: PLE1205
                    return False

        try:
            p = Path(conf_path)
            text = p.read_text() if p.is_file() else ""
            has_bind = bool(re.search(r"^[ \t]*(bind-interfaces|bind-dynamic)[ \t]*$", text, re.MULTILINE))
            has_except = bool(re.search(r"^[ \t]*except-interface[ \t]*=[ \t]*" + re.escape(self.iface) + r"[ \t]*$", text, re.MULTILINE))
            to_add = []
            if not has_bind:
                to_add.append("bind-interfaces")
            if not has_except:
                to_add.append(f"except-interface={self.iface}")
            if to_add:
                if text and not text.endswith("\n"):
                    text += "\n"
                text += "\n".join(to_add) + "\n"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
                changed_files.append(conf_path)
        except (OSError, ValueError) as e:
            self.logger.debug("error", f"Could not modify {conf_path}: {e}")  # noqa: PLE1205
            return False

        if not changed_files:
            self.logger.debug("warn", f"{conf_path} (and its conf-dir) already scope bind mode and exclude {self.iface} with no explicit override left — this isn't the same conflict, won't touch it.")  # noqa: PLE1205
            return False

        if overridden_in:
            self.logger.debug("info", f"Found an explicit interface=/listen-address= override in: {', '.join(overridden_in)} — this was silently beating except-interface, so it's now commented out.")  # noqa: PLE1205
        self.logger.debug("info", f"Updated: {', '.join(changed_files)}.")  # noqa: PLE1205
        if info["unit"]:
            self.logger.debug("info", f"Restarting {info['unit']}...")  # noqa: PLE1205
            return self._restart_unit_and_keep_iface_unmanaged(info["unit"])

        self.logger.debug("warn", f"No systemd unit found for pid {info['pid']} — sending SIGTERM directly instead of a service restart. If nothing supervises it, you may need to start it again yourself.")  # noqa: PLE1205
        _run(["kill", info["pid"]])
        time.sleep(1)
        return True

    def _apply_systemd_resolved_fix(self, unit):
        unit = unit or "systemd-resolved"
        drop_in_dir = Path("/etc/systemd/resolved.conf.d")
        drop_in_path = drop_in_dir / "no-stub-listener.conf"
        netops.snapshot_extra_file(self.save_dir, str(drop_in_path), self.logger.debug, restart_unit=unit)
        try:
            drop_in_dir.mkdir(parents=True, exist_ok=True)
            drop_in_path.write_text("[Resolve]\nDNSStubListener=no\n")
        except (OSError, ValueError) as e:
            self.logger.debug("error", f"Could not write {drop_in_path}: {e}")  # noqa: PLE1205
            return False
        self.logger.debug("info", f"Wrote {drop_in_path}. Restarting {unit}...")  # noqa: PLE1205
        return self._restart_unit_and_keep_iface_unmanaged(unit)

    def _restart_unit_and_keep_iface_unmanaged(self, unit):
        res = _run(["systemctl", "restart", unit], timeout=15)
        if res.returncode != 0:
            self.logger.debug("error", f"Failed to restart {unit}: {res.stderr.strip()}")  # noqa: PLE1205
            return False

        time.sleep(3)
        if self._which("nmcli"):
            nmcli_res = _run(["nmcli", "device", "set", self.iface, "managed", "no"], timeout=10)
            if nmcli_res.returncode != 0:
                self.logger.debug("warn", f"{unit} restarted, but could not keep {self.iface} unmanaged: {nmcli_res.stderr.strip()}")  # noqa: PLE1205
                self.logger.debug("ok", f"{unit} restarted.")  # noqa: PLE1205
                return True
            self.logger.debug("ok", f"{unit} restarted; {self.iface} kept unmanaged.")  # noqa: PLE1205
            return True
        self.logger.debug("ok", f"{unit} restarted; nmcli unavailable so managed state was not changed.")  # noqa: PLE1205
        return True

    @staticmethod
    def _which(name):
        import shutil
        return shutil.which(name) is not None