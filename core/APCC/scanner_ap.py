

import os
import re
import sys
import time
import threading
import ipaddress
import subprocess
import shlex
from datetime import datetime
from pathlib import Path


from core.APCC.deps import check_dependencies, check_root
from core.APCC.binpaths import startup_module, get_bin
from core.APCC import settings as settings_mod
from core.APCC import confgen
from core.APCC import netops
from core.APCC import reslimit

from core.APCC.clients import ClientManager
from core.APCC.logging_ap import APLogger
from core.APCC.domain_filter import DomainFilter
from core.APCC.domain_control import DomainControl, RedirectServer
from core.APCC.termkeys import TermKeys
from core.APCC.settings_ui import run_settings_editor
from core.APCC.logfilters_ui import run_logfilters_editor
from core.APCC.clients_ui import run_clients_menu
from core.APCC.domain_control_ui import run_domain_control_menu


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
        except Exception:
            pass
        unit = ""
        try:
            cgroup = Path(f"/proc/{pid}/cgroup").read_text()
            m2 = re.search(r"/([\w@.\-]+\.service)\b", cgroup)
            if m2:
                unit = m2.group(1)
        except Exception:
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
    except Exception:
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



class ScannerAP:
    def __init__(self, iface, savepath="./ap_sessions"):
        self.iface = iface
        self.save_dir = Path(savepath)
        self._log_lock = threading.RLock()
        self._log_paused = False
        self._paused_log_queue = []
        self._scroll_active = False
        self._scroll_bottom = None
        self.debug = self._log

        self.settings = None
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.gateway = None
        self.ap_running = False
        self.dhcp_enabled = False
        self.bridge_enabled = False

        self.session_dir = None
        self.lease_file = str(self.save_dir / "dnsmasq.leases")
        self.client_mgr = ClientManager(iface, self.lease_file)
        self.logger = None





        self.domain_filter = DomainFilter(self.save_dir / "insp_filter")




        self.domain_control = DomainControl(self.save_dir)
        self.redirect_server = RedirectServer(self.domain_control, self.debug)

        self._display_thread_stop = None
        self.running = False
        self._hostapd_log_thread = None
        self._ap_lock = threading.RLock()
        self._auto_reconnect_pending = False
        self._reconnect_in_progress = False
        self._reconnect_attempts = 0
        self._watchdog_thread = None





    def _reapply_client_timeouts(self):
        for mac in self.domain_control.timeout_macs:
            netops.set_client_timeout(self.iface, mac, True, self.debug)

    def _startup(self):
        if not check_dependencies(self.debug):
            print("Required tools missing — install them and re-run.")
            sys.exit(1)
        check_root(self.debug)





        netops.backup_state(self.save_dir, self.debug)

        self.settings = settings_mod.load_settings(self.save_dir)

        ts = datetime.now().strftime("%m_%d_%H-%M")
        self.session_dir = self.save_dir / ts
        self.logger = APLogger(self.iface, self.session_dir, self.client_mgr,
                                self.debug, domain_filter=self.domain_filter)





    def _write_configs(self):
        corrected, warnings = settings_mod.validate_settings(self.settings)
        self.settings = corrected
        settings_mod.save_settings(self.save_dir, self.settings)
        for w in warnings:
            self.debug("warn", f"[settings] {w}")

        hostapd_conf = confgen.generate_hostapd_conf(self.settings, self.iface)
        gateway = self._gateway_for(self.settings["ip_range"])
        extra_lines = self.domain_control.generate_dnsmasq_lines(self.domain_filter, gateway)
        dnsmasq_conf, gateway = confgen.generate_dnsmasq_conf(
            self.settings, self.iface, self.lease_file, extra_lines=extra_lines)

        conf_dir = self.save_dir / "conf"
        conf_dir.mkdir(parents=True, exist_ok=True)
        hostapd_path = conf_dir / "hostapd.conf"
        dnsmasq_path = conf_dir / "dnsmasq.conf"
        hostapd_path.write_text(hostapd_conf)
        dnsmasq_path.write_text(dnsmasq_conf)
        return hostapd_path, dnsmasq_path, gateway

    def _release_interface(self):
        if self._which("nmcli"):
            _run(["nmcli", "device", "set", self.iface, "managed", "no"])
        try:
            _run(["pkill", "-f", f"wpa_supplicant.*{self.iface}"])
        except Exception:
            pass

    def _warn_if_phy_conflict(self):
        try:
            phy_res = _run(["iw", "dev", self.iface, "info"])
            phy_match = re.search(r"wiphy\s+(\d+)", phy_res.stdout)
            if not phy_match:
                return
            my_phy = phy_match.group(1)

            all_res = _run(["iw", "dev"])
            blocks = all_res.stdout.split("Interface ")
            for block in blocks[1:]:
                name = block.split()[0]
                if name == self.iface:
                    continue
                other_phy = re.search(r"wiphy\s+(\d+)", block)
                if other_phy and other_phy.group(1) == my_phy:
                    self.debug("warn",
                               f"Interface '{name}' shares the same radio "
                               f"(phy{my_phy}) as {self.iface} and is still "
                               f"active — this is a common cause of channel-"
                               f"set failures. Bring it down first: "
                               f"ip link set {name} down")
        except Exception:
            pass

    @staticmethod
    def _which(name):
        import shutil
        return shutil.which(name) is not None

    @staticmethod
    def _gateway_for(network):
        return str(next(ipaddress.ip_network(network, strict=False).hosts()))

    def _cleanup_failed_start(self, gateway, prefix):
        if self.dnsmasq_proc:
            self._stop_dnsmasq()
        if gateway is not None and prefix is not None:
            _run(["ip", "addr", "del", f"{gateway}/{prefix}", "dev", self.iface])

    def _reap_hostapd_proc(self, proc):
        out = ""
        if not proc:
            return out
        try:
            if proc.stdout:
                out = proc.stdout.read()
        except Exception:
            out = ""
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
        return out

    def _teardown_after_unexpected_loss(self):
        if self.logger:
            self.logger.stop_sniff()
        self._stop_dnsmasq()
        self.redirect_server.stop()
        self.hostapd_proc = None
        if self.bridge_enabled:
            netops.teardown_nat(self.iface, self.settings["bridge_iface"],
                                 self.settings["ip_range"], self.debug)
        netops.deisolate_ap_iface(self.iface, self.debug, quiet=True)
        self.ap_running = False
        reslimit.remove_limits(self.iface, self.debug)
        self._auto_reconnect_pending = True

    def _watchdog_loop(self, stop_event):
        while not stop_event.wait(2):
            with self._ap_lock:
                if (self.ap_running and self.hostapd_proc
                        and self.hostapd_proc.poll() is not None):
                    self.debug("warn",
                               f"{self.iface} appears to have disconnected "
                               "(hostapd exited unexpectedly) — waiting for "
                               "it to reappear to auto-reconnect...")
                    self._teardown_after_unexpected_loss()
                should_retry = self._auto_reconnect_pending and not self._reconnect_in_progress

            if should_retry and Path(f"/sys/class/net/{self.iface}").exists():
                with self._ap_lock:
                    if self._auto_reconnect_pending and not self._reconnect_in_progress:
                        self._reconnect_in_progress = True
                        self._reconnect_attempts += 1
                        if self._reconnect_attempts >= 5:
                            self._auto_reconnect_pending = False
                            self._reconnect_in_progress = False
                            continue

                backoff = min(8, 2 ** max(0, self._reconnect_attempts - 1))
                time.sleep(backoff)
                self.debug("ok", f"{self.iface} reappeared — reconnecting (attempt {self._reconnect_attempts})...")
                self._start_ap_impl()
                with self._ap_lock:
                    if self.ap_running:
                        self._auto_reconnect_pending = False
                        self._reconnect_attempts = 0
                    else:
                        self._auto_reconnect_pending = self._reconnect_attempts < 5
                    self._reconnect_in_progress = False





    def start_ap(self, kr=None):
        with self._ap_lock:
            self._auto_reconnect_pending = False
            self._start_ap_impl(kr=kr)

    def _start_ap_impl(self, kr=None):
        if self.ap_running:
            return
        hostapd_path, dnsmasq_path, gateway = self._write_configs()
        self.gateway = gateway
        network = self.settings["ip_range"]
        prefix = network.split("/")[-1]

        if not self.dhcp_enabled:




            _run(["pkill", "-f", f"dnsmasq.*{dnsmasq_path.name}"])




        if self.logger:
            self.logger.stop_sniff()

        self._release_interface()








        _run(["ip", "link", "set", self.iface, "down"])
        _run(["iw", "dev", self.iface, "set", "type", "managed"])

        self._warn_if_phy_conflict()

        _run(["ip", "addr", "flush", "dev", self.iface])
        if self.settings.get("mac_addr"):
            res = _run(["ip", "link", "set", self.iface, "address",
                        self.settings["mac_addr"]])
            if res.returncode != 0:
                self.debug("warn", f"Could not set MAC override: {res.stderr.strip()}")
        _run(["ip", "link", "set", self.iface, "up"])
        if self.dhcp_enabled:
            _run(["ip", "addr", "add", f"{gateway}/{prefix}", "dev", self.iface])














        if self.dhcp_enabled:
            if not self._start_dnsmasq(dnsmasq_path, kr=kr):
                self._cleanup_failed_start(gateway, prefix)
                self.dhcp_enabled = False

        try:
            tx_mbm = int(self.settings.get("tx_power_dbm", 20)) * 100
            res = _run(["iw", "dev", self.iface, "set", "txpower", "fixed", str(tx_mbm)])
            if res.returncode != 0:
                self.debug("warn", f"Could not set tx power: {res.stderr.strip()}")
        except Exception as e:
            self.debug("warn", f"tx power set failed: {e}")

        self.hostapd_proc = subprocess.Popen(
            [get_bin("hostapd"), str(hostapd_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        reslimit.exclude_pid_from_limits(self.hostapd_proc.pid, self.debug)
        time.sleep(1.5)
        if self.hostapd_proc.poll() is not None:
            out = self._reap_hostapd_proc(self.hostapd_proc)
            self.debug("critical", "hostapd failed to start.")
            if out.strip():
                for line in out.strip().splitlines()[-10:]:
                    self.debug("critical", f"  hostapd: {line}")
            self.hostapd_proc = None
            self._cleanup_failed_start(gateway, prefix)
            return





        status = _run([get_bin("hostapd_cli"), "-i", self.iface, "status"])
        if status.returncode != 0 or "state=ENABLED" not in status.stdout:
            self.debug("critical",
                       "hostapd is running but the BSS did not come up "
                       "(not broadcasting). Common causes: the adapter's "
                       "driver doesn't support AP/master mode, an invalid "
                       "channel for your regulatory domain, or (5GHz) a "
                       "pending DFS radar check.")
            if status.stdout.strip():
                self.debug("critical", f"  hostapd_cli status: {status.stdout.strip()}")
            self._reap_hostapd_proc(self.hostapd_proc)
            self.hostapd_proc = None
            self._cleanup_failed_start(gateway, prefix)
            return

        self._hostapd_log_thread = threading.Thread(
            target=self._drain_hostapd_log, daemon=True)
        self._hostapd_log_thread.start()

        if self.bridge_enabled:
            netops.setup_nat(self.iface, self.settings["bridge_iface"],
                              self.settings["ip_range"], self.debug)
        else:




            netops.isolate_ap_iface(self.iface, self.debug)









        self._reapply_client_timeouts()

        reslimit.apply_profile(self.settings.get("resource_profile", "normal"),
                                self.iface, self.debug)

        self.ap_running = True
        if self.logger:
            self.logger.start_sniff()

        self.debug("ok", f"AP '{self.settings['ssid']}' started on {self.iface}.")

    def _drain_hostapd_log(self):
        proc = self.hostapd_proc
        if not proc or not proc.stdout:
            return
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.debug("info", f"hostapd: {line}")
        except Exception:
            pass

    def stop_ap(self):
        with self._ap_lock:
            self._auto_reconnect_pending = False
            self._stop_ap_impl()

    def _stop_ap_impl(self):
        if not self.ap_running:
            return
        if self.logger:
            self.logger.stop_sniff()
        self._stop_dnsmasq()
        self.redirect_server.stop()
        if self.hostapd_proc:
            self.hostapd_proc.terminate()
            try:
                self.hostapd_proc.wait(timeout=3)
            except Exception:
                self.hostapd_proc.kill()
            self.hostapd_proc = None
        if self.bridge_enabled:
            netops.teardown_nat(self.iface, self.settings["bridge_iface"],
                                 self.settings["ip_range"], self.debug)
        netops.deisolate_ap_iface(self.iface, self.debug, quiet=True)



        _run(["ip", "addr", "flush", "dev", self.iface])
        if self._which("nmcli"):
            _run(["nmcli", "device", "set", self.iface, "managed", "yes"])
        reslimit.remove_limits(self.iface, self.debug)
        self.ap_running = False
        self.debug("ok", "AP stopped.")

    def _start_dnsmasq(self, dnsmasq_path, kr=None, _retries_left=2):


        _run(["pkill", "-f", f"dnsmasq.*{dnsmasq_path.name}"])
        time.sleep(0.3)

        static_hosts_path = self.save_dir / "conf" / "dhcp-hosts"
        lines = [f"{mac},{ip}" for mac, ip in self.client_mgr.static_ips.items()]
        static_hosts_path.write_text("\n".join(lines) + ("\n" if lines else ""))

        conf_text = dnsmasq_path.read_text()
        if "dhcp-hostsfile" not in conf_text:
            conf_text += f"dhcp-hostsfile={static_hosts_path}\n"
            dnsmasq_path.write_text(conf_text)

        self.dnsmasq_proc = subprocess.Popen(
            [get_bin("dnsmasq"), "--no-daemon", "--conf-file=" + str(dnsmasq_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        reslimit.exclude_pid_from_limits(self.dnsmasq_proc.pid, self.debug)
        time.sleep(0.5)
        if self.dnsmasq_proc.poll() is not None:
            out = ""
            try:
                out = self.dnsmasq_proc.stdout.read()
            except Exception:
                pass

            address_in_use = "address already in use" in out.lower()
            owners = _diagnose_port_owners((53, 67)) if address_in_use else {}
            fix_target = None
            for info in owners.values():
                if info["name"] == "dnsmasq" or info["name"].startswith("systemd-resolve"):
                    fix_target = info
                    break

            attempting = fix_target is not None
            self.debug("info" if attempting else "error",
                       "dnsmasq couldn't bind — port 53/67 already in use, "
                       "adjusting the conflicting service..." if attempting
                       else "dnsmasq failed to start.")

            if address_in_use:
                if owners:
                    seen = {}
                    for port, info in owners.items():
                        key = (info["name"], info["pid"])
                        seen.setdefault(key, []).append(str(port))
                    culprits = ", ".join(
                        f"{name} (pid {pid}, port{'s' if len(ports) > 1 else ''} "
                        f"{'/'.join(ports)})"
                        for (name, pid), ports in seen.items()
                    )
                    self.debug("info" if attempting else "error",
                               f"Port 53/67 on {self.iface} is already held "
                               f"by: {culprits}.")
                    for info in owners.values():
                        detail = (f"  pid {info['pid']} ({info['name']}): "
                                  f"{info['cmdline'] or '<cmdline unavailable>'}")
                        if info["unit"]:
                            detail += f"  [unit: {info['unit']}]"
                        self.debug("info", detail)

                    fixed = False
                    if fix_target is not None:
                        info = fix_target
                        unit_lower = info["unit"].lower()
                        if info["name"] == "dnsmasq" and "networkmanager" in unit_lower:
                            self.debug("info",
                                       f"Held by {info['unit']}'s own internal "
                                       "dnsmasq (shared/NAT connection on your "
                                       "other interface). Scoping it to specific "
                                       "interfaces instead of the wildcard "
                                       "address (tracked under this session's "
                                       "backup, reverted at exit or via --fix).")
                            fixed = self._apply_nm_dnsmasq_fix(info["unit"])
                        elif info["name"] == "dnsmasq":
                            self.debug("info",
                                       f"Held by dnsmasq under "
                                       f"{info['unit'] or 'no systemd unit'} — "
                                       "scoping its own conf file to specific "
                                       "interfaces instead of the wildcard "
                                       "address (tracked under this session's "
                                       "backup, reverted at exit or via --fix).")
                            fixed = self._apply_generic_dnsmasq_fix(info)
                        elif info["name"].startswith("systemd-resolve"):
                            self.debug("info",
                                       "Held by systemd-resolved's DNS stub "
                                       "listener. Disabling just that listener "
                                       "(host DNS resolution keeps working — "
                                       "this only drops the network-facing "
                                       "socket; tracked under this session's "
                                       "backup, reverted at exit or via --fix).")
                            fixed = self._apply_systemd_resolved_fix(info["unit"])
                    else:
                        for info in owners.values():
                            self.debug("error",
                                       f"Don't know how to safely reconfigure "
                                       f"'{info['name']}' automatically — "
                                       "stop or reconfigure it manually, or "
                                       "scope it to a specific interface if it "
                                       "supports that, then retry.")

                    if fixed and _retries_left > 0:
                        self.debug("info", "Retrying dnsmasq startup...")
                        return self._start_dnsmasq(dnsmasq_path, kr=None,
                                                    _retries_left=_retries_left - 1)
                    elif fixed:
                        self.debug("error",
                                   "Still couldn't bind after applying a fix and "
                                   "retrying — giving up rather than retrying "
                                   "indefinitely. Check manually with: "
                                   "sudo ss -tulpn | grep -E ':53|:67'")
                else:
                    self.debug("error",
                               f"Port 53/67 already bound on {self.iface}, but "
                               "the owning process couldn't be identified "
                               "(ss not available or output unparsable). Check "
                               "manually with: sudo ss -tulpn | grep -E ':53|:67'")


            if out.strip():
                for line in out.strip().splitlines()[-10:]:
                    self.debug("error", f"  dnsmasq: {line}")
            self.dnsmasq_proc = None
            return False
        return True

    def _apply_nm_dnsmasq_fix(self, unit):
        unit = unit or "NetworkManager"

        snippet_dir = Path("/etc/NetworkManager/dnsmasq-shared.d")
        snippet_path = snippet_dir / "bind-interfaces.conf"
        netops.snapshot_extra_file(self.save_dir, str(snippet_path), self.debug,
                                    restart_unit=unit)
        try:
            snippet_dir.mkdir(parents=True, exist_ok=True)
            snippet_path.write_text(
                f"bind-interfaces\nexcept-interface={self.iface}\n")
        except Exception as e:
            self.debug("error", f"Could not write {snippet_path}: {e}")
            return False
        self.debug("info", f"Wrote {snippet_path}. Restarting {unit}...")
        return self._restart_unit_and_keep_iface_unmanaged(unit)

    def _apply_generic_dnsmasq_fix(self, info):
        conf_path = _dnsmasq_conf_path(info["cmdline"])
        conf_dir_files = _dnsmasq_conf_dir_files(info["cmdline"])
        all_files = [conf_path] + [f for f in conf_dir_files if f != conf_path]

        for f in all_files:
            netops.snapshot_extra_file(self.save_dir, f, self.debug,
                                        restart_unit=info["unit"] or None)

        changed_files = []
        overridden_in = []




        override_re = re.compile(
            r"^[ \t]*(interface[ \t]*=[ \t]*" + re.escape(self.iface) +
            r"|listen-address[ \t]*=[ \t]*" +
            re.escape(self.gateway or "\x00no-gateway-set\x00") +
            r")[ \t]*$",
            re.MULTILINE,
        )
        for f in all_files:
            p = Path(f)
            if not p.is_file():
                continue
            try:
                text = p.read_text()
            except Exception as e:
                self.debug("error", f"Could not read {f}: {e}")
                continue
            new_text, n = override_re.subn(
                lambda m: "#" + m.group(0) +
                          "  # commented out by scannerap: overrode except-interface",
                text,
            )
            if n:
                try:
                    p.write_text(new_text)
                    changed_files.append(f)
                    overridden_in.append(f)
                except Exception as e:
                    self.debug("error", f"Could not modify {f}: {e}")
                    return False



        try:
            p = Path(conf_path)
            text = p.read_text() if p.is_file() else ""





            has_bind = bool(re.search(
                r"^[ \t]*(bind-interfaces|bind-dynamic)[ \t]*$", text,
                re.MULTILINE))
            has_except = bool(re.search(
                r"^[ \t]*except-interface[ \t]*=[ \t]*" +
                re.escape(self.iface) + r"[ \t]*$", text, re.MULTILINE))
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
        except Exception as e:
            self.debug("error", f"Could not modify {conf_path}: {e}")
            return False

        if not changed_files:
            self.debug("warn", f"{conf_path} (and its conf-dir) already "
                                f"scope bind mode and exclude {self.iface} "
                                "with no explicit override left — this "
                                "isn't the same conflict, won't touch it.")
            return False

        if overridden_in:
            self.debug("info",
                       "Found an explicit interface=/listen-address= "
                       f"override in: {', '.join(overridden_in)} — this "
                       "was silently beating except-interface, so it's "
                       "now commented out.")
        self.debug("info", f"Updated: {', '.join(changed_files)}.")
        if info["unit"]:
            self.debug("info", f"Restarting {info['unit']}...")
            return self._restart_unit_and_keep_iface_unmanaged(info["unit"])



        self.debug("warn", f"No systemd unit found for pid {info['pid']} — "
                            "sending SIGTERM directly instead of a service "
                            "restart. If nothing supervises it, you may "
                            "need to start it again yourself.")
        _run(["kill", info["pid"]])
        time.sleep(1)
        return True

    def _apply_systemd_resolved_fix(self, unit):
        unit = unit or "systemd-resolved"

        drop_in_dir = Path("/etc/systemd/resolved.conf.d")
        drop_in_path = drop_in_dir / "no-stub-listener.conf"
        netops.snapshot_extra_file(self.save_dir, str(drop_in_path), self.debug,
                                    restart_unit=unit)
        try:
            drop_in_dir.mkdir(parents=True, exist_ok=True)
            drop_in_path.write_text("[Resolve]\nDNSStubListener=no\n")
        except Exception as e:
            self.debug("error", f"Could not write {drop_in_path}: {e}")
            return False
        self.debug("info", f"Wrote {drop_in_path}. Restarting {unit}...")
        return self._restart_unit_and_keep_iface_unmanaged(unit)

    def _restart_unit_and_keep_iface_unmanaged(self, unit):
        res = _run(["systemctl", "restart", unit], timeout=15)
        if res.returncode != 0:
            self.debug("error", f"Failed to restart {unit}: {res.stderr.strip()}")
            return False

        time.sleep(3)

        if self._which("nmcli"):
            nmcli_res = _run(["nmcli", "device", "set", self.iface, "managed", "no"], timeout=10)
            if nmcli_res.returncode != 0:
                self.debug("warn", f"{unit} restarted, but could not keep {self.iface} unmanaged: {nmcli_res.stderr.strip()}")
                self.debug("ok", f"{unit} restarted.")
                return True
            self.debug("ok", f"{unit} restarted; {self.iface} kept unmanaged.")
            return True

        self.debug("ok", f"{unit} restarted; nmcli unavailable so managed state was not changed.")
        return True


    def _stop_dnsmasq(self):
        if self.dnsmasq_proc:
            self.dnsmasq_proc.terminate()
            try:
                self.dnsmasq_proc.wait(timeout=3)
            except Exception:
                self.dnsmasq_proc.kill()
            self.dnsmasq_proc = None





    def _display_loop(self, stop_event):
        self._display_shown = 0
        while not stop_event.is_set():
            if self.logger and self.logger.display_on:
                with self.logger._display_lock:
                    buf = list(self.logger.display_buffer)
                for line in buf[self._display_shown:]:
                    self._emit_line(line)
                self._display_shown = len(buf)
            time.sleep(0.3)





    def _handle_key(self, key, kr):
        if key is None:
            return
        k = key.lower() if isinstance(key, str) and len(key) == 1 else key

        if k == "x":
            self.running = False

        elif k == "s":
            self.settings = run_settings_editor(kr, self.settings, self.save_dir)
            time.sleep(2)

        elif k == "q":
            if self.ap_running:
                self.stop_ap()
            else:
                self.start_ap(kr=kr)

        elif k == "w":
            turning_on = not self.dhcp_enabled
            if not turning_on:
                self.dhcp_enabled = False
                removed_note = ""
                if self.ap_running:
                    self._stop_dnsmasq()
                    self.redirect_server.stop()
                    network = self.settings["ip_range"]
                    prefix = network.split("/")[-1]
                    gateway = self._gateway_for(network)
                    _run(["ip", "addr", "del", f"{gateway}/{prefix}", "dev", self.iface])
                    removed_note = f" (gateway {gateway}/{prefix} removed from {self.iface}, lease file cleared)"
                try:
                    Path(self.lease_file).unlink()
                except FileNotFoundError:
                    pass
                except Exception as e:
                    self.debug("warn", f"Could not clear lease file: {e}")
                self.debug("info", f"DHCP -> OFF{removed_note}")
            elif not self.ap_running:


                self.dhcp_enabled = True
                self.debug("info",
                           "DHCP -> ON (will start once the AP is running; "
                           f"range {self.settings['dhcp_start']}-"
                           f"{self.settings['dhcp_end']}, "
                           f"lease {self.settings['dhcp_lease_time']})")
            else:
                network = self.settings["ip_range"]
                prefix = network.split("/")[-1]
                gateway = str(list(ipaddress.ip_network(network, strict=False).hosts())[0])
                _run(["ip", "addr", "add", f"{gateway}/{prefix}", "dev", self.iface])
                self._write_configs()
                if self._start_dnsmasq(self.save_dir / "conf" / "dnsmasq.conf", kr=kr):
                    self.dhcp_enabled = True
                    pid = self.dnsmasq_proc.pid if self.dnsmasq_proc else "?"
                    if self.domain_control.redirects:
                        self.redirect_server.start(gateway)
                    self.debug("info",
                               f"DHCP -> ON (gateway {gateway}/{prefix} on {self.iface}, "
                               f"range {self.settings['dhcp_start']}-"
                               f"{self.settings['dhcp_end']}, "
                               f"lease {self.settings['dhcp_lease_time']}, "
                               f"dnsmasq pid {pid})")
                else:



                    _run(["ip", "addr", "del", f"{gateway}/{prefix}", "dev", self.iface])
                    self.debug("warn",
                               f"DHCP -> OFF (dnsmasq failed to start — gateway "
                               f"{gateway}/{prefix} removed from {self.iface} again)")

        elif k == "e":
            self.bridge_enabled = not self.bridge_enabled
            if self.bridge_enabled:
                iface_in = kr.prompt_line(
                    "  Bridge/uplink interface to share internet from "
                    "(e.g. eth0, wlan0): ").strip()
                if iface_in:
                    self.settings["bridge_iface"] = iface_in
                    detected = netops.detect_gateway(iface_in)
                    if detected:
                        self.settings["bridge_gateway"] = None
                        self.debug("debug", f"Auto-detected gateway {detected} for {iface_in}.")
                    else:
                        manual = kr.prompt_line(
                            f"  Could not auto-detect a gateway for {iface_in} "
                            "— enter one manually to force traffic out this "
                            "interface specifically, or press Enter to use "
                            "plain NAT instead (subject to the kernel's own "
                            "metric-based interface choice): ").strip()
                        self.settings["bridge_gateway"] = manual or None



                else:
                    self.debug("info", "No bridge interface given — bridge mode not enabled.")
                    self.bridge_enabled = False
            self.debug("info", f"Bridge/NAT mode -> {'ON' if self.bridge_enabled else 'OFF'}"
                                f"{' (' + self.settings['bridge_iface'] + ')' if self.bridge_enabled else ''}")
            if self.ap_running:
                if self.bridge_enabled:
                    netops.setup_nat(self.iface, self.settings["bridge_iface"],
                                      self.settings["ip_range"], self.debug,
                                      gateway_override=self.settings.get("bridge_gateway"))
                else:
                    netops.teardown_nat(self.iface, self.settings["bridge_iface"],
                                         self.settings["ip_range"], self.debug)
                    netops.isolate_ap_iface(self.iface, self.debug)
                self._reapply_client_timeouts()

        elif k == "r":
            if self.logger.recording:
                self.logger.stop_recording()
                self.debug("info", "Recording stopped.")
            else:
                self.logger.start_recording()
                self.debug("info", f"Recording -> {self.session_dir}")

        elif k == "y":
            run_clients_menu(kr, self.client_mgr, self.debug)

        elif k == "t":
            self.logger.display_on = not self.logger.display_on
            self.debug("info", f"Live log display -> {'ON' if self.logger.display_on else 'OFF'}")

        elif k == "g":
            result = run_logfilters_editor(
                kr, self.logger.enabled_categories,
                domain_filter=self.domain_filter,
                full_address=self.logger.full_address,
                show_device=self.logger.show_device)
            self.logger.enabled_categories = result["categories"]
            self.logger.full_address = result["full_address"]
            self.logger.show_device = result["show_device"]

        elif k == "f":
            def apply_domain_control(timeout_mac=None, timeout_enabled=None):
                if timeout_mac is not None:
                    if self.ap_running:







                        netops.set_client_timeout(self.iface, timeout_mac.lower(),
                                                   timeout_enabled, self.debug)
                    return






                self._write_configs()
                if self.dhcp_enabled and self.ap_running:
                    self._stop_dnsmasq()
                    if self._start_dnsmasq(self.save_dir / "conf" / "dnsmasq.conf", kr=kr):
                        gateway = self._gateway_for(self.settings["ip_range"])
                        if self.domain_control.redirects:
                            self.redirect_server.start(gateway)
                        else:
                            self.redirect_server.stop()
                    else:






                        self.dhcp_enabled = False
                        self.redirect_server.stop()
                        self.debug("warn", "DHCP -> OFF (dnsmasq failed to restart "
                                            "after the Domain Control change — see "
                                            "the error above)")

            run_domain_control_menu(kr, self.domain_control, self.domain_filter,
                                     self.client_mgr, self.debug, apply_domain_control)

        elif k == "h":
            self.logger.clear_display()
            self._display_shown = 0
            print("\033[2J\033[H", end="")

        elif k == "j":




            bridge_iface = self.settings["bridge_iface"] if self.bridge_enabled else ""
            netops.fix_rules(self.iface, bridge_iface,
                              self.settings["ip_range"], self.debug,
                              gateway_override=self.settings.get("bridge_gateway"))
            self._reapply_client_timeouts()

    def _status_lines(self):
        return [
            "--- ScannerAP ---",
            f"iface={self.iface}  ssid={self.settings['ssid']}  "
            f"ap_running={self.ap_running}  dhcp={self.dhcp_enabled}  "
            f"bridge={self.bridge_enabled}  recording={self.logger.recording}",
            "Keys: [S]ettings [Q]AP on/off [W]DHCP [E]Bridge [R]ecord "
            "[Y]Clients [T]LogDisplay [F]Domain [G]LogFilters "
            "[H]ClearDisplay [J]FixRules [X]Quit",
        ]

    def _term_rows(self):
        import shutil
        return shutil.get_terminal_size().lines

    def _set_scroll_region(self):
        rows = self._term_rows()
        self._status_line_count = len(self._status_lines())
        self._scroll_bottom = max(1, rows - self._status_line_count - 1)
        sys.stdout.write(f"\033[1;{self._scroll_bottom}r")
        sys.stdout.write(f"\033[{self._scroll_bottom};1H")
        sys.stdout.flush()
        self._scroll_active = True

    def _reset_scroll_region(self):
        self._scroll_active = False
        rows = self._term_rows()
        sys.stdout.write("\033[r")
        if self._scroll_bottom is not None:





            sys.stdout.write(f"\033[{self._scroll_bottom + 1};1H\033[J")
        else:
            sys.stdout.write(f"\033[{rows};1H\n")
        sys.stdout.flush()

    def _draw_status_bar(self):
        with self._log_lock:
            rows = self._term_rows()
            lines = self._status_lines()
            sys.stdout.write("\0337")
            for i, line in enumerate(lines):
                row = self._scroll_bottom + 1 + i
                if row > rows:
                    break
                sys.stdout.write(f"\033[{row};1H\033[2K{line}")
            sys.stdout.write("\0338")
            sys.stdout.flush()

    def _pause_logging(self):
        with self._log_lock:
            self._log_paused = True

    def _resume_logging(self):
        with self._log_lock:
            self._log_paused = False
            queued = self._paused_log_queue
            self._paused_log_queue = []
        for line in queued:
            self._emit_line(line)

    def _emit_line(self, line):
        with self._log_lock:
            if self._log_paused:
                self._paused_log_queue.append(line)
                return
            if not self._scroll_active or not sys.stdout.isatty():
                print(line)
                return







            sys.stdout.write(f"\033[{self._scroll_bottom};1H\033[2K{line}\n")
            sys.stdout.flush()
            self._draw_status_bar()

    _LEVEL_STYLE = {

        "debug":    ("DEBUG",    "\033[2;37m"),
        "info":     ("INFO",     "\033[36m"),
        "ok":       ("OK",       "\033[32m"),
        "warn":     ("WARN",     "\033[33m"),
        "error":    ("ERROR",    "\033[31m"),
        "critical": ("CRITICAL", "\033[1;37;41m"),
    }
    _RESET = "\033[0m"

    def _log(self, level, msg):
        label, color = self._LEVEL_STYLE.get(level, (level.upper(), ""))
        ts = datetime.now().strftime("%H:%M:%S")
        if color and sys.stdout.isatty():
            line = f"[{ts}] {color}[{label}]{self._RESET} {msg}"
        else:
            line = f"[{ts}] [{label}] {msg}"
        self._emit_line(line)





    def run(self, fix=False):
        if os.geteuid() != 0:
            print("[!] This needs root. Re-run with sudo.")
            return

        if not startup_module(self.debug):
            print("[!] Could not set up a local hostapd/hostapd_cli/dnsmasq "
                  "install — see messages above.")
            return

        if fix:
            self._run_fix()
            return

        self._startup()
        self.running = True




        stop_event = threading.Event()
        display_thread = threading.Thread(target=self._display_loop,
                                           args=(stop_event,), daemon=True)
        display_thread.start()

        watchdog_thread = threading.Thread(target=self._watchdog_loop,
                                            args=(stop_event,), daemon=True)
        watchdog_thread.start()

        self._set_scroll_region()
        self._draw_status_bar()
        last_bar_draw = time.time()
        try:
            with TermKeys() as kr:
                while self.running:
                    try:
                        key = kr.getch(timeout=0.2)
                    except Exception as e:





                        self.debug("error", f"Key read error: {e}")
                        key = None
                    if key:
                        in_submenu = key.lower() in ("s", "y", "g", "f") if isinstance(key, str) else False
                        try:
                            if in_submenu:
                                self._pause_logging()
                                self._reset_scroll_region()
                                print("\033[2J\033[H", end="")
                            self._handle_key(key, kr)
                        except Exception as e:
                            self.debug("error", f"Command failed: {e}")
                        finally:
                            if in_submenu:
                                self._set_scroll_region()
                                self._resume_logging()
                        self._draw_status_bar()
                        last_bar_draw = time.time()
                    elif time.time() - last_bar_draw > 1.0:




                        self._draw_status_bar()
                        last_bar_draw = time.time()
        except KeyboardInterrupt:
            pass
        finally:
            stop_event.set()
            if display_thread.is_alive():
                display_thread.join(timeout=1)
            if watchdog_thread.is_alive():
                watchdog_thread.join(timeout=1)
            self._reset_scroll_region()
            self.shutdown()

    def shutdown(self):
        print("\n[*] Shutting down ScannerAP...")
        if self.logger:
            self.logger.stop_recording()
            self.logger.stop_sniff()
        self.stop_ap()
        netops.restore_state(self.save_dir, self.debug, iface=self.iface)



        try:
            Path(self.lease_file).unlink()
        except FileNotFoundError:
            pass
        except Exception as e:
            self.debug("warn", f"Could not clear lease file: {e}")
        self.client_mgr.filtered.clear()
        self.client_mgr.static_ips.clear()

        print("[*] Done.")

    def _run_fix(self):
        if not check_dependencies(self.debug):
            print("Required tools missing — install them and re-run.")
            sys.exit(1)
        check_root(self.debug)
        self.settings = settings_mod.load_settings(self.save_dir)
        bridge_iface = self.settings.get("bridge_iface", "")
        print(f"[*] Hard-resetting network rules for {self.iface}...")
        netops.reset_rules(self.iface, bridge_iface,
                            self.settings["ip_range"], self.debug)
        netops.restore_extra_files(self.save_dir, self.debug, iface=self.iface)
        print("[*] Done.")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Interactive defensive/research AP")
    p.add_argument("iface", help="interface to run the AP on")
    p.add_argument("-o", "--savepath", default="./ap_sessions")
    p.add_argument("--fix", action="store_true",
                    help="Hard-reset network rules and revert any leftover "
                         "runtime config fixes for this interface, then "
                         "exit — does not start the interactive AP.")
    args = p.parse_args()
    ScannerAP(iface=args.iface, savepath=args.savepath).run(fix=args.fix)