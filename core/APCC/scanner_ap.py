import difflib
import ipaddress
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from core.APCC import confgen, netops, reslimit
from core.APCC import settings as settings_mod
from core.APCC.binpaths import get_bin, startup_module
from core.APCC.clients import ClientManager
from core.APCC.commands import CommandRouter
from core.APCC.deps import check_dependencies, check_root
from core.APCC.domain_control import DomainControl, RedirectServer
from core.APCC.domain_filter import DomainFilter
from core.APCC.logging_ap import LOG_CATEGORIES, APLogger
from core.APCC.termkeys import (
    BACKSPACE,
    CTRL_A,
    CTRL_E,
    CTRL_K,
    CTRL_L,
    CTRL_U,
    CTRL_W,
    DELETE,
    DOWN,
    END,
    HOME,
    LEFT,
    RIGHT,
    UP,
    TermKeys,
)


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



class ScannerAP:
    DEFAULT_UPSTREAM_DNS: ClassVar[list[str]] = ["1.1.1.1", "8.8.8.8"]

    def __init__(self, iface, savepath="./ap_sessions"):
        self.iface = iface
        self.save_dir = Path(savepath)
        self._log_lock = threading.RLock()
        self._prompt_active = False
        self._input_buf = []
        self._cursor = 0
        self._history = []
        self._display_shown = 0
        self.debug = self._log

        self.settings = None
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.gateway = None
        self.radio_on = False
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
        self._dnsmasq_log_thread = None
        self._ap_lock = threading.RLock()
        self._auto_reconnect_pending = False
        self._reconnect_in_progress = False
        self._reconnect_attempts = 0
        self._watchdog_thread = None

        self.router = self._build_commands()




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





    # Reliable public resolvers used as dnsmasq's upstream when the user hasn't
    # pinned one. dnsmasq runs on the AP host, so these queries egress the same
    # way the host's own DNS does — they work whenever the host has internet,
    # and (unlike the uplink gateway) are guaranteed to actually answer. Kept
    # portable: written into dnsmasq's own config, never read from host files.

    def _resolve_upstream_dns(self):
        configured = (self.settings.get("upstream_dns") or "").strip()
        if configured:
            return [p.strip() for p in configured.replace(";", ",").split(",")
                    if p.strip()]
        if self.bridge_enabled and self.settings.get("bridge_iface"):
            return list(self.DEFAULT_UPSTREAM_DNS)
        return []

    def _write_configs(self):
        corrected, warnings = settings_mod.validate_settings(self.settings)
        self.settings = corrected
        settings_mod.save_settings(self.save_dir, self.settings)
        for w in warnings:
            self.debug("warn", f"[settings] {w}")

        hostapd_conf = confgen.generate_hostapd_conf(self.settings, self.iface)
        gateway = self._gateway_for(self.settings["ip_range"])
        extra_lines = self.domain_control.generate_dnsmasq_lines(self.domain_filter, gateway)
        client_mtu = netops.resolve_client_mtu(
            self.settings.get("bridge_iface", ""), self.settings.get("mtu", 0))
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

    def _release_interface(self):
        # Make NetworkManager let go of the radio WITHOUT touching its config:
        # these are all runtime device operations that revert on 'radio off' /
        # quit (we hand managed back), so nothing persistent is changed.
        #   1. disconnect — tears down any active connection (e.g. it had
        #      already joined your home Wi-Fi), which 'managed no' alone does
        #      not do mid-session, so NM stops owning the link.
        #   2. managed no — NM then ignores the device entirely.
        #   3. kill any wpa_supplicant bound to this iface so nothing re-auths.
        if self._which("nmcli"):
            _run(["nmcli", "device", "disconnect", self.iface], timeout=8)
            _run(["nmcli", "device", "set", self.iface, "managed", "no"])
        try:
            _run(["pkill", "-f", f"wpa_supplicant.*{self.iface}"])
        except OSError as e:
            self.debug("warn", f"Could not kill wpa_supplicant for {self.iface}: {e}")

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
        except (AttributeError, IndexError, TypeError, ValueError) as e:
            self.debug("warn", f"Could not inspect phy layout: {e}")

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
        except (OSError, ValueError):
            out = ""
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
        except OSError:
            pass
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except (OSError, ValueError):
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
        self.radio_on = False
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





    def start_radio(self):
        with self._ap_lock:
            if self.radio_on:
                self.debug("info", "Radio already on.")
                return
            self._radio_up()
            self.debug("ok", f"Radio on — {self.iface} claimed "
                             "(released from other managers so only APCC uses it).")

    def stop_radio(self):
        with self._ap_lock:
            if not self.radio_on:
                self.debug("info", "Radio already off.")
                return
            if self.ap_running:
                self.debug("warn", "AP is running on this radio — 'ap off' first.")
                return
            self._radio_down()
            self.debug("ok", f"Radio off — {self.iface} released back to the system.")

    def _radio_up(self):
        """Claim the interface exclusively for APCC and bring the radio up:
        release it from NetworkManager/wpa_supplicant, reset it to a clean
        managed state, apply any MAC/tx-power overrides, and bind it up so
        nothing else can grab it out from under the AP."""
        if self.logger:
            self.logger.stop_sniff()

        self._release_interface()

        _run(["ip", "link", "set", self.iface, "down"])
        _run(["iw", "dev", self.iface, "set", "type", "managed"])

        self._warn_if_phy_conflict()

        # Regulatory domain (affects which channels / tx power are legal).
        cc = (self.settings.get("country_code") or "").strip().upper()
        if cc:
            _run(["iw", "reg", "set", cc])

        _run(["ip", "addr", "flush", "dev", self.iface])
        if self.settings.get("mac_addr"):
            res = _run(["ip", "link", "set", self.iface, "address",
                        self.settings["mac_addr"]])
            if res.returncode != 0:
                self.debug("warn", f"Could not set MAC override: {res.stderr.strip()}")
        _run(["ip", "link", "set", self.iface, "up"])

        # Power save off by default — a sleeping AP radio drops beacons/ACKs.
        ps = "on" if self.settings.get("power_save") else "off"
        _run(["iw", "dev", self.iface, "set", "power_save", ps])

        try:
            tx_mbm = int(self.settings.get("tx_power_dbm", 20)) * 100
            res = _run(["iw", "dev", self.iface, "set", "txpower", "fixed", str(tx_mbm)])
            if res.returncode != 0:
                self.debug("warn", f"Could not set tx power: {res.stderr.strip()}")
        except (ValueError, TypeError) as e:
            self.debug("warn", f"tx power set failed: {e}")

        self.radio_on = True

    def _radio_down(self):
        _run(["ip", "addr", "flush", "dev", self.iface])
        if self._which("nmcli"):
            _run(["nmcli", "device", "set", self.iface, "managed", "yes"])
        self.radio_on = False

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

        # Stage 1 - radio: claim the interface and bring it up. Already done if
        # the user ran 'radio on' first; otherwise 'ap on' brings it up itself.
        if not self.radio_on:
            self._radio_up()

        # Stage 2 - addressing + DHCP (only when DHCP is enabled).
        if self.dhcp_enabled:
            _run(["ip", "addr", "add", f"{gateway}/{prefix}", "dev", self.iface])
            if not self._start_dnsmasq(dnsmasq_path, kr=kr):
                self._cleanup_failed_start(gateway, prefix)
                self.dhcp_enabled = False

        # Stage 3 - access point: start broadcasting.
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
                              self.settings["ip_range"], self.debug,
                              gateway_override=self.settings.get("bridge_gateway"),
                              configured_mtu=self.settings.get("mtu", 0))
        else:




            netops.isolate_ap_iface(self.iface, self.debug)









        self._reapply_client_timeouts()
        self.client_mgr.reapply_blocks()

        reslimit.apply_profile(self.settings.get("resource_profile", "normal"),
                                self.iface, self.debug)

        self.ap_running = True
        if self.logger:
            self.logger.start_sniff()

        self.debug("ok", f"AP '{self.settings['ssid']}' started on {self.iface}.")

    # The useful hostapd events are: the AP coming up/down, a client joining
    # or leaving, and anything that went wrong. The intermediate per-join
    # trace (IEEE 802.11 authenticated/associated, WPA handshake steps,
    # RADIUS accounting) is dropped so a single connect is one line, not six.
    _HOSTAPD_KEEP = ("ap-enabled", "ap-disabled", "ap-sta-connected",
                     "ap-sta-disconnected", "deauthenticated", "disassociated",
                     "fail", "error", "warn", "denied", "reject", "invalid",
                     "dfs", "radar", "unable")

    def _drain_hostapd_log(self):
        proc = self.hostapd_proc
        if not proc or not proc.stdout:
            return
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line and any(k in line.lower() for k in self._HOSTAPD_KEEP):
                    self.debug("info", f"hostapd: {line}")
        except (OSError, ValueError) as e:
            self.debug("warn", f"hostapd log drain ended: {e}")

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
            except (OSError, subprocess.TimeoutExpired):
                self.hostapd_proc.kill()
            self.hostapd_proc = None
        if self.bridge_enabled:
            netops.teardown_nat(self.iface, self.settings["bridge_iface"],
                                 self.settings["ip_range"], self.debug)
        netops.deisolate_ap_iface(self.iface, self.debug, quiet=True)



        _run(["ip", "addr", "flush", "dev", self.iface])
        reslimit.remove_limits(self.iface, self.debug)
        self.ap_running = False
        # The radio stays claimed so 'ap on' can bring it straight back up;
        # 'radio off' (or shutdown) hands the interface back to the system.
        self.debug("ok", "AP stopped (radio still on).")

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
        self._dnsmasq_log_thread = threading.Thread(
            target=self._drain_dnsmasq_log, args=(self.dnsmasq_proc,), daemon=True)
        self._dnsmasq_log_thread.start()
        return True

    # Keep only the lines worth reading: the one-line result of each DHCP
    # handshake (DISCOVER/OFFER/REQUEST/ACK/NAK...), the upstream dnsmasq
    # chose, and real errors. Everything else dnsmasq emits per lease — the
    # "sent size: ... option NN", "requested options:", "available DHCP
    # range", "next server", "tags:" and per-query A/AAAA trace — is dropped
    # so one client joining doesn't scroll 30 lines off the screen.
    _DNSMASQ_KEEP = ("dhcpdiscover", "dhcpoffer", "dhcprequest", "dhcpack",
                     "dhcpnak", "dhcpdecline", "dhcprelease", "dhcpinform",
                     "no servers", "using nameserver", "using server",
                     "failed", "error", "refused", "cannot", "warning",
                     "bad address", "started, version")

    def _drain_dnsmasq_log(self, proc):
        if not proc or not proc.stdout:
            return
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line and any(k in line.lower() for k in self._DNSMASQ_KEEP):
                    self.debug("info", f"dnsmasq: {line}")
        except (OSError, ValueError) as e:
            self.debug("warn", f"dnsmasq log drain ended: {e}")

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
        except (OSError, ValueError) as e:
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
            except (OSError, ValueError) as e:
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
                except (OSError, ValueError) as e:
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
        except (OSError, ValueError) as e:
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
        except (OSError, ValueError) as e:
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
            except (OSError, subprocess.TimeoutExpired):
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





    def _build_commands(self):
        r = CommandRouter()
        r.register("help", self._cmd_help, "List commands, or 'help <cmd>' for one.",
                   usage="help [command]", aliases=("?",))
        r.register("status", self._cmd_status, "Show current AP/DHCP/bridge state.")
        r.register("quit", self._cmd_quit, "Stop everything and exit.",
                   aliases=("exit", "x"))
        r.register("radio", self._cmd_radio,
                   "Claim the interface and power the radio on/off.",
                   usage="radio [on|off]")
        r.register("ap", self._cmd_ap, "Start/stop the access point.",
                   usage="ap [on|off]")
        r.register("dhcp", self._cmd_dhcp, "Enable/disable the DHCP+DNS server.",
                   usage="dhcp [on|off]")
        r.register("bridge", self._cmd_bridge,
                   "Share internet via an uplink (NAT), or turn it off.",
                   usage="bridge on [iface] [gateway] | bridge off")
        r.register("record", self._cmd_record, "Start/stop packet recording.",
                   usage="record [on|off]")
        r.register("display", self._cmd_display, "Toggle the live log display.",
                   usage="display [on|off]", aliases=("logdisplay",))
        r.register("clear", self._cmd_clear, "Clear the log display.")
        r.register("fix", self._cmd_fix, "Re-apply NAT/firewall rules.")
        r.register("diag", self._cmd_diag,
                   "Diagnose the bridge/NAT path (forwarding, firewall, uplink).")
        # settings
        r.register("show", self._cmd_show, "Show settings (optionally filtered).",
                   usage="show [key]")
        r.register("get", self._cmd_get, "Print one setting's value.", usage="get <key>")
        r.register("set", self._cmd_set, "Change a setting.", usage="set <key> <value>")
        # clients
        r.register("clients", self._cmd_clients, "List connected clients.")
        r.register("client", self._cmd_client, "Act on a client.",
                   usage="client <mac|idx> <deauth|log|ip|timeout> [on|off|addr]")
        # domain control
        r.register("block", self._cmd_block, "Block a domain (DNS sinkhole).",
                   usage="block <domain>")
        r.register("unblock", self._cmd_unblock, "Remove a block or redirect.",
                   usage="unblock <domain>")
        r.register("redirect", self._cmd_redirect, "Redirect a domain to a URL.",
                   usage="redirect <domain> <url>")
        r.register("blockfile", self._cmd_blockfile, "Enable/disable a block-list file.",
                   usage="blockfile <name> [on|off]")
        r.register("domains", self._cmd_domains, "Show domain block/redirect state.")
        # log filters
        r.register("filter", self._cmd_filter, "Log filters: categories, files, toggles.",
                   usage="filter [cat|file|fulladdr|showdevice|reload] ...",
                   aliases=("filters",))
        return r

    @staticmethod
    def _onoff(args, current):
        """Resolve on/off/toggle from command args to a bool target state."""
        if not args:
            return not current
        a = args[0].lower()
        if a in ("on", "1", "true", "yes", "enable", "enabled"):
            return True
        if a in ("off", "0", "false", "no", "disable", "disabled"):
            return False
        raise ValueError(f"expected on/off, got '{args[0]}'")

    # Help is grouped by what each command is for, not alphabetically, so the
    # natural bring-up order (radio -> ap -> dhcp -> bridge) reads top-to-bottom.
    _HELP_GROUPS = (
        ("Access point", ("radio", "ap", "dhcp", "bridge", "fix", "diag")),
        ("Clients", ("clients", "client")),
        ("Domains", ("block", "unblock", "redirect", "blockfile", "domains")),
        ("Traffic & logging", ("record", "display", "filter", "clear")),
        ("Settings", ("show", "get", "set")),
        ("Session", ("status", "help", "quit")),
    )

    def _cmd_help(self, args, kr):
        if args:
            cmd, err = self.router.resolve(args[0])
            if err:
                print(err)
            else:
                usage = cmd.usage or cmd.name
                aka = f"   (aliases: {', '.join(cmd.aliases)})" if cmd.aliases else ""
                print(f"{usage}\n    {cmd.help}{aka}")
            return

        print("Commands (prefixes work, e.g. 'br on eth0'):")
        shown = set()
        for title, names in self._HELP_GROUPS:
            print(f"\n  {title}:")
            for name in names:
                cmd, _err = self.router.resolve(name)
                if not cmd:
                    continue
                shown.add(cmd.name)
                print(f"    {cmd.usage or cmd.name:<34} {cmd.help}")
        # Anything not placed in a group above still gets listed, so a newly
        # registered command never silently vanishes from help.
        leftover = [c for c in self.router.commands() if c.name not in shown]
        if leftover:
            print("\n  Other:")
            for cmd in leftover:
                print(f"    {cmd.usage or cmd.name:<34} {cmd.help}")

    def _cmd_status(self, args, kr):
        for line in self._status_lines():
            print(line)

    def _cmd_quit(self, args, kr):
        self.running = False

    def _setting_keys(self):
        return [f[0] for f in settings_mod.FIELDS]

    def _resolve_setting_key(self, token):
        token = token.lower()
        keys = self._setting_keys()
        if token in keys:
            return token
        matches = [k for k in keys if k.startswith(token)]
        return matches[0] if len(matches) == 1 else None

    def _unknown_key_msg(self, token):
        guess = difflib.get_close_matches(
            token.lower(), self._setting_keys(), n=3, cutoff=0.5)
        if guess:
            return f"unknown setting: {token} — did you mean: {', '.join(guess)}?"
        return f"unknown setting: {token} (try 'show' to list keys)"

    def _cmd_show(self, args, kr):
        flt = args[0].lower() if args else None
        for key, label, kind, options, _grayed in settings_mod.FIELDS:
            if flt and flt not in key.lower() and flt not in label.lower():
                continue
            val = self.settings.get(key, "")
            hint = ""
            if kind == "choice":
                hint = f"  {{{'|'.join(options)}}}"
            elif kind == "bool":
                hint = "  {on|off}"
            print(f"  {key:<16} = {val!s:<18} {label}{hint}")

    def _cmd_get(self, args, kr):
        if not args:
            print("usage: get <key>")
            return
        key = self._resolve_setting_key(args[0])
        if not key:
            print(self._unknown_key_msg(args[0]))
            return
        print(f"{key} = {self.settings.get(key)}")

    def _cmd_set(self, args, kr):
        if len(args) < 2:
            print("usage: set <key> <value>   (try 'show' to list keys)")
            return
        key = self._resolve_setting_key(args[0])
        if not key:
            print(self._unknown_key_msg(args[0]))
            return
        _k, _label, kind, options, _grayed = next(
            f for f in settings_mod.FIELDS if f[0] == key)
        raw = " ".join(args[1:]).strip()
        if kind == "bool":
            value = raw.lower() in ("on", "1", "true", "yes", "enable", "enabled")
        elif kind == "int":
            try:
                value = int(raw)
            except ValueError:
                print(f"{key} expects an integer")
                return
        elif kind == "choice":
            if raw not in options:
                print(f"{key} must be one of: {', '.join(options)}")
                return
            value = raw
        else:
            value = raw
        self.settings[key] = value
        corrected, warnings = settings_mod.validate_settings(self.settings)
        self.settings = corrected
        settings_mod.save_settings(self.save_dir, self.settings)
        print(f"{key} = {self.settings.get(key)}")
        for w in warnings:
            print(f"  (adjusted) {w}")
        print("  note: radio/DHCP settings take effect on the next 'ap off' / 'ap on'.")

    def _cmd_radio(self, args, kr):
        target = self._onoff(args, self.radio_on)
        if target:
            self.start_radio()
        else:
            self.stop_radio()

    def _cmd_ap(self, args, kr):
        target = self._onoff(args, self.ap_running)
        if target and not self.ap_running:
            self.start_ap(kr=kr)
        elif not target and self.ap_running:
            self.stop_ap()
        else:
            self.debug("info", f"AP already {'on' if target else 'off'}.")

    def _cmd_dhcp(self, args, kr):
        self._set_dhcp(self._onoff(args, self.dhcp_enabled), kr)

    def _cmd_bridge(self, args, kr):
        on = self._onoff(args, self.bridge_enabled)
        iface_arg = args[1] if on and len(args) > 1 else None
        gw_arg = args[2] if on and len(args) > 2 else None
        self._set_bridge(on, kr, iface_arg, gw_arg)

    def _cmd_record(self, args, kr):
        target = self._onoff(args, self.logger.recording)
        if target and not self.logger.recording:
            self.logger.start_recording()
            self.debug("info", f"Recording -> {self.session_dir}")
        elif not target and self.logger.recording:
            self.logger.stop_recording()
            self.debug("info", "Recording stopped.")
        else:
            self.debug("info", f"Recording already {'on' if target else 'off'}.")

    def _cmd_clients(self, args, kr):
        clients = self.client_mgr.list_clients()
        if not clients:
            print("  No clients connected.")
            return
        for i, c in enumerate(clients):
            state = "logging" if not c["filtered"] else "filtered"
            if self.client_mgr.is_blocked(c["mac"]):
                state += ", blocked"
            print(f"  [{i}] {c['name']:<20} {c['mac']}  ip={c['ip']:<15} ({state})")

    def _resolve_client(self, token):
        clients = self.client_mgr.list_clients()
        if token.isdigit():
            i = int(token)
            if 0 <= i < len(clients):
                return clients[i]["mac"].lower()
            return None
        tok = token.lower()
        if ":" in tok:
            return tok
        for c in clients:
            if c["mac"].lower().startswith(tok) or c["name"].lower().startswith(tok):
                return c["mac"].lower()
        return None

    _CLIENT_ACTIONS = ("deauth", "block", "log", "ip", "timeout")

    def _cmd_client(self, args, kr):
        if len(args) < 2:
            print("usage: client <mac|idx> <deauth | block [on|off] | "
                  "log [on|off] | ip <addr> | timeout [on|off]>")
            return
        mac = self._resolve_client(args[0])
        if not mac:
            print(f"no such client: {args[0]} (use 'clients' to list)")
            return
        action = args[1].lower()
        if action == "deauth":
            ok = self.client_mgr.deauth(mac)
            self.debug("ok" if ok else "error",
                       f"Deauth {mac}: {'kicked' if ok else 'failed'}"
                       + (" (one-shot — it will reconnect; use "
                          "'client <mac> block on' to keep it off)" if ok else ""))
        elif action == "block":
            on = self._onoff(args[2:], not self.client_mgr.is_blocked(mac))
            if on:
                ok = self.client_mgr.block(mac)
                self.debug("ok" if ok else "warn",
                           f"{mac} blocked — kicked and denied on reassociation"
                           + ("" if ok else " (deny-ACL push failed; is the AP up?)"))
            else:
                ok = self.client_mgr.unblock(mac)
                self.debug("ok" if ok else "warn",
                           f"{mac} unblocked — may reconnect again"
                           + ("" if ok else " (deny-ACL removal failed; is the AP up?)"))
        elif action == "log":
            on = self._onoff(args[2:], not self.client_mgr.is_filtered(mac))
            self.client_mgr.filtered[mac] = not on
            self.debug("info", f"{mac} Log Device -> {'ON' if on else 'OFF'}")
        elif action == "ip":
            if len(args) < 3:
                print("usage: client <mac|idx> ip <addr>")
                return
            self.client_mgr.set_static_ip(mac, args[2])
            self.debug("info", f"{mac} -> static IP {args[2]} "
                               "(falls back to DHCP automatically if unavailable)")
        elif action == "timeout":
            currently = mac in {m.lower() for m in self.domain_control.timeout_macs}
            on = self._onoff(args[2:], not currently)
            self.domain_control.set_timeout(mac, on)
            if self.ap_running:
                netops.set_client_timeout(self.iface, mac, on, self.debug)
            self.debug("info", f"{mac} timeout -> {'ON' if on else 'OFF'}")
        else:
            guess = difflib.get_close_matches(action, self._CLIENT_ACTIONS, n=1)
            hint = f" — did you mean '{guess[0]}'?" if guess else ""
            print(f"unknown client action: {action}{hint} "
                  f"({' | '.join(self._CLIENT_ACTIONS)})")

    def _cmd_display(self, args, kr):
        self.logger.display_on = self._onoff(args, self.logger.display_on)
        self.debug("info", f"Live log display -> {'ON' if self.logger.display_on else 'OFF'}")

    def _cmd_filter(self, args, kr):
        if not args:
            print("categories:")
            for c in LOG_CATEGORIES:
                box = "x" if c in self.logger.enabled_categories else " "
                print(f"  [{box}] {c}")
            print(f"fulladdr = {self.logger.full_address}   "
                  f"showdevice = {self.logger.show_device}")
            print("filter files:")
            files = self.domain_filter.describe_files()
            if not files:
                print(f"  (none in {self.domain_filter.directory})")
            for fname, enabled, count, errc in files:
                box = "x" if enabled else " "
                extra = f", {errc} errors" if errc else ""
                print(f"  [{box}] {fname} ({count} patterns{extra})")
            return
        sub = args[0].lower()
        if sub == "cat":
            if len(args) < 2:
                print("usage: filter cat <name> [on|off]")
                return
            name = args[1].lower()
            if name not in LOG_CATEGORIES:
                print(f"unknown category: {name} ({', '.join(LOG_CATEGORIES)})")
                return
            on = self._onoff(args[2:], name not in self.logger.enabled_categories)
            if on:
                self.logger.enabled_categories.add(name)
            else:
                self.logger.enabled_categories.discard(name)
            self.debug("info", f"log category {name} -> {'on' if on else 'off'}")
        elif sub in ("fulladdr", "full_address"):
            self.logger.full_address = self._onoff(args[1:], self.logger.full_address)
            self.debug("info", f"fulladdr -> {self.logger.full_address}")
        elif sub in ("showdevice", "show_device"):
            self.logger.show_device = self._onoff(args[1:], self.logger.show_device)
            self.debug("info", f"showdevice -> {self.logger.show_device}")
        elif sub == "file":
            if len(args) < 2:
                print("usage: filter file <name> [on|off]")
                return
            fname = args[1]
            files = {f[0]: f[1] for f in self.domain_filter.describe_files()}
            if fname not in files:
                print(f"unknown filter file: {fname}")
                return
            on = self._onoff(args[2:], not files[fname])
            self.domain_filter.set_file_enabled(fname, on)
            self.debug("info", f"filter file {fname} -> {'on' if on else 'off'}")
        elif sub == "reload":
            self.domain_filter.load()
            self.debug("ok", "filter files reloaded")
        else:
            print(f"unknown filter subcommand: {sub} "
                  "(cat | file | fulladdr | showdevice | reload)")

    def _apply_domain_change(self, kr):
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
                self.debug("warn", "DHCP -> OFF (dnsmasq failed to restart after the "
                                    "domain change — see the error above)")

    def _cmd_block(self, args, kr):
        if not args:
            print("usage: block <domain>")
            return
        status, extra = self.domain_control.add_block(args[0])
        if status == "conflict":
            print(f"{args[0]} is currently a redirect to {extra}; 'unblock' it first")
            return
        self.debug("ok", f"Blocking {args[0]}")
        self._apply_domain_change(kr)

    def _cmd_unblock(self, args, kr):
        if not args:
            print("usage: unblock <domain>")
            return
        result = self.domain_control.reset(args[0])
        if result == "ok":
            self.debug("ok", f"Removed {args[0]}")
            self._apply_domain_change(kr)
        else:
            print(f"{args[0]}: not currently blocked or redirected")

    def _cmd_redirect(self, args, kr):
        if len(args) < 2:
            print("usage: redirect <domain> <target-url>")
            return
        status, _extra = self.domain_control.add_redirect(args[0], args[1])
        if status == "conflict":
            print(f"{args[0]} is currently blocked; 'unblock' it first")
            return
        self.debug("ok", f"Redirecting {args[0]} -> {args[1]}")
        self._apply_domain_change(kr)

    def _cmd_blockfile(self, args, kr):
        if not args:
            print("usage: blockfile <name> [on|off]   (names from 'domains')")
            return
        fname = args[0]
        on = self._onoff(args[1:], fname not in self.domain_control.block_files)
        self.domain_control.set_block_file_enabled(fname, on)
        self.debug("info", f"block file {fname} -> {'on' if on else 'off'}")
        self._apply_domain_change(kr)

    def _cmd_domains(self, args, kr):
        print(self.domain_control.summary(self.domain_filter))

    def _cmd_clear(self, args, kr):
        self.logger.clear_display()
        self._display_shown = 0
        print("\033[2J\033[H", end="")

    def _cmd_fix(self, args, kr):
        bridge_iface = self.settings["bridge_iface"] if self.bridge_enabled else ""
        netops.fix_rules(self.iface, bridge_iface,
                          self.settings["ip_range"], self.debug,
                          gateway_override=self.settings.get("bridge_gateway"))
        self._reapply_client_timeouts()

    def _cmd_diag(self, args, kr):
        bridge_iface = self.settings["bridge_iface"] if self.bridge_enabled else ""
        netops.diagnose(self.iface, bridge_iface, self.settings["ip_range"],
                        self.debug, gateway=self.settings.get("bridge_gateway"))
        clients = self.client_mgr.list_clients()
        with_ip = [c for c in clients if c["ip"] not in ("?", "", None)]
        self.debug("info" if with_ip else "warn",
                   f"clients: {len(clients)} associated, {len(with_ip)} with a DHCP lease"
                   + ("" if with_ip else " — if a client is connected but has NO lease, "
                      "DHCP isn't completing (watch for 'dnsmasq: ...DHCP...' lines)."))
        for c in clients:
            self.debug("info", f"  {c['name']} {c['mac']} ip={c['ip']}")

    def _set_dhcp(self, on, kr):
        if not on:
            if not self.dhcp_enabled:
                self.debug("info", "DHCP already off.")
                return
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
            except OSError as e:
                self.debug("warn", f"Could not clear lease file: {e}")
            self.debug("info", f"DHCP -> OFF{removed_note}")
            return

        if self.dhcp_enabled:
            self.debug("info", "DHCP already on.")
            return
        if not self.ap_running:
            self.dhcp_enabled = True
            self.debug("info",
                       "DHCP -> ON (will start once the AP is running; "
                       f"range {self.settings['dhcp_start']}-"
                       f"{self.settings['dhcp_end']}, "
                       f"lease {self.settings['dhcp_lease_time']})")
            return

        network = self.settings["ip_range"]
        prefix = network.split("/")[-1]
        gateway = str(next(iter(ipaddress.ip_network(network, strict=False).hosts())))
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

    def _set_bridge(self, on, kr, iface_arg=None, gw_arg=None):
        if on:
            iface_in = (iface_arg or kr.prompt_line(
                "  Bridge/uplink interface to share internet from "
                "(e.g. eth0, wlan0): ")).strip()
            if not iface_in:
                self.debug("info", "No bridge interface given — bridge mode not enabled.")
                self.bridge_enabled = False
                return
            self.settings["bridge_iface"] = iface_in
            if gw_arg:
                self.settings["bridge_gateway"] = gw_arg
                self.debug("debug", f"Using manual gateway {gw_arg} for {iface_in}.")
            else:
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
            self.bridge_enabled = True
        else:
            self.bridge_enabled = False

        settings_mod.save_settings(self.save_dir, self.settings)
        self.debug("info", f"Bridge/NAT mode -> {'ON' if self.bridge_enabled else 'OFF'}"
                            f"{' (' + self.settings['bridge_iface'] + ')' if self.bridge_enabled else ''}")
        if self.ap_running:
            if self.bridge_enabled:
                netops.setup_nat(self.iface, self.settings["bridge_iface"],
                                  self.settings["ip_range"], self.debug,
                                  gateway_override=self.settings.get("bridge_gateway"),
                                  configured_mtu=self.settings.get("mtu", 0))
                # dnsmasq may have started before the uplink existed and locked
                # onto the host resolver (127.0.0.53); regenerate its config so
                # upstream DNS now points at the uplink, and restart it.
                if self.dhcp_enabled:
                    self._apply_domain_change(kr)
            else:
                netops.teardown_nat(self.iface, self.settings["bridge_iface"],
                                     self.settings["ip_range"], self.debug)
                netops.isolate_ap_iface(self.iface, self.debug)
            self._reapply_client_timeouts()

    def _safe_run(self, cmd, args, kr):
        try:
            cmd.fn(args, kr)
        except Exception as e:  # noqa: BLE001 — command dispatch must not kill the REPL
            self.debug("error", f"{cmd.name} failed: {e}")

    def _prompt_text(self):
        return "APCC> "

    def _render_line(self):
        """Repaint the current input line and place the cursor. One full
        redraw per edit keeps cursor math trivial and handles log lines that
        scroll in above the prompt."""
        buf = "".join(self._input_buf)
        out = "\r\033[2K" + self._prompt_text() + buf
        tail = len(self._input_buf) - self._cursor
        if tail > 0:
            out += f"\033[{tail}D"
        sys.stdout.write(out)
        sys.stdout.flush()

    def _read_line(self, kr):
        """Read one command line with readline-style editing: left/right and
        Home/End move the cursor, up/down walk history, Backspace/Delete edit
        in place, Tab completes, and Ctrl-A/E/U/K/W/L behave as in a shell.
        The prompt is redrawn whenever a background log line arrives, so
        output scrolls above a live prompt."""
        with self._log_lock:
            self._input_buf = []
            self._cursor = 0
            self._prompt_active = True
            sys.stdout.write(self._prompt_text())
            sys.stdout.flush()
        hist_pos = len(self._history)   # len == "editing a fresh line"
        stash = ""                      # the fresh line, parked while browsing
        try:
            while self.running:
                ch = kr.getch(timeout=0.3)
                if ch is None:
                    continue
                with self._log_lock:
                    if ch in ("\r", "\n"):
                        line = "".join(self._input_buf)
                        sys.stdout.write("\n")
                        sys.stdout.flush()
                        self._prompt_active = False
                        if line.strip() and (not self._history or self._history[-1] != line):
                            self._history.append(line)
                        return line
                    hist_pos, stash = self._handle_edit_key(ch, hist_pos, stash)
        except KeyboardInterrupt:
            with self._log_lock:
                sys.stdout.write("^C\n")
                sys.stdout.flush()
                self._input_buf = []
                self._cursor = 0
                self._prompt_active = False
            return None
        with self._log_lock:
            self._prompt_active = False
        return None

    def _handle_edit_key(self, ch, hist_pos, stash):
        """Apply one editing keystroke to the input buffer. Returns the
        (possibly updated) history cursor and parked fresh-line stash."""
        buf = self._input_buf
        if ch == BACKSPACE:
            if self._cursor > 0:
                del buf[self._cursor - 1]
                self._cursor -= 1
                self._render_line()
        elif ch == DELETE:
            if self._cursor < len(buf):
                del buf[self._cursor]
                self._render_line()
        elif ch == LEFT:
            if self._cursor > 0:
                self._cursor -= 1
                self._render_line()
        elif ch == RIGHT:
            if self._cursor < len(buf):
                self._cursor += 1
                self._render_line()
        elif ch in (HOME, CTRL_A):
            self._cursor = 0
            self._render_line()
        elif ch in (END, CTRL_E):
            self._cursor = len(buf)
            self._render_line()
        elif ch == CTRL_U:                       # clear to start of line
            del buf[:self._cursor]
            self._cursor = 0
            self._render_line()
        elif ch == CTRL_K:                       # clear to end of line
            del buf[self._cursor:]
            self._render_line()
        elif ch == CTRL_W:                       # delete previous word
            i = self._cursor
            while i > 0 and buf[i - 1] == " ":
                i -= 1
            while i > 0 and buf[i - 1] != " ":
                i -= 1
            del buf[i:self._cursor]
            self._cursor = i
            self._render_line()
        elif ch == CTRL_L:                       # clear screen, keep the line
            sys.stdout.write("\033[2J\033[H")
            self._render_line()
        elif ch in (UP, DOWN):
            hist_pos, stash = self._history_step(ch, hist_pos, stash)
        elif ch == "\t":
            self._complete_buffer()
        elif isinstance(ch, str) and len(ch) == 1 and ch.isprintable():
            buf.insert(self._cursor, ch)
            self._cursor += 1
            self._render_line()
        # ESC and anything else: ignored
        return hist_pos, stash

    def _history_step(self, direction, hist_pos, stash):
        if not self._history:
            return hist_pos, stash
        if direction == UP:
            if hist_pos == len(self._history):
                stash = "".join(self._input_buf)
            if hist_pos > 0:
                hist_pos -= 1
                self._set_buffer(self._history[hist_pos])
        else:  # DOWN
            if hist_pos < len(self._history):
                hist_pos += 1
                text = stash if hist_pos == len(self._history) else self._history[hist_pos]
                self._set_buffer(text)
        return hist_pos, stash

    def _set_buffer(self, text):
        self._input_buf = list(text)
        self._cursor = len(self._input_buf)
        self._render_line()

    def _complete_buffer(self):
        """Tab completion, terminal-style: complete to the longest common
        prefix, or print the candidate list when the choice is ambiguous.
        Completion operates at the end of the line; the cursor jumps there."""
        self._cursor = len(self._input_buf)
        buf = "".join(self._input_buf)
        prefix, cands = self._completion_candidates(buf)
        if not cands:
            return
        if len(cands) == 1:
            completion = cands[0][len(prefix):] + " "
        else:
            common = os.path.commonprefix(cands)
            completion = common[len(prefix):]
        if completion:
            self._input_buf.extend(completion)
            self._cursor = len(self._input_buf)
            self._render_line()
        elif len(cands) > 1:
            sys.stdout.write("\n  " + "   ".join(cands) + "\n")
            self._render_line()

    def _completion_candidates(self, buf):
        trailing_space = buf.endswith(" ")
        tokens = buf.split()
        if not tokens or (len(tokens) == 1 and not trailing_space):
            prefix = tokens[0] if tokens else ""
            names = []
            for c in self.router.commands():
                names.append(c.name)
                names.extend(c.aliases)
            return prefix, sorted(n for n in set(names) if n.startswith(prefix))
        cmd, _err = self.router.resolve(tokens[0])
        if cmd is None:
            return "", []
        args = tokens[1:]
        prefix = "" if trailing_space else tokens[-1]
        pos = len(args) if trailing_space else len(args) - 1
        cands = self._arg_candidates(cmd.name, args, pos)
        return prefix, sorted(c for c in cands if c.startswith(prefix))

    def _arg_candidates(self, name, args, pos):
        onoff = ["off", "on"]
        if name in ("radio", "ap", "dhcp", "record", "display", "bridge"):
            return onoff if pos == 0 else []
        if name == "help":
            return [c.name for c in self.router.commands()] if pos == 0 else []
        if name == "show":
            return self._setting_keys() if pos == 0 else []
        if name in ("get", "set"):
            if pos == 0:
                return self._setting_keys()
            if name == "set" and pos == 1 and args:
                key = self._resolve_setting_key(args[0])
                if key:
                    _k, _l, kind, options, _g = next(
                        f for f in settings_mod.FIELDS if f[0] == key)
                    if kind == "choice":
                        return list(options)
                    if kind == "bool":
                        return onoff
            return []
        if name == "client":
            if pos == 0:
                return [c["mac"] for c in self.client_mgr.list_clients()]
            if pos == 1:
                return ["block", "deauth", "ip", "log", "timeout"]
            if pos == 2 and len(args) >= 2 and args[1].lower() in ("log", "timeout", "block"):
                return onoff
            return []
        if name == "filter":
            if pos == 0:
                return ["cat", "file", "fulladdr", "reload", "showdevice"]
            sub = args[0].lower() if args else ""
            if sub == "cat":
                return list(LOG_CATEGORIES) if pos == 1 else (onoff if pos == 2 else [])
            if sub == "file":
                if pos == 1:
                    return [f[0] for f in self.domain_filter.describe_files()]
                return onoff if pos == 2 else []
            if sub in ("fulladdr", "showdevice") and pos == 1:
                return onoff
            return []
        if name == "blockfile":
            if pos == 0:
                return [f[0] for f in self.domain_filter.describe_files()]
            return onoff if pos == 1 else []
        if name == "unblock" and pos == 0:
            return sorted(set(self.domain_control.blocked)
                          | set(self.domain_control.redirects))
        return []

    def _run_command_line(self, line, kr):
        cmd, args = self.router.parse(line)
        if cmd is None:
            if isinstance(args, str):
                print(args)
            return
        self._safe_run(cmd, args, kr)

    def _status_lines(self):
        br = ""
        if self.bridge_enabled and self.settings.get("bridge_iface"):
            br = f" ({self.settings['bridge_iface']})"
        return [
            "--- APCC ---",
            f"iface={self.iface}  ssid={self.settings['ssid']}",
            (f"radio={self.radio_on}  ap={self.ap_running}  dhcp={self.dhcp_enabled}  "
            f"bridge={self.bridge_enabled}{br}  recording={self.logger.recording}"),
        ]





    def _emit_line(self, line):
        with self._log_lock:
            if self._prompt_active and sys.stdout.isatty():
                # Erase the prompt, print the log line, then redraw the prompt
                # with whatever the user has typed so far (and their cursor
                # position) — shell-style "output scrolls above a live prompt".
                sys.stdout.write("\r\033[2K" + line + "\n")
                self._render_line()
            else:
                print(line)

    _LEVEL_STYLE: ClassVar[dict[str, tuple[str, str]]] = {

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

        # Prefer the Textual control-panel UI; fall back to the classic
        # raw-terminal REPL if Textual isn't available or APCC_CLASSIC=1.
        if os.environ.get("APCC_CLASSIC") != "1" and sys.stdout.isatty():
            try:
                from core.APCC.tui import run_tui
            except (ImportError, RuntimeError) as e:
                self.debug("warn", f"Textual UI unavailable ({e}); "
                                   "falling back to the classic console.")
            else:
                run_tui(self)
                return

        self._run_classic()

    def _run_classic(self):
        self.running = True

        stop_event = threading.Event()
        display_thread = threading.Thread(target=self._display_loop,
                                           args=(stop_event,), daemon=True)
        display_thread.start()

        watchdog_thread = threading.Thread(target=self._watchdog_loop,
                                            args=(stop_event,), daemon=True)
        watchdog_thread.start()

        print(f"APCC on {self.iface}.  Bring it up in order:  "
              "radio on  ->  ap on  ->  dhcp on  ->  bridge on")
        print("'help' lists commands, Tab completes, Up/Down recall history, "
              "'status' shows state, 'quit' exits.")
        try:
            with TermKeys() as kr:
                while self.running:
                    line = self._read_line(kr)
                    if line is None:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    self._run_command_line(line, kr)
        except KeyboardInterrupt:
            pass
        finally:
            stop_event.set()
            if display_thread.is_alive():
                display_thread.join(timeout=1)
            if watchdog_thread.is_alive():
                watchdog_thread.join(timeout=1)
            self.shutdown()

    def shutdown(self):
        print("\n[*] Shutting down APCC...")
        if self.logger:
            self.logger.stop_recording()
            self.logger.stop_sniff()
        self.stop_ap()
        if self.radio_on:
            self.stop_radio()
        netops.restore_state(self.save_dir, self.debug, iface=self.iface)



        try:
            Path(self.lease_file).unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            self.debug("warn", f"Could not clear lease file: {e}")
        self.client_mgr.filtered.clear()
        self.client_mgr.static_ips.clear()
        self.client_mgr.blocked_macs.clear()

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
                            self.settings["ip_range"], self.debug,
                            gateway_override=self.settings.get("bridge_gateway"))
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