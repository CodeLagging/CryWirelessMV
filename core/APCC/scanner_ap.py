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

from core.APCC import netops, reslimit
from core.APCC import settings as settings_mod
from core.APCC.ap_cmd_handlers import APCommandHandlersMixin
from core.APCC.ap_state import APStateManager
from core.APCC.binpaths import get_bin, startup_module
from core.APCC.clients import ClientManager
from core.APCC.commands import CommandRouter
from core.APCC.deps import check_dependencies, check_root
from core.APCC.domain_control import DomainControl, RedirectServer
from core.APCC.domain_filter import DomainFilter
from core.APCC.line_editor import LineEditorMixin
from core.APCC.logging_ap import APLogger
from core.APCC.termkeys import TermKeys
from core.log_config import log_at
from core.validators import validate_iface


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

class ScannerAP(LineEditorMixin, APCommandHandlersMixin):
    def __init__(self, iface, savepath="./ap_sessions"):
        self.iface = validate_iface(iface) # Validate on entry
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
        self.client_mgr = ClientManager(self.iface, self.lease_file)
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
        self.state_mgr = None # Initialized in _startup

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
        
        self.state_mgr = APStateManager(self.iface, self.save_dir, self.settings, self.logger)

    def _write_configs(self):
        # Delegate to state manager
        return self.state_mgr.write_configs(self.domain_control, self.domain_filter)

    def _release_interface(self):
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
        if self.logger:
            self.logger.stop_sniff()

        self._release_interface()

        _run(["ip", "link", "set", self.iface, "down"])
        _run(["iw", "dev", self.iface, "set", "type", "managed"])

        self._warn_if_phy_conflict()

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

        if not self.radio_on:
            self._radio_up()

        if self.dhcp_enabled:
            _run(["ip", "addr", "add", f"{gateway}/{prefix}", "dev", self.iface])
            self.dnsmasq_proc = self.state_mgr.start_dnsmasq(dnsmasq_path, self.client_mgr, kr=kr)
            if not self.dnsmasq_proc:
                self._cleanup_failed_start(gateway, prefix)
                self.dhcp_enabled = False

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
        self.debug("ok", "AP stopped (radio still on).")

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
        r.register("show", self._cmd_show, "Show settings (optionally filtered).",
                   usage="show [key]")
        r.register("get", self._cmd_get, "Print one setting's value.", usage="get <key>")
        r.register("set", self._cmd_set, "Change a setting.", usage="set <key> <value>")
        r.register("clients", self._cmd_clients, "List connected clients.")
        r.register("client", self._cmd_client, "Act on a client.",
                   usage="client <mac|idx> <deauth|log|ip|timeout> [on|off|addr]")
        r.register("block", self._cmd_block, "Block a domain (DNS sinkhole).",
                   usage="block <domain>")
        r.register("unblock", self._cmd_unblock, "Remove a block or redirect.",
                   usage="unblock <domain>")
        r.register("redirect", self._cmd_redirect, "Redirect a domain to a URL.",
                   usage="redirect <domain> <url>")
        r.register("blockfile", self._cmd_blockfile, "Enable/disable a block-list file.",
                   usage="blockfile <name> [on|off]")
        r.register("domains", self._cmd_domains, "Show domain block/redirect state.")
        r.register("filter", self._cmd_filter, "Log filters: categories, files, toggles.",
                   usage="filter [cat|file|fulladdr|showdevice|reload] ...",
                   aliases=("filters",))
        return r

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
        # Forensic trail: every netops/firewall/routing/diag/command message
        # funnels through here, so this is the single hook that routes all
        # privileged iptables/hostapd/dnsmasq operations into structured logging.
        log_at(level, msg)
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
    try:
        ScannerAP(iface=args.iface, savepath=args.savepath).run(fix=args.fix)
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)