import difflib
import ipaddress
import shlex
import subprocess
from pathlib import Path

from core.APCC import netops
from core.APCC import settings as settings_mod
from core.APCC.logging_ap import LOG_CATEGORIES


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


class APCommandHandlersMixin:
    """All interactive command handlers for the APCC prompt."""

    @staticmethod
    def _onoff(args, current):
        if not args:
            return not current
        a = args[0].lower()
        if a in ("on", "1", "true", "yes", "enable", "enabled"):
            return True
        if a in ("off", "0", "false", "no", "disable", "disabled"):
            return False
        raise ValueError(f"expected on/off, got '{args[0]}'")

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
            proc = self.state_mgr.start_dnsmasq(self.save_dir / "conf" / "dnsmasq.conf", self.client_mgr, kr=kr)
            if proc:
                self.dnsmasq_proc = proc
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
        proc = self.state_mgr.start_dnsmasq(self.save_dir / "conf" / "dnsmasq.conf", self.client_mgr, kr=kr)
        if proc:
            self.dnsmasq_proc = proc
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

        self.state_mgr.bridge_enabled = self.bridge_enabled
        settings_mod.save_settings(self.save_dir, self.settings)
        self.debug("info", f"Bridge/NAT mode -> {'ON' if self.bridge_enabled else 'OFF'}"
                            f"{' (' + self.settings['bridge_iface'] + ')' if self.bridge_enabled else ''}")
        if self.ap_running:
            if self.bridge_enabled:
                netops.setup_nat(self.iface, self.settings["bridge_iface"],
                                  self.settings["ip_range"], self.debug,
                                  gateway_override=self.settings.get("bridge_gateway"),
                                  configured_mtu=self.settings.get("mtu", 0))
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
