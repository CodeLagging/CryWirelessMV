"""Textual control-panel UI for APCC.

A thin shell over the existing ScannerAP backend — no AP/DHCP/bridge/domain
logic is reimplemented here. Two panes: the left is the live log, the right is
a fixed-width side panel with a Services section (live on/off toggles) and
collapsible setting categories (one open at a time). Every toggle, field and
button just drives the same backend methods / commands the classic console
uses.

Deliberately plain — no custom theme, default terminal palette.
"""

import io
import queue
import re
import threading
from contextlib import redirect_stdout
from functools import partial
from typing import ClassVar

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import (
    Button,
    Collapsible,
    Footer,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    Switch,
)

from core.APCC import settings as settings_mod
from core.APCC.logging_ap import LOG_CATEGORIES

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# Friendlier labels for the raw log-category keys.
_CAT_LABELS = {
    "dns": "DNS queries",
    "tls_sni": "TLS SNI (HTTPS hostnames)",
    "new_device": "New device joins",
    "malformed": "Malformed packets",
    "traffic": "All traffic (verbose)",
}


def _strip_ansi(text):
    return _ANSI_RE.sub("", text)


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


class _DummyKr:
    """Stand-in for TermKeys — the panel supplies args directly, so the
    backend's interactive prompts just return blank."""

    def prompt_line(self, msg, hide=False):
        return ""

    def prompt_line_cancelable(self, msg, hide=False, seed=""):
        return "", True


class _QueueWriter(io.TextIOBase):
    """Captures command print() output line-by-line into the UI's log queue."""

    def __init__(self, q):
        self._q = q
        self._buf = ""

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._q.put(_strip_ansi(line))
        return len(s)

    def flush(self):
        if self._buf:
            self._q.put(_strip_ansi(self._buf))
            self._buf = ""


class APCCTui(App):
    # No theme styling on purpose — just layout. Colors stay at the terminal's
    # own palette; borders are neutral.
    CSS = """
    Screen { layout: horizontal; }

    #log { width: 2fr; height: 1fr; border: round $foreground 40%;
           padding: 0 1; margin: 1 0 1 1; }

    #right { width: 48; height: 1fr; }
    #panel-title { text-style: bold; padding: 1 1 0 1; }
    #status { padding: 0 1 0 1; color: $text-muted; }

    #accordion { height: 1fr; padding: 0 1; }
    Collapsible { border: round $foreground 30%; margin: 0 0 1 0; padding: 0; }
    Collapsible > Contents { padding: 0 1; }

    .row { height: auto; padding: 0 1; }
    .row Label { width: 1fr; padding-top: 1; }
    .row Switch { width: auto; }
    .row Select { width: 18; }
    .row Input { width: 18; }
    .btnrow { height: auto; padding: 1 1 0 1; }
    .subhdr { text-style: bold; padding: 1 0 0 0; color: $text-muted; }
    #domains-summary { padding: 1 0 0 0; color: $text-muted; }

    /* Docked to the bottom of the panel so it's always on screen, regardless
       of how tall the accordion gets. The bottom margin lifts it clear of the
       footer row. */
    #buttons { dock: bottom; height: 1; padding: 0 1; margin: 0 0 1 0; }
    #buttons Button {
        width: 1fr; min-width: 4; height: 1; margin: 0 1 0 0;
        padding: 0; border: none;
    }
    """

    # Command palette (^p) disabled — this is a fixed control panel, not a
    # command surface.
    ENABLE_COMMAND_PALETTE = False

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("ctrl+q", "quit", "Quit"),
        # Clear is on the Clear button; keep the shortcut but hide it from the
        # footer.
        Binding("ctrl+l", "clear_log", "Clear log", show=False),
    ]

    # Live on/off toggles -> their command name.
    _ACTIONS = (("radio", "Radio"), ("ap", "Access Point"),
                ("dhcp", "DHCP + DNS"), ("record", "Record traffic"))

    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        self._q = queue.Queue()
        self._ui_ready = False         # ignore mount-time widget events
        self._syncing = False          # programmatic switch updates
        self._collapsing = False       # programmatic collapsible updates
        self._watchdog_stop = threading.Event()
        self._display_shown = 0
        self._file_by_slug = {}        # widget-id slug -> real filename
        scanner._emit_line = lambda line: self._q.put(_strip_ansi(line))

    # ---- layout -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield RichLog(id="log", markup=False, highlight=False, wrap=True)
        with Vertical(id="right"):
            yield Static("APCC Control Panel", id="panel-title")
            yield Static("", id="status")
            with VerticalScroll(id="accordion"):
                with Collapsible(title="Services", collapsed=False, id="cat-services"):
                    for key, label in self._ACTIONS:
                        with Horizontal(classes="row"):
                            yield Label(label)
                            yield Switch(id=f"act-{key}", value=False)
                    with Horizontal(classes="row"):
                        yield Label("Bridge / internet share (NAT)")
                        yield Switch(id="act-bridge", value=False)
                    with Horizontal(classes="row"):
                        yield Label("Uplink interface")
                        yield Input(id="bridge-iface",
                                    value=self.scanner.settings.get("bridge_iface", ""),
                                    placeholder="eth0")
                for cat, keys in settings_mod.CATEGORIES:
                    with Collapsible(title=cat, collapsed=True, id=f"cat-{_slug(cat)}"):
                        for key in keys:
                            yield self._field_row(key)
                yield from self._compose_logging()
                yield from self._compose_domains()
            with Horizontal(id="buttons"):
                yield Button("Apply", id="btn-apply", variant="primary")
                yield Button("Diag", id="btn-diag")
                yield Button("Fix", id="btn-fix")
                yield Button("Clear", id="btn-clear")
                yield Button("Quit", id="btn-quit", variant="error")
        yield Footer()

    def _field_row(self, key):
        s = self.scanner.settings
        field = next((f for f in settings_mod.FIELDS if f[0] == key), None)
        if field is None:
            return Horizontal(Label(f"(unknown: {key})"), classes="row")
        _k, label, kind, options, grayed = field
        disabled = bool(grayed and grayed(s))
        wid = f"set-{key}"
        if kind == "bool":
            control = Switch(id=wid, value=bool(s.get(key)), disabled=disabled)
        elif kind == "choice":
            val = s.get(key) if s.get(key) in options else options[0]
            control = Select([(o, o) for o in options], id=wid, value=val,
                             allow_blank=False, disabled=disabled)
        else:
            control = Input(id=wid, value=str(s.get(key, "")), disabled=disabled)
        return Horizontal(Label(label), control, classes="row")

    def _compose_logging(self):
        lg = self.scanner.logger
        cats = getattr(lg, "enabled_categories", set()) or set()
        with Collapsible(title="Logging & Capture", collapsed=True, id="cat-logging"):
            with Horizontal(classes="row"):
                yield Label("Live log display")
                yield Switch(id="logopt-display", value=getattr(lg, "display_on", False))
            yield Static("Capture categories:", classes="subhdr")
            for cat in LOG_CATEGORIES:
                with Horizontal(classes="row"):
                    yield Label(_CAT_LABELS.get(cat, cat))
                    yield Switch(id=f"logcat-{cat}", value=cat in cats)
            with Horizontal(classes="row"):
                yield Label("Full address (no truncation)")
                yield Switch(id="logopt-fulladdr", value=getattr(lg, "full_address", False))
            with Horizontal(classes="row"):
                yield Label("Show device names")
                yield Switch(id="logopt-showdevice", value=getattr(lg, "show_device", False))
            files = self._filter_files()
            if files:
                yield Static("Log-filter files:", classes="subhdr")
                for fname, enabled, count, errc in files:
                    sl = _slug(fname)
                    self._file_by_slug[sl] = fname
                    with Horizontal(classes="row"):
                        yield Label(f"{fname} ({count})")
                        yield Switch(id=f"filterfile-{sl}", value=bool(enabled))

    def _compose_domains(self):
        with Collapsible(title="Domains / DNS (block & redirect)", collapsed=True,
                         id="cat-domains"):
            with Horizontal(classes="row"):
                yield Label("Block domain")
                yield Input(id="dom-block", placeholder="ads.example.com")
            with Horizontal(classes="row"):
                yield Label("Unblock (domain/file)")
                yield Input(id="dom-unblock", placeholder="example.com")
            with Horizontal(classes="row"):
                yield Label("Redirect domain")
                yield Input(id="dom-redirect", placeholder="foo.com")
            with Horizontal(classes="row"):
                yield Label("… to URL")
                yield Input(id="dom-redirect-url", placeholder="http://10.0.0.1")
            with Horizontal(classes="btnrow"):
                yield Button("Add redirect", id="btn-redirect")
            files = self._block_files()
            if files:
                yield Static("Block-list files (DNS sinkhole):", classes="subhdr")
                enabled = getattr(self.scanner.domain_control, "block_files", set())
                for fname, _en, count, _errc in files:
                    sl = _slug(fname)
                    self._file_by_slug[sl] = fname
                    with Horizontal(classes="row"):
                        yield Label(f"{fname} ({count})")
                        yield Switch(id=f"blockfile-{sl}", value=fname in enabled)
            yield Static("", id="domains-summary")

    def _filter_files(self):
        try:
            return self.scanner.domain_filter.describe_files()
        except (AttributeError, OSError, ValueError) as e:
            self._q.put(f"[warn] could not describe filter files: {e}")
            return []

    def _block_files(self):
        return self._filter_files()

    # ---- lifecycle --------------------------------------------------------

    def on_mount(self):
        self.scanner.running = True
        threading.Thread(target=self.scanner._watchdog_loop,
                         args=(self._watchdog_stop,), daemon=True).start()
        self.set_interval(0.05, self._drain_queue)
        self.set_interval(0.3, self._drain_display)
        self.set_interval(0.6, self._refresh_state)
        self.set_timer(0.3, self._mark_ready)
        self._refresh_domains()

    def _mark_ready(self):
        self._ui_ready = True

    def _drain_queue(self):
        log = self.query_one("#log", RichLog)
        drained = 0
        while drained < 200:
            try:
                line = self._q.get_nowait()
            except queue.Empty:
                break
            log.write(line)
            drained += 1

    def _drain_display(self):
        lg = self.scanner.logger
        if not lg or not getattr(lg, "display_on", False):
            return
        with lg._display_lock:
            buf = list(lg.display_buffer)
        for line in buf[self._display_shown:]:
            self._q.put(_strip_ansi(line))
        self._display_shown = len(buf)

    def _refresh_state(self):
        sc = self.scanner
        br = ""
        if sc.bridge_enabled and sc.settings.get("bridge_iface"):
            br = f" ({sc.settings['bridge_iface']})"
        rec = sc.logger.recording if sc.logger else False
        self.query_one("#status", Static).update(
            f"radio={_b(sc.radio_on)}  ap={_b(sc.ap_running)}  "
            f"dhcp={_b(sc.dhcp_enabled)}  bridge={_b(sc.bridge_enabled)}{br}\n"
            f"record={_b(rec)}  ssid={sc.settings.get('ssid', '')}")
        self._syncing = True
        try:
            self._sync_switch("act-radio", sc.radio_on)
            self._sync_switch("act-ap", sc.ap_running)
            self._sync_switch("act-dhcp", sc.dhcp_enabled)
            self._sync_switch("act-bridge", sc.bridge_enabled)
            if sc.logger:
                self._sync_switch("act-record", sc.logger.recording)
        finally:
            self._syncing = False

    def _sync_switch(self, wid, value):
        try:
            sw = self.query_one(f"#{wid}", Switch)
        except (NoMatches, AttributeError, TypeError):
            return
        if sw.value != bool(value):
            sw.value = bool(value)

    def _refresh_domains(self):
        try:
            txt = self.scanner.domain_control.summary(self.scanner.domain_filter)
            self.query_one("#domains-summary", Static).update(txt)
        except (NoMatches, AttributeError, OSError, ValueError) as e:
            self._q.put(f"[warn] could not refresh domains summary: {e}")

    # ---- accordion: one open at a time -----------------------------------

    @on(Collapsible.Toggled)
    def _on_collapsible(self, event):
        if self._collapsing:
            return
        col = event.collapsible
        if col.collapsed:
            return
        self._collapsing = True
        try:
            for other in self.query(Collapsible):
                if other is not col and not other.collapsed:
                    other.collapsed = True
        finally:
            self._collapsing = False

    # ---- running backend actions -----------------------------------------

    @work(thread=True, exclusive=False, group="cmd")
    def _run_command(self, line):
        self._q.put(f"APCC> {line}")
        writer = _QueueWriter(self._q)
        try:
            with redirect_stdout(writer):
                self.scanner._run_command_line(line, _DummyKr())
            writer.flush()
        except Exception as e:  # noqa: BLE001 — worker thread, must not kill UI
            self._q.put(f"[error] {line!r} failed: {e}")
        if not self.scanner.running:
            self.call_from_thread(self._shutdown_and_exit)

    @work(thread=True, exclusive=False, group="cmd")
    def _run_raw(self, label, fn):
        if label:
            self._q.put(f"APCC> {label}")
        writer = _QueueWriter(self._q)
        try:
            with redirect_stdout(writer):
                fn()
            writer.flush()
        except Exception as e:  # noqa: BLE001 — worker thread, must not kill UI
            self._q.put(f"[error] {label or 'action'} failed: {e}")

    # ---- toggles ----------------------------------------------------------

    @on(Switch.Changed)
    def _on_switch(self, event: Switch.Changed):
        if self._syncing or not self._ui_ready:
            return
        wid = event.switch.id or ""
        on_ = event.value
        onoff = "on" if on_ else "off"
        if wid.startswith("act-"):
            name = wid[len("act-"):]
            if on_ == self._action_state(name):
                return  # sync echo, not a click (Switch.Changed is async)
            if name == "bridge":
                self._toggle_bridge(on_)
            else:
                self._run_command(f"{name} {onoff}")
        elif wid.startswith("set-"):
            self._apply_setting(wid[len("set-"):], on_)
        elif wid.startswith("logcat-"):
            self._run_command(f"filter cat {wid[len('logcat-'):]} {onoff}")
        elif wid == "logopt-display":
            self._run_command(f"display {onoff}")
        elif wid == "logopt-fulladdr":
            self._run_command(f"filter fulladdr {onoff}")
        elif wid == "logopt-showdevice":
            self._run_command(f"filter showdevice {onoff}")
        elif wid.startswith("filterfile-"):
            fname = self._file_by_slug.get(wid[len("filterfile-"):])
            if fname:
                self._run_command(f"filter file {fname} {onoff}")
        elif wid.startswith("blockfile-"):
            fname = self._file_by_slug.get(wid[len("blockfile-"):])
            if fname:
                self._run_command(f"blockfile {fname} {onoff}")
                self.set_timer(0.4, self._refresh_domains)

    def _action_state(self, name):
        sc = self.scanner
        return {
            "radio": sc.radio_on,
            "ap": sc.ap_running,
            "dhcp": sc.dhcp_enabled,
            "bridge": sc.bridge_enabled,
            "record": bool(sc.logger and sc.logger.recording),
        }.get(name, False)

    def _toggle_bridge(self, on_):
        if on_:
            iface = self.query_one("#bridge-iface", Input).value.strip()
            if not iface:
                self._q.put("bridge: enter an uplink iface first (e.g. eth0).")
                self._syncing = True
                self.query_one("#act-bridge", Switch).value = False
                self._syncing = False
                return
            self._run_command(f"bridge on {iface}")
        else:
            self._run_command("bridge off")

    # ---- settings & domain inputs ----------------------------------------

    @on(Select.Changed)
    def _on_select(self, event: Select.Changed):
        if self._syncing or not self._ui_ready or not event.select.id:
            return
        if event.select.id.startswith("set-") and event.value is not Select.BLANK:
            self._apply_setting(event.select.id[len("set-"):], event.value)

    @on(Input.Submitted)
    def _on_input_submit(self, event: Input.Submitted):
        wid = event.input.id or ""
        val = event.value.strip()
        if wid == "bridge-iface":
            self.scanner.settings["bridge_iface"] = val
            self._q.put(f"bridge_iface = {val}")
        elif wid.startswith("set-"):
            self._apply_setting(wid[len("set-"):], event.value)
        elif wid == "dom-block" and val:
            self._run_command(f"block {val}")
            event.input.value = ""
            self.set_timer(0.4, self._refresh_domains)
        elif wid == "dom-unblock" and val:
            self._run_command(f"unblock {val}")
            event.input.value = ""
            self.set_timer(0.4, self._refresh_domains)

    def _apply_setting(self, key, value):
        self._run_raw("", partial(self._do_apply_setting, key, value))

    def _do_apply_setting(self, key, value):
        field = next((f for f in settings_mod.FIELDS if f[0] == key), None)
        if not field:
            print(f"unknown setting: {key}")
            return
        if field[2] == "bool":
            value = "on" if value else "off"
        self.scanner._run_command_line(f"set {key} {value}", _DummyKr())
        self.call_from_thread(self._refresh_grayed)

    def _refresh_grayed(self):
        s = self.scanner.settings
        for key, label, kind, options, grayed in settings_mod.FIELDS:
            if key == "bridge_iface":
                continue
            try:
                w = self.query_one(f"#set-{key}")
            except (NoMatches, AttributeError, TypeError):
                continue
            w.disabled = bool(grayed and grayed(s))

    # ---- buttons ----------------------------------------------------------

    @on(Button.Pressed)
    def _on_button(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "btn-diag":
            self._run_command("diag")
        elif bid == "btn-fix":
            self._run_command("fix")
        elif bid == "btn-clear":
            self.action_clear_log()
        elif bid == "btn-quit":
            self._run_command("quit")
        elif bid == "btn-redirect":
            d = self.query_one("#dom-redirect", Input).value.strip()
            u = self.query_one("#dom-redirect-url", Input).value.strip()
            if d and u:
                self._run_command(f"redirect {d} {u}")
                self.query_one("#dom-redirect", Input).value = ""
                self.query_one("#dom-redirect-url", Input).value = ""
                self.set_timer(0.4, self._refresh_domains)
            else:
                self._q.put("redirect: need both a domain and a target URL")
        elif bid == "btn-apply":
            if self.scanner.ap_running:
                self._run_raw("apply + restart", self._restart_ap)
            else:
                self._q.put("Settings saved. Turn the radio + AP on to apply.")

    def _restart_ap(self):
        was_dhcp = self.scanner.dhcp_enabled
        self.scanner.stop_ap()
        self.scanner.start_ap(kr=_DummyKr())
        if was_dhcp and not self.scanner.dhcp_enabled:
            self.scanner._set_dhcp(True, _DummyKr())

    # ---- actions ----------------------------------------------------------

    def action_clear_log(self):
        self.query_one("#log", RichLog).clear()
        if self.scanner.logger:
            self.scanner.logger.clear_display()
        self._display_shown = 0

    def action_quit(self):
        self.scanner.running = False
        self._shutdown_and_exit()

    def _shutdown_and_exit(self):
        self._watchdog_stop.set()
        try:
            self.scanner.shutdown()
        except Exception:  # noqa: BLE001, S110 — TUI exit path must always complete
            pass
        self.exit()


def _b(value):
    return "on" if value else "off"


def run_tui(scanner):
    """Entry point used by ScannerAP.run(). `scanner` must already be
    _startup()'d (settings loaded, logger created)."""
    APCCTui(scanner).run()