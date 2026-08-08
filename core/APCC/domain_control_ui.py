from .termkeys import UP, DOWN, RIGHT, is_back

_OPTIONS = ["Block Domain", "Redirect Domain", "Reset Domain",
            "Timeout Client", "List Domains"]


def _redraw_main(idx, domain_filter):
    print("\033[2J\033[H", end="")
    print("--- Domain Control --- (Up/Down: move, Enter/Right: select, Esc/Q: back)\n")
    for i, label in enumerate(_OPTIONS):
        marker = "> " if i == idx else "  "
        print(f"{marker}{label}")
    print()
    files = domain_filter.describe_files()
    if files:
        print(f"Filter files ({domain_filter.directory}) — enter a file name "
              "at 'Block Domain' to block everything in it:")
        for fname, _enabled, count, _err in files:
            print(f"  {fname}  ({count} pattern{'s' if count != 1 else ''})")
    else:
        print(f"No filter files found in {domain_filter.directory}.")
    print()


def _flash(kr, message):
    print(message)
    print("\n  (press any key to continue)")
    key = None
    while key is None:
        key = kr.getch(timeout=None)


def _block_domain(kr, domain_control, domain_filter, apply_fn):
    raw, cancelled = kr.prompt_line_cancelable(
        "  Domain or file name to block (Esc to cancel): ")
    if cancelled:
        return
    name = raw.strip()
    if not name:
        return
    file_names = {f for f, _e, _c, _err in domain_filter.describe_files()}
    if name in file_names:
        if name in domain_control.block_files:
            _flash(kr, f"'{name}' is already blocking.")
            return
        domain_control.set_block_file_enabled(name, True)
        apply_fn()
        _flash(kr, f"Blocking all domains in '{name}'.")
        return
    status, detail = domain_control.add_block(name.lower())
    if status == "conflict":
        _flash(kr, f"'{name}' already redirects to {detail} — ignored, still redirecting.")
        return
    apply_fn()
    _flash(kr, f"Blocking '{name.lower()}'.")


def _redirect_domain(kr, domain_control, apply_fn):
    raw, cancelled = kr.prompt_line_cancelable(
        "  Domain to redirect (Esc to cancel): ")
    if cancelled or not raw.strip():
        return
    domain = raw.strip().lower()
    target, cancelled = kr.prompt_line_cancelable(
        "  Redirect to (http(s) URL, Esc to cancel): ")
    if cancelled or not target.strip():
        return
    status, _detail = domain_control.add_redirect(domain, target.strip())
    if status == "conflict":
        _flash(kr, f"'{domain}' is already blocked — ignored, still blocked.")
        return
    apply_fn()
    _flash(kr, f"Redirecting '{domain}' -> {target.strip()}\n"
                "(plaintext HTTP only — HTTPS to this domain will show a "
                "connection/certificate error, not a clean redirect).")


def _reset_domain(kr, domain_control, apply_fn):
    raw, cancelled = kr.prompt_line_cancelable(
        "  Domain or file name to reset (Esc to cancel): ")
    if cancelled or not raw.strip():
        return
    name = raw.strip().lower()
    status = domain_control.reset(name)
    if status == "not_found":


        status = domain_control.reset(raw.strip())
    if status == "not_found":
        _flash(kr, f"'{raw.strip()}' wasn't blocked, redirected, or an enabled file.")
        return
    apply_fn()
    _flash(kr, f"'{raw.strip()}' reset.")


def _timeout_client(kr, domain_control, client_manager, apply_fn, debug):
    idx = 0
    while True:
        clients = client_manager.list_clients()
        if clients:
            idx = max(0, min(idx, len(clients) - 1))
        print("\033[2J\033[H", end="")
        print("--- Timeout Client --- (Up/Down: move, Enter/Right: toggle, Esc/Q: back)\n")
        if not clients:
            print("  No clients connected.\n")
        for i, c in enumerate(clients):
            marker = "> " if i == idx else "  "
            state = "TIMED OUT" if c["mac"].lower() in domain_control.timeout_macs else "normal"
            print(f"{marker}{c['name']} [ {c['mac']} ]  ip={c['ip']}  ({state})")
        print()

        key = None
        while key is None:
            key = kr.getch(timeout=0.5)
            if key is None:
                new_clients = client_manager.list_clients()
                if new_clients != clients:
                    clients = new_clients
                    if clients:
                        idx = max(0, min(idx, len(clients) - 1))

        if key == UP and clients:
            idx = (idx - 1) % len(clients)
        elif key == DOWN and clients:
            idx = (idx + 1) % len(clients)
        elif key in (RIGHT, "\r", "\n") and clients:
            mac = clients[idx]["mac"]
            now_out = mac.lower() not in domain_control.timeout_macs
            domain_control.set_timeout(mac, now_out)
            apply_fn(timeout_mac=mac, timeout_enabled=now_out)
            debug("info", f"{mac} Timeout -> {'ON' if now_out else 'OFF'}")
        elif is_back(key):
            return


def _list_domains(kr, domain_control, domain_filter):
    print("\033[2J\033[H", end="")
    print("--- Domain Control: List ---\n")
    print(domain_control.summary(domain_filter))
    print("\n  (press any key to continue)")
    key = None
    while key is None:
        key = kr.getch(timeout=None)


def run_domain_control_menu(kr, domain_control, domain_filter, client_manager,
                             debug, apply_fn):
    idx = 0
    while True:
        _redraw_main(idx, domain_filter)
        key = None
        while key is None:
            key = kr.getch(timeout=0.5)

        if key == UP:
            idx = (idx - 1) % len(_OPTIONS)
        elif key == DOWN:
            idx = (idx + 1) % len(_OPTIONS)
        elif key in (RIGHT, "\r", "\n"):
            if idx == 0:
                _block_domain(kr, domain_control, domain_filter, apply_fn)
            elif idx == 1:
                _redirect_domain(kr, domain_control, apply_fn)
            elif idx == 2:
                _reset_domain(kr, domain_control, apply_fn)
            elif idx == 3:
                _timeout_client(kr, domain_control, client_manager, apply_fn, debug)
            elif idx == 4:
                _list_domains(kr, domain_control, domain_filter)
        elif is_back(key):
            return
