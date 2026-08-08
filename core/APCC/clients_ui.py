from .termkeys import UP, DOWN, RIGHT, is_back


def _redraw_list(clients, idx):
    print("\033[2J\033[H", end="")
    print("--- Connected Clients --- (Up/Down: move, Enter/Right: select, Esc/Q: back)\n")
    if not clients:
        print("  No clients connected.\n")
    for i, c in enumerate(clients):
        marker = "> " if i == idx else "  "
        filt = "filtered" if c["filtered"] else "logging"
        print(f"{marker}{c['name']} [ {c['mac']} ]  ip={c['ip']}  ({filt})")
    print()


def run_clients_menu(kr, client_manager, debug):
    idx = 0
    while True:
        clients = client_manager.list_clients()
        if clients:
            idx = max(0, min(idx, len(clients) - 1))
        _redraw_list(clients, idx)

        key = None
        while key is None:
            key = kr.getch(timeout=0.5)
            if key is None:



                new_clients = client_manager.list_clients()
                if new_clients != clients:
                    clients = new_clients
                    if clients:
                        idx = max(0, min(idx, len(clients) - 1))
                    _redraw_list(clients, idx)

        if key == UP and clients:
            idx = (idx - 1) % len(clients)
        elif key == DOWN and clients:
            idx = (idx + 1) % len(clients)
        elif key in (RIGHT, "\r", "\n") and clients:
            _client_submenu(kr, client_manager, clients[idx], debug)
        elif is_back(key):
            return


def _redraw_submenu(client, idx, options):
    print("\033[2J\033[H", end="")
    print(f"--- Client: {client['name']} [ {client['mac']} ] ---\n")
    for i, label in enumerate(options):
        marker = "> " if i == idx else "  "
        print(f"{marker}{label}")
    print("\n  Up/Down: move, Enter/Right: select, Esc/Q: back\n")


def _client_submenu(kr, client_manager, client, debug):
    idx = 0
    while True:
        logging_on = not client_manager.is_filtered(client["mac"])
        options = [
            "Deauth / remove from AP (once)",
            f"Log Device: {'ON' if logging_on else 'OFF'}",
            "Assign static IP",
        ]
        _redraw_submenu(client, idx, options)

        key = None
        while key is None:
            key = kr.getch(timeout=0.5)

        if key == UP:
            idx = (idx - 1) % len(options)
        elif key == DOWN:
            idx = (idx + 1) % len(options)
        elif key in (RIGHT, "\r", "\n"):
            if idx == 0:
                ok = client_manager.deauth(client["mac"])
                debug("ok" if ok else "error",
                      f"Deauth {client['mac']}: {'sent' if ok else 'failed'}")
                return
            elif idx == 1:
                client_manager.toggle_filter(client["mac"])
                logging_on = not client_manager.is_filtered(client["mac"])
                debug("info", f"{client['mac']} Log Device -> "
                               f"{'ON' if logging_on else 'OFF'}")
            elif idx == 2:
                ip = kr.prompt_line("  Static IP to assign: ").strip()
                if ip:
                    client_manager.set_static_ip(client["mac"], ip)
                    debug("info", f"{client['mac']} -> static IP {ip} "
                                   f"(falls back to normal DHCP automatically if taken/unavailable)")
        elif is_back(key):
            return
