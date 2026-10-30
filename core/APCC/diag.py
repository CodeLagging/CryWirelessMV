"""Bridge/NAT diagnostics for the APCC module.

Read-only probes that explain *why* a bridged client can't reach the internet:
traffic counters, conntrack flow counts, a real TCP/DNS egress probe sourced
from the AP subnet, same-radio AP+STA detection, and the overall `diagnose`
report. Depends on firewall/routing primitives; nothing depends on it except
the public re-export in `netops`.
"""

import ipaddress
import re
import socket
from pathlib import Path

from core.APCC.firewall import (
    _chain_counters,
    _forward_policy,
    _sysctl_read,
    iptables_backend,
    verify_nat,
)
from core.APCC.netutil import _run
from core.APCC.routing import PBR_TABLE_ID, _iface_default_gateway
from core.validators import validate_iface


def report_traffic_counters(ap_iface, bridge_iface, ip_range, debug):
    """Read the live packet counters on the forward/NAT rules and the conntrack
    table so we can see whether REAL client traffic (arriving over the air on
    the AP iface) is actually being forwarded — the host-sourced ping test can't
    show this because locally-generated packets skip the FORWARD chain."""
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    fwd_out = fwd_in = masq = None
    for line in _chain_counters(None, "FORWARD").splitlines():
        p = line.split()
        if len(p) >= 7 and p[0].isdigit():
            pkts, inif, outif = p[0], p[5], p[6]
            if inif == ap_iface and outif == bridge_iface:
                fwd_out = pkts
            elif inif == bridge_iface and outif == ap_iface:
                fwd_in = pkts
    for line in _chain_counters("nat", "POSTROUTING").splitlines():
        p = line.split()
        if len(p) >= 7 and p[0].isdigit() and p[2] == "MASQUERADE" and p[6] == bridge_iface:
            masq = p[0]

    debug("info", f"forward counters: client->net ({ap_iface}->{bridge_iface})="
                   f"{fwd_out if fwd_out is not None else '?'} pkts, "
                   f"net->client ({bridge_iface}->{ap_iface})="
                   f"{fwd_in if fwd_in is not None else '?'} pkts, "
                   f"MASQUERADE={masq if masq is not None else '?'} pkts")

    try:
        prefix = str(ipaddress.ip_network(ip_range, strict=False).network_address)
        prefix = prefix.rsplit(".", 1)[0] + "."
    except (ValueError, TypeError, AttributeError):
        prefix = None
    flows = None
    if prefix:
        text = ""
        try:
            text = Path("/proc/net/nf_conntrack").read_text()
        except OSError:
            text = ""
        if not text.strip():
            # /proc/net/nf_conntrack can be empty/disabled even when tracking
            # works; fall back to the conntrack tool (prints to stdout/stderr).
            ct = _run(["conntrack", "-L"])
            text = (ct.stdout or "") + (ct.stderr or "")
        flows = len(re.findall(r"src=" + re.escape(prefix), text))
    debug("info", f"conntrack flows sourced from {prefix or ip_range}x: "
                   f"{flows if flows is not None else '?'}")
    if fwd_out in ("0", None) and (flows in (0, None)):
        debug("warn", "No forwarded client packets seen yet. Browse something on a "
                       "client (with mobile data OFF so it can't use cellular), then run "
                       "'diag' again: if client->net stays 0, the phone's data isn't "
                       "reaching the AP over the air (driver/RF/power-save) — not a "
                       "routing problem; if it climbs but there's still no internet, the "
                       "break is past the AP.")


def _iface_phy(iface):
    validate_iface(iface)
    try:
        return Path(f"/sys/class/net/{iface}/phy80211/name").read_text().strip()
    except OSError:
        return None


def _first_host(ip_range):
    try:
        net = ipaddress.ip_network(ip_range, strict=False)
        return str(next(net.hosts()))
    except (ValueError, TypeError, StopIteration):
        return None


def tcp_connect_probe(src_ip, host, port, timeout=4):
    """Open a real TCP connection from the AP's LAN IP out through the NAT path,
    to confirm TCP (not just ICMP) survives forwarding + MASQUERADE + the uplink
    — the original 'small packets work, TCP apps fail' symptom lives here."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.bind((src_ip, 0))
        except OSError:
            pass
        rc = s.connect_ex((host, port))
        s.close()
        return rc == 0
    except (OSError, ValueError):
        return False


def dns_probe(server_ip, name="example.com", timeout=3):
    """Send a minimal A-record query straight to a DNS server (our dnsmasq on
    the AP gateway) and report whether it answers — tests the exact path a
    client's DNS takes, without depending on dig/nslookup being installed."""
    txid = b"\x12\x34"
    header = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    packet = header + q + b"\x00\x01\x00\x01"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (server_ip, 53))
        data, _ = s.recvfrom(512)
        s.close()
        ancount = int.from_bytes(data[6:8], "big")
        return ancount > 0
    except (OSError, ValueError):
        return False


def diagnose(ap_iface: str, bridge_iface: str, ip_range: str, debug, gateway=None):
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    debug("info", "=== bridge diagnostics ===")
    debug("info", f"iptables backend: {iptables_backend()}")
    debug("info", f"ip_forward={_sysctl_read('/proc/sys/net/ipv4/ip_forward')} "
                   f"all.forwarding={_sysctl_read('/proc/sys/net/ipv4/conf/all/forwarding')}")
    for iface in (ap_iface, bridge_iface):
        if not iface:
            continue
        fwd = _sysctl_read(f"/proc/sys/net/ipv4/conf/{iface}/forwarding")
        rpf = _sysctl_read(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter")
        off = _run(["ethtool", "-k", iface]).stdout or ""
        on_offloads = [o for o in ("generic-receive-offload", "generic-segmentation-offload",
                                    "tcp-segmentation-offload")
                       if re.search(rf"^{o}: on", off, re.MULTILINE)]
        offtxt = ("offloads ON: " + ", ".join(on_offloads)) if on_offloads else "offloads off"
        debug("info", f"{iface}: forwarding={fwd} rp_filter={rpf}  ({offtxt})")

    # Same-radio AP+STA: a very common reason a Wi-Fi AP "works" but clients
    # drop and traffic stalls, even with perfect host-side rules.
    phy_ap = _iface_phy(ap_iface)
    phy_up = _iface_phy(bridge_iface) if bridge_iface else None
    if phy_ap and phy_up and phy_ap == phy_up:
        debug("warn", f"{ap_iface} (AP) and {bridge_iface} (uplink) are the SAME radio "
                       f"({phy_ap}). Most Wi-Fi chips cannot reliably run an access point "
                       "and a client uplink at the same time — the usual symptom is exactly "
                       "this: clients connect then drop, and traffic doesn't pass. Use a "
                       "separate Wi-Fi adapter or a wired uplink for the bridge.")

    addr = _run(["ip", "-4", "addr", "show", "dev", ap_iface]).stdout or ""
    addrs = re.findall(r"inet (\S+)", addr)
    debug("info" if addrs else "warn",
          f"{ap_iface} IPv4: {', '.join(addrs) if addrs else 'NONE (clients have no gateway to reach)'}")

    debug("info", f"FORWARD policy: {_forward_policy()}")

    if bridge_iface:
        pbr = (_run(["ip", "route", "show", "table", str(PBR_TABLE_ID)]).stdout or "").strip()
        pbr_line = pbr.replace("\n", "  |  ") if pbr else "empty"
        has_local = ip_range.rsplit("/", 1)[0].rsplit(".", 1)[0] in pbr and " dev " + ap_iface in pbr
        debug("info" if has_local else "warn",
              f"policy table {PBR_TABLE_ID}: {pbr_line}"
              + ("" if has_local else f"  — MISSING the local {ap_iface} route; "
                 "gateway->client replies (DNS/ICMP) will be sent out the uplink"))

    ap_gw = _first_host(ip_range)
    if ap_gw:
        dns_ok = dns_probe(ap_gw)
        debug("info" if dns_ok else "warn",
              f"DNS probe to dnsmasq at {ap_gw}: "
              f"{'answered (resolution works for clients)' if dns_ok else 'NO ANSWER — clients cannot resolve names (dnsmasq down, wrong upstream, or port 53 blocked)'}")

    if bridge_iface:
        gw = gateway or _iface_default_gateway(bridge_iface)
        debug("info", f"uplink {bridge_iface} gateway: {gw or 'unknown'}")
        if gw:
            ping = _run(["ping", "-c", "1", "-W", "2", "-I", bridge_iface, gw])
            debug("info" if ping.returncode == 0 else "warn",
                  f"ping gateway {gw} via {bridge_iface}: "
                  f"{'reachable' if ping.returncode == 0 else 'FAILED (uplink may be down)'}")
        # The decisive test: source a packet from the AP's LAN IP so it takes
        # the exact policy-route + MASQUERADE path a client's traffic takes.
        if ap_gw:
            cp = _run(["ping", "-c", "1", "-W", "3", "-I", ap_gw, "8.8.8.8"])
            icmp_ok = cp.returncode == 0
            tcp_ok = tcp_connect_probe(ap_gw, "1.1.1.1", 443)
            debug("ok" if icmp_ok else "warn",
                  f"client-path ICMP (src {ap_gw} -> 8.8.8.8 through NAT): "
                  f"{'works' if icmp_ok else 'FAILED'}")
            debug("ok" if tcp_ok else "warn",
                  f"client-path TCP (src {ap_gw} -> 1.1.1.1:443 through NAT): "
                  f"{'works' if tcp_ok else 'FAILED'}")
            if icmp_ok and tcp_ok:
                debug("ok", "Full egress path works for AP-subnet-sourced traffic (ICMP+TCP). "
                             "If real clients still fail, the break is NOT host routing/NAT — "
                             "it's the client leg: the Wi-Fi data path on the AP radio, or the "
                             "client isn't actually sending via this network (e.g. phone on "
                             "cellular). Watch the forward counters below while a client browses.")
            elif icmp_ok and not tcp_ok:
                debug("warn", "ICMP works but TCP does not through the NAT path — this matches "
                               "the 'small packets pass, apps fail' symptom. Suspect the uplink "
                               "blocking/altering TCP, or an MSS/offload issue on the uplink NIC "
                               "(try: ethtool -K <uplink> tx off gro off).")

    ct_max = _sysctl_read("/proc/sys/net/netfilter/nf_conntrack_max")
    ct_cnt = _sysctl_read("/proc/sys/net/netfilter/nf_conntrack_count")
    debug("info", f"conntrack: count={ct_cnt or '?'} max={ct_max or 'module not loaded'}")

    if bridge_iface:
        report_traffic_counters(ap_iface, bridge_iface, ip_range, debug)
        verify_nat(ap_iface, bridge_iface, ip_range, debug, gateway=gateway)
    else:
        debug("info", "No uplink set — AP is in isolated mode (no internet by design).")
    debug("info", "=== end diagnostics ===")
