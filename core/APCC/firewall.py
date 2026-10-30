"""iptables / sysctl primitives for the APCC rogue-AP path.

This module owns the low-level firewall and forwarding operations: the INPUT
allow-rules that keep DHCP/DNS reachable, IPv6 forwarding blocks, per-client
timeout drops, interface isolation, the kernel forwarding sysctls, and the
host-firewall detection / NAT self-check. It deliberately knows nothing about
policy routing or NAT orchestration — those live in `routing.py` and
`netops.py` and call into here.
"""

import shlex
from pathlib import Path

from core.APCC.netutil import _run, _run_checked
from core.validators import validate_iface

_AP_SVC_TAG = "scannerap_svc"

# Core services a client must always be able to reach on the AP host itself:
# DNS (so names resolve), DHCP (so it gets a lease), and ICMP (ping / PMTU).
# Without these, a host whose INPUT policy is default-DROP (ufw, firewalld,
# most servers) silently drops client DNS and the whole AP looks broken even
# though forwarding is fine.
_AP_SVC_MATCHES = [
    ["-p", "udp", "--dport", "53"],
    ["-p", "tcp", "--dport", "53"],
    ["-p", "udp", "--dport", "67"],
    ["-p", "icmp"],
]


def allow_ap_services(ap_iface: str, debug):
    validate_iface(ap_iface)
    _deny_ap_services(ap_iface)
    for match in _AP_SVC_MATCHES:
        _run(["iptables", "-I", "INPUT", "1", "-i", ap_iface, *match,
              "-m", "comment", "--comment", _AP_SVC_TAG, "-j", "ACCEPT"])
    debug("info", f"Ensured DNS/DHCP/ICMP from {ap_iface} clients are accepted "
                   "(survives a default-deny INPUT policy).")


def _deny_ap_services(ap_iface: str):
    dump = _run(["iptables-save", "-t", "filter"]).stdout
    for line in dump.splitlines():
        if line.startswith("-A INPUT") and _AP_SVC_TAG in line:
            _run(["iptables", *shlex.split(line.replace("-A INPUT", "-D INPUT", 1))])


def ensure_conntrack_headroom(debug, minimum=32768):
    """Raise nf_conntrack_max if it's small. Browsers and apps like Discord
    open many simultaneous connections; a tiny table drops NEW connections
    silently under load while a single steady flow keeps working."""
    path = Path("/proc/sys/net/netfilter/nf_conntrack_max")
    try:
        current = int(path.read_text().strip())
    except (OSError, ValueError):
        return  # module not loaded / not applicable
    if current >= minimum:
        return
    try:
        path.write_text(f"{minimum}\n")
        debug("info", f"Raised nf_conntrack_max {current} -> {minimum} "
                       "(more room for simultaneous client connections).")
    except (OSError, ValueError) as e:
        debug("warn", f"Could not raise nf_conntrack_max (was {current}): {e}")


def _ip6tables_available():
    return _run(["ip6tables", "-L", "-n"]).returncode == 0


def block_ipv6_forwarding(ap_iface: str, debug):
    """We hand clients IPv4 only and don't NAT v6. Drop forwarded IPv6 on the
    AP interface so clients don't half-attempt IPv6 (Happy-Eyeballs stalls) and
    so nothing leaks out un-NATed if the host has v6 forwarding enabled."""
    validate_iface(ap_iface)
    if not _ip6tables_available():
        return
    _unblock_ipv6_forwarding(ap_iface)
    for direction in ("-i", "-o"):
        _run(["ip6tables", "-I", "FORWARD", "1", direction, ap_iface,
              "-m", "comment", "--comment", _AP_SVC_TAG, "-j", "DROP"])
    debug("info", f"IPv6 forwarding on {ap_iface} blocked (clients are IPv4-only "
                   "here; prevents un-NATed v6 leaks and IPv6 connection stalls).")


def _unblock_ipv6_forwarding(ap_iface: str):
    if not _ip6tables_available():
        return
    dump = _run(["ip6tables-save", "-t", "filter"]).stdout
    for line in dump.splitlines():
        if line.startswith("-A FORWARD") and _AP_SVC_TAG in line:
            _run(["ip6tables", *shlex.split(line.replace("-A FORWARD", "-D FORWARD", 1))])


def set_client_timeout(ap_iface: str, mac: str, enabled: bool, debug):
    validate_iface(ap_iface)
    while True:
        res = _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-m", "mac",
                     "--mac-source", mac, "-j", "DROP"])
        if res.returncode != 0:
            break
    if enabled:
        _run_checked(["iptables", "-I", "FORWARD", "1", "-i", ap_iface, "-m", "mac",
                       "--mac-source", mac, "-j", "DROP"], debug, f"Timing out {mac}")


def ip_forward_is_enabled() -> bool:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    except OSError:
        return False


def enable_ip_forward():
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    except (OSError, ValueError) as e:
        print(f"[!] Could not enable ip_forward: {e}")


def disable_ip_forward():
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    except (OSError, ValueError) as e:
        print(f"[!] Could not disable ip_forward: {e}")


def _sysctl_read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _sysctl_write(path, value):
    try:
        Path(path).write_text(f"{value}\n")
        return True
    except (OSError, ValueError) as e:
        print(f"[!] Could not write {path}: {e}")
        return False


def ensure_forwarding(ap_iface: str, bridge_iface: str, debug):
    """Global ip_forward is NOT sufficient on its own. The kernel also gates
    routing on conf.all.forwarding and the per-interface forwarding flag, and
    some systems (NetworkManager, sysctl.d, security hardening) leave one of
    those at 0 — so packets are silently not routed even though our iptables
    rules are perfect. Set and verify all of them."""
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)

    targets = [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv4/conf/all/forwarding",
    ]
    for iface in (ap_iface, bridge_iface):
        if iface:
            targets.append(f"/proc/sys/net/ipv4/conf/{iface}/forwarding")
    stuck = []
    for path in targets:
        if _sysctl_read(path) is None:
            continue  # not applicable on this kernel/iface
        _sysctl_write(path, 1)
        if _sysctl_read(path) != "1":
            stuck.append(path)
    if stuck:
        debug("warn", "IP forwarding could not be enabled (stuck at 0): "
                       + ", ".join(stuck) + " — something on the system is "
                       "forcing it off (check sysctl.d, NetworkManager, or a "
                       "hardening profile). Routing will not work until this is 1.")
    return not stuck


def iptables_backend():
    out = (_run(["iptables", "-V"]).stdout or "").lower()
    if "nf_tables" in out:
        return "nf_tables"
    if "legacy" in out:
        return "legacy"
    return "unknown"


def isolate_ap_iface(ap_iface: str, debug):
    validate_iface(ap_iface)
    deisolate_ap_iface(ap_iface, debug, quiet=True)
    # Clients still get DHCP/DNS from the AP in isolated mode — just no internet.
    allow_ap_services(ap_iface, debug)
    res = _run_checked(["iptables", "-I", "FORWARD", "1", "-i", ap_iface, "-j", "DROP"],
                        debug, f"Isolating {ap_iface}")
    disable_ip_forward()
    if res.returncode == 0:
        debug("info", f"{ap_iface} isolated — forwarding explicitly blocked "
                        "(bridge/NAT is off).")
    return res.returncode == 0


def deisolate_ap_iface(ap_iface: str, debug, quiet=False):
    validate_iface(ap_iface)
    while True:
        res = _run(["iptables", "-D", "FORWARD", "-i", ap_iface, "-j", "DROP"])
        if res.returncode != 0:
            break
    if not quiet:
        debug("info", f"{ap_iface} isolation rule removed.")


def _warn_if_forward_blocked(bridge_iface, debug):
    res = _run(["iptables", "-L", "FORWARD", "-n"])
    first_line = res.stdout.splitlines()[0] if res.stdout else ""
    if "policy DROP" in first_line or "policy REJECT" in first_line:
        debug("warn",
              f"FORWARD chain default policy is {first_line.split('policy ')[-1].split(')')[0]} "
              "— something else (commonly Docker, ufw, or firewalld) is "
              "managing this chain. Our ACCEPT rules are inserted at the "
              "top and should still win, but if that other tool reapplies "
              "its own rules afterward (e.g. Docker restarting, `ufw "
              "reload`), it can push ours back down or remove them. If "
              "NAT stops passing traffic again with no changes on this "
              "end, that's the first thing to check.")


def _forward_policy():
    res = _run(["iptables", "-L", "FORWARD", "-n"])
    line = res.stdout.splitlines()[0] if res.stdout else ""
    if "policy " in line:
        return line.split("policy ", 1)[1].split(")")[0].strip()
    return "unknown"


def detect_host_firewall():
    """Find host firewalls that enforce their own forward policy independently
    of our iptables rules — the most common reason NAT silently fails even
    though our rules look correct. Returns [(name, advice), ...]."""
    import re

    findings = []

    ufw = _run(["ufw", "status"])
    if ufw.returncode == 0 and "status: active" in (ufw.stdout or "").lower():
        findings.append(("ufw", ("ufw is active — it defaults to dropping forwarded "
                                 "traffic. Set DEFAULT_FORWARD_POLICY=\"ACCEPT\" in "
                                 "/etc/default/ufw and run 'ufw reload'.")))

    fw = _run(["firewall-cmd", "--state"])
    if fw.returncode == 0 and "running" in (fw.stdout or "").lower():
        findings.append(("firewalld", ("firewalld is running — it owns the forward chain "
                                        "and will drop our forwarded traffic unless the "
                                        "uplink zone permits it (enable masquerade/forward "
                                        "on the zone).")))

    all_rules = _run(["iptables", "-S"]).stdout or ""
    if "-P FORWARD DROP" in all_rules and "DOCKER" in all_rules:
        findings.append(("docker", ("Docker is managing iptables (FORWARD policy DROP and "
                                     "DOCKER chains present). It can reinsert its rules and "
                                     "push ours down whenever the daemon or a container "
                                     "restarts.")))

    nft = _run(["nft", "list", "ruleset"])
    if (nft.returncode == 0
            and re.search(r"hook\s+forward\b", nft.stdout or "")
            and re.search(r"hook\s+forward[^}]*?policy\s+drop", nft.stdout, re.DOTALL)):
        findings.append(("nftables", ("A native nftables chain hooks 'forward' with "
                                      "'policy drop'. nftables evaluates this independently "
                                      "of our iptables rules, so it drops forwarded packets "
                                      "regardless. Allow your AP subnet to forward in that "
                                      "nft ruleset, or disable the conflicting firewall.")))
    return findings


def verify_nat(ap_iface: str, bridge_iface: str, ip_range: str, debug, gateway=None):
    """Post-setup self-check: confirm the system is actually in a state where
    forwarding can work, and surface the exact reason if not."""
    validate_iface(ap_iface)
    if bridge_iface:
        validate_iface(bridge_iface)
    ok = True
    if _sysctl_read("/proc/sys/net/ipv4/ip_forward") != "1":
        debug("error", "ip_forward is 0 — routing is disabled at the kernel level.")
        ok = False

    fwd_present = _run(["iptables", "-C", "FORWARD", "-i", ap_iface, "-o", bridge_iface,
                        "-s", ip_range, "-j", "ACCEPT"]).returncode == 0
    masq_present = _run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", ip_range,
                         "-o", bridge_iface, "-j", "MASQUERADE"]).returncode == 0
    if not fwd_present:
        debug("warn", "Our FORWARD ACCEPT rule is not present — another tool may have "
                       "flushed or reordered it.")
        ok = False
    if not masq_present:
        debug("warn", "Our MASQUERADE rule is not present.")
        ok = False

    for name, advice in detect_host_firewall():
        debug("warn", f"[{name}] {advice}")
        ok = False

    if ok:
        debug("ok", "NAT self-check passed: forwarding on, rules present, no host "
                     "firewall overriding the forward path.")
    else:
        debug("warn", "NAT self-check found problems above — these are the likely "
                       "reason clients can't reach the internet. Run 'diag' for detail.")
    return ok


def _chain_counters(table, chain):
    args = ["iptables"]
    if table:
        args += ["-t", table]
    args += ["-L", chain, "-v", "-n", "-x"]
    return _run(args).stdout or ""
