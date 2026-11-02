"""Behaviour tests for NAT orchestration (setup_nat / teardown_nat / fix / reset)
with a mocked subprocess layer and stubbed firewall/routing collaborators."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC import netops


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class _Recorder:
    def __init__(self):
        self.calls = []

    def run(self, cmd, *a, **k):
        self.calls.append(list(cmd) if not isinstance(cmd, str) else cmd.split())
        return _Result(returncode=1)      # delete-loops break

    def run_checked(self, cmd, debug, what):
        self.calls.append(list(cmd))
        return _Result(returncode=0)      # inserts succeed

    def issued(self, *needles):
        return any(all(n in call for n in needles) for call in self.calls)


def _noop(*a, **k):
    pass


# collaborators imported into the netops namespace that we stub out so only the
# iptables command construction in netops itself is exercised.
_STUBBED = [
    "ensure_forwarding", "deisolate_ap_iface", "allow_ap_services",
    "ensure_conntrack_headroom", "block_ipv6_forwarding", "setup_policy_routing",
    "teardown_policy_routing", "verify_nat", "_warn_if_forward_blocked",
    "_deny_ap_services", "_unblock_ipv6_forwarding",
]


@pytest.fixture
def rec(monkeypatch):
    r = _Recorder()
    monkeypatch.setattr(netops, "_run", r.run)
    monkeypatch.setattr(netops, "_run_checked", r.run_checked)
    for name in _STUBBED:
        monkeypatch.setattr(netops, name, _noop)
    monkeypatch.setattr(netops, "isolate_ap_iface", lambda *a, **k: True)
    return r


IP = "192.168.50.0/24"


def test_setup_nat_builds_masquerade_and_forward(rec):
    ok = netops.setup_nat("wlan1", "eth0", IP, _noop)
    assert ok is True
    assert rec.issued("POSTROUTING", "MASQUERADE", "eth0")
    assert rec.issued("FORWARD", "wlan1", "eth0", "ACCEPT")
    assert rec.issued("TCPMSS")                      # MSS clamp applied


def test_setup_nat_without_bridge_is_noop(rec):
    assert netops.setup_nat("wlan1", "", IP, _noop) is False


def test_teardown_nat_deletes_masquerade_and_forward(rec):
    netops.teardown_nat("wlan1", "eth0", IP, _noop)
    assert rec.issued("-D", "POSTROUTING", "MASQUERADE")
    assert rec.issued("-D", "FORWARD")


def test_fix_rules_without_bridge_isolates(rec, monkeypatch):
    seen = {}
    monkeypatch.setattr(netops, "isolate_ap_iface",
                        lambda iface, debug: seen.setdefault("isolated", iface))
    netops.fix_rules("wlan1", "", IP, _noop)
    assert seen.get("isolated") == "wlan1"


def test_reset_rules_flushes_then_rebuilds(rec):
    netops.reset_rules("wlan1", "eth0", IP, _noop)
    assert rec.issued("-F", "FORWARD")               # chain flushed
    assert rec.issued("POSTROUTING", "MASQUERADE", "eth0")  # NAT rebuilt
