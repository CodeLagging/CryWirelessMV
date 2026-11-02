"""Behaviour tests for firewall rule construction, with a mocked subprocess layer.

These assert the *exact iptables commands* each function issues, so the
security-critical rule logic is covered without touching the host firewall.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC import firewall


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class _Recorder:
    def __init__(self, stdout=""):
        self.calls = []
        self._stdout = stdout

    def run(self, cmd, *a, **k):
        # rc=1 so `while True` delete-loops ("-D ... until no such rule") break
        # on the first iteration instead of spinning forever.
        self.calls.append(list(cmd) if not isinstance(cmd, str) else cmd.split())
        return _Result(self._stdout, returncode=1)

    def run_checked(self, cmd, debug, what):
        self.calls.append(list(cmd))
        return _Result(self._stdout, returncode=0)

    def issued(self, *needles):
        return any(all(n in call for n in needles) for call in self.calls)


def _noop(*a, **k):
    pass


@pytest.fixture
def rec(monkeypatch):
    r = _Recorder()
    monkeypatch.setattr(firewall, "_run", r.run)
    monkeypatch.setattr(firewall, "_run_checked", r.run_checked)
    return r


def test_allow_ap_services_accepts_dns_dhcp_icmp(rec):
    firewall.allow_ap_services("wlan1", _noop)
    assert rec.issued("INPUT", "ACCEPT", "53")       # DNS
    assert rec.issued("INPUT", "ACCEPT", "67")       # DHCP
    assert rec.issued("INPUT", "ACCEPT", "icmp")     # ICMP


def test_isolate_ap_iface_drops_forward_and_disables_forwarding(rec, monkeypatch):
    writes = []
    monkeypatch.setattr(firewall, "disable_ip_forward", lambda: writes.append("disabled"))
    ok = firewall.isolate_ap_iface("wlan1", _noop)
    assert ok is True
    assert rec.issued("FORWARD", "wlan1", "DROP")
    assert writes == ["disabled"]


def test_deisolate_removes_drop_rule(rec):
    # _run returns rc=0 once then the loop would spin; make it stop after first
    firewall.deisolate_ap_iface("wlan1", _noop, quiet=True)
    assert rec.issued("-D", "FORWARD", "wlan1", "DROP")


def test_set_client_timeout_adds_mac_drop(rec):
    firewall.set_client_timeout("wlan1", "de:ad:be:ef:00:01", True, _noop)
    assert rec.issued("FORWARD", "--mac-source", "de:ad:be:ef:00:01", "DROP")


def test_iptables_backend_detects_nftables(monkeypatch):
    monkeypatch.setattr(firewall, "_run",
                        lambda *a, **k: _Result("iptables v1.8.9 (nf_tables)"))
    assert firewall.iptables_backend() == "nf_tables"


def test_ensure_forwarding_reports_stuck(monkeypatch):
    # sysctl always reads back 0 -> forwarding is "stuck", returns False
    monkeypatch.setattr(firewall, "_sysctl_read", lambda p: "0")
    monkeypatch.setattr(firewall, "_sysctl_write", lambda p, v: True)
    warned = []
    assert firewall.ensure_forwarding("wlan1", "eth0",
                                      lambda lvl, m: warned.append(m)) is False
    assert any("forwarding" in w.lower() for w in warned)


def test_ensure_forwarding_succeeds_when_enabled(monkeypatch):
    monkeypatch.setattr(firewall, "_sysctl_read", lambda p: "1")
    monkeypatch.setattr(firewall, "_sysctl_write", lambda p, v: True)
    assert firewall.ensure_forwarding("wlan1", "", _noop) is True


def test_verify_nat_fails_when_forwarding_off(monkeypatch):
    monkeypatch.setattr(firewall, "_sysctl_read", lambda p: "0")  # ip_forward=0
    monkeypatch.setattr(firewall, "_run", lambda *a, **k: _Result(returncode=1))
    monkeypatch.setattr(firewall, "detect_host_firewall", list)
    assert firewall.verify_nat("wlan1", "eth0", "192.168.50.0/24", _noop) is False
