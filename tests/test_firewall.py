"""Tests for the extracted firewall primitives.

These exercise the logic that does not require real iptables by driving the
module's `_run` wrapper through monkeypatching, so the command construction and
decision logic are covered without touching the host's firewall.
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


def test_iptables_backend_detects_nftables(monkeypatch):
    monkeypatch.setattr(firewall, "_run",
                        lambda *a, **k: _Result("iptables v1.8.9 (nf_tables)"))
    assert firewall.iptables_backend() == "nf_tables"


def test_iptables_backend_detects_legacy(monkeypatch):
    monkeypatch.setattr(firewall, "_run",
                        lambda *a, **k: _Result("iptables v1.8.7 (legacy)"))
    assert firewall.iptables_backend() == "legacy"


def test_iptables_backend_unknown_when_absent(monkeypatch):
    monkeypatch.setattr(firewall, "_run", lambda *a, **k: _Result("", returncode=1))
    assert firewall.iptables_backend() == "unknown"


def test_forward_policy_parses_drop(monkeypatch):
    chain = "Chain FORWARD (policy DROP)\n"
    monkeypatch.setattr(firewall, "_run", lambda *a, **k: _Result(chain))
    assert firewall._forward_policy() == "DROP"


def test_forward_policy_unknown_when_empty(monkeypatch):
    monkeypatch.setattr(firewall, "_run", lambda *a, **k: _Result(""))
    assert firewall._forward_policy() == "unknown"


def test_detect_host_firewall_flags_active_ufw(monkeypatch):
    def fake_run(cmd, *a, **k):
        if cmd[:2] == ["ufw", "status"]:
            return _Result("Status: active\n")
        return _Result("", returncode=1)
    monkeypatch.setattr(firewall, "_run", fake_run)
    names = [name for name, _advice in firewall.detect_host_firewall()]
    assert "ufw" in names


def test_detect_host_firewall_clean_when_nothing_running(monkeypatch):
    monkeypatch.setattr(firewall, "_run", lambda *a, **k: _Result("", returncode=1))
    assert firewall.detect_host_firewall() == []


def test_set_client_timeout_rejects_bad_iface():
    with pytest.raises(ValueError):
        firewall.set_client_timeout("bad iface!", "aa:bb:cc:dd:ee:ff", True, lambda *a: None)


def test_allow_ap_services_rejects_bad_iface():
    with pytest.raises(ValueError):
        firewall.allow_ap_services("eth0; rm -rf /", lambda *a: None)
