"""Unit tests for the pure, side-effect-free helpers in netops.

These functions drive the MTU/MSS black-hole mitigations, so a regression here
silently breaks "connects but pages don't load" for every bridged client.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC import netops
from core.APCC.diag import _first_host
from core.APCC.netops import (
    DEFAULT_MTU,
    MIN_MTU,
    MSS_OVERHEAD,
    _mss_for,
    resolve_client_mtu,
)

# --- _mss_for --------------------------------------------------------------

def test_mss_for_standard_mtu():
    assert _mss_for(1500) == 1500 - MSS_OVERHEAD  # 1460


def test_mss_for_reduced_mtu():
    assert _mss_for(1400) == 1400 - MSS_OVERHEAD  # 1360


def test_mss_for_never_below_floor():
    # Tiny MTU must not drop MSS below the 536 TCP floor.
    assert _mss_for(100) == 536
    assert _mss_for(576) == 536


def test_mss_for_caps_at_default():
    # Jumbo frame must not advertise an MSS above the 1500-derived cap.
    assert _mss_for(9000) == DEFAULT_MTU - MSS_OVERHEAD


# --- resolve_client_mtu ----------------------------------------------------

def test_resolve_client_mtu_explicit_setting_wins():
    assert resolve_client_mtu("", configured=1400) == 1400


def test_resolve_client_mtu_caps_explicit_at_default():
    assert resolve_client_mtu("", configured=9000) == DEFAULT_MTU


def test_resolve_client_mtu_ignores_too_small_configured():
    # Below MIN_MTU is ignored; with no detectable iface it falls to default.
    assert resolve_client_mtu("", configured=100) == DEFAULT_MTU


def test_resolve_client_mtu_default_when_nothing_known():
    assert resolve_client_mtu("", configured=0) == DEFAULT_MTU


@pytest.mark.parametrize("bad", [None, "x", -5])
def test_resolve_client_mtu_handles_garbage_configured(bad):
    assert resolve_client_mtu("", configured=bad) == DEFAULT_MTU


def test_resolve_client_mtu_uses_detected_iface_mtu(monkeypatch):
    monkeypatch.setattr(netops, "iface_mtu", lambda iface: 1280)
    assert resolve_client_mtu("eth0", configured=0) == 1280


def test_resolve_client_mtu_rejects_detected_below_min(monkeypatch):
    monkeypatch.setattr(netops, "iface_mtu", lambda iface: MIN_MTU - 1)
    assert resolve_client_mtu("eth0", configured=0) == DEFAULT_MTU


# --- _first_host -----------------------------------------------------------

def test_first_host_returns_gateway_address():
    assert _first_host("192.168.50.0/24") == "192.168.50.1"


def test_first_host_handles_host_bits_set():
    assert _first_host("10.0.0.5/8") == "10.0.0.1"


@pytest.mark.parametrize("bad", ["garbage", "", "999.1.1.1/24"])
def test_first_host_returns_none_on_bad_input(bad):
    assert _first_host(bad) is None
