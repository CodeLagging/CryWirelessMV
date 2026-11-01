"""Behaviour tests for hostapd/dnsmasq config generation (pure string output)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC import confgen
from core.APCC.settings import DEFAULTS, validate_settings


def _settings(**overrides):
    s, _ = validate_settings(dict(DEFAULTS, **overrides))
    return s


# --- hostapd ---------------------------------------------------------------

def test_hostapd_has_core_directives():
    conf = confgen.generate_hostapd_conf(_settings(), "wlan1")
    assert "interface=wlan1" in conf
    assert f"ssid={DEFAULTS['ssid']}" in conf


def test_hostapd_open_network_has_no_psk():
    conf = confgen.generate_hostapd_conf(_settings(security="open"), "wlan1")
    assert "wpa_passphrase" not in conf


def test_hostapd_wpa2_has_passphrase_and_wpa():
    conf = confgen.generate_hostapd_conf(_settings(security="wpa2", psk="supersecret"), "wlan1")
    assert "wpa_passphrase=supersecret" in conf
    assert "wpa=" in conf


def test_hostapd_wpa3_enables_sae():
    conf = confgen.generate_hostapd_conf(_settings(security="wpa3", psk="supersecret"), "wlan1")
    assert "SAE" in conf or "sae" in conf


@pytest.mark.parametrize("band,channel", [("2.4", 6), ("5", 36)])
def test_hostapd_channel_matches_band(band, channel):
    conf = confgen.generate_hostapd_conf(_settings(band=band, channel=channel), "wlan1")
    assert f"channel={channel}" in conf


# --- dnsmasq ---------------------------------------------------------------

def test_dnsmasq_returns_conf_and_gateway():
    conf, gateway = confgen.generate_dnsmasq_conf(_settings(), "wlan1", "/tmp/leases")
    assert "interface=wlan1" in conf
    assert "dhcp-range=" in conf
    assert gateway.startswith("192.168.50.")


def test_dnsmasq_includes_extra_block_lines():
    conf, _ = confgen.generate_dnsmasq_conf(
        _settings(), "wlan1", "/tmp/leases",
        extra_lines=["address=/ads.example.com/"])
    assert "address=/ads.example.com/" in conf


def test_dnsmasq_sets_mtu_when_given():
    conf, _ = confgen.generate_dnsmasq_conf(_settings(), "wlan1", "/tmp/leases", mtu=1400)
    assert "1400" in conf


def test_dnsmasq_uses_upstream_dns():
    conf, _ = confgen.generate_dnsmasq_conf(
        _settings(), "wlan1", "/tmp/leases", upstream_dns=["1.1.1.1"])
    assert "server=1.1.1.1" in conf
