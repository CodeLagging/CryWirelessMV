"""Tests for settings.validate_settings — the pure correct-and-warn logic."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC.settings import DEFAULTS, validate_settings


def _validate(**overrides):
    return validate_settings(dict(DEFAULTS, **overrides))


def _has_warning(warnings, needle):
    return any(needle.lower() in w.lower() for w in warnings)


# --- baseline --------------------------------------------------------------

def test_defaults_are_valid_no_warnings():
    corrected, warnings = _validate()
    assert warnings == []
    assert corrected["channel"] == 6


def test_input_dict_is_not_mutated():
    original = dict(DEFAULTS, channel=999)
    snapshot = dict(original)
    validate_settings(original)
    assert original == snapshot  # function copies, never mutates its argument


# --- security coupling -----------------------------------------------------

def test_open_blanks_psk_and_disables_pmf_sae():
    corrected, _ = _validate(security="open", psk="whatever", pmf="required", sae=True)
    assert corrected["psk"] == ""
    assert corrected["pmf"] == "disabled"
    assert corrected["sae"] is False


def test_wpa2_disables_sae():
    corrected, warnings = _validate(security="wpa2", sae=True)
    assert corrected["sae"] is False
    assert _has_warning(warnings, "sae")


def test_wpa2_downgrades_required_pmf():
    corrected, warnings = _validate(security="wpa2", pmf="required")
    assert corrected["pmf"] == "optional"
    assert _has_warning(warnings, "pmf")


def test_wpa3_forces_pmf_sae_and_ccmp():
    corrected, warnings = _validate(security="wpa3", pmf="optional", sae=False, cipher="tkip")
    assert corrected["pmf"] == "required"
    assert corrected["sae"] is True
    assert corrected["cipher"] == "ccmp"
    assert warnings  # several corrections warned


def test_transition_mode_forces_sae_and_pmf():
    corrected, warnings = _validate(security="wpa2/wpa3", pmf="disabled")
    assert corrected["sae"] is True
    assert corrected["pmf"] == "optional"
    assert _has_warning(warnings, "pmf")


def test_short_psk_reset_to_default():
    corrected, warnings = _validate(security="wpa2", psk="short")
    assert corrected["psk"] == "changeme123"
    assert _has_warning(warnings, "psk")


# --- channel ---------------------------------------------------------------

def test_channel_non_int_reset_to_6():
    corrected, warnings = _validate(channel="abc")
    assert corrected["channel"] == 6
    assert _has_warning(warnings, "channel")


def test_channel_invalid_24ghz_reset_to_6():
    corrected, warnings = _validate(band="2.4", channel=20)
    assert corrected["channel"] == 6
    assert _has_warning(warnings, "2.4ghz")


def test_channel_invalid_5ghz_reset_to_36():
    corrected, warnings = _validate(band="5", channel=37)
    assert corrected["channel"] == 36
    assert _has_warning(warnings, "5ghz")


def test_channel_valid_5ghz_passes():
    corrected, warnings = _validate(band="5", channel=149)
    assert corrected["channel"] == 149
    assert not _has_warning(warnings, "channel")


# --- ip range / dhcp -------------------------------------------------------

def test_bad_ip_range_reset_to_default():
    corrected, warnings = _validate(ip_range="not-a-network")
    assert corrected["ip_range"] == str(DEFAULTS["ip_range"])
    assert _has_warning(warnings, "ip range")


def test_dhcp_start_outside_network_reset():
    corrected, warnings = _validate(dhcp_start="10.0.0.5")  # not in 192.168.50.0/24
    assert corrected["dhcp_start"] == DEFAULTS["dhcp_start"]
    assert _has_warning(warnings, "dhcp_start")


# --- numeric bounds --------------------------------------------------------

def test_max_clients_zero_reset_to_10():
    corrected, warnings = _validate(max_clients=0)
    assert corrected["max_clients"] == 10
    assert _has_warning(warnings, "max_clients")


def test_beacon_interval_out_of_range_reset():
    corrected, warnings = _validate(beacon_interval=5)
    assert corrected["beacon_interval"] == 100
    assert _has_warning(warnings, "beacon")


def test_dtim_out_of_range_reset():
    corrected, warnings = _validate(dtim_period=999)
    assert corrected["dtim_period"] == 2
    assert _has_warning(warnings, "dtim")


def test_mtu_invalid_reset_to_zero():
    corrected, warnings = _validate(mtu=300)  # below 576 and not 0
    assert corrected["mtu"] == 0
    assert _has_warning(warnings, "mtu")


def test_mtu_valid_values_pass():
    assert _validate(mtu=0)[0]["mtu"] == 0
    assert _validate(mtu=1400)[0]["mtu"] == 1400


def test_rts_threshold_invalid_reset():
    corrected, warnings = _validate(rts_threshold=100)  # not -1, below 256
    assert corrected["rts_threshold"] == -1
    assert _has_warning(warnings, "rts")


# --- upstream dns ----------------------------------------------------------

def test_upstream_dns_filters_invalid_tokens():
    corrected, warnings = _validate(upstream_dns="8.8.8.8, bogus, 1.1.1.1")
    assert corrected["upstream_dns"] == "8.8.8.8,1.1.1.1"
    assert _has_warning(warnings, "bogus")


# --- second counters -------------------------------------------------------

def test_ap_max_inactivity_zero_reset_to_300():
    corrected, warnings = _validate(ap_max_inactivity=0)
    assert corrected["ap_max_inactivity"] == 300
    assert _has_warning(warnings, "idle timeout")


def test_negative_rekey_reset():
    corrected, warnings = _validate(wpa_group_rekey=-5)
    assert corrected["wpa_group_rekey"] == 600
    assert _has_warning(warnings, "rekey")


# --- channel width / phy coupling ------------------------------------------

def test_channel_width_invalid_reset_to_20():
    corrected, warnings = _validate(channel_width="99")
    assert corrected["channel_width"] == "20"
    assert _has_warning(warnings, "channel width")


def test_24ghz_wide_width_reset_to_20():
    corrected, warnings = _validate(band="2.4", channel_width="80")
    assert corrected["channel_width"] == "20"
    assert _has_warning(warnings, "20/40")


def test_vht_disabled_on_24ghz():
    corrected, warnings = _validate(band="2.4", vht_enabled=True)
    assert corrected["vht_enabled"] is False
    assert _has_warning(warnings, "vht")


def test_vht_requires_ht_enables_it():
    corrected, warnings = _validate(band="5", channel=36, vht_enabled=True, ht_enabled=False)
    assert corrected["ht_enabled"] is True
    assert _has_warning(warnings, "vht requires ht")
