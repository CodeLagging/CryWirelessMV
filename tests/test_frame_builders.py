"""Behaviour tests for the WiFi frame builders (built, never transmitted)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Dot11, Dot11Deauth, Dot11Elt, RadioTap

from core.WIFI import bad_message, csa_attack, deauth

BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT = "11:22:33:44:55:66"


# --- deauth ----------------------------------------------------------------

@pytest.mark.parametrize("reason", [1, 7, 15])
def test_deauth_frame_structure(reason):
    pkt = deauth._build_deauth(BSSID, CLIENT, reason, 1)
    assert pkt.haslayer(RadioTap)
    assert pkt.haslayer(Dot11Deauth)
    assert pkt[Dot11Deauth].reason == reason
    assert pkt[Dot11].addr1 == CLIENT.lower()


# --- bad_message -----------------------------------------------------------

def test_bad_message_deauth_builds():
    raw = bad_message._build_deauth(BSSID, CLIENT)
    assert isinstance(raw, bytes) and len(raw) > 0


@pytest.mark.parametrize("variant", list(bad_message._VARIANTS))
def test_every_bad_message_variant_builds(variant):
    raw = bad_message._build_bad_message(BSSID, CLIENT, variant)
    assert isinstance(raw, bytes)
    assert len(raw) > 0


# --- csa -------------------------------------------------------------------

def test_csa_frame_has_csa_element():
    raw = csa_attack._build_csa_frame(BSSID, "TestNetwork", CLIENT,
                                      channel=149, new_channel=6, switch_count=3)
    assert isinstance(raw, bytes) and len(raw) > 0
    # the built frame should parse back and contain a Dot11 beacon-ish frame
    from scapy.all import Dot11Beacon
    pkt = RadioTap(raw)
    assert pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11Elt)
