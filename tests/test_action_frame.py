"""Behaviour tests for the 802.11 action-frame builders (built, not transmitted)."""

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

af = importlib.import_module("core.WIFI.action_frame")

BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT = "11:22:33:44:55:66"


@pytest.mark.parametrize("key", list(af._BUILDERS))
def test_every_builder_produces_a_frame(key):
    action_key, _, variant_key = key.partition(":")
    raw = af._build_action_frame(action_key, variant_key, BSSID, CLIENT)
    assert raw is not None
    assert isinstance(raw, bytes)
    assert len(raw) > 0


def test_unknown_action_key_returns_none():
    assert af._build_action_frame("does-not-exist", "", BSSID, CLIENT) is None


def test_variant_falls_back_to_base_builder():
    # an unknown variant on a known action key falls back to the base entry
    base = af._resolve_builder("12", "")
    fallback = af._resolve_builder("12", "nonsense-variant")
    assert fallback is base


def test_variant_selects_distinct_builder():
    assert af._resolve_builder("14", "multi") is not af._resolve_builder("14", "")
