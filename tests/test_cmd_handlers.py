"""Tests for the pure command-parsing helpers in APCommandHandlersMixin."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC.ap_cmd_handlers import APCommandHandlersMixin

_onoff = APCommandHandlersMixin._onoff


def test_onoff_no_args_toggles():
    assert _onoff([], current=False) is True
    assert _onoff([], current=True) is False


@pytest.mark.parametrize("word", ["on", "1", "true", "yes", "enable", "enabled"])
def test_onoff_truthy_words(word):
    assert _onoff([word], current=False) is True


@pytest.mark.parametrize("word", ["off", "0", "false", "no", "disable", "disabled"])
def test_onoff_falsy_words(word):
    assert _onoff([word], current=True) is False


def test_onoff_is_case_insensitive():
    assert _onoff(["ON"], current=False) is True
    assert _onoff(["Off"], current=True) is False


def test_onoff_rejects_garbage():
    with pytest.raises(ValueError):
        _onoff(["maybe"], current=False)
