"""Tests for the CommandRouter dispatcher (exact / alias / unique-prefix match)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC.commands import CommandRouter


def _router():
    r = CommandRouter()
    r.register("radio", lambda a, k: None, "toggle radio", aliases=("r",))
    r.register("record", lambda a, k: None, "packet recording")
    r.register("status", lambda a, k: None, "show status", aliases=("st",))
    r.register("quit", lambda a, k: None, "exit", aliases=("exit", "x"))
    return r


# --- resolve ---------------------------------------------------------------

def test_resolve_exact_name():
    cmd, err = _router().resolve("status")
    assert err is None and cmd.name == "status"


def test_resolve_exact_alias():
    cmd, err = _router().resolve("x")
    assert err is None and cmd.name == "quit"


def test_resolve_is_case_insensitive():
    cmd, err = _router().resolve("STATUS")
    assert err is None and cmd.name == "status"


def test_resolve_unique_prefix():
    cmd, err = _router().resolve("qu")
    assert err is None and cmd.name == "quit"


def test_resolve_exact_alias_wins_over_prefix():
    cmd, err = _router().resolve("r")  # 'r' is an exact alias of radio
    assert err is None and cmd.name == "radio"


def test_resolve_ambiguous_prefix_two_commands():
    cmd, err = _router().resolve("ra")  # only 'radio' starts with 'ra'
    assert err is None and cmd.name == "radio"


def test_resolve_ambiguous_reports_all():
    r = CommandRouter()
    r.register("block", lambda a, k: None, "b")
    r.register("blockfile", lambda a, k: None, "bf")
    cmd, err = r.resolve("bl")
    assert cmd is None
    assert "ambiguous" in err and "block" in err and "blockfile" in err


def test_resolve_unknown_with_suggestion():
    cmd, err = _router().resolve("recrod")  # typo of 'record'
    assert cmd is None
    assert "did you mean" in err and "record" in err


def test_resolve_unknown_without_suggestion():
    cmd, err = _router().resolve("zzzzzz")
    assert cmd is None
    assert err == "unknown command: zzzzzz (try 'help')"


def test_alias_prefix_and_name_collapse_to_one_candidate():
    # 'st' is an alias of status AND 'status' starts with 'st'; both collapse.
    cmd, err = _router().resolve("st")
    assert err is None and cmd.name == "status"


# --- parse -----------------------------------------------------------------

def test_parse_blank_returns_none_none():
    assert _router().parse("   ") == (None, None)


def test_parse_none_returns_none_none():
    assert _router().parse(None) == (None, None)


def test_parse_splits_args():
    cmd, args = _router().parse("status foo bar")
    assert cmd.name == "status" and args == ["foo", "bar"]


def test_parse_command_with_no_args():
    cmd, args = _router().parse("quit")
    assert cmd.name == "quit" and args == []


def test_parse_unbalanced_quote_is_error():
    cmd, err = _router().parse('status "oops')
    assert cmd is None and err.startswith("parse error:")


def test_parse_propagates_resolve_error():
    cmd, err = _router().parse("nope")
    assert cmd is None and "unknown command" in err


# --- commands --------------------------------------------------------------

def test_commands_returns_name_sorted():
    names = [c.name for c in _router().commands()]
    assert names == sorted(names)
    assert set(names) == {"radio", "record", "status", "quit"}
