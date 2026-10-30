"""Tests for the pure domain-filter parsing and domain-control decision logic."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.APCC.domain_control import DomainControl
from core.APCC.domain_filter import (
    BadPattern,
    DomainFilter,
    _flatten_json,
    _parse_text_line,
    compile_pattern,
)

# --- compile_pattern -------------------------------------------------------

def test_compile_plain_domain_exact_match():
    rx = compile_pattern("example.com")
    assert rx.match("example.com")
    assert not rx.match("sub.example.com")


def test_compile_is_lowercased_and_dot_stripped():
    rx = compile_pattern("EXAMPLE.COM.")
    assert rx.match("example.com")


def test_compile_bare_wildcard_matches_any_prefix():
    rx = compile_pattern("*.example.com")
    assert rx.match("a.example.com")
    assert rx.match("deep.sub.example.com")
    assert not rx.match("example.com")


def test_compile_digit_wildcard_class():
    rx = compile_pattern("*1.example.com")  # *1 -> [0-9]*
    assert rx.match("123.example.com")
    assert not rx.match("abc.example.com")


def test_compile_alpha_wildcard_class():
    rx = compile_pattern("cdn*2.example.com")  # *2 -> [A-Za-z]*
    assert rx.match("cdnedge.example.com")
    assert not rx.match("cdn9.example.com")


def test_compile_empty_raises_badpattern():
    with pytest.raises(BadPattern):
        compile_pattern("   ")


def test_badpattern_is_valueerror():
    assert issubclass(BadPattern, ValueError)


# --- _parse_text_line ------------------------------------------------------

@pytest.mark.parametrize("line,expected", [
    ("example.com", ["example.com"]),
    ("  spaced.com  ", ["spaced.com"]),
    ("# a comment", []),
    ("", []),
    ("domain.com # trailing comment", ["domain.com"]),
    ("0.0.0.0 ads.example.com", ["ads.example.com"]),
    ("127.0.0.1 a.com b.com", ["a.com", "b.com"]),
])
def test_parse_text_line(line, expected):
    assert _parse_text_line(line) == expected


# --- _flatten_json ---------------------------------------------------------

def test_flatten_json_nested():
    data = {"a": ["x.com", {"b": "y.com"}], "c": "z.com"}
    assert sorted(_flatten_json(data)) == ["x.com", "y.com", "z.com"]


def test_flatten_json_plain_string():
    assert _flatten_json("only.com") == ["only.com"]


# --- _suffixes -------------------------------------------------------------

def test_suffixes_walks_up_the_domain():
    assert list(DomainFilter._suffixes("a.b.example.com")) == [
        "a.b.example.com", "b.example.com", "example.com", "com",
    ]


# --- DomainControl (tmp_path -> no shared state) ----------------------------

def test_add_block_then_in_blocked(tmp_path):
    dc = DomainControl(tmp_path)
    assert dc.add_block("Example.COM.") == ("ok", None)
    assert "example.com" in dc.blocked


def test_add_block_conflicts_with_redirect(tmp_path):
    dc = DomainControl(tmp_path)
    dc.add_redirect("example.com", "http://1.2.3.4")
    status, extra = dc.add_block("example.com")
    assert status == "conflict" and extra == "http://1.2.3.4"


def test_add_redirect_conflicts_with_block(tmp_path):
    dc = DomainControl(tmp_path)
    dc.add_block("example.com")
    assert dc.add_redirect("example.com", "http://x") == ("conflict", None)


def test_reset_removes_and_reports(tmp_path):
    dc = DomainControl(tmp_path)
    dc.add_block("example.com")
    assert dc.reset("example.com") == "ok"
    assert "example.com" not in dc.blocked
    assert dc.reset("example.com") == "not_found"


def test_generate_dnsmasq_lines(tmp_path):
    dc = DomainControl(tmp_path)
    dc.add_block("blocked.com")
    dc.add_redirect("redir.com", "ignored")

    class _FakeFilter:
        def raw_patterns_for_file(self, fname):
            return []

    lines = dc.generate_dnsmasq_lines(_FakeFilter(), "192.168.50.1")
    assert "address=/blocked.com/" in lines
    assert "address=/redir.com/192.168.50.1" in lines
