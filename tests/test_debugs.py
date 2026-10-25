import io
import os
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from debugs import debug


def _capture(fn, *args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args)
    return buf.getvalue()

def test_debug_info_prints_message():
    out = _capture(debug, "info", "hello world")
    assert "hello world" in out
    assert "INFO" in out

def test_debug_all_levels_print():
    for level in ("info", "warn", "error", "ok", "debug", "critical"):
        out = _capture(debug, level, f"{level} msg")
        assert f"{level} msg" in out

def test_debug_uppercase_level_works():
    out = _capture(debug, "INFO", "uppercase test")
    assert "uppercase test" in out

def test_debug_handles_unknown_level_gracefully():
    out = _capture(debug, "nonexistent", "should not crash")
    assert "should not crash" in out