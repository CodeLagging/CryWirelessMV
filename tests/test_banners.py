import io
import os
import sys
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import banner


def test_check_os_passes_on_linux():
    with patch("platform.system", return_value="Linux"):
        banner.check_os()

def test_check_os_exits_on_windows():
    with patch("platform.system", return_value="Windows"):
        try:
            banner.check_os()
        except SystemExit as e:
            assert e.code == 1
        else:
            raise AssertionError("check_os() did not exit on Windows")

def test_print_banner_does_not_crash():
    buf = io.StringIO()
    with redirect_stdout(buf):
        banner.print_banner()
    assert buf.getvalue() != ""

def test_banner_menu_functions_run():
    for fn in (banner.bluetooth, banner.scan_results, banner.ble_menu,
               banner.wifi_attack, banner.other_attacks):
        buf = io.StringIO()
        with redirect_stdout(buf):
            fn()
        assert buf.getvalue() != ""