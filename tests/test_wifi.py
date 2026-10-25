import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_scapy_dependency():
    try:
        import scapy
        assert hasattr(scapy, "__version__")
    except ImportError:
        pytest.fail("Scapy is missing!")

def test_wifi_modules_import():
    modules = [
        "core.WIFI.handshake_module",
        "core.wifi_module",
        "core.WIFI.scanner",
        "core.WIFI.probe_dos",
        "core.WIFI.quiet_device"
    ]
    for mod in modules:
        try:
            __import__(mod)
        except ImportError as e:
            pytest.fail(f"Failed to import {mod}: {e}")

@patch("subprocess.run")
def test_subprocess_handling(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
    try:
        from core.wifi_module import ModuleSetup
        ModuleSetup()
    except ImportError:
        pytest.skip("ModuleSetup not found")
    except (RuntimeError, OSError) as e:
        pytest.fail(f"ModuleSetup crashed on init: {e}")