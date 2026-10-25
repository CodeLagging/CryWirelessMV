import os
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_SCRIPT = os.path.join(ROOT_DIR, "main.py")

def test_main_script_exists():
    assert os.path.isfile(MAIN_SCRIPT), "main.py is missing from the root directory!"

def test_cli_help_command():
    result = subprocess.run(
        [sys.executable, MAIN_SCRIPT, "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT_DIR,
        timeout=10
    )
    assert result.returncode in [0, 1, 2]
    assert "Traceback (most recent call last)" not in result.stderr

def test_cli_no_args_does_not_crash():
    result = subprocess.run(
        [sys.executable, MAIN_SCRIPT],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT_DIR,
        input="exit\n",
        timeout=10
    )
    assert "Traceback (most recent call last)" not in result.stderr