"""Subprocess helpers shared across the APCC network modules.

Every network operation shells out to system tools (`iptables`, `ip`, `iw`,
`nmcli`, ...). These two wrappers centralize that so a missing binary or a
hung command degrades to a warning instead of taking down a teardown path and
leaving the host's networking half-configured.
"""

import shlex
import subprocess


class _DummyResult:
    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 1


def _run(cmd, check=False, capture=True, timeout=8):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True,
                              check=check, timeout=timeout)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return _DummyResult()


def _run_checked(cmd, debug, what):
    res = _run(cmd)
    if res.returncode != 0:
        stderr = (res.stderr or "").strip()
        debug("warn", f"{what} failed (exit {res.returncode})"
                       f"{': ' + stderr if stderr else ''} — command: {' '.join(cmd)}")
    return res
