import os
import subprocess
import shlex
import resource
from pathlib import Path


class _DummyResult:
    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 1


def _run(cmd, check=False, capture=True):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True, check=check)
    except (FileNotFoundError, OSError):
        return _DummyResult()


CGROUP_ROOT = Path("/sys/fs/cgroup")
CGROUP_NAME = "scannerap"













RESOURCE_PROFILES = {
    "lowest":   {"memory_mb": 96,   "cpu_percent": 15,  "max_open_files": 256,  "pps_limit": 150},
    "low":      {"memory_mb": 160,  "cpu_percent": 30,  "max_open_files": 512,  "pps_limit": 500},
    "normal":   {"memory_mb": 256,  "cpu_percent": 50,  "max_open_files": 1024, "pps_limit": 1500},
    "high":     {"memory_mb": 512,  "cpu_percent": 80,  "max_open_files": 2048, "pps_limit": 6000},
    "highest":  {"memory_mb": 1024, "cpu_percent": 100, "max_open_files": 4096, "pps_limit": 20000},
    "uncapped": {"memory_mb": None, "cpu_percent": None, "max_open_files": None, "pps_limit": None},
}
PROFILE_NAMES = list(RESOURCE_PROFILES.keys())


def _cgroup_v2_available():
    return (CGROUP_ROOT / "cgroup.controllers").is_file()


def _setup_cgroup(profile, debug):
    if not _cgroup_v2_available():
        debug("warn", "cgroup v2 not available on this system — memory/CPU "
                       "ceiling will only be a soft Python-side limit, not "
                       "kernel-enforced. (iptables packet-rate limiting "
                       "still applies regardless.)")
        return

    cg_dir = CGROUP_ROOT / CGROUP_NAME
    try:
        cg_dir.mkdir(exist_ok=True)

        avail = (CGROUP_ROOT / "cgroup.controllers").read_text().split()
        want = [c for c in ("memory", "cpu") if c in avail]
        (CGROUP_ROOT / "cgroup.subtree_control").write_text(
            " ".join(f"+{c}" for c in want))

        if profile["memory_mb"] is not None:
            (cg_dir / "memory.max").write_text(str(profile["memory_mb"] * 1024 * 1024))
        else:
            (cg_dir / "memory.max").write_text("max")

        if profile["cpu_percent"] is not None:
            period = 100000
            quota = int(period * profile["cpu_percent"] / 100)
            (cg_dir / "cpu.max").write_text(f"{quota} {period}")
        else:
            (cg_dir / "cpu.max").write_text("max 100000")

        (cg_dir / "cgroup.procs").write_text(str(os.getpid()))
        debug("ok", f"cgroup limits applied: memory={profile['memory_mb']}MB "
                       f"cpu={profile['cpu_percent']}%")
    except Exception as e:
        debug("warn", f"Could not apply cgroup limits: {e}")


def _teardown_cgroup(debug):
    if not _cgroup_v2_available():
        return
    cg_dir = CGROUP_ROOT / CGROUP_NAME
    try:
        if cg_dir.is_dir():
            (CGROUP_ROOT / "cgroup.procs").write_text(str(os.getpid()))
            cg_dir.rmdir()
    except Exception:
        pass


_original_nofile = None





def _apply_rlimits(profile, debug):
    global _original_nofile
    try:
        if profile["max_open_files"] is not None:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if _original_nofile is None:
                _original_nofile = (soft, hard)
            new_soft = min(profile["max_open_files"], hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))










    except Exception as e:
        debug("warn", f"Could not apply rlimits: {e}")


def _restore_rlimits(debug):
    if _original_nofile is None:
        return
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, _original_nofile)
    except Exception as e:
        debug("warn", f"Could not restore rlimits: {e}")


def _setup_pps_limit(iface, pps, debug):
    if pps is None:
        return


    _run(["iptables", "-D", "INPUT", "-i", iface, "-m", "hashlimit",
          "--hashlimit-above", f"{pps}/sec", "--hashlimit-mode", "srcip",
          "--hashlimit-name", "scannerap_pps", "-j", "DROP"])
    res = _run(["iptables", "-I", "INPUT", "-i", iface, "-m", "hashlimit",
                "--hashlimit-above", f"{pps}/sec", "--hashlimit-mode", "srcip",
                "--hashlimit-name", "scannerap_pps", "-j", "DROP"])
    if res.returncode == 0:
        debug("ok", f"Packet-rate limit applied: {pps}pps per source on {iface}")
    else:
        debug("warn", f"Could not apply packet-rate limit: {res.stderr.strip()}")


def _teardown_pps_limit(iface, debug):
    _run(["iptables", "-D", "INPUT", "-i", iface, "-m", "hashlimit",
          "--hashlimit-above", "1/sec", "--hashlimit-mode", "srcip",
          "--hashlimit-name", "scannerap_pps", "-j", "DROP"])


    for _ in range(5):
        res = _run(["iptables", "-D", "INPUT", "-i", iface, "-m", "hashlimit",
                     "--hashlimit-name", "scannerap_pps", "-j", "DROP"])
        if res.returncode != 0:
            break


def exclude_pid_from_limits(pid, debug):
    if not _cgroup_v2_available():
        return
    try:
        (CGROUP_ROOT / "cgroup.procs").write_text(str(pid))
    except Exception as e:
        debug("warn", f"Could not exclude pid {pid} from resource limits: {e}")


def apply_profile(profile_name, iface, debug):
    profile = RESOURCE_PROFILES.get(profile_name, RESOURCE_PROFILES["normal"])
    if profile_name == "uncapped":
        debug("info", "Resource profile: uncapped — no limits applied.")
        return
    _setup_cgroup(profile, debug)
    _apply_rlimits(profile, debug)
    _setup_pps_limit(iface, profile["pps_limit"], debug)


def remove_limits(iface, debug):
    _teardown_pps_limit(iface, debug)
    _teardown_cgroup(debug)
    _restore_rlimits(debug)
