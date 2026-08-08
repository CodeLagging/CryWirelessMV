import os
import stat
import shutil
import subprocess
from pathlib import Path

DEPS_DIR = Path(__file__).resolve().parent / "scannerap_deps"



REQUIRED_FILES = {
    "hostapd": "usr/sbin/hostapd",
    "hostapd_cli": "usr/sbin/hostapd_cli",
    "dnsmasq": "usr/sbin/dnsmasq",
}


def _run(cmd, cwd=None, timeout=60):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                               check=False, timeout=timeout)
    except Exception as e:
        class _Failed:
            returncode = 1
            stdout = ""
            stderr = str(e)
        return _Failed()


def _bin_path(name):
    return DEPS_DIR / REQUIRED_FILES[name]


def _check_integrity(debug):
    if not DEPS_DIR.is_dir():
        return False
    for name, rel in REQUIRED_FILES.items():
        p = DEPS_DIR / rel
        if not p.is_file():
            debug("warn", f"scannerap_deps integrity check: missing {rel}")
            return False
        if not os.access(p, os.X_OK):
            debug("warn", f"scannerap_deps integrity check: {rel} is not executable")
            return False
        if p.stat().st_size == 0:
            debug("warn", f"scannerap_deps integrity check: {rel} is empty")
            return False
        res = _run([str(p), "-v"], timeout=5)



        if not (res.stdout.strip() or res.stderr.strip()):
            debug("warn", f"scannerap_deps integrity check: {rel} produced no "
                           "output running '-v' — likely corrupted or "
                           "incompatible with this system")
            return False
    return True


def _download_and_extract(packages, debug):
    apt_bin = shutil.which("apt-get") or shutil.which("apt")
    dpkg_deb = shutil.which("dpkg-deb")
    if not apt_bin or not dpkg_deb:
        return False

    res = _run([apt_bin, "download", *packages], cwd=str(DEPS_DIR), timeout=120)
    debs = list(DEPS_DIR.glob("*.deb"))
    if res.returncode != 0 or not debs:
        debug("warn", f"Could not download {' '.join(packages)}: "
                       f"{res.stderr.strip() or 'no .deb produced'}")
        return False

    for deb in debs:
        res = _run([dpkg_deb, "-x", str(deb), str(DEPS_DIR)], timeout=30)
        if res.returncode != 0:
            debug("warn", f"Failed to extract {deb.name}: {res.stderr.strip()}")
        try:
            deb.unlink()
        except Exception:
            pass
    return True


def _install(debug):
    if DEPS_DIR.exists():
        shutil.rmtree(DEPS_DIR, ignore_errors=True)
    DEPS_DIR.mkdir(parents=True, exist_ok=True)

    apt_bin = shutil.which("apt-get") or shutil.which("apt")
    dpkg_deb = shutil.which("dpkg-deb")
    if not apt_bin or not dpkg_deb:
        debug("critical",
              "No supported package manager found for automatic install "
              "(currently supports Debian/Ubuntu's apt + dpkg only). "
              f"Extract hostapd/hostapd_cli/dnsmasq into {DEPS_DIR} "
              "yourself, e.g.:\n"
              f"    mkdir -p {DEPS_DIR} && cd {DEPS_DIR}\n"
              "    apt download hostapd dnsmasq-base\n"
              "    for f in *.deb; do dpkg -x \"$f\" .; done")
        return False

    debug("info", f"Installing hostapd/dnsmasq into {DEPS_DIR} (local only, "
                   "not system-wide)...")








    if not _download_and_extract(["hostapd", "dnsmasq-base"], debug):
        return False




    if not _bin_path("dnsmasq").is_file():
        debug("info", "dnsmasq binary not found after dnsmasq-base — "
                       "trying the 'dnsmasq' package name as a fallback...")
        _download_and_extract(["dnsmasq"], debug)

    for name in REQUIRED_FILES:
        p = _bin_path(name)
        if p.is_file():
            mode = p.stat().st_mode
            p.chmod(mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    debug("ok", f"Installed hostapd/dnsmasq locally under {DEPS_DIR}.")
    return True


def startup_module(debug):
    if _check_integrity(debug):
        debug("info", f"scannerap_deps looks good at {DEPS_DIR} — skipping install.")
        return True

    debug("warn", f"{DEPS_DIR} missing or failed its integrity check — "
                   "(re)installing...")
    if not _install(debug):
        return False

    if not _check_integrity(debug):
        debug("critical", "Install completed but the integrity check still failed.")
        return False

    return True


def get_bin(name):
    p = _bin_path(name)
    if not p.is_file():
        raise RuntimeError(
            f"{name} not found under {DEPS_DIR} — startup_module() "
            "hasn't been run or didn't succeed. This tool never falls "
            "back to a system-wide install.")
    return str(p)
