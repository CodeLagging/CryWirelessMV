"""Assert the security/governance docs exist and carry real content."""

import os
from pathlib import Path

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    return Path(ROOT_DIR, *parts).read_text(encoding="utf-8")


def _nonempty(*parts, min_chars=200):
    path = Path(ROOT_DIR, *parts)
    assert path.is_file(), f"{os.path.join(*parts)} is missing"
    assert len(path.read_text(encoding="utf-8").strip()) >= min_chars, (
        f"{os.path.join(*parts)} exists but is too short to be a real document"
    )


def test_security_policy_present_and_substantial():
    _nonempty("SECURITY.md")


def test_threat_model_present_and_substantial():
    _nonempty("THREAT_MODEL.md")


def test_changelog_present_and_substantial():
    _nonempty("CHANGELOG.md")


def test_threat_model_covers_key_boundaries():
    text = _read("THREAT_MODEL.md").lower()
    for keyword in ("validate_iface", "root", "scapy", "shell=true"):
        assert keyword in text, f"THREAT_MODEL.md should mention {keyword!r}"
