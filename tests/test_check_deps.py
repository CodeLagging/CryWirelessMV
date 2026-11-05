"""Tests for scripts/check_deps.py (dependency-manifest consistency)."""

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

import check_deps


@pytest.mark.parametrize("spec,expected", [
    ("colorama==0.4.6", "colorama"),
    ("dbus-next>=0.2.3", "dbus-next"),
    ("PyYAML==6.0.3", "pyyaml"),
    ("macholib==1.16.4 ; sys_platform == 'darwin'", "macholib"),
    ("some_pkg[extra]>=1.0", "some-pkg"),
])
def test_dep_name_normalization(spec, expected):
    assert check_deps.dep_name(spec) == expected


def test_live_manifests_are_consistent():
    # the real project's pyproject direct deps must all be in requirements.txt
    assert check_deps.direct_deps()  # non-empty (PEP 621 standard)
    assert check_deps.direct_deps() <= check_deps.requirements_deps()


def test_main_exits_zero_on_the_real_repo():
    assert check_deps.main() == 0
