#!/usr/bin/env python3
"""Assert the dependency manifests agree.

repo tooling sometimes misreads a project's direct dependencies; this makes the
contract explicit and gate-able. It confirms pyproject.toml declares its runtime
deps in standard PEP 621 form and that every one of them is present in the
lockfile-derived requirements.txt. Exits non-zero on any mismatch.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def dep_name(spec: str) -> str:
    """Normalize a requirement line to its canonical package name."""
    head = re.split(r"[<>=!~;\[ ]", spec.strip(), maxsplit=1)[0]
    return head.lower().replace("_", "-")


def direct_deps() -> set[str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    deps = data.get("project", {}).get("dependencies", [])
    return {dep_name(d) for d in deps}


def requirements_deps() -> set[str]:
    names = set()
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.add(dep_name(line))
    return names


def main() -> int:
    direct = direct_deps()
    if not direct:
        print("ERROR: pyproject.toml [project.dependencies] is empty or non-standard")
        return 1

    locked = requirements_deps()
    missing = sorted(direct - locked)
    if missing:
        print(f"ERROR: direct deps missing from requirements.txt: {missing}")
        return 1

    print(f"OK: {len(direct)} direct deps all present in requirements.txt "
          f"({len(locked)} packages locked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
