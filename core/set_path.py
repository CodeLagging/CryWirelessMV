from __future__ import annotations
import os
import sys
import glob
from pathlib import Path


def _get_main_dir() -> Path:
    main_mod = sys.modules.get("__main__")
    if main_mod is not None and getattr(main_mod, "__file__", None):
        return Path(main_mod.__file__).resolve().parent
    return Path.cwd()


def _is_venv_dir(d: Path) -> bool:
    bin_dir = d / "bin"
    if bin_dir.is_dir() and (bin_dir / "activate").exists() and \
            ((bin_dir / "python3").exists() or (bin_dir / "python").exists()):
        return True
    scripts_dir = d / "Scripts"
    if scripts_dir.is_dir() and (scripts_dir / "activate.bat").exists() and \
            (scripts_dir / "python.exe").exists():
        return True
    return False


def _find_venv_dir(root_dir: Path) -> Path | None:
    if _is_venv_dir(root_dir):
        return root_dir
    try:
        for child in root_dir.iterdir():
            if child.is_dir() and _is_venv_dir(child):
                return child
    except OSError:
        pass
    return None


def _venv_site_packages(venv_dir: Path) -> list[str]:
    found = []
    for pat in (
        str(venv_dir / "lib" / "*" / "site-packages"),
        str(venv_dir / "lib64" / "*" / "site-packages"),
        str(venv_dir / "Lib" / "site-packages"),
    ):
        found.extend(glob.glob(pat))
    return found


def paths(root_dir: str | Path | None = None):
    core_dir = Path(__file__).resolve().parent
    base_dir = Path(root_dir).resolve() if root_dir is not None else _get_main_dir()

    sys_paths = [str(core_dir), str(base_dir)]
    venv_dir = _find_venv_dir(base_dir)
    if venv_dir:
        sys_paths += _venv_site_packages(venv_dir)

    sys.path[:0] = sys_paths
    seen, deduped = set(), []
    for p in sys.path:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    sys.path[:] = deduped

    os.environ["PYTHONPATH"] = os.pathsep.join(
        sys_paths + [os.environ.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)

    result = {"BASE_DIR": base_dir, "CORE_DIR": core_dir, "VENV_DIR": venv_dir}
    for name, p in result.items():
        setattr(paths, name, p)
    paths.ALL = result
    return result


if __name__ == "__main__":
    print(paths())