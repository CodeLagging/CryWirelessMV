import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.set_path import _find_venv_dir, _is_venv_dir, paths


def test_paths_returns_dict_with_expected_keys():
    result = paths(root_dir=os.getcwd())
    assert isinstance(result, dict)
    assert "BASE_DIR" in result
    assert "CORE_DIR" in result
    assert "VENV_DIR" in result
    assert isinstance(result["BASE_DIR"], Path)
    assert isinstance(result["CORE_DIR"], Path)

def test_paths_base_dir_matches_input():
    target = Path(os.getcwd()).resolve()
    result = paths(root_dir=target)
    assert result["BASE_DIR"] == target

def test_paths_core_dir_is_set_path_parent():
    result = paths(root_dir=os.getcwd())
    assert (result["CORE_DIR"] / "set_path.py").is_file()

def test_is_venv_dir_false_for_empty_dir(tmp_path):
    assert _is_venv_dir(tmp_path) is False

def test_is_venv_dir_true_for_linux_venv(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "activate").write_text("")
    (bin_dir / "python3").write_text("")
    assert _is_venv_dir(tmp_path) is True

def test_find_venv_dir_returns_none_when_absent(tmp_path):
    assert _find_venv_dir(tmp_path) is None

def test_find_venv_dir_finds_child_venv(tmp_path):
    child = tmp_path / "myenv"
    child.mkdir()
    bin_dir = child / "bin"
    bin_dir.mkdir()
    (bin_dir / "activate").write_text("")
    (bin_dir / "python").write_text("")
    found = _find_venv_dir(tmp_path)
    assert found == child