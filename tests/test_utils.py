import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_linter_config_exists():
    configs = [".ruff.toml", "ruff.toml", "pyproject.toml"]
    has_linter = any(os.path.isfile(os.path.join(ROOT_DIR, c)) for c in configs)
    assert has_linter, "No Ruff/linter configuration file found in root!"

def test_lockfile_exists():
    lockfiles = ["uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"]
    has_lock = any(os.path.isfile(os.path.join(ROOT_DIR, f)) for f in lockfiles)
    assert has_lock, "No lockfile found in root!"

def test_ci_workflow_exists():
    ci_path = os.path.join(ROOT_DIR, ".github", "workflows")
    assert os.path.isdir(ci_path), "No .github/workflows directory found!"
    yml_files = [f for f in os.listdir(ci_path) if f.endswith((".yml", ".yaml"))]
    assert len(yml_files) > 0, "No CI workflow YAML files found in .github/workflows/"

def test_tests_directory_exists():
    assert os.path.isdir(os.path.join(ROOT_DIR, "tests")), "No tests/ directory found!"

def test_readme_exists():
    readme_names = ["README.md", "README.rst", "README.txt", "readme.md"]
    has_readme = any(os.path.isfile(os.path.join(ROOT_DIR, r)) for r in readme_names)
    assert has_readme, "No README file found in root!"

def test_gitignore_exists():
    assert os.path.isfile(os.path.join(ROOT_DIR, ".gitignore")), "No .gitignore found!"

def test_security_policy_exists():
    assert os.path.isfile(os.path.join(ROOT_DIR, "SECURITY.md")), "No SECURITY.md found!"

def test_changelog_exists():
    assert os.path.isfile(os.path.join(ROOT_DIR, "CHANGELOG.md")), "No CHANGELOG.md found!"

def test_dependabot_config_exists():
    path = os.path.join(ROOT_DIR, ".github", "dependabot.yml")
    assert os.path.isfile(path), "No dependabot.yml found in .github/"