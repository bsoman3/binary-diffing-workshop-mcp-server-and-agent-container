"""Packaging metadata and the mise setup."""

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
PROJECT = PYPROJECT["project"]
DEPS = PROJECT["dependencies"]


def _mise() -> dict:
    return tomllib.loads((ROOT / "mise.toml").read_text())


def _dep(name):
    return next((d for d in DEPS if re.match(rf"{name}(\[|[<>=!~ ]|$)", d)), None)


def test_requires_python_311_or_later():
    assert PROJECT["requires-python"] == ">=3.11"


def test_requires_mcp_sdk_2_3_within_major_version_2():
    mcp = _dep("mcp")
    assert mcp is not None
    assert ">=2.3" in mcp and "<3" in mcp


def test_ghidrecomp_is_an_optional_extra():
    assert _dep("ghidrecomp") is None
    extras = PROJECT.get("optional-dependencies", {})
    assert any(any(d.startswith("ghidrecomp") for d in group) for group in extras.values())


def test_direct_dependencies_and_single_sourced_version():
    assert _dep("pydantic") is not None
    assert _dep("jpype1") is not None
    assert "version" not in PROJECT
    assert "version" in PROJECT.get("dynamic", [])


def test_console_script_and_module_entry_points():
    assert PROJECT["scripts"]["ghidra-mcp"] == "ghidra_mcp.server:main"
    result = subprocess.run(
        [sys.executable, "-m", "ghidra_mcp", "--version"], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    from ghidra_mcp import __version__

    assert __version__ in result.stdout


def test_mise_provides_python_and_a_project_venv_and_requires_ghidra_and_jdk_paths():
    mise = _mise()
    assert mise["tools"] == {"python": "3.13"}  # Ghidra and the JDK are paths, not mise tools
    env = mise["env"]
    # uv (which mise uses when installed) leaves pip out of new venvs unless asked to seed it
    assert env["_"]["python"]["venv"] == {"path": ".venv", "create": True, "uv_create_args": ["--seed"]}
    for var in ("GHIDRA_INSTALL_DIR", "JAVA_HOME", "GHIDRA_WORKSHOP_DIR"):
        assert "mise.local.toml" in env[var]["required"]


def test_mise_tasks_install_test_and_serve():
    tasks = _mise()["tasks"]
    assert tasks["install"]["run"] == 'python -m pip install -e ".[ghidrecomp,dev]"'  # the venv's own pip
    assert tasks["test"]["run"] == 'pytest -m "not integration and not exercise"'
    assert tasks["check"]["run"] == "pytest tests/exercises"
    assert tasks["test:integration"]["run"] == "pytest -m integration"
    assert tasks["test:gui"]["run"] == "pytest -m gui"
    assert tasks["test:gui"]["env"] == {"GHIDRA_MCP_GUI_TESTS": "1"}
    assert tasks["serve"]["run"] == "ghidra-mcp"
    assert tasks["gui"]["run"] == "ghidra-mcp --gui"
    # raw: mise delivers Ctrl+C once and lets the server finish closing the project
    assert tasks["serve"]["raw"] is True and tasks["gui"]["raw"] is True


def test_local_paths_come_from_an_ignored_mise_local_toml():
    example = tomllib.loads((ROOT / "mise.local.toml.example").read_text())
    assert {"GHIDRA_INSTALL_DIR", "JAVA_HOME", "GHIDRA_WORKSHOP_DIR"} <= set(example["env"])
    assert "mise.local.toml" in (ROOT / ".gitignore").read_text().split()
