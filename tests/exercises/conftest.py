"""Setup shared by the exercise acceptance tests.

Every test here is marked ``exercise``: `mise run test` skips them, and `mise run check` (or
`mise run check:<exercise>`) runs them. They call tools through MCP, as an agent would, against
fake programs from tests/program_fakes.py, so no Ghidra is needed.
"""

import types
from pathlib import Path

import pytest

from ghidra_mcp import server
from ghidra_mcp import tools as tools_module
from tests.fakes import FakeContext
from tests.program_fakes import install_modules

EXERCISES = Path(__file__).parent


def pytest_collection_modifyitems(config, items):
    for item in items:
        if EXERCISES in Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.exercise)


@pytest.fixture(autouse=True)
def ghidra_stubs(monkeypatch):
    """Stand-ins for the Ghidra and JPype names the tools import (there is no JVM in these tests)."""
    install_modules(monkeypatch, {
        "ghidra.util.task": {
            "ConsoleTaskMonitor": lambda: "monitor",
            "TaskMonitor": types.SimpleNamespace(DUMMY="monitor"),
        },
        "ghidra.program.model.listing": {"CommentType": types.SimpleNamespace(EOL="EOL")},
    })

    class FakeJByte:
        """JByte[size] makes a Java byte[]; here it is a list that Memory.getBytes fills."""

        def __getitem__(self, size):
            return [0] * size

    monkeypatch.setattr(tools_module, "JByte", FakeJByte())


@pytest.fixture
def serve(monkeypatch):
    """serve(*entries): make the server answer for these binaries (LoadedPrograms) by name."""

    def _serve(*entries):
        ctx = FakeContext()
        ctx.programs = {entry.name: entry for entry in entries}
        monkeypatch.setattr(server.mcp, "_ghidra_context", ctx, raising=False)
        return ctx

    return _serve
