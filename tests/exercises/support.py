"""Helpers for the exercise acceptance tests."""

from mcp import Client

from ghidra_mcp import server
from ghidra_mcp.context import LoadedProgram, Status
from tests.program_fakes import FakeDecompiler, FakeProjectHandle


def loaded(name, program, decompiler=None) -> LoadedProgram:
    """A binary that is analyzed and open, backed by a fake program."""
    entry = LoadedProgram(name=name, pathname=f"/{name}", project=FakeProjectHandle(), status=Status.READY)
    entry.program = program
    entry.decompiler = decompiler or FakeDecompiler()
    return entry


async def call(tool, arguments):
    """Call a tool through MCP, as an agent would. Fails the test if the tool isn't registered."""
    async with Client(server.mcp) as client:
        registered = {t.name for t in (await client.list_tools()).tools}
        assert tool in registered, f"{tool} is not registered as a tool (see AGENTS.md)"
        return await client.call_tool(tool, arguments)


async def tool_names():
    async with Client(server.mcp) as client:
        return {tool.name for tool in (await client.list_tools()).tools}


def text(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


def structured(result):
    """The tool's structured result; fails the test with the tool's message if it errored."""
    assert not result.is_error, text(result)
    assert result.structured_content is not None, "the tool must return a pydantic model"
    return result.structured_content


