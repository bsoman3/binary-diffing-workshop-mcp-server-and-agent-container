"""Queries: listings, searches, code views, references, disclosure, partial results."""

import pytest
from mcp import Client

from ghidra_mcp import server
from ghidra_mcp.errors import Stop
from tests.program_fakes import (
    Addr,
    Data,
    DecompileResult,
    FakeDecompiler,
    FakeProgram,
    Function,
    Instruction,
    MemoryBlock,
    Reference,
    Symbol,
    install_modules,
    tools_for,
)
from tests.fakes import FakeContext

EXT_PUTS = Function("puts", Addr(0x20, "EXTERNAL"), namespace="libc.so.6", external=True)
EOL = "EOL"

QUERY_TOOLS = [
    "list_functions", "list_segments", "get_function_by_address", "decompile_function",
    "disassemble_function", "list_cross_references", "search_strings",
]


def make_program():
    return FakeProgram(
        functions=[
            Function("main", 0x401000, size=0x10),
            Function("helper", 0x401100, size=0x20),
            Function("puts", 0x401200, thunk_of=EXT_PUTS),
            EXT_PUTS,
            Function("method", 0x401300, namespace="Foo"),
        ],
        symbols=[
            Symbol("Foo", 0x0, symbol_type="Class"),
            Symbol("std", 0x0, symbol_type="Namespace"),
            Symbol("libc.so.6", 0x0, symbol_type="Library"),
            Symbol("_start", 0x401400, entry_point=True),
            Symbol("_init", 0x401500, entry_point=True),
            Symbol("g_count", 0x404000),
        ],
        memory=[
            MemoryBlock(".text", 0x401000, 0x1000, perms="rx"),
            MemoryBlock(".data", 0x404000, 0x2000, perms="rw"),
            MemoryBlock(".bss", 0x406000, 0x100, perms="rw", initialized=False),
            MemoryBlock(".none", 0x407000, 0x100, perms=""),
        ],
        defined_data=[
            Data(0x404000, label="g_count", value=5, type_name="int"),
            Data(0x404010, label=None, value=None, type_name="undefined4"),
            Data(0x404020, label="g_bad", value=RuntimeError("corrupt value")),
            Data(0x404030, label="g_last", value="x", type_name="char"),
        ],
        instructions=[
            Instruction(0x401000, b"\x55", "PUSH", ("RBP",)),
            Instruction(0x401001, b"\x48\x89\xe5", "MOV", ("RBP", "RSP")),
            Instruction(0x401004, RuntimeError("no bytes"), "RET", RuntimeError("no operands")),
            Instruction(0x401100, b"\xc3", "RET"),
        ],
        comments={
            (EOL, Addr(0x401001)): "set up frame",
            (EOL, Addr(0x401004)): RuntimeError("comment unreadable"),
        },
        references=[
            Reference(0x401005, 0x401100),
            Reference(0x401105, 0x404000, "READ"),
            Reference(0x401106, 0x404000, "WRITE"),
        ],
        strings=[
            Data(0x405000, value="Hello World"),
            Data(0x405010, value="hello again"),
            Data(0x405020, value=RuntimeError("bad encoding")),
            Data(0x405030, value="other"),
        ],
    )


@pytest.fixture
def program():
    return make_program()


@pytest.fixture
def decompiler():
    return FakeDecompiler()


@pytest.fixture
def ghidra_stubs(monkeypatch, program):
    """Ghidra classes the query tools import, stubbed without a JVM."""
    iterator_calls = []

    def for_program(prog):
        iterator_calls.append(prog)
        return iter(prog.strings)

    install_modules(monkeypatch, {
        "ghidra.util.task": {"ConsoleTaskMonitor": lambda: "monitor", "TaskMonitor": object},
        "ghidra.program.model.listing": {"CommentType": type("CommentType", (), {"EOL": EOL})},
        "ghidra.program.util": {"DefinedStringIterator": type("DSI", (), {"forProgram": staticmethod(for_program)})},
    })
    return iterator_calls


@pytest.fixture
def tools(program, decompiler, ghidra_stubs):
    return tools_for(program, decompiler)


# ── Listings ─────────────────────────────────────────────────────────────────


def test_function_listing_excludes_externals_and_thunks(tools):
    functions, total = tools.list_functions()
    assert [(f.name, f.address) for f in functions] == [
        ("main", "00401000"), ("helper", "00401100"), ("Foo::method", "00401300"),
    ]
    assert functions[0].signature == "undefined main(void)" and total == 3


def test_function_listing_filters_by_qualified_name(tools):
    functions, total = tools.list_functions(query="FOO::")
    assert [f.name for f in functions] == ["Foo::method"] and total == 1


def test_function_listing_pages_and_reports_the_total(tools):
    functions, total = tools.list_functions(offset=1, limit=1)
    assert [f.name for f in functions] == ["helper"] and total == 3


def test_function_listing_returns_at_most_500_per_page(tools):
    functions, total = tools.list_functions(limit=500)
    assert total == 3


@pytest.mark.parametrize("limit", [0, 501, 6000])
def test_a_function_page_outside_1_to_500_is_rejected(tools, limit):
    with pytest.raises(ValueError, match="offset"):
        tools.list_functions(limit=limit)


def test_segments(tools):
    segments = {s.name: s for s in tools.list_segments()}
    text = segments[".text"]
    assert (text.start, text.end, text.size, text.permissions, text.initialized) == (
        "00401000", "00401fff", 0x1000, "rx", True,
    )
    assert segments[".none"].permissions == "-" and not segments[".bss"].initialized


# ── Searches ─────────────────────────────────────────────────────────────────


def test_string_search_is_case_insensitive_with_a_total_beyond_the_limit(tools):
    result = tools.search_strings("HELLO", limit=1)
    assert [(s.value, s.address) for s in result.strings] == [("Hello World", "00405000")]
    assert result.total == 2


def test_string_search_uses_defined_string_iterator(tools, ghidra_stubs, program):
    tools.search_strings("o")
    assert ghidra_stubs == [program]


def test_an_unreadable_string_is_listed_as_a_failure(tools):
    result = tools.search_strings("o")
    assert result.partial
    assert [(f.address, f.error) for f in result.failures] == [("00405020", "bad encoding")]


# ── Code views ───────────────────────────────────────────────────────────────


def test_function_by_address_at_or_containing(tools):
    assert tools.get_function_by_address("0x401100").name == "helper"
    info = tools.get_function_by_address("401105")
    assert (info.name, info.address, info.signature, info.external) == (
        "helper", "00401100", "undefined helper(void)", False,
    )


def test_no_function_at_the_address_is_value_error(tools):
    with pytest.raises(ValueError):
        tools.get_function_by_address("0x404000")


def test_decompilation_returns_code_signature_and_full_label_within_120_seconds(program, ghidra_stubs):
    long_name = "a_function_name_that_is_much_longer_than_fifty_characters_in_total"
    program.functions.append(Function(long_name, 0x401600))
    decompiler = FakeDecompiler()
    result = tools_for(program, decompiler).decompile_function_by_name_or_addr(long_name)
    assert result.code == "int main(void) { return 0; }" and result.signature == "int main(void)"
    assert result.name == f"{long_name}-00401600"
    assert decompiler.calls == [(long_name, 120)]
    assert result.resolution is None


def test_a_decompiler_failure_is_stop_with_its_message(program, ghidra_stubs):
    decompiler = FakeDecompiler(DecompileResult(error="Decompiler timed out"))
    with pytest.raises(Stop, match="Decompiler timed out"):
        tools_for(program, decompiler).decompile_function_by_name_or_addr("main")


def test_a_decompiler_result_without_function_or_error_is_stop(program, ghidra_stubs):
    decompiler = FakeDecompiler(DecompileResult(code=None, error=""))
    with pytest.raises(Stop, match="no result"):
        tools_for(program, decompiler).decompile_function_by_name_or_addr("main")


def test_disassembly_lists_instructions_with_bytes_operands_and_comments(tools):
    result = tools.disassemble_function("main")
    assert (result.function_name, result.address) == ("main", "00401000")
    first, second = result.instructions[:2]
    assert (first.address, first.bytes, first.mnemonic, first.operands, first.comment) == (
        "00401000", "55", "PUSH", "RBP", None,
    )
    assert (second.bytes, second.operands, second.comment) == ("4889e5", "RBP, RSP", "set up frame")
    assert len(result.instructions) == 3


def test_disassembly_marks_unreadable_fields(tools):
    result = tools.disassemble_function("main")
    assert result.partial
    last = result.instructions[-1]
    assert last.mnemonic == "RET"
    assert [e.split(":")[0] for e in last.errors] == ["bytes", "operands", "comment"]
    assert all(not line.errors for line in result.instructions[:2])


# ── References ───────────────────────────────────────────────────────────────


def test_references_to_a_target(tools):
    result = tools.list_cross_references("helper")
    assert [(r.function_name, r.from_address, r.to_address, r.type) for r in result.cross_references] == [
        ("main", "00401005", "00401100", "UNCONDITIONAL_CALL"),
    ]
    assert result.resolution is None


# ── Disclosure ───────────────────────────────────────────────────────────────


def test_loose_matches_are_disclosed_in_the_result(tools):
    assert tools.decompile_function_by_name_or_addr("help").resolution == (
        "'help' resolved to helper @ 00401100 (partial name match)"
    )
    assert "address inside the function" in tools.disassemble_function("0x401004").resolution
    assert tools.list_cross_references("g_cou").resolution == (
        "'g_cou' resolved to g_count @ 00404000 (partial name match)"
    )


# ── Query contract ───────────────────────────────────────────────────────────


def test_queries_never_modify_the_program(tools, program):
    tools.list_functions()
    tools.list_segments()
    tools.get_function_by_address("0x401000")
    tools.decompile_function_by_name_or_addr("main")
    tools.disassemble_function("main")
    tools.list_cross_references("helper")
    tools.search_strings("o")
    assert program.transactions == [] and tools.project.saved == 0


@pytest.mark.anyio
async def test_every_query_tool_returns_a_typed_model(monkeypatch):
    monkeypatch.setattr(server.mcp, "_ghidra_context", FakeContext(), raising=False)
    async with Client(server.mcp) as client:
        listed = {t.name: t for t in (await client.list_tools()).tools}
    for name in QUERY_TOOLS:
        assert listed[name].output_schema, name
