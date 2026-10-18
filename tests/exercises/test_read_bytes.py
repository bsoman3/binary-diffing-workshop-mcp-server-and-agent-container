"""Exercise 2 acceptance tests: the read_bytes tool.

read_bytes(binary_name, address, size=32) -> BytesReadResult reads raw bytes from a binary's
memory image. Run with: mise run check:read-bytes
"""

import pytest

from tests.exercises.support import call, loaded, structured, text, tool_names
from tests.program_fakes import FakeProgram, MemoryBlock


def program(data_fill=None):
    data = bytes(data_fill) * (0x2000 // len(data_fill)) if data_fill else None
    return FakeProgram(memory=[
        MemoryBlock(".text", 0x401000, 0x1000, perms="rx"),
        MemoryBlock(".data", 0x404000, 0x2000, perms="rw", data=data),  # bytes 00 01 02 … ff 00 01 …
        MemoryBlock(".bss", 0x406000, 0x100, perms="rw", initialized=False),
    ])


@pytest.fixture
def binaries(serve):
    serve(loaded("prog", program()), loaded("other", program(data_fill=b"\xff\xee\xdd\xcc")))


async def read(**arguments):
    return await call("read_bytes", {"binary_name": "prog", **arguments})


@pytest.mark.anyio
async def test_read_bytes_is_registered_as_a_tool(binaries):
    assert "read_bytes" in await tool_names()


@pytest.mark.anyio
async def test_returns_the_bytes_as_hex_with_the_normalized_address(binaries):
    result = structured(await read(address="0x404000", size=4))
    assert result["address"] == "00404000"
    assert result["data"] == "00010203"
    assert (result["size"], result["requested_size"], result["partial"]) == (4, 4, False)


@pytest.mark.anyio
async def test_reads_from_the_binary_named_by_binary_name(binaries):
    result = structured(await call("read_bytes", {"binary_name": "other", "address": "0x404000", "size": 4}))
    assert result["data"] == "ffeeddcc"


@pytest.mark.anyio
@pytest.mark.parametrize("address", ["404004", "0x404004"])
async def test_parses_hex_addresses_with_or_without_0x(binaries, address):
    assert structured(await read(address=address, size=4))["data"] == "04050607"


@pytest.mark.anyio
async def test_bytes_above_0x7f_are_returned_unsigned(binaries):
    # Ghidra hands back Java bytes, which are signed (-128..127).
    assert structured(await read(address="0x404080", size=2))["data"] == "8081"


@pytest.mark.anyio
async def test_size_defaults_to_32(binaries):
    result = structured(await read(address="0x404000"))
    assert result["size"] == 32 and len(result["data"]) == 64


@pytest.mark.anyio
async def test_reads_up_to_8192_bytes(binaries):
    result = structured(await read(address="0x404000", size=8192))
    assert result["size"] == 8192 and not result["partial"]


@pytest.mark.anyio
@pytest.mark.parametrize("size", [0, -1, 8193])
async def test_a_size_outside_1_to_8192_is_fix_input(binaries, size):
    result = await read(address="0x404000", size=size)
    assert result.is_error and "[fix_input]" in text(result), text(result)


@pytest.mark.anyio
async def test_an_unparseable_address_is_fix_input(binaries):
    result = await read(address="not-an-address", size=4)
    assert result.is_error and "[fix_input]" in text(result), text(result)


@pytest.mark.anyio
async def test_an_unmapped_address_is_fix_input_naming_the_address(binaries):
    result = await read(address="0x500000", size=4)
    assert result.is_error and "[fix_input]" in text(result), text(result)
    assert "500000" in text(result)


@pytest.mark.anyio
async def test_uninitialized_memory_is_an_error_that_says_so(binaries):
    result = await read(address="0x406000", size=4)
    assert result.is_error and "uninitialized" in text(result).lower(), text(result)


@pytest.mark.anyio
async def test_a_read_past_the_end_of_memory_returns_what_exists_marked_partial(binaries):
    result = structured(await read(address="0x405ffe", size=8))  # two bytes before the end of .data
    assert result["data"] == "feff"
    assert (result["size"], result["requested_size"], result["partial"]) == (2, 8, True)
