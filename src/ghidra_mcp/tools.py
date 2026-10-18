"""
Native Ghidra tool implementations.
No ChromaDB, no ML/embedding — all search uses Ghidra's own iterators and APIs.
"""

import contextlib
import functools
import logging
import typing
from dataclasses import dataclass
from enum import Enum

from jpype import JByte

from ghidra_mcp.errors import STOP, Stop, classify
from ghidra_mcp.models import (
    BytesReadResult,
    CrossReferenceInfo,
    CrossReferenceInfos,
    DecompiledFunction,
    DisassemblyLine,
    DisassemblyResult,
    FunctionInfo,
    ItemFailure,
    MemorySegment,
    StringInfo,
    StringSearchResults,
)

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from ghidra_mcp.context import LoadedProgram

logger = logging.getLogger(__name__)

T = typing.TypeVar("T")

# Upper bound on one decompile_function call; a timeout is reported as a decompiler failure.
DECOMPILE_TIMEOUT_SECONDS = 120
# Largest page list_functions returns; page through more with offset.
MAX_FUNCTION_PAGE = 500


class ResolutionMode(str, Enum):
    """Read tools may accept a unique loose match and disclose it; write tools need an exact one."""

    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class Resolved(typing.Generic[T]):
    """A resolved target, with a disclosure note when read mode accepted a loose match."""

    target: T
    note: str | None = None


def handle_exceptions(func):
    """Run a GhidraTools method under its program's lock; log a failure once, at a level
    matching its recovery category, and re-raise."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        program_info = getattr(args[0], "program_info", None) if args else None
        lock = getattr(program_info, "lock", None)
        try:
            with lock if lock is not None else contextlib.nullcontext():
                return func(*args, **kwargs)
        except Exception as e:
            if getattr(e, "_ghidra_mcp_logged", False):
                raise
            category = classify(e)
            if category is None:
                logger.error(f"Error in {func.__name__}: {e!s}", exc_info=e)
            elif category == STOP:
                logger.warning(f"Error in {func.__name__}: {e!s}")
            else:
                logger.debug(f"Error in {func.__name__}: {e!s}")
            try:
                e._ghidra_mcp_logged = True  # type: ignore[attr-defined]
            except Exception:
                pass  # some exception types (e.g. Java proxies) reject new attributes
            raise

    return wrapper


class GhidraTools:
    """All native Ghidra tool implementations."""

    def __init__(self, program_info: "LoadedProgram"):
        self.program_info = program_info
        self.program = program_info.program
        self.project = program_info.project
        self.decompiler = program_info.decompiler

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _func_label(self, func: "Function") -> str:
        return f"{func.getSymbol().getName(True)}-{func.entryPoint}"

    @staticmethod
    def _error_text(e: Exception) -> str:
        message = e.getMessage() if hasattr(e, "getMessage") else None
        return str(message or e) or type(e).__name__

    def _parse_address(self, address: str):
        """Parse a hex address string (with or without 0x prefix) into a Ghidra Address."""
        af = self.program.getAddressFactory()
        addr_str = address[2:] if address.lower().startswith("0x") else address
        try:
            addr = af.getAddress(addr_str)
        except Exception as e:
            raise ValueError(f"Invalid address '{address}': {e}") from e
        if addr is None:
            raise ValueError(f"Invalid address: {address}")
        return addr

    # -------------------------------------------------------------------------
    # Function resolution
    # -------------------------------------------------------------------------

    def _try_address(self, text: str):
        """The address a string parses as, or None. Ghidra accepts an optional 0x prefix."""
        try:
            return self.program.getAddressFactory().getAddress(text)
        except Exception:
            return None

    @staticmethod
    def _function_label(func: "Function") -> str:
        return f"{func.getSymbol().getName(True)} @ {func.getEntryPoint()}"

    @staticmethod
    def _same_function(a: "Function", b: "Function") -> bool:
        return str(a.getEntryPoint()) == str(b.getEntryPoint())

    @handle_exceptions
    def resolve_function(self, name_or_address: str, mode: ResolutionMode) -> Resolved["Function"]:
        """
        Resolve a function from an address or a name (namespace-qualified, case-insensitive).

        Both interpretations are considered; if they lead to different functions, the call
        fails listing both. Read mode also accepts a unique partial name match or an address
        inside a function, and discloses it in the note. Write mode accepts only an exact name
        or an entry-point address, and refuses thunks and external functions.
        """
        fm = self.program.getFunctionManager()
        query = name_or_address
        query_lc = query.lower()

        addr = self._try_address(query)
        at = fm.getFunctionAt(addr) if addr is not None else None
        containing = None
        if addr is not None and at is None:
            containing = fm.getFunctionContaining(addr)
        by_address = at or containing

        functions = self.get_all_functions(include_externals=True)
        exact = [f for f in functions if f.getSymbol().getName(True).lower() == query_lc]
        partial = [] if exact else [
            f for f in functions if query_lc in f.getSymbol().getName(True).lower()
        ]
        by_name, partial_match = None, False
        if len(exact) == 1:
            by_name = exact[0]
        elif not exact and len(partial) == 1 and mode is ResolutionMode.READ:
            by_name, partial_match = partial[0], True

        if by_address is not None and by_name is not None and not self._same_function(by_address, by_name):
            where = "is the entry of" if at is not None else "lies inside"
            raise ValueError(
                f"'{query}' is both an address and a name: address {addr} {where} "
                f"{self._function_label(by_address)}, and the name matches "
                f"{self._function_label(by_name)}. Pass the entry address of the one you mean."
            )

        if at is not None:
            resolved = Resolved(at)
        elif containing is not None:
            if mode is ResolutionMode.READ:
                resolved = Resolved(
                    containing,
                    f"'{query}' resolved to {self._function_label(containing)} "
                    "(address inside the function)",
                )
            elif by_name is not None:  # the exact name names the same function
                resolved = Resolved(by_name)
            else:
                raise ValueError(
                    f"Write tools need a function's entry-point address; {addr} lies inside "
                    f"{self._function_label(containing)}."
                )
        elif by_name is not None:
            note = None
            if partial_match:
                note = f"'{query}' resolved to {self._function_label(by_name)} (partial name match)"
            resolved = Resolved(by_name, note)
        elif len(exact) > 1:
            hints = ", ".join(self._function_label(f) for f in exact)
            raise ValueError(f"Ambiguous match for '{query}'. Did you mean: {hints}")
        elif partial:
            hints = ", ".join(self._function_label(f) for f in partial)
            raise ValueError(f"Function '{query}' not found. Did you mean: {hints}")
        elif addr is not None and mode is ResolutionMode.WRITE:
            raise ValueError(
                f"Function '{query}' not found: no function's name matches, and write tools need "
                f"a function's entry-point address, but no function starts at {addr}."
            )
        else:
            raise ValueError(f"Function '{query}' not found.")

        if mode is ResolutionMode.WRITE:
            self._refuse_thunk_or_external(query, resolved.target)
        return resolved

    def _refuse_thunk_or_external(self, query: str, func: "Function") -> None:
        if func.isThunk():
            target = func.getThunkedFunction(True)
            target_label = self._function_label(target) if target is not None else "an unknown function"
            raise ValueError(
                f"'{query}' is a thunk for {target_label}; write tools don't act on thunks. "
                "Target the thunked function instead."
            )
        if func.isExternal():
            raise ValueError(
                f"'{query}' is an external function ({self._function_label(func)}) with no body "
                "in this program; write tools don't act on external functions."
            )

    # -------------------------------------------------------------------------
    # Symbol resolution
    # -------------------------------------------------------------------------

    def _symbols_by_name(self) -> list["Symbol"]:
        return self.get_all_symbols(include_externals=True, include_dynamic=True)

    @staticmethod
    def _symbol_label(sym: "Symbol") -> str:
        return f"{sym.getName(True)} @ {sym.getAddress()}"

    @staticmethod
    def _by_address(symbols: list["Symbol"]) -> dict[str, "Symbol"]:
        """One representative symbol per address, in order."""
        grouped: dict[str, "Symbol"] = {}
        for sym in symbols:
            grouped.setdefault(str(sym.getAddress()), sym)
        return grouped

    @handle_exceptions
    def resolve_reference_target(self, name_or_address: str) -> Resolved[typing.Any]:
        """
        Resolve the target address of a cross-reference lookup.

        A string that parses as an address in the program (in memory, or with symbols defined
        there) is its own target, however many symbols are defined there. Otherwise the target
        is the address of the one symbol (dynamic and external ones included) whose qualified
        name equals the query case-insensitively, or, disclosed, the one whose name contains it.
        If the address and a name lead to different targets, the call fails listing both.
        """
        query = name_or_address
        query_lc = query.lower()
        st = self.program.getSymbolTable()

        addr = self._try_address(query)
        if addr is not None and not (
            self.program.getMemory().contains(addr) or list(st.getSymbols(addr))
        ):
            addr = None

        symbols = self._symbols_by_name()
        exact = self._by_address([s for s in symbols if s.getName(True).lower() == query_lc])
        partial = {} if exact else self._by_address(
            [s for s in symbols if query_lc in s.getName(True).lower()]
        )
        by_name, partial_match = None, False
        if len(exact) == 1:
            by_name = next(iter(exact.values()))
        elif not exact and len(partial) == 1:
            by_name, partial_match = next(iter(partial.values())), True

        if addr is not None and by_name is not None and str(by_name.getAddress()) != str(addr):
            raise ValueError(
                f"'{query}' is both an address and a name: address {addr}, and the name matches "
                f"{self._symbol_label(by_name)}. Pass the address you mean."
            )
        if addr is not None:
            return Resolved(addr)
        if by_name is not None:
            note = None
            if partial_match:
                note = f"'{query}' resolved to {self._symbol_label(by_name)} (partial name match)"
            return Resolved(by_name.getAddress(), note)
        if len(exact) > 1:
            hints = ", ".join(self._symbol_label(s) for s in exact.values())
            raise ValueError(f"Ambiguous match for '{query}'. Did you mean: {hints}")
        if partial:
            hints = ", ".join(self._symbol_label(s) for s in partial.values())
            raise ValueError(f"Symbol '{query}' not found. Did you mean: {hints}")
        raise ValueError(f"Symbol '{query}' not found.")

    # -------------------------------------------------------------------------
    # Core listing helpers (return raw Ghidra objects)
    # -------------------------------------------------------------------------

    @handle_exceptions
    def get_all_functions(self, include_externals: bool = False) -> list["Function"]:
        """Every function. Without externals, both external and thunk functions are left out."""
        fm = self.program.getFunctionManager()
        functions = list(fm.getFunctions(True))  # every non-external function, thunks included
        if include_externals:
            return functions + list(fm.getExternalFunctions())
        return [f for f in functions if not f.isExternal() and not f.thunk]

    @handle_exceptions
    def get_all_symbols(
        self, include_externals: bool = False, include_dynamic: bool = False
    ) -> list["Symbol"]:
        st = self.program.getSymbolTable()
        return [
            s
            for s in st.getAllSymbols(include_dynamic)
            if include_externals or not s.isExternal()
        ]

    # -------------------------------------------------------------------------
    # Navigation / discovery tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def list_functions(
        self, query: str | None = None, offset: int = 0, limit: int = 100
    ) -> tuple[list[FunctionInfo], int]:
        """List all non-external functions, with optional case-insensitive name filter."""
        if not 1 <= limit <= MAX_FUNCTION_PAGE:
            raise ValueError(
                f"limit must be between 1 and {MAX_FUNCTION_PAGE}, not {limit}; "
                "use offset to page through more."
            )
        funcs = self.get_all_functions(include_externals=False)
        results: list[FunctionInfo] = []
        for func in funcs:
            name = func.getSymbol().getName(True)
            if query and query.lower() not in name.lower():
                continue
            results.append(
                FunctionInfo(
                    name=name,
                    address=str(func.getEntryPoint()),
                    signature=str(func.getSignature()),
                    external=func.isExternal(),
                )
            )
        total = len(results)
        return results[offset : offset + limit], total

    @handle_exceptions
    def list_segments(self) -> list[MemorySegment]:
        """List all memory segments (blocks) in the binary."""
        mem = self.program.getMemory()
        segments: list[MemorySegment] = []
        for block in mem.getBlocks():
            perms = ""
            if block.isRead():
                perms += "r"
            if block.isWrite():
                perms += "w"
            if block.isExecute():
                perms += "x"
            segments.append(
                MemorySegment(
                    name=block.getName(),
                    start=str(block.getStart()),
                    end=str(block.getEnd()),
                    size=block.getSize(),
                    permissions=perms or "-",
                    type=str(block.getType()),
                    initialized=block.isInitialized(),
                )
            )
        return segments

    # -------------------------------------------------------------------------
    # Function lookup tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def get_function_by_address(self, address: str) -> FunctionInfo:
        """Return function metadata for the function at or containing the given address."""
        addr = self._parse_address(address)
        fm = self.program.getFunctionManager()

        func = fm.getFunctionAt(addr)
        if func is None:
            func = fm.getFunctionContaining(addr)
        if func is None:
            raise ValueError(f"No function at or containing address {address}")

        return FunctionInfo(
            name=func.getSymbol().getName(True),
            address=str(func.getEntryPoint()),
            signature=str(func.getSignature()),
            external=func.isExternal(),
        )

    # -------------------------------------------------------------------------
    # Decompilation tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def decompile_function_by_name_or_addr(self, name_or_address: str) -> DecompiledFunction:
        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        result = self.decompile_function(resolved.target, DECOMPILE_TIMEOUT_SECONDS)
        return result.model_copy(update={"resolution": resolved.note})

    def decompile_function(self, func: "Function", timeout: int = DECOMPILE_TIMEOUT_SECONDS) -> DecompiledFunction:
        """Decompile a function; a decompiler failure (including a timeout) raises Stop."""
        from ghidra.util.task import ConsoleTaskMonitor

        result: "DecompileResults" = self.decompiler.decompileFunction(
            func, timeout, ConsoleTaskMonitor()
        )
        error = result.getErrorMessage()
        if error:
            raise Stop(f"Decompilation of {self._func_label(func)} failed: {error}")
        decompiled = result.decompiledFunction
        if decompiled is None:
            raise Stop(f"Decompilation of {self._func_label(func)} produced no result.")
        return DecompiledFunction(
            name=self._func_label(func), code=decompiled.getC(), signature=decompiled.getSignature()
        )

    @handle_exceptions
    def disassemble_function(self, name_or_address: str) -> DisassemblyResult:
        """Return the assembly listing for a function.

        A field that can't be read is left empty and named in that line's errors, and the
        result is marked partial.
        """
        from ghidra.program.model.listing import CommentType

        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        func = resolved.target
        listing = self.program.getListing()
        instructions: list[DisassemblyLine] = []

        for instr in listing.getInstructions(func.getBody(), True):
            errors: list[str] = []
            try:
                instr_bytes = bytes([b & 0xFF for b in instr.getBytes()]).hex()
            except Exception as e:
                instr_bytes = ""
                errors.append(f"bytes: {self._error_text(e)}")

            operand_parts = []
            try:
                for i in range(instr.getNumOperands()):
                    operand_parts.append(instr.getDefaultOperandRepresentation(i))
            except Exception as e:
                errors.append(f"operands: {self._error_text(e)}")

            comment = None
            try:
                comment = listing.getComment(CommentType.EOL, instr.getAddress())
            except Exception as e:
                errors.append(f"comment: {self._error_text(e)}")

            instructions.append(
                DisassemblyLine(
                    address=str(instr.getAddress()),
                    bytes=instr_bytes,
                    mnemonic=instr.getMnemonicString(),
                    operands=", ".join(operand_parts),
                    comment=comment,
                    errors=errors,
                )
            )

        return DisassemblyResult(
            function_name=func.getSymbol().getName(True),
            address=str(func.getEntryPoint()),
            instructions=instructions,
            partial=any(line.errors for line in instructions),
            resolution=resolved.note,
        )

    # -------------------------------------------------------------------------
    # Cross-reference tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def list_cross_references(self, name_or_address: str) -> CrossReferenceInfos:
        """All references TO a symbol or address."""
        resolved = self.resolve_reference_target(name_or_address)
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        refs: list[CrossReferenceInfo] = []

        for ref in rm.getReferencesTo(resolved.target):
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            refs.append(
                CrossReferenceInfo(
                    function_name=from_func.getName() if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return CrossReferenceInfos(cross_references=refs, resolution=resolved.note)

    # -------------------------------------------------------------------------
    # String / bytes tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> StringSearchResults:
        """
        Search defined strings using Ghidra's DefinedStringIterator.
        Simple case-insensitive substring match — no ChromaDB, no ML model.
        A string whose value can't be read is reported in failures, and the result is marked partial.
        """
        from ghidra.program.util import DefinedStringIterator

        query_lc = query.lower()
        results: list[StringInfo] = []
        failures: list[ItemFailure] = []
        total = 0

        for data in DefinedStringIterator.forProgram(self.program):
            try:
                val = str(data.getValue())
            except Exception as e:
                failures.append(ItemFailure(address=str(data.getAddress()), error=self._error_text(e)))
                continue
            if query_lc in val.lower():
                total += 1
                if len(results) < limit:
                    results.append(StringInfo(value=val, address=str(data.getAddress())))

        return StringSearchResults(
            strings=results, total=total, partial=bool(failures), failures=failures
        )

    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Read raw bytes from the program's memory image.

        Exercise 2: implement this; tests/exercises/test_read_bytes.py has the acceptance tests.
        Allocate the Java byte buffer that Memory.getBytes fills with JByte[size] (imported at the
        top of this file).
        """
        raise NotImplementedError("read_bytes is exercise 2")
