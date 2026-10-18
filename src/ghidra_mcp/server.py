"""
Lightweight Ghidra MCP server.

Native Ghidra tools only — no ChromaDB, no ML/embedding.
Transports: stdio and streamable-http (MCP Python SDK 2.x).
"""

import logging
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import ExitStack, asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import click
import pyghidra
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from ghidra_mcp import __version__, gui
from ghidra_mcp.context import AnalysisOptions, GhidraContext
from ghidra_mcp.errors import STOP, classify, describe
from ghidra_mcp.models import (
    CrossReferenceInfos,
    CurrentAddress,
    CurrentFunction,
    DecompiledFunction,
    DisassemblyResult,
    FunctionInfo,
    FunctionList,
    MemorySegments,
    ProgramInfo,
    ProgramInfos,
    StringSearchResults,
)
from ghidra_mcp.tools import GhidraTools

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class _DropInterruptedShutdown(logging.Filter):
    """Drop the traceback uvicorn logs when Ctrl+C cancels the app's lifespan while an MCP session
    is open (Starlette reports it as a failed shutdown). Only that record is dropped."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return not (
            record.levelno >= logging.ERROR and "KeyboardInterrupt" in message and "CancelledError" in message
        )


logging.getLogger("uvicorn.error").addFilter(_DropInterruptedShutdown())
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Server setup
# ─────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(server: MCPServer) -> AsyncIterator[GhidraContext]:
    try:
        yield server._ghidra_context  # type: ignore[attr-defined]
    finally:
        pass


_CATEGORY_TAGS = ("[fix_input]", "[retry_later]", "[stop]")
_SDK_PREFIX = "Error executing tool "


def _tag_sdk_message(text: str) -> str:
    """Add a recovery category to an error the SDK produced before or around a tool."""
    if any(tag in text for tag in _CATEGORY_TAGS):
        return text
    if text.startswith(_SDK_PREFIX):
        name, sep, detail = text[len(_SDK_PREFIX):].partition(": ")
        if sep:  # argument rejected against the tool's input schema
            return f"{_SDK_PREFIX}{name}: [fix_input] {detail}"
        return f"{text}: [{STOP}] Internal error; details are in the server log."
    return f"[fix_input] {text}"  # e.g. "Unknown tool: <name>"


async def _categorize_sdk_failures(ctx, call_next):
    """Middleware: give SDK-generated tool errors (unknown tool, bad arguments) a category too."""
    result = await call_next(ctx)
    if ctx.method == "tools/call" and isinstance(result, dict) and result.get("isError"):
        for block in result.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                block["text"] = _tag_sdk_message(block.get("text", ""))
                break
    return result


mcp = MCPServer("ghidra-mcp", lifespan=_lifespan, middleware=[_categorize_sdk_failures])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _err(e: Exception) -> ToolError:
    """Convert a tool failure into a ToolError whose message starts with its recovery category.

    The SDK shows a ToolError's message to the model; an unexpected exception's text is
    withheld from the client and logged with its traceback instead.
    """
    if isinstance(e, ToolError):
        return e
    category = classify(e)
    if category is None:
        if not getattr(e, "_ghidra_mcp_logged", False):
            logger.error(f"Unexpected tool failure: {e!s}", exc_info=e)
        return ToolError(f"[{STOP}] Internal error; details are in the server log.")
    return ToolError(f"[{category}] {describe(e)}")


def _tools(ctx: Context, binary_name: str) -> GhidraTools:
    ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
    return GhidraTools(ghidra_ctx.get_program_info(binary_name))


@contextmanager
def _locked(*entries) -> Iterator[None]:
    """Hold the programs' locks, taken in pathname order so that two-binary calls can't deadlock."""
    unique = {entry.pathname: entry for entry in entries}
    with ExitStack() as stack:
        for pathname in sorted(unique):
            stack.enter_context(unique[pathname].lock)
        yield


# ─────────────────────────────────────────────────────────────────────────────
# Project management
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """List every binary loaded in the active Ghidra project along with its analysis status.

    Includes binaries still being imported. Each entry has a status (importing, analyzing,
    ready, failed), the failure reason when failed, configuration warnings recorded during
    analysis, and Ghidra metadata. Use this first to discover binary names required by other
    tools.
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        programs = [
            ProgramInfo(
                name=pi.name,
                file_path=str(pi.file_path) if pi.file_path else None,
                load_time=pi.load_time,
                analysis_complete=pi.analysis_complete,
                status=pi.status.value,
                failure=pi.failure,
                warnings=list(pi.warnings),
                metadata=dict(pi.metadata),
            )
            for pi in ghidra_ctx.list_entries()
        ]
        return ProgramInfos(programs=programs)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def import_binary(
    binary_path: str,
    ctx: Context,
    pdb_path: str | None = None,
    gdts: list[str] | None = None,
    analyzer_options: dict[str, Any] | None = None,
    no_symbols: bool = False,
) -> str:
    """Import a binary (or every file under a directory) and analyze it in the background.

    The analysis options apply to this binary only. list_project_binaries shows its status
    (importing, analyzing, ready, failed) and any configuration warnings.

    Args:
        binary_path: Absolute path to the binary file (or directory) to import.
        pdb_path: Path to a PDB file for this binary.
        gdts: Paths of GDT type archives to apply, in order.
        analyzer_options: Ghidra analysis options to set, as {option name: value},
            e.g. {"Decompiler Parameter ID": false}.
        no_symbols: Disable PDB symbol loading for this binary.
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        options = AnalysisOptions.create(
            no_symbols=no_symbols, pdb_path=pdb_path, gdts=gdts, analyzer_options=analyzer_options
        )
        queued, existing = ghidra_ctx.import_binary_backgrounded(binary_path, options)
        parts = []
        if queued:
            parts.append(f"Importing '{binary_path}' in the background as {', '.join(queued)}.")
        if existing:
            parts.append(
                f"Already in the project, not re-imported: {', '.join(existing)}. Its stored "
                "analysis options are unchanged."
            )
        parts.append("Use list_project_binaries to check analysis status.")
        return " ".join(parts)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Navigation / discovery
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def list_functions(
    binary_name: str,
    ctx: Context,
    query: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> FunctionList:
    """List the binary's own functions (no externals or thunks) with addresses and signatures.

    Args:
        binary_name: Name of the binary.
        query: Optional case-insensitive substring to filter function names.
        offset: Number of results to skip (pagination).
        limit: Maximum number of results to return (1–500); use offset for more.
    """
    try:
        funcs, total = _tools(ctx, binary_name).list_functions(
            query=query, offset=offset, limit=limit
        )
        return FunctionList(functions=funcs, total=total)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_segments(binary_name: str, ctx: Context) -> MemorySegments:
    """List all memory segments (sections) of a binary.

    Returns name, address range, size, r/w/x permissions, type, and initialization status.
    Useful for understanding the binary's memory layout before diving into code.

    Args:
        binary_name: Name of the binary.
    """
    try:
        return MemorySegments(segments=_tools(ctx, binary_name).list_segments())
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Function lookup
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def get_function_by_address(binary_name: str, address: str, ctx: Context) -> FunctionInfo:
    """Get function metadata (name, signature) for the function at or containing an address.

    Lighter than decompile_function — returns metadata only, no pseudo-C output.

    Args:
        binary_name: Name of the binary.
        address: Hex address (with or without 0x prefix).
    """
    try:
        return _tools(ctx, binary_name).get_function_by_address(address)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Disassembly / decompilation
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def disassemble_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DisassemblyResult:
    """Get the assembly listing for a function.

    Returns every instruction in the function body with address, raw bytes, mnemonic,
    operands, and any EOL comments. A field that can't be read is left empty and named in
    that instruction's 'errors', and the result is marked 'partial'.
    If no function's name matches exactly, a unique partial name match (or an address
    inside a function) is used, and the result's 'resolution' field says so. Otherwise the
    error lists the candidates.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function name (case-insensitive) or hex address.
    """
    try:
        return _tools(ctx, binary_name).disassemble_function(name_or_address)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def decompile_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DecompiledFunction:
    """Decompile a function and return its pseudo-C source code.

    Decompilation is limited to 120 seconds; a decompiler failure or timeout is an error.
    If no function's name matches exactly, a unique partial name match (or an address
    inside a function) is used, and the result's 'resolution' field says so. Otherwise the
    error lists the candidates.

    Args:
        binary_name: Name of the binary containing the function.
        name_or_address: Function name (case-insensitive) or hex address (e.g. '0x401000').
    """
    try:
        return _tools(ctx, binary_name).decompile_function_by_name_or_addr(name_or_address)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Cross-references
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def list_cross_references(
    binary_name: str, name_or_address: str, ctx: Context
) -> CrossReferenceInfos:
    """Find all cross-references (xrefs) TO a function, symbol, or address.

    Useful for finding callers, data consumers, and jump targets. A hex address is used as
    is. Otherwise the target is the symbol whose name matches exactly, or the one symbol whose
    name contains the query (reported in the 'resolution' field); if several match, the error
    lists them. Each result's function_name is the function containing the reference's source.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function/symbol name or hex address to find references to.
    """
    try:
        return _tools(ctx, binary_name).list_cross_references(name_or_address)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Strings
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def search_strings(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 100,
) -> StringSearchResults:
    """Search for strings defined in a binary using a case-insensitive substring match.

    An empty query lists every defined string (up to limit).

    Uses Ghidra's native DefinedStringIterator — no ML model, no ChromaDB.
    The 'total' field shows how many matches exist even if limit was reached. A string that
    can't be read is listed in 'failures', and the result is marked 'partial'.

    Args:
        binary_name: Name of the binary.
        query: Case-insensitive substring to search for.
        limit: Maximum number of results to return (default: 100).
    """
    try:
        return _tools(ctx, binary_name).search_strings(query=query, limit=limit)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# GUI-only tools (registered by register_gui_tools in GUI mode)
# ─────────────────────────────────────────────────────────────────────────────


def get_current_address(ctx: Context) -> CurrentAddress:
    """GUI mode only. Where the analyst's cursor is in Ghidra's CodeBrowser.

    Returns the binary open in the most recently focused CodeBrowser, the cursor's address,
    and the name of the function containing it (if any).
    """
    try:
        ghidra_ctx: gui.GuiGhidraContext = ctx.request_context.lifespan_context
        return CurrentAddress(**ghidra_ctx.current_location())
    except Exception as e:
        raise _err(e) from e


def get_current_function(ctx: Context) -> CurrentFunction:
    """GUI mode only. The function containing the analyst's cursor in Ghidra's CodeBrowser.

    Fails if the cursor is not inside a function.
    """
    try:
        ghidra_ctx: gui.GuiGhidraContext = ctx.request_context.lifespan_context
        binary, func = ghidra_ctx.current_function()
        return CurrentFunction(
            binary_name=binary,
            function=FunctionInfo(
                name=str(func.getName(True)),
                address=str(func.getEntryPoint()),
                signature=str(func.getSignature()),
                external=bool(func.isExternal()),
            ),
        )
    except Exception as e:
        raise _err(e) from e


def go_to(binary_name: str, name_or_address: str, ctx: Context) -> str:
    """GUI mode only. Show a location in Ghidra's CodeBrowser: makes the binary the current
    program and moves the cursor there.

    Args:
        binary_name: Name of the binary.
        name_or_address: Hex address, or a symbol or function name (a unique partial name is
            used and reported).
    """
    try:
        ghidra_ctx: gui.GuiGhidraContext = ctx.request_context.lifespan_context
        return ghidra_ctx.go_to(binary_name, name_or_address)
    except Exception as e:
        raise _err(e) from e


GUI_TOOLS = (get_current_address, get_current_function, go_to)


def register_gui_tools() -> None:
    """Register the GUI-only tools; called only in GUI mode."""
    for fn in GUI_TOOLS:
        mcp.add_tool(fn)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-v", "--version")
# Transport
@click.option(
    "-t", "--transport",
    type=click.Choice(["stdio", "streamable-http"], case_sensitive=False),
    default="stdio", envvar="MCP_TRANSPORT", show_default=True,
    help="MCP transport protocol.",
)
@click.option("-p", "--port", type=int, default=8000, envvar="MCP_PORT", show_default=True)
@click.option("-o", "--host", default="127.0.0.1", envvar="MCP_HOST", show_default=True)
# Project
@click.option(
    "--project-path",
    type=click.Path(path_type=Path),
    default=Path("ghidra_projects"),
    show_default=True,
    help="Directory for the Ghidra project, or path to an existing .gpr file.",
)
@click.option("--project-name", default="my_project", show_default=True)
# Analysis (per-binary options are import_binary arguments)
@click.option(
    "--wait-for-analysis/--no-wait-for-analysis", default=True, show_default=True,
    help="Let tool calls for a binary still being analyzed wait up to 45 s before "
         "returning retry_later. Startup never blocks.",
)
@click.option("--verbose-analysis/--no-verbose-analysis", default=False, show_default=True,
              help="Verbose Ghidra analysis logging.")
@click.option("--symbols-path", type=click.Path(), default=None,
              help="Path to local symbol store directory.")
# Project management (exits after running)
@click.option("--list-project-binaries", is_flag=True,
              help="Print all binaries in the project and exit.")
@click.option("--delete-project-binary", type=str, default=None,
              help="Delete a binary from the project by name and exit.")
@click.option("--analyze-only", is_flag=True,
              help="Import inputs, analyze every binary to completion, report each status, "
                   "and exit (non-zero if any binary failed).")
@click.option("--gui", "gui_mode", is_flag=True,
              help="GUI mode: open the Ghidra GUI in this process and serve over streamable HTTP "
                   "alongside it.")
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    port: int,
    host: str,
    project_path: Path,
    project_name: str,
    wait_for_analysis: bool,
    verbose_analysis: bool,
    symbols_path: str | None,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    analyze_only: bool,
    gui_mode: bool,
    input_paths: tuple[str, ...],
) -> None:
    """Lightweight Ghidra MCP server — native Ghidra tools, no ML/embedding.

    \b
    input_paths  Binaries to import and analyze on startup (optional).

    \b
    Examples:
      # Import and serve a binary over stdio:
      ghidra-mcp /path/to/binary

      # Serve over HTTP for remote clients (tool calls wait up to 45 s for analysis):
      ghidra-mcp --transport streamable-http --host 0.0.0.0 /path/to/binary

      # Pre-analyze a large binary once, then serve instantly on later starts:
      ghidra-mcp --analyze-only /path/to/binary

      # List binaries in an existing project:
      ghidra-mcp --project-path ./myproject --list-project-binaries

      # GUI mode: watch and steer the agent in Ghidra's GUI (serves on http://127.0.0.1:8000/mcp):
      ghidra-mcp --gui --project-path ~/ghidra_projects /path/to/binary
    """
    # Ghidra rejects path elements starting with "." (such as ".."), and MCP
    # client configs pass "~" unexpanded.
    project_path = project_path.expanduser().resolve()
    if project_path.suffix.lower() == ".rep":
        raise click.UsageError(
            f"{project_path} is a Ghidra project's data folder; pass the project file instead: "
            f"--project-path {project_path.with_suffix('.gpr')}"
        )

    # Handle .gpr file paths
    if project_path.suffix.lower() == ".gpr":
        project_dir = str(project_path.parent)
        project_name = project_path.stem
    else:
        project_dir = str(project_path)

    if gui_mode:
        click_ctx = click.get_current_context()
        explicit_transport = click_ctx.get_parameter_source("transport") != click.core.ParameterSource.DEFAULT
        if transport == "stdio" and explicit_transport:
            raise click.UsageError("--gui serves over streamable-http; the stdio transport is not available.")
        for flag, given in (("--analyze-only", analyze_only), ("--list-project-binaries", list_project_binaries),
                            ("--delete-project-binary", delete_project_binary)):
            if given:
                raise click.UsageError(f"{flag} cannot be combined with --gui.")
        try:
            gui.check_port(host, port)
        except OSError as e:
            click.echo(f"Error: cannot serve on {host}:{port}: {e}", err=True)
            sys.exit(1)
        gui.ensure_project(project_dir, project_name)
        gui.launch(
            project_dir=project_dir, project_name=project_name, input_paths=input_paths, host=host,
            port=port, wait_for_analysis=wait_for_analysis, verbose_analysis=verbose_analysis,
            symbols_path=symbols_path,
        )
        return

    pyghidra.start(verbose_analysis)

    ctx = GhidraContext(
        project_name=project_name,
        project_path=project_dir,
        verbose_analysis=verbose_analysis,
        wait_for_analysis=wait_for_analysis,
        symbols_path=symbols_path,
    )

    interrupted = False
    try:
        _run_headless(
            ctx, list_project_binaries=list_project_binaries, delete_project_binary=delete_project_binary,
            input_paths=input_paths, analyze_only=analyze_only, transport=transport, host=host, port=port,
        )
    except KeyboardInterrupt:
        interrupted = True
        logger.warning("Interrupted: cancelling analysis and closing the project.")
    finally:
        try:
            ctx.close()
        except KeyboardInterrupt:
            lock = Path(project_dir) / project_name
            logger.warning(
                f"Interrupted again: the project was not closed; its lock files remain: {lock}.lock, {lock}.lock~"
            )
            sys.exit(130)
    if interrupted:
        sys.exit(130)


def _run_headless(ctx: GhidraContext, *, list_project_binaries: bool, delete_project_binary: str | None,
                  input_paths: tuple[str, ...], analyze_only: bool, transport: str, host: str, port: int) -> None:
    """One-shot commands, startup import, --analyze-only, or serving; main closes the context."""
    # One-shot management commands
    if list_project_binaries:
        try:
            bins = ctx.list_binaries()
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        if bins:
            for name in bins:
                click.echo(f"- {name}")
        else:
            click.echo("No binaries in project.")
        return

    if delete_project_binary:
        try:
            deleted = ctx.delete_program(delete_project_binary)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        if not deleted:
            click.echo(
                f"Error: could not delete '{delete_project_binary}'; see the log for details.",
                err=True,
            )
            sys.exit(1)
        click.echo(f"Deleted: {delete_project_binary}")
        return

    # Import any binaries provided on the command line
    if input_paths:
        logger.info(f"Importing {len(input_paths)} binary/binaries...")
        ctx.import_binaries([Path(p) for p in input_paths])

    if analyze_only:
        ctx.analyze_project(wait=True)
        any_failed = False
        for pi in ctx.list_entries():
            if pi.analysis_complete:
                click.echo(f"{pi.name}: ready")
            else:
                any_failed = True
                click.echo(f"{pi.name}: failed ({pi.failure or pi.status.value})")
        if any_failed:
            sys.exit(1)
        return

    # analysis runs in the background; the handshake is never delayed.
    ctx.analyze_project()

    # Attach context to the server instance (read by _lifespan)
    mcp._ghidra_context = ctx  # type: ignore[attr-defined]

    logger.info(f"Starting server (transport={transport}, host={host}, port={port})")

    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http", host=host, port=port)


if __name__ == "__main__":
    main()
