# ghidra-mcp-lite (workshop edition)

An MCP server that runs Ghidra through pyghidra. In this workshop you help a student add tools to it; each exercise's acceptance tests are in `tests/exercises/`.

## Rules

- **Work from this repository only.** Don't look for other copies or versions of this project: other branches or remotes, other clones on disk, or the web. The point of the workshop is to build the tools here.
- **Reach the workshop binaries only through the MCP tools.** Don't read, copy or script the files in the workshop folder that `GHIDRA_WORKSHOP_DIR` names, usually `~/ghidra-workshop` (the binaries and the Ghidra project), even if you find a way to. Don't add a tool that takes a file path or runs arbitrary code: each tool should do one Ghidra analysis of a binary named by `binary_name`.
- **Don't edit `tests/exercises/`.** Those are the acceptance tests. Put your own tests in new files under `tests/`.
- **Keep `mise run test` passing.**
- **Don't commit.** The student reviews and commits your changes. In the workshop container `.git` is read-only, so git can show status, diffs and history, but can't stage or commit.

## How a tool is put together

A tool has four parts. Follow an existing tool such as `get_function_by_address`.

1. **The wrapper** in `src/ghidra_mcp/server.py` is what the agent sees. `@mcp.tool()` registers it, its parameters become the tool's arguments, and its docstring becomes the tool's description (the `Args:` section describes each argument). Keep it a plain `def`, not `async def`: the SDK runs plain functions on a worker thread, which Ghidra calls need.

   ```python
   @mcp.tool()
   def get_function_by_address(binary_name: str, address: str, ctx: Context) -> FunctionInfo:
       """Get function metadata (name, signature) for the function at or containing an address.

       Args:
           binary_name: Name of the binary.
           address: Hex address (with or without 0x prefix).
       """
       try:
           return _tools(ctx, binary_name).get_function_by_address(address)
       except Exception as e:
           raise _err(e) from e
   ```

   - `_tools(ctx, binary_name)` selects the binary and returns a `GhidraTools` for it. It fails with `[fix_input]` if no binary has that name, and with `[retry_later]` if the binary is still being analyzed (after waiting up to 45 s).
   - `_err(e)` turns an exception into the error the agent sees, tagged with a recovery category (see Failures).
   - A tool that reads two binaries gets both from the context and holds both locks with `_locked`, so two calls can't deadlock:

     ```python
     ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
     first = ghidra_ctx.get_program_info(binary_name)
     second = ghidra_ctx.get_program_info(other_binary_name) if other_binary_name else first
     with _locked(first, second):
         ...  # GhidraTools(first), GhidraTools(second)
     ```

2. **The implementation** is a `GhidraTools` method in `src/ghidra_mcp/tools.py`, decorated with `@handle_exceptions`. The decorator holds the binary's lock while the method runs and logs failures. `self.program` is the Ghidra `Program`.

3. **The result** is a pydantic model in `src/ghidra_mcp/models.py`. Return a model, not a dict or a string, so the agent gets structured output with a schema. Describe each field with `Field(description=...)`.

4. **Tests.** See Testing below.

## Failures

Raise an exception and let `_err` classify it:

| Raise | The agent sees | Meaning |
|---|---|---|
| `ValueError` (or `FixInput`) | `[fix_input] <message>` | Change the request: a bad address, a size out of range, an unknown function |
| `RetryLater` | `[retry_later] <message>` | Try the same request again later |
| `Stop` | `[stop] <message>` | Don't retry: the request can't succeed |
| anything else | `[stop] Internal error; …` | The message is hidden from the agent; the traceback goes to the server log |

`FixInput`, `RetryLater` and `Stop` are in `src/ghidra_mcp/errors.py`. Write messages for the agent: say what was wrong and what to do instead.

## Helpers to reuse

In `GhidraTools`:

- `self._parse_address(text)` turns hex, with or without `0x`, into a Ghidra `Address`; it raises `ValueError` if the text doesn't parse.
- `self.resolve_function(name_or_address, ResolutionMode.READ)` finds a function by name (case-insensitive, optionally namespace-qualified) or by address. It also accepts a unique partial name, or an address inside a function, and then sets `.note` to say what it matched; return that note in a `resolution` field so the agent knows. `.target` is the `Function`.
- `self.decompile_function(func)` returns a `DecompiledFunction` with the C `code` and `signature`.
- `self._error_text(e)` gives a readable message for a Java exception.

## Testing

- `mise run test` runs the unit tests. They use fakes and need no Ghidra.
- `mise run check` runs the exercise acceptance tests; `mise run check:<name>` runs one exercise's (see `mise tasks`).
- `mise run test:integration` runs the integration tests against the real Ghidra.

`tests/program_fakes.py` is an in-memory stand-in for a Ghidra `Program`; `tools_for(program)` gives a `GhidraTools` over one (see `tests/test_queries.py`). `tests/exercises/support.py` shows how to call a tool through MCP, as an agent would.

The fakes model only the Ghidra API the tools use, roughly:

- **Memory:** `program.getMemory()`, then `getBlock(addr)`, `block.isInitialized()`, `getBytes(addr, buf)`. Allocate `buf` with `JByte[size]`; the tests replace `JByte` with a fake. Java bytes are signed, so mask each one with `& 0xFF`.
- **Functions:** `program.getFunctionManager()`, then `getFunctionAt(addr)`, `getFunctionContaining(addr)`, `getFunctions(True)`. On a function: `getName(True)`, `getEntryPoint()`, `getBody()`, `isThunk()`, `getThunkedFunction(True)`, `getFunctionThunkAddresses(True)`, `isExternal()`.
- **References:** `program.getReferenceManager()`, then `getReferencesTo(addr)` and `getReferencesFrom(addr)`. On a reference: `getFromAddress()`, `getToAddress()`, `getReferenceType().isCall()`.
- **Instructions:** `program.getListing().getInstructions(func.getBody(), True)`. On an instruction: `getAddress()`, `getMnemonicString()`, `getNumOperands()`, `getDefaultOperandRepresentation(i)`, `getFlowType()` (`isCall()`, `isComputed()`), `str(instr)`.

If your code calls something the fakes lack, a test fails with `AttributeError`. Add what you need to `tests/program_fakes.py`, behaving as Ghidra does.

## Running the server

The student runs the server in their own terminal (`mise run workshop:serve`, or `mise run workshop:gui` for the Ghidra GUI). You can't start it, because you can't read the workshop folder. The server registers its tools when it starts, so after you add or change a tool, ask the student to restart the server and reconnect you.
