# A Lightweight MCP Server and devcontainer for AI Assisted Binary Diffing

An MCP server that runs Ghidra headless (or inside the Ghidra GUI) and gives an AI agent a small set of native Ghidra tools: listing functions and segments, searching strings, decompiling, disassembling, and following cross-references. In the workshop you and your agent add more tools to it.

**Start with [SETUP.md](SETUP.md)** to set up for the workshop, and see [AGENTS.md](AGENTS.md) for how a tool is put together.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **[mise](https://mise.jdx.dev)** | Sets up the project's Python environment and runs it. Install with `brew install mise` or see the mise docs |
| **Ghidra 12.1+** | Tested on 12.1.4. Download from [ghidra-sre.org](https://ghidra-sre.org); you point the project at it |
| **JDK 21+** | Required by Ghidra 12.1; you point the project at it |

mise provides Python 3.13 in a project-local virtual environment (`.venv`). The package itself supports Python 3.11–3.14; 3.13 is pinned because pyghidra's JPype dependency ships prebuilt wheels up to 3.13. Nothing is installed or configured outside the project directory.

---

## How It Works

### Finding Ghidra

pyghidra locates Ghidra through `GHIDRA_INSTALL_DIR` and the JDK through `JAVA_HOME`, both set by mise from `mise.local.toml`. The server fails to start with a clear error if either path is wrong.

### Loading a Binary and Running Analysis

Pass one or more binary paths as positional arguments on startup:

```bash
ghidra-mcp /path/to/binary [/path/to/another ...]
```

What happens internally:

1. `pyghidra.start()` initialises the Ghidra JVM (loads Ghidra's JAR files into the Python process via JPype).
2. A Ghidra project is created or opened at `--project-path` / `--project-name` (defaults: `./ghidra_projects/my_project`).
3. Each binary is imported into the project via `GhidraProject.importProgram()` and saved. Binaries are named `<filename>-<sha1[:6]>` to allow the same filename from different paths.
4. Ghidra auto-analysis (`analyzeAll`) runs in a background thread. The server answers the MCP handshake immediately; a tool call for a binary that is still being analyzed fails with `[retry_later]`.
5. The Ghidra project is persisted to disk. On the next startup with the same `--project-path`, already-analyzed binaries are re-opened instantly, with no re-analysis.

By default, a tool call for a binary that is still being analyzed waits up to 45 s for it, then fails with `[retry_later]`, saying how long analysis has been running or where the binary is in the queue. To fail straight away instead:

```bash
ghidra-mcp --no-wait-for-analysis /path/to/binary
```

Large binaries (Go binaries in particular) can take many minutes to analyze. Pre-analyze them once, then every later start serves them instantly:

```bash
ghidra-mcp --analyze-only /path/to/binary   # exits non-zero if any binary failed
```

---

## Quick Start

Run these from the project directory (`mise run serve` and `mise run gui` pass their arguments to `ghidra-mcp`):

```bash
# Import, analyze, and serve a binary over stdio
mise run serve /path/to/target_binary

# Serve over HTTP (useful for remote VMs)
mise run serve --transport streamable-http --host 0.0.0.0 --port 8000 /path/to/target_binary

# Open an existing Ghidra project without importing anything
mise run serve --project-path /path/to/existing_project.gpr

# List what's already in the project
mise run serve --project-path ~/ghidra_projects --list-project-binaries

# Analyze ahead of time without serving
mise run serve --analyze-only /path/to/target_binary

# GUI mode: open the Ghidra GUI and serve alongside it (see GUI Mode)
mise run gui --project-path ~/ghidra_projects /path/to/target_binary
```

---

## MCP Client Configuration

There are two deployment patterns:

- **Local** — the MCP client launches the server as a subprocess on the same machine (`stdio` transport). Use this for desktop RE work.
- **Remote** — the server runs on a VM or container (`streamable-http` transport). The MCP client connects over HTTP. Use this for cloud-based headless analysis (e.g. a t3.small).

A client launches the server outside your shell, so local configurations run it through mise: `mise exec -C /path/to/this/repo -- ghidra-mcp …` applies the project's Python environment and the paths in `mise.local.toml`. Use absolute paths. If the client cannot find `mise` (for example, an editor started from the Dock), give its full path instead, such as `/opt/homebrew/bin/mise` (see `which mise`).

---

### Claude Code

Config file: `~/.claude/settings.json`

**Local (stdio):**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "mise",
      "args": [
        "exec", "-C", "/path/to/this/repo", "--",
        "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
      ]
    }
  }
}
```

**Remote VM (streamable-http):**

Start the server on the VM, from the project directory:
```bash
mise run serve --transport streamable-http --host 0.0.0.0 --port 8000 /path/to/binary
```

Configure Claude Code to connect:
```json
{
  "mcpServers": {
    "ghidra": {
      "type": "http",
      "url": "http://<vm-ip>:8000/mcp"
    }
  }
}
```

Add via CLI:
```bash
# stdio
claude mcp add ghidra -- mise exec -C /path/to/this/repo -- ghidra-mcp --project-path /path/to/ghidra_projects /path/to/binary

# remote HTTP
claude mcp add --transport http ghidra http://<vm-ip>:8000/mcp
```

---

### GitHub Copilot (VS Code)

Create or edit `.vscode/mcp.json` in your workspace:

**Local (stdio):**

```json
{
  "servers": {
    "ghidra": {
      "type": "stdio",
      "command": "mise",
      "args": [
        "exec", "-C", "/path/to/this/repo", "--",
        "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
      ]
    }
  }
}
```

**Remote VM (HTTP):**

```json
{
  "servers": {
    "ghidra": {
      "type": "http",
      "url": "http://<vm-ip>:8000/mcp"
    }
  }
}
```

For a user-level (not workspace) config, add the same block under `"mcp"` in VS Code's `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "ghidra": {
        "type": "stdio",
        "command": "mise",
        "args": [
          "exec", "-C", "/path/to/this/repo", "--",
          "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
        ]
      }
    }
  }
}
```

---

### Cline

Config file locations:
- **macOS:** `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Linux:** `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Windows:** `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

Or configure from the Cline panel: **MCP Servers → Edit MCP Settings**.

**Local (stdio):**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "mise",
      "args": [
        "exec", "-C", "/path/to/this/repo", "--",
        "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Remote VM (HTTP):**

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://<vm-ip>:8000/mcp",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

---

## GUI Mode

Run the server inside the Ghidra GUI to watch the agent's work:

```bash
mise run gui --project-path ~/ghidra_projects /path/to/binary
claude mcp add --transport http ghidra http://127.0.0.1:8000/mcp   # in another terminal
```

`--gui` opens the Ghidra GUI in the server's own process with the project open, and serves MCP over streamable HTTP (`--host`/`--port` as usual). The tools work on the same in-memory programs CodeBrowser shows.

- **Analysis is Ghidra's own.** Imports open the program in CodeBrowser as a new, non-current tab and run Ghidra's auto-analysis there, with its progress bar and cancel button. Ghidra does not report analyzer failures to the server, so a binary whose analysis partly failed is listed as `ready`. Analysis you start yourself from the Analysis menu shows as `analyzing`. A program that was not analyzed (you cancelled, or imported it without analyzing) is `failed` until you analyze it in Ghidra and restart `ghidra-mcp --gui`.
- **Three extra tools.** `get_current_address` and `get_current_function` report where your cursor is in the most recently focused CodeBrowser; `go_to` moves CodeBrowser to a binary, address, or symbol. They exist only in GUI mode.
- **You own saving.** The server never saves the project in GUI mode; save from Ghidra when you want to keep its state.
- **One project, one session.** GUI mode serves the project it opened; if you close or switch projects in the GUI, tool calls fail until you restart `ghidra-mcp --gui`. Closing the Ghidra GUI stops the server. stdio is not available in GUI mode.

A Ghidra project can be open in only one process at a time, so a headless `ghidra-mcp` and a separately started Ghidra GUI cannot share a project; GUI mode is how to use both at once.

---

## CLI Reference

```
ghidra-mcp [OPTIONS] [INPUT_PATHS]...
```

| Option | Default | Description |
|--------|---------|-------------|
| `-t, --transport` | `stdio` | Transport: `stdio` or `streamable-http` |
| `-p, --port` | `8000` | Port (HTTP transports only) |
| `-o, --host` | `127.0.0.1` | Host (HTTP transports only). Use `0.0.0.0` for remote access |
| `--project-path` | `./ghidra_projects` | Project directory, or path to an existing project's `.gpr` file (not its `.rep` folder). `~` and relative paths are resolved; `mise run` resolves relative paths from the project directory |
| `--project-name` | `my_project` | Project name (ignored when `--project-path` is a `.gpr` file) |
| `--wait-for-analysis` / `--no-wait-for-analysis` | on | Let tool calls for a binary still being analyzed wait up to 45 s before returning `retry_later`. Startup never blocks |
| `--verbose-analysis` | off | Print verbose Ghidra analysis output to stderr |
| `--symbols-path` | auto | Local symbol store directory |
| `--list-project-binaries` | — | Print all binaries in the project and exit |
| `--delete-project-binary NAME` | — | Delete a binary from the project and exit |
| `--gui` | off | GUI mode: open the Ghidra GUI in this process and serve over streamable HTTP alongside it (see [GUI Mode](#gui-mode)) |
| `--analyze-only` | — | Import inputs, analyze every binary to completion, print each binary's status, and exit (non-zero if any failed) |

Environment variables: `MCP_TRANSPORT`, `MCP_PORT`, `MCP_HOST`, `GHIDRA_INSTALL_DIR`.

---

## Tool Reference

### Project Management

| Tool | Description |
|------|-------------|
| `list_project_binaries` | List all binaries, including ones still importing, with status (`importing`, `analyzing`, `ready`, `failed`), failure reason, configuration warnings, and metadata |
| `import_binary` | Import a binary (or directory) from disk and analyze it in the background. Optional per-binary analysis options: `pdb_path`, `gdts`, `analyzer_options` (`{option name: value}`), `no_symbols` |

### Navigation / Discovery

| Tool | Description |
|------|-------------|
| `list_functions` | Functions defined in the binary (excludes external/imported functions and thunks) with addresses and signatures; filterable by name |
| `list_segments` | Memory segments: name, range, size, r/w/x, type |
| `search_strings` | Case-insensitive substring search over all defined strings (an empty query lists them all) |

### Function Lookup

| Tool | Description |
|------|-------------|
| `get_function_by_address` | Function name and signature at an address (no decompilation) |

### Disassembly / Decompilation

| Tool | Description |
|------|-------------|
| `disassemble_function` | Assembly listing: address, bytes, mnemonic, operands, EOL comments (unreadable fields are listed per instruction) |
| `decompile_function` | Pseudo-C output via the Ghidra decompiler (up to 120 s; a decompiler failure is an error) |

### Cross-References

| Tool | Description |
|------|-------------|
| `list_cross_references` | All references *to* a function, symbol, or address |

### GUI Mode Only

| Tool | Description |
|------|-------------|
| `get_current_address` | The binary, address, and function at the cursor in CodeBrowser |
| `get_current_function` | The function containing the cursor in CodeBrowser |
| `go_to` | Show a binary, address, or symbol in CodeBrowser |
