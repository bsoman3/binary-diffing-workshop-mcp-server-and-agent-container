#!/usr/bin/env bash
# Runs once when the container is created: install the server into the container's venv
# and point each agent at the server.
set -euo pipefail
cd /workspace

# The repo belongs to the host user, not the container's, and git refuses to work in a
# repo another user owns.
git config --global --add safe.directory /workspace

mise trust --all
# .venv is a volume mount point, so it exists but is empty, and mise only creates a
# venv when the folder is missing.
[ -x .venv/bin/python ] || python -m venv .venv
mise run install

MCP_URL=http://127.0.0.1:8000/mcp

claude mcp add --scope user --transport http ghidra "$MCP_URL" 2>/dev/null || true

if ! grep -qs '^\[mcp_servers.ghidra\]' ~/.codex/config.toml; then
    printf '\n[mcp_servers.ghidra]\nurl = "%s"\n' "$MCP_URL" >> ~/.codex/config.toml
fi

copilot mcp add --transport http ghidra "$MCP_URL" 2>/dev/null || true
