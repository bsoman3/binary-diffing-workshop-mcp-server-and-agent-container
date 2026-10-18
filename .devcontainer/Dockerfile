# Agent container for the workshop. Ghidra, the JDK and the workshop binaries stay on the
# host; the agent edits this repo and reaches the binaries only through the server's port.
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# socat forwards the container's 127.0.0.1:8000 to the server on the host (see CMD).
# Removing the sudoers entry leaves the agent without root.
RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/sudoers.d/vscode \
    && mkdir -p /workspace/.venv \
    && chown -R vscode:vscode /workspace

USER vscode
ENV MISE_YES=1 \
    PATH=/home/vscode/.local/bin:/home/vscode/.local/share/mise/shims:$PATH \
    CLAUDE_CONFIG_DIR=/home/vscode/.claude

# Python 3.13 matches mise.toml; Node runs the agent CLIs.
RUN curl -fsSL https://mise.run | sh \
    && mise use -g python@3.13 node@22 \
    && npm install -g @anthropic-ai/claude-code @openai/codex @github/copilot \
    && mise reshim \
    && echo 'eval "$(mise activate bash)"' >> ~/.bashrc \
    && mkdir -p ~/.claude ~/.codex ~/.copilot

# The server only accepts requests addressed to localhost, so agents use
# http://127.0.0.1:8000/mcp and socat relays it to the host.
CMD ["socat", "TCP-LISTEN:8000,bind=127.0.0.1,fork,reuseaddr", "TCP:host.docker.internal:8000"]
