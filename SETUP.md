# Workshop setup

## System Requirements

| | |
|---|---|
| **Computer** | macOS or Linux. On Windows, use WSL2. About 5 GB of free disk space |
| **git** | |
| **Docker Desktop** | On macOS or Linux. Start it before step 7. To use Docker Engine on Linux instead, see [Options](#use-docker-engine-on-linux) |
| **Node.js** | Any current version, for `npm` |
| **[mise](https://mise.jdx.dev)** | `brew install mise`, or `curl https://mise.run \| sh` |
| **Ghidra 12.1 or later** | Download it from [ghidra-sre.org](https://ghidra-sre.org) and unzip it anywhere. Tested on 12.1.4 |
| **JDK 21 or later** | On macOS: `brew install --cask temurin@21`. On Ubuntu: `sudo apt install openjdk-21-jdk` |
| **An AI coding agent** | Claude Code, Codex or GitHub Copilot, and an account you can sign in with. You install the agent in step 7 |
| **The workshop files** | Provided on Discord |

## 1. Clone the repo

```bash
git clone https://github.com/bsoman3/binary-diffing-workshop-mcp-server-and-agent-container.git
cd binary-diffing-workshop-mcp-server-and-agent-container
git switch -c my-work
```

## 2. Create a home for the workshop binaries

```bash
mkdir -p ~/ghidra-workshop/binaries
```
or your preferred path to the binaries. Put the files shared on discord here.

Keep this folder outside the repo. Your agent must not read it; it reaches the binaries only through the server.

## 3. Local Settings for the MCP server

Copy the example settings file:

```bash
cp mise.local.toml.example mise.local.toml
```

Open `mise.local.toml` and set the three paths:

```toml
[env]
GHIDRA_INSTALL_DIR = "/path/to/ghidra_12.1.4_PUBLIC"
JAVA_HOME = "/path/to/jdk-21"
GHIDRA_WORKSHOP_DIR = "/Users/you/ghidra-workshop"
```

- `GHIDRA_INSTALL_DIR`: the Ghidra folder you unzipped. It contains `ghidraRun`.
- `JAVA_HOME`: on macOS, run `/usr/libexec/java_home -v 21` and paste what it prints. On Ubuntu it's usually `/usr/lib/jvm/java-21-openjdk-amd64`.
- `GHIDRA_WORKSHOP_DIR`: the full path of the folder from step 2. 

## 4. Install the server

```bash
mise trust
mise install
mise run install
mise run test
```

The last command runs the tests. Its last line should say `passed`.

## 5. Analyze the binaries

```bash
mise run workshop:analyze
```

Ghidra analyzes each binary once and saves the result. This takes a few minutes per binary. Wait for it to finish.

## 6. Start the server

```bash
mise run workshop:gui
```

This starts Ghidra with the workshop project. And runs the server at `http://127.0.0.1:8000/mcp`. Leave both running.

**The server doesn't save for you.** Before you stop the server, save in Ghidra: **File → Save All**. Anything you don't save is lost, and unsaved analysis runs again at the next start.

## 7. Start the workshop container

This is the container in which your agent will run. It can read and edit the repo, but it can't commit, and it can't see your workshop folder.

Open a second terminal, go to the repo folder, and run:

```bash
npm install -g @devcontainers/cli
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

The first `devcontainer up` takes a few minutes. The last command gives you a shell inside the container.

## 8. Start your agent

In the container shell, run one of these:

```bash
claude
codex
copilot
```

Sign in as required. The agent should already be connected to the mcp server running from step 6.

## 9. Check your setup

Ask your agent:

1. "List the binaries in the Ghidra project."

   It should list the binarie(s).

2. "List the files in ~/ghidra-workshop/binaries."

   It should fail, because that folder isn't in the container. If it lists the binaries, see [Troubleshooting](#troubleshooting).

**THAT'S IT! YOU'RE READY!**

## During the workshop

**After you add or change a tool,** restart the server and reconnect your agent:

1. In Ghidra, choose **File → Save All**.
2. In the server terminal, press Ctrl+C. Ghidra closes.
3. Commit your agent's changes in the same terminal: `git add -A && git commit -m "Add <tool>"`. The agent can't commit from the container, so commit here, on your computer.
4. Run `mise run workshop:gui` again.
5. In Claude Code, run `/mcp`. In Codex or Copilot, quit and start the agent again.

**To stop the server,** choose **File → Save All** in Ghidra, then press Ctrl+C in the server terminal. Don't just close the terminal (if you do, the binaries will get re-analyzed. No biggie).

**To come back later,** start the server (step 6), then run the two `devcontainer` commands from step 7.

## Options

### Run the server without the Ghidra GUI

In step 6, and whenever you restart the server, run this instead:

```bash
mise run workshop:serve
```

The server runs at the same address, without opening Ghidra. It saves its analysis itself, so you don't need to save. Stop it with Ctrl+C.

### Use Docker Engine on Linux

Docker Desktop lets the container reach the server on your computer's `127.0.0.1`. Docker Engine doesn't, so the server has to listen on Docker's network instead:

1. In step 3, also add this line under `[env]` in `mise.local.toml`:

   ```toml
   MCP_HOST = "172.17.0.1"
   ```

2. If you use the ufw firewall, allow the container to reach the server:

   ```bash
   sudo ufw allow in on docker0 to any port 8000
   ```

3. Start or restart the server (step 6).

### Open the container in VS Code

Instead of step 7:

1. Install the Dev Containers extension in VS Code.
2. Open the repo folder in VS Code.
3. Run **Dev Containers: Reopen in Container** from the command palette.
4. Open a terminal in VS Code, and continue with step 8.

### Keep the workshop files somewhere else

Copy them anywhere outside the repo, and set `GHIDRA_WORKSHOP_DIR` in step 3 to that folder. If you also run your agent without Docker, deny that folder instead of `~/ghidra-workshop` in its settings.

### Run your agent without Docker

You can run your agent directly on your computer instead of in the container. Then you use its own sandbox to block it from the workshop folder.

Skip steps 7 and 8, and set up your agent as below. Then do step 9. The second check should be refused by the sandbox.

#### Claude Code

Works on macOS, Linux and WSL2. On Linux and WSL2, install `bubblewrap` and `socat` first.

1. Connect Claude Code to the server. Run this from the repo:

   ```bash
   claude mcp add --transport http ghidra http://127.0.0.1:8000/mcp
   ```

2. Start Claude Code from the repo with these settings. Use this command every time you start Claude Code for the workshop:

   ```bash
   claude --settings '{"sandbox": {"enabled": true, "failIfUnavailable": true, "allowUnsandboxedCommands": false, "filesystem": {"denyRead": ["~/ghidra-workshop"]}}, "permissions": {"deny": ["Read(~/ghidra-workshop/**)"]}}'
   ```

   - `denyRead` stops Claude's shell commands from reading the folder, and the `Read(...)` rule stops its file tools.
   - `allowUnsandboxedCommands: false` stops Claude from retrying a blocked command outside the sandbox.

3. Run `/mcp` to check that `ghidra` is connected.

#### Codex CLI

Update Codex to the latest version first. Works on macOS, Linux, WSL2 and Windows.

1. Add this to `~/.codex/config.toml`. Replace `/Users/you` with your home folder (`echo $HOME` prints it). Put the first two lines above any `[table]` already in the file:

   ```toml
   approval_policy = "never"
   default_permissions = "workshop"

   [permissions.workshop]
   extends = ":workspace"

   [permissions.workshop.filesystem]
   "/Users/you/ghidra-workshop" = "deny"

   [mcp_servers.ghidra]
   url = "http://127.0.0.1:8000/mcp"
   ```

   - The `workshop` profile is Codex's usual workspace sandbox, plus a rule that blocks `~/ghidra-workshop`. The path must be absolute.
   - `approval_policy = "never"` turns off approval prompts, so Codex can't ask to run a command outside the sandbox.
   - If your config already sets `sandbox_mode` or has a `[sandbox_workspace_write]` table, comment them out. They can't be combined with `default_permissions`.
   - These settings apply to every Codex session. Remove them after the workshop.

2. Start Codex from the repo. `codex mcp list` should show `ghidra`.

#### GitHub Copilot CLI

On Linux, install `bubblewrap` (0.5.0 or later) and `slirp4netns` first. On Windows, the sandbox needs a recent Windows 11 build.

1. Connect Copilot to the server:

   ```bash
   copilot mcp add --transport http ghidra http://127.0.0.1:8000/mcp
   ```

2. Start `copilot` from the repo and run `/sandbox`:
   - On the **General** tab, check that the sandbox is on, and turn off **Allow sandbox bypass**.
   - On the **Filesystem** tab, select **User-configured paths**, press <kbd>A</kbd>, enter the full path of `~/ghidra-workshop` (such as `/Users/you/ghidra-workshop`), and set it to **Denied**.
   - On the **Network** tab, turn on **Allow local network**, so Copilot can reach the server.

#### GitHub Copilot app

1. Add an MCP server named `ghidra` with the URL `http://127.0.0.1:8000/mcp`.
2. Open **Settings**, select this project under **Projects**, and open **Sandbox**. In the **Denied** list, click **Add folder** and choose `~/ghidra-workshop`.

Don't use VS Code's regular agent mode for the workshop. Only its Agent Host sessions are sandboxed.

## Troubleshooting

**mise says a variable must be set.** Open `mise.local.toml` and set all three paths (step 3).

**`devcontainer up` says it can't connect to Docker.** Start Docker, then run it again.

**The agent can't connect to the server.**
- Check that the server is still running in its terminal.
- On Linux with Docker Engine, follow [Use Docker Engine on Linux](#use-docker-engine-on-linux).
- Copilot CLI without Docker: if **Allow local network** is on and it still can't connect, turn off **Sandbox MCP servers** in `/sandbox`.

**Codex can't sign in from the container.** Run `codex login --device-auth`, and follow the instructions.

**The agent doesn't see a new tool.** Restart the server and reconnect the agent ([During the workshop](#during-the-workshop)).

**Tool calls return `retry_later`.** The server is still analyzing the binaries. Wait, or stop the server and run step 5 first.

**The server analyzes the binaries again every time it starts.** The analysis was never saved. Run step 5 and let it finish, and choose **File → Save All** in Ghidra before you stop the server.

**The agent can list `~/ghidra-workshop/binaries`.** The agent is running outside the container, or its sandbox isn't set up. Quit it, and start it inside the container (steps 7 and 8).
