# Install & Connect Private Desktop MCP with an Agent

Last reviewed: 2026-11-25

This guide is written for both people and AI coding agents (Claude Code, Codex, Cursor, VS Code Copilot, Gemini CLI, OpenClaw, Windsurf, and Antigravity).

It separates two roles that can run on the same computer or across different computers:

1. **Connecting an AI Client (Remote Streamable HTTP MCP)** — registering the Cloudflare Access-protected `/mcp` endpoint in the user's AI client or installing the repository plugin/skill.
2. **Running the Device Connector (`private-desktop-mcp connect`)** — running the outbound WebSocket agent on each Windows, macOS, or Linux desktop the user wants to control.

---

## Prompt to Paste into Your Coding Agent

```text
Install and configure Private Desktop MCP for me using the official instructions at:
https://github.com/KFCheems/private-desktop-mcp/blob/main/docs/agent-install.md

Before changing anything:
1. Identify my operating system and AI client(s), and run `npx --yes @juexibobi/private-desktop-mcp@latest doctor --json`.
2. Ask whether I want to:
   (a) register the remote MCP server in my AI client,
   (b) pair/connect this computer as a controllable desktop device (and whether to use `--readonly` or `--allow-dir`), or
   (c) both.
3. Preview the exact configuration file changes using `setup-client <client> --dry-run --json` and wait for my confirmation before writing files.
4. Never ask me to paste Cloudflare tokens, Access cookies, or `device.json` secrets into chat.
```

---

## Instructions for the Installing Agent

### Step 1: Preflight Check (Read-Only)

Run the built-in JSON doctor to verify Node.js (`>=20.18.1`), effective system proxy (Windows WinINET / macOS `scutil` / environment), relay reachability, and local pairing state:

```bash
npx --yes @juexibobi/private-desktop-mcp@latest doctor --json
```

### Step 2: Register the Remote MCP Server in the AI Client

#### Option A: Native Plugin / Extension Install (Recommended where supported)

- **Claude Code**:
  ```bash
  claude mcp add --transport http private-desktop https://private-desktop-device-relay.ljx2043979076.workers.dev/mcp
  ```
  Or install from the plugin marketplace:
  ```text
  /plugin marketplace add KFCheems/private-desktop-mcp
  /plugin install private-desktop-mcp@private-desktop-mcp
  ```
- **Codex**:
  ```bash
  codex plugin marketplace add KFCheems/private-desktop-mcp
  ```
- **Gemini CLI**:
  ```bash
  gemini extensions install https://github.com/KFCheems/private-desktop-mcp
  ```
- **Antigravity**:
  ```bash
  agy plugin install https://github.com/KFCheems/private-desktop-mcp
  ```
- **Agent Skill only** (`npx skills`):
  ```bash
  npx --yes skills add KFCheems/private-desktop-mcp
  ```

#### Option B: Automated Non-Destructive Config Merge (`setup-client`)

For `claude-code`, `claude-desktop`, `cursor`, `vscode`, `codex`, `gemini`, or `windsurf`:

1. **Preview first (`--dry-run --json`)**:
   ```bash
   npx --yes @juexibobi/private-desktop-mcp@latest setup-client <client> --dry-run --json
   ```
   *(If the user self-hosts their own Cloudflare Worker, append `--relay https://<their-worker-domain>`.)*
2. Show the user `path`, `action`, and `preview`, and wait for confirmation.
3. **Apply**:
   ```bash
   npx --yes @juexibobi/private-desktop-mcp@latest setup-client <client> --json
   ```

### Step 3: Pair & Start the Device Connector (When Controlling the Local Machine)

1. Choose the appropriate safety profile with the user:
   - **Read-only + Workspace Jail (Safest default for exploration/debugging)**:
     ```bash
     npx --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect --readonly --allow-dir "<workspace_path>" --json
     ```
   - **Full Desktop Commander access (Filesystem + Shell + Process management)**:
     ```bash
     npx --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect --json
     ```
2. If `"paired": false`, the connector emits a single JSON line:
   ```json
   {"event":"pairing_required","deviceName":"...","code":"XXXXXXXXXX","approvalUrl":"https://.../admin/devices","pairId":"...","expiresIn":3600}
   ```
   Display the **`code`** and **`approvalUrl`** to the user and ask them to sign into Cloudflare Access in their browser and click **批准设备 (Approve)**.
3. Once approved, the connector saves `device.json` locally (`0600`) and maintains the outbound WebSocket connection until stopped with `Ctrl+C`.

### Step 4: Verify Multi-Device MCP Connectivity

Once connected, verify from the MCP client with a harmless read-only call:

1. Call `relay_list_devices` (or read resource `relay://devices`) to confirm the machine appears as `online: true`.
2. Call `relay_ping_device` to verify round-trip latency and `gatewayReady: true`.
