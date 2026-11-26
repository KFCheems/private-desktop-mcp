# Private Desktop MCP

Self-hosted, **Agent-Native** multi-device [Model Context Protocol](https://modelcontextprotocol.io/) bridge for Desktop Commander (and optional additional local MCP servers) using Cloudflare Workers, SQLite-backed Durable Objects, and a one-command cross-platform connector.

**Transport:** Streamable HTTP (`POST` + `DELETE`, supporting both MCP `2025-*` and stateless `2026-07-28`) to AI clients; outgoing WebSocket with zero-cost hibernation heartbeat from each device to the relay.

## Quick Start: Install with Your Coding Agent

Paste the block below into Claude Code, Codex, Cursor, VS Code Copilot, Gemini CLI, OpenClaw, or Antigravity:

```text
Install and configure Private Desktop MCP for me using the official instructions at:
https://github.com/KFCheems/private-desktop-mcp/blob/main/docs/agent-install.md
Before changing anything, identify my OS and AI client, run `npx --yes @juexibobi/private-desktop-mcp@latest doctor --json`, preview client config changes with `setup-client <client> --dry-run --json`, and wait for my confirmation.
```

Or install directly via native agent plugin / extension marketplaces:

```bash
# Claude Code
/plugin marketplace add KFCheems/private-desktop-mcp
/plugin install private-desktop-mcp@private-desktop-mcp

# Codex
codex plugin marketplace add KFCheems/private-desktop-mcp

# Gemini CLI
gemini extensions install https://github.com/KFCheems/private-desktop-mcp

# Antigravity
agy plugin install https://github.com/KFCheems/private-desktop-mcp

# Agent Skill only (npx skills)
npx --yes skills add KFCheems/private-desktop-mcp
```

## Public npm release (Device Connector)

```powershell
npx.cmd --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect
```

Each release gets its own immutable npm version. **Do not overwrite a fixed `.tgz` at a stable URL**: npm caching might start an old version.

## What's new in v0.5.0 (Agent-Native Edition)

### Agent-Native MCP Protocol & Multi-Device Self-Healing
- **Edge-Always-Alive MCP Lifecycle**: `initialize`, `notifications/initialized`, `ping`, `server/discover`, `tools/list`, `resources/list`, `resources/read` (`relay://*`), `prompts/list`, and `prompts/get` succeed at the Cloudflare Worker edge **even when zero devices are online or multiple devices are online without a selection**, allowing agents to connect, inspect inventory, and guide the user instead of failing with HTTP transport errors.
- **Dynamic Server Instructions**: `initialize` / `server/discover` automatically injects live paired-device inventory (`online/offline`, OS, read-only status, selected target) and multi-device routing guidance into MCP `instructions`.
- **Schema-Native `_device` Parameter**: Every upstream tool in `tools/list` (`read_file`, `start_process`, `write_file`, etc.) has an optional `_device` string property injected into its `inputSchema.properties`, enabling schema-strict agents to target any paired computer per call without mutating global selection.
- **Built-in Edge Meta-Tools, Resources & Prompts**:
  - **Tools**: `relay_list_devices`, `relay_select_device`, `relay_ping_device`, `relay_set_device_policy` (lock/unlock read-only mode or rename a device in chat), and `relay_recent_activity`.
  - **Resources**: `relay://devices`, `relay://status`, and `relay://audit` (`application/json`).
  - **Prompts**: `multi-device-triage` and `safe-remote-maintenance`.
- **Self-Healing Tool Errors**: When a `tools/call` targets an offline or ambiguous device, the relay returns a structured JSON-RPC `isError: true` result containing `errorCode`, `onlineDevices`, `selectedDeviceId`, and `nextActions` so the agent recovers autonomously.

### Agent-Native CLI & Ecosystem Manifests
- **Universal `--json` Mode**: `doctor --json`, `status --json`, `report --json`, `reset --json`, `setup-client --json`, and `connect --json` (emits `{"event":"pairing_required",...}` and `{"event":"pairing_approved",...}`).
- **Automated Client Configurator (`setup-client`)**: Non-destructively merges the remote MCP endpoint into `claude-code`, `claude-desktop`, `cursor`, `vscode`, `codex`, `gemini`, `windsurf`, or `all`, with `--dry-run` preview support.
- **Cross-Platform Agent Manifests & Playbooks**: Ships [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md), [docs/agent-install.md](docs/agent-install.md), [skills/private-desktop-mcp/SKILL.md](skills/private-desktop-mcp/SKILL.md), `plugin.json`, `.claude-plugin/`, `gemini-extension.json`, and `.antigravity-plugin/`.

### Security, Governance & Reliability (v0.4.0+)
- **Cryptographic Cloudflare Access JWT verification (`worker/auth.mjs`)**: Verifies RS256 signatures against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (with automatic `kid` key-rotation refresh), `aud`, `iss`, `exp`, and `nbf`.
- **Hardened local gateway (`gateway.mjs`)**: Per-launch ephemeral Bearer authentication (`MCP_LOCAL_TOKEN`), loopback `Host` validation (anti-DNS-rebinding), browser `Origin` rejection (anti-CSRF), and authenticated `/healthz`.
- **Local policy guardrails & Outbound DLP (`bin/policy.mjs`)**: `--readonly`, `--allow-dir <dir>` (symlink-aware path jail), `--allow-tools` / `--deny-tools`, self-credential protection (`PrivateDesktopMCP/device.json`), and automatic outbound secret redaction (PEM keys, AWS/GitHub/OpenAI/Slack/Google tokens, and active relay tokens).
- **Zero-cost WebSocket hibernation heartbeat & auto-recovery**: RFC 6455 `ws.ping()` + DO `setWebSocketAutoResponse("ping", "pong")`, jittered backoff reset, `DELETE /mcp` + client `AbortSignal` cancel propagation, and automatic local `gateway.mjs` crash recovery.

## CLI commands & flags

```powershell
# Connect (default)
private-desktop-mcp connect

# Safe read-only mode jailed to a workspace directory
private-desktop-mcp connect --readonly --allow-dir C:\workspace

# Configure MCP clients (with --dry-run preview and --json for agents)
private-desktop-mcp setup-client claude-code --dry-run --json
private-desktop-mcp setup-client cursor

# Aggregate extra local MCP servers alongside Desktop Commander
private-desktop-mcp connect --servers ./client-configs/servers.example.json

# Machine-readable diagnostics & status
private-desktop-mcp doctor --json
private-desktop-mcp report --json
private-desktop-mcp status --json
private-desktop-mcp reset --json
```

## Current canonical endpoint

```text
https://private-desktop-device-relay.ljx2043979076.workers.dev/mcp
```

## Pairing devices

1. On a machine with Node.js 20.18.1+ run `private-desktop-mcp connect`.
2. The first run prints an expiring pairing code and opens (or prints) the Access-protected approval URL.
3. Sign into Cloudflare Access and approve the **matching code** in `/admin/devices`.
4. The device saves its scoped credential in `PrivateDesktopMCP/device.json` and connects via WebSocket. Never commit or share that credential.
5. Leave the terminal open while using tools. Press **Ctrl+C** to disconnect. No startup tasks or system services are installed.
6. With multiple devices online, switch devices directly in chat via `relay_list_devices` / `relay_select_device`, pass `_device: "<name>"` on a tool call, or select one at `/admin/devices`.

## Cloudflare deployment & self-hosting

The Worker source is in `worker/index.mjs` and `worker/auth.mjs`. Infrastructure is described in `wrangler.toml`.

1. Configure a Cloudflare Access self-hosted application protecting `/mcp` and `/admin/*` with an Owner-only policy. Never protect `/relay/*` with Access.
2. Configure cryptographic Access JWT verification on the Worker before deploying:

```bash
wrangler secret put CF_ACCESS_TEAM_DOMAIN   # e.g. https://your-team.cloudflareaccess.com
wrangler secret put CF_ACCESS_AUD           # Access application AUD tag
wrangler deploy
```

## Security

This tool provides remote filesystem and command-execution capabilities. Restrict Cloudflare Access to your own identity, configure `CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`, approve only devices you control, and consider running `--readonly` or `--allow-dir` for day-to-day workflows. See [SECURITY.md](SECURITY.md) and [AGENTS.md](AGENTS.md).
