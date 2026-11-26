# AGENTS.md — Guide for AI Agents Operating and Maintaining Private Desktop MCP

This document defines the behavioral contracts for AI coding agents working with **Private Desktop MCP (`@juexibobi/private-desktop-mcp`)** in two roles:

1. **Operator Mode (User Usage & Remote Multi-Device Orchestration)** — when a user asks you to connect their machine, configure an MCP client, inspect paired desktops, run commands across multiple computers, or manage read-only guardrails.
2. **Developer Mode (Repository Maintenance & Evolution)** — when a user asks you to modify, test, release, or deploy the connector and Cloudflare Worker relay.

---

## Part 1: Operator Playbook (Using Private Desktop MCP for the User)

### 1. Inspect Current State First (Machine-Readable Preflight)

Always run non-destructive JSON preflight checks before changing local configuration or starting a connector:

```bash
npx --yes @juexibobi/private-desktop-mcp@latest doctor --json
npx --yes @juexibobi/private-desktop-mcp@latest status --json
npx --yes @juexibobi/private-desktop-mcp@latest report --json
```

### 2. Configuring an AI Client (`setup-client`)

Follow the preview-before-confirm contract in [docs/agent-install.md](docs/agent-install.md):

1. Preview the exact configuration change with `--dry-run --json` first:
   ```bash
   npx --yes @juexibobi/private-desktop-mcp@latest setup-client <client> --dry-run --json
   ```
   Supported `<client>` values: `claude-code`, `claude-desktop`, `cursor`, `vscode`, `codex`, `gemini`, `windsurf`, `all`.
2. Show the user the target file path and preview, wait for confirmation, then apply without `--dry-run`.

### 3. Starting & Pairing a Device Connector

- **Default full mode**:
  ```bash
  npx --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect --json
  ```
- **Least-privilege read-only + directory jail mode (recommended for untrusted or exploratory sessions)**:
  ```bash
  npx --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect --readonly --allow-dir <workspace_path> --json
  ```
- **Aggregating additional local stdio MCP servers alongside Desktop Commander**:
  ```bash
  npx --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect --servers ./client-configs/servers.example.json
  ```
- When a machine is not paired yet, `--json` emits a structured event:
  ```json
  {"event":"pairing_required","deviceName":"...","code":"...","approvalUrl":"https://.../admin/devices","pairId":"...","expiresIn":3600}
  ```
  Present the `code` and `approvalUrl` to the user so they can approve it behind Cloudflare Access.

### 4. Multi-Device Orchestration via MCP Tools, Resources & Prompts

When connected to the remote `/mcp` Streamable HTTP endpoint:

- **Resources (`resources/list`, `resources/read`)** — always available at the Cloudflare edge, even when 0 devices are online:
  - `relay://devices`: Live inventory of paired devices, online state, OS/arch, read-only locks, and current selection.
  - `relay://status`: Worker version, protocol features, and Access verification posture.
  - `relay://audit`: Recent sanitized metadata-only audit log.
- **Built-in Edge Meta-Tools (`tools/call`)**:
  - `relay_list_devices`: List all paired desktops and their live status.
  - `relay_select_device`: Set the default active target desktop by `device_id` or `device_name`.
  - `relay_ping_device`: Measure WebSocket RTT and verify local `gateway.mjs` health.
  - `relay_set_device_policy`: Lock/unlock a device to read-only mode at the Cloudflare edge (`read_only: true|false`) or rename it (`new_name`).
  - `relay_recent_activity`: Inspect sanitized audit entries (timestamps, actor, device, tool name, HTTP status, duration).
- **Per-Call Device Targeting (`_device`)**:
  - Every upstream tool schema includes an optional `_device` string property. Pass `_device: "<device_name_or_id>"` on any tool call (e.g., `read_file`, `list_directory`, `start_process`) to route that single call to a specific machine without changing the global selection.
- **Self-Healing Tool Errors**:
  - If a target device is offline or multiple devices are online without a selection, `tools/call` returns an `isError: true` structured payload containing `onlineDevices`, `selectedDeviceId`, and `nextActions`. Follow `nextActions` (e.g., call `relay_select_device` or pass `_device`) automatically.

---

## Part 2: Developer Playbook (Maintaining the Repository)

### 1. Workspace Map

```text
worker/
  index.mjs          Cloudflare Worker router & SQLite-backed DeviceHub Durable Object (MCP edge lifecycle, meta-tools, resources, prompts, WebSocket relay, audit log, admin UI)
  auth.mjs           Cryptographic Cloudflare Access RS256 JWT verifier (Web Crypto API, JWKS caching + key-rotation refresh)
bin/
  cli.mjs            Cross-platform device connector CLI (connect, status, doctor, report, setup-client, reset; --json, heartbeat watchdog, child gateway supervisor)
  policy.mjs         Local tool governance (--readonly, --allow-dir symlink-aware path jail, allow/deny lists, self-credential guard) & outbound DLP secret redaction
  client-setup.mjs   Non-destructive MCP client config generator/merger with --dry-run preview
  proxy.mjs          System proxy autodetection (Windows WinINET, macOS scutil, environment HTTPS_PROXY/NO_PROXY)
  activity.mjs       JSON-RPC/SSE parser, correlation IDs, and TRACE/DEBUG/LIVE terminal activity formatters
  logging.mjs        Terminal secret redaction and timestamped logging helpers
gateway.mjs          Local loopback Streamable HTTP MCP gateway fronting @wonderwhy-er/desktop-commander + optional extra stdio MCP servers (Bearer + Host + Origin guard)
skills/
  private-desktop-mcp/SKILL.md   Bundled Agent Skill for coding agents
docs/
  agent-install.md   Canonical agent-driven setup & safety runbook
tests/
  *.test.mjs         Node.js built-in test runner suites covering worker auth, DeviceHub DO, gateway, policy/DLP, client setup, proxy, activity, and packaging
```

### 2. Boundary & Security Invariants

1. **Zero secret leakage**: Never commit `device.json`, Cloudflare API keys/tokens (`cfk_`, `cfut_`, `cfat_`), Access cookies, or `.env` files. Never weaken `bin/policy.mjs` protection of the `PrivateDesktopMCP` credential directory.
2. **Fail-closed edge authentication**: `worker/auth.mjs` must verify RS256 signatures, `iss`, `aud`, `exp`, and `nbf` against `CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`.
3. **Loopback gateway isolation**: `gateway.mjs` binds only to `127.0.0.1`, validates loopback `Host` headers (anti-DNS-rebinding), rejects browser `Origin` headers (anti-CSRF), and requires a per-launch 32-byte `MCP_LOCAL_TOKEN`.
4. **Edge-always-alive MCP discovery**: `initialize`, `notifications/initialized`, `ping`, `server/discover`, `tools/list`, `resources/list`, `resources/read` (`relay://*`), `prompts/list`, and `prompts/get` must succeed at the Worker edge even when zero devices are connected.
5. **Direct dependency declaration**: Every package imported by `bin/*.mjs` or `gateway.mjs` must be declared directly in `package.json` `dependencies` and listed in `package.json` `files` so `npx --install-strategy=nested` works on a clean machine.

### 3. Verification & Release Workflow

Run the full verification gate before opening a PR or tagging a release:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm pack --dry-run --json
```

Releases are published automatically via GitHub Actions OIDC Trusted Publishing (`.github/workflows/release.yml`) when a `v*` tag matching `package.json` and `server.json` `version` is pushed.
