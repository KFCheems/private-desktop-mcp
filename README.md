# Private Desktop MCP

Self-hosted multi-device [Model Context Protocol](https://modelcontextprotocol.io/) bridge for Desktop Commander (and optional additional local MCP servers) using Cloudflare Workers, SQLite-backed Durable Objects, and a one-command cross-platform connector.

**Transport:** Streamable HTTP (`POST` + `DELETE`, supporting both MCP `2025-*` and stateless `2026-07-28`) to AI clients; outgoing WebSocket with zero-cost hibernation heartbeat from each device to the relay.

## Public npm release

```powershell
npx.cmd --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect
```

Each release gets its own immutable npm version. **Do not overwrite a fixed `.tgz` at a stable URL**: npm caching might start an old version.

## What's new in v0.4.0

### Security & Governance
- **Cryptographic Cloudflare Access JWT verification (`worker/auth.mjs`)**: Verifies RS256 signatures against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (with automatic `kid` key-rotation refresh), `aud`, `iss`, `exp`, and `nbf`. Fails closed if unconfigured (with an explicit temporary `ALLOW_UNVERIFIED_ACCESS_HEADER=true` migration opt-in).
- **Hardened local gateway (`gateway.mjs`)**: Enforces per-launch ephemeral Bearer authentication (`MCP_LOCAL_TOKEN`), loopback `Host` validation (anti-DNS-rebinding), and browser `Origin` rejection (anti-CSRF).
- **Local policy guardrails (`bin/policy.mjs`)**:
  - `--readonly` (or `PCC_READONLY=1`): allows read-only tools only and hides mutating tools from `tools/list`.
  - `--allow-dir <dir>` (repeatable, or `PCC_ALLOW_DIRS`): jails file tool paths to allowed directories (resolving symlinks and blocking `..` traversal).
  - `--allow-tools <csv>` / `--deny-tools <csv>`: explicit tool allowlist/denylist.
  - Always blocks remote access to the connector's own credential directory (`PrivateDesktopMCP/device.json`).
- **Outbound DLP secret redaction (enabled by default, `--no-dlp` to opt out)**: Redacts PEM private keys, AWS/GitHub/OpenAI/Slack/Google tokens, and the active device/gateway bearer tokens from tool responses before sending them back to the cloud LLM.
- **Edge read-only lock & emergency kill-switch**: Toggle per-device read-only lock or revoke all devices at once from `/admin/devices`.
- **Removed hardcoded diagnostic file path**: `/relay/diagnostic` now permits read-only MCP introspection methods only.

### Reliability & Multi-Device Experience
- **Zero-cost WebSocket hibernation heartbeat**: Durable Object `setWebSocketAutoResponse("ping", "pong")` paired with a 25s client heartbeat watchdog detects half-open sockets after OS sleep or Wi-Fi switches without waking hibernated DOs.
- **Fixed reconnect backoff & jitter**: Resets exponential backoff once a session stays healthy and applies random jitter.
- **Local gateway auto-recovery & fast-fail**: Supervises the local `gateway.mjs` child process, immediately fails in-flight calls if it exits unexpectedly, and restarts it automatically with bounded backoff.
- **In-chat multi-device meta-tools**: Built-in `relay_list_devices`, `relay_select_device`, `relay_ping_device`, and `relay_recent_activity` tools let AI clients inspect online machines, switch targets, measure RTT latency, and view sanitized metadata audit logs without leaving chat. Individual tool calls can also target a specific machine via `_device` argument or `X-Target-Device` header.
- **SQLite audit log & upgraded admin dashboard**: Uses Durable Object SQLite (`audit_logs`) to record metadata-only call history (never file contents or command output), plus device platform, CLI version, mode, rename, read-only toggle, and revoke-all controls.
- **Streamable HTTP improvements**: Forwards `DELETE /mcp` session teardown and propagates client `AbortSignal` cancellations (`{ kind: "cancel" }`) all the way to the local gateway.
- **Optional multi-MCP aggregation**: Pass `--servers <config.json>` (or `PCC_MCP_CONFIG`, see [client-configs/servers.example.json](client-configs/servers.example.json)) to aggregate additional local stdio MCP servers under `<server>__<tool>` namespaces alongside Desktop Commander.
- **Upgraded Desktop Commander**: Bumped `@wonderwhy-er/desktop-commander` to `0.3.4` (security patches, Windows process-tree termination, lazy PDF/Office loading, explicit MCP tool annotations).
- **Diagnostics & cross-platform proxy**: Added `doctor` and `report` CLI subcommands, macOS `scutil --proxy` autodetection alongside Windows WinINET, rotating user-private gateway logs (`PrivateDesktopMCP/logs/gateway.log`), and `--relay`/`--port`/`--name` overrides for clean self-hosting.

## Terminal logging

PCC uses **TRACE logging by default**. The normal `connect` command prints MCP call IDs, sanitized/truncated command and response previews, timings, connection details, and errors.

**Privacy:** TRACE can reveal sensitive file contents or command output locally in your terminal. Redaction is best effort; avoid sharing or recording the terminal. Use `--debug` for detailed metadata without content previews, or `--safe` for compact logs. The child gateway log is stored in the user-private `PrivateDesktopMCP/logs/gateway.log` directory and rotates automatically at 5 MB.

## System proxy detection (Windows & macOS)

- **Windows**: Automatically uses the current user's effective WinINET system proxy (static HTTP/Mixed proxies, bypass rules, PAC/WPAD).
- **macOS**: Automatically queries `scutil --proxy` (HTTPS/HTTP proxies and `ExceptionsList`).
- **Environment override**: Explicit `HTTPS_PROXY`, `HTTP_PROXY`, or `ALL_PROXY` settings take precedence on all platforms (`NO_PROXY` respected). Supported proxy transport is HTTP/HTTPS CONNECT.

## CLI commands & flags

```powershell
# Connect (default)
private-desktop-mcp connect

# Safe read-only mode jailed to a workspace directory
private-desktop-mcp connect --readonly --allow-dir C:\workspace

# Connect to your own self-hosted Cloudflare Worker
private-desktop-mcp connect --relay https://my-relay.example.workers.dev --name WorkPC

# Aggregate extra local MCP servers alongside Desktop Commander
private-desktop-mcp connect --servers ./client-configs/servers.example.json

# Diagnostics & status
private-desktop-mcp doctor
private-desktop-mcp report
private-desktop-mcp status
private-desktop-mcp reset
```

## Current canonical endpoint

```text
https://private-desktop-device-relay.ljx2043979076.workers.dev/mcp
```

Client configuration templates are available in `.mcp.json` and `client-configs/` (`vscode-mcp.json`, `mcpServers.json`, `cursor-mcp.json`, `codex.toml.example`).

## Pairing devices

1. On a machine with Node.js 20.18.1+ run `private-desktop-mcp connect`.
2. The first run prints an expiring pairing code and opens (or prints) the Access-protected approval URL.
3. Sign into Cloudflare Access and approve the **matching code** in `/admin/devices`.
4. The device saves its scoped credential in `PrivateDesktopMCP/device.json` and connects via WebSocket. Never commit or share that credential.
5. Leave the terminal open while using tools. Press **Ctrl+C** to disconnect. No startup tasks or system services are installed.
6. With multiple devices online, switch devices directly in chat via `relay_list_devices` / `relay_select_device`, pass `_device: "<name>"` on a tool call, or select one at `/admin/devices`.

## Cloudflare deployment & self-hosting

The Worker source is in `worker/index.mjs` and `worker/auth.mjs`. Infrastructure is described in `wrangler.toml`.

1. Configure a Cloudflare Access self-hosted application protecting `/mcp` and `/admin/*` with an Owner-only policy. Never protect `/relay/*` with Access (otherwise device WebSocket connections are blocked).
2. Configure cryptographic Access JWT verification on the Worker before deploying:

```bash
wrangler secret put CF_ACCESS_TEAM_DOMAIN   # e.g. https://your-team.cloudflareaccess.com
wrangler secret put CF_ACCESS_AUD           # Access application AUD tag
```

3. For self-hosted custom domains/workers, optionally configure `SHARED_HOSTS`, `ALLOWED_OWNER_HOSTS`, `ALLOWED_RELAY_HOSTS`, and `PUBLIC_BASE_URL` (see comments in `wrangler.toml`).
4. Deploy with `wrangler deploy`.

## Running from source

```bash
npm install
npm test
node bin/cli.mjs connect
```

## Security

This tool provides remote filesystem and command-execution capabilities. Restrict Cloudflare Access to your own identity, configure `CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`, approve only devices you control, and consider running `--readonly` or `--allow-dir` for day-to-day workflows. See [SECURITY.md](SECURITY.md).
