# Private Desktop MCP

Self-hosted multi-device [Model Context Protocol](https://modelcontextprotocol.io/) bridge for Desktop Commander using Cloudflare Workers, Durable Objects and a one-command Windows connector.

**Transport:** Streamable HTTP to ChatGPT; outgoing WebSocket from the device to the relay.

## Public npm release

```powershell
npx.cmd --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect
```

Each release gets its own immutable npm version. **Do not overwrite a fixed `.tgz` at a stable URL**: npm caching might start an old version.

### Terminal logging

The default `connect` command displays timestamped connection events, local gateway startup, incoming MCP method/tool names, HTTP/RPC success or failure, execution durations and reconnect activity. The terminal stays open for live monitoring.

For more details, use `--debug`:

```powershell
npx.cmd --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect --debug
```

### Windows system proxy detection (v0.3.4)

PCC automatically uses the current Windows user's **effective system proxy** (WinINET), including static HTTP/Mixed proxies, Windows proxy bypass rules, and supported PAC/WPAD configurations. It uses the same detected proxy for the HTTPS device-pairing API and for the secure WebSocket relay. No manual `HTTPS_PROXY` configuration is required for normal Windows system proxy settings.

Explicit `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` settings take precedence over Windows settings; `NO_PROXY` exclusions are respected for an explicitly configured environment proxy. Supported proxy transport is HTTP/HTTPS CONNECT. SOCKS-only proxy endpoints must be exposed through an HTTP/Mixed port. The detected proxy is re-checked periodically when retrying a lost connection. If system lookup fails or times out, PCC reports a warning and tries a direct connection.

Debug mode prints **redacted parameter metadata and response size/type**, not command contents, file contents or raw tool results. Sensitive fields and inline tokens are masked, but local paths and other non-sensitive metadata may still appear, so avoid sharing debug logs publicly. The child gateway's detailed stderr/stdout is still stored at `%TEMP%\private-desktop-mcp-device.log`. Neither logging mode changes device pairing, OAuth or startup behavior.

## Current independent endpoint

```text
https://private-desktop-device-relay.ljx2043979076.workers.dev/mcp
```

Set up a remote Streamable HTTP MCP connection with Cloudflare Access OAuth. The gateway and device pairing admin page share this free workers.dev host. The old qqking.top route is a temporary fallback, not a dependency of this connector.

## Pairing devices

1. On a Windows machine with Node.js 20.18.1+ run `private-desktop-mcp connect` after installation (or the npx command above).
2. The first run prints an expiring pairing code and an Access-protected approval URL.
3. Sign into Cloudflare Access and approve the **matching code** in the admin page.
4. The device saves a locally scoped credential in the user's AppData and connects via WebSocket. Never commit or share that credential.
5. Leave the terminal open while using tools. Press **Ctrl+C** to disconnect. No startup tasks or Windows services are installed.
6. Reconnecting the same paired device needs no further approval. Revoke old devices from the admin page.

If multiple devices are online, select the intended one at the admin page. The relay must never route to an arbitrary device when the target is ambiguous.

## Running without npm publication

Install from your own checked-out repository with `npm install` then `node bin/cli.mjs connect`. To install globally from the project: `npm install -g .`.

## Cloudflare deployment

The Worker source is in `worker/index.mjs`. The infrastructure is described by `wrangler.toml`. Production has a **separate Cloudflare Access self-hosted application** protecting exactly `/mcp` and `/admin/*`, with Owner-only policy. Device pairing paths `/relay/*` remain reachable but device WebSocket access is protected by a bearer token issued only after pairing approval.

Never protect the **entire Worker** with Worker-level Access: this would prevent WebSocket connections. Never deploy the Worker without first configuring path-based Access for the MCP and admin endpoints. Use Wrangler or Cloudflare API credentials provided directly in your own secure environment.

`worker/index.mjs` currently supports the legacy qqking.top host for rollback. The free workers.dev endpoint is the canonical address.

## Releases

- CI executes syntax tests and package validation.
- Immutable versioned npm packages carry the authoritative `latest` dist-tag.
- Release workflow uses **GitHub Actions OIDC npm trusted publishing** for this repository and release.yml; no long-lived npm publish token is needed.
- GitHub Releases preserves the same immutable `.tgz` as a backup.
- Secrets, local `device.json`, `.env`, `node_modules` and existing Cloudflare Access policies are not stored in Git.

## Security

This tool has Windows filesystem and command-execution capabilities. Restrict Cloudflare Access to your own identity, approve only devices you control and never expose a naked HTTP MCP endpoint. See [SECURITY.md](SECURITY.md).


## Detailed live console (v0.3.5)

PCC now displays an expanded terminal startup banner with computer, device ID, Node version, gateway PID, local MCP URL, Cloudflare relay state and logging mode. Every incoming MCP method/tool call has a short correlation ID, safe parameter summary, MCP/HTTP outcome, duration and structured result summaries (process PID, exit code, line count and output size when available). WebSocket disconnections include close code, connection uptime, total calls and failures. A tool can fail at the MCP layer even when HTTP returns 200; this is reported as an **MCP tool error**.

Logging has three levels:

| Command option | Terminal contents | Privacy |
| --- | --- | --- |
| No option | Rich startup, call and response summaries; no raw files/commands | Default |
| \`--debug\` | Adds redacted request metadata, result sizes and aggregate counters | Safe diagnostic metadata |
| \`--trace\` | Also shows sanitized, truncated command and response previews | **Local opt-in; may expose confidential user text** |

Example for full local previews (not recommended when screen sharing or saving terminal transcripts):

\`\`\`powershell
npx.cmd --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect --trace
\`\`\`

**Important:** \`--trace\` is best-effort redaction, not a guarantee that arbitrary secrets embedded in file contents or command results will be removed. Use normal logging or \`--debug\` for everyday use. All logs print to the local terminal and are not transmitted to third-party logging services by this feature. The underlying gateway's diagnostics remain in \`%TEMP%\private-desktop-mcp-device.log\`.
