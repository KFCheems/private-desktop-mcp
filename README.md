# Private Desktop MCP

Self-hosted multi-device [Model Context Protocol](https://modelcontextprotocol.io/) bridge for Desktop Commander using Cloudflare Workers, Durable Objects and a one-command Windows connector.

**Transport:** Streamable HTTP to ChatGPT; outgoing WebSocket from the device to the relay.

## Public release (after npm owner authorizes publishing)

```powershell
npx.cmd --yes --prefer-online @juexibobi/private-desktop-mcp@latest connect
```

Each release gets its own immutable npm version. **Do not overwrite a fixed `.tgz` at a stable URL**: npm caching might start an old version.

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
- Release workflow supports **GitHub Actions OIDC npm trusted publishing**, after an npm owner manually configures this repository as a trusted publisher on npmjs.com.
- GitHub Releases preserves the same immutable `.tgz` as a backup.
- Secrets, local `device.json`, `.env`, `node_modules` and existing Cloudflare Access policies are not stored in Git.

## Security

This tool has Windows filesystem and command-execution capabilities. Restrict Cloudflare Access to your own identity, approve only devices you control and never expose a naked HTTP MCP endpoint. See [SECURITY.md](SECURITY.md).
