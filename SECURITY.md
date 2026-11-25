# Security policy

This is a private remote-execution tool, not a public unauthenticated MCP server.

## Trust & defense-in-depth boundaries

1. **Cloudflare Access + RS256 JWT verification**: Protect `/mcp` and `/admin/*` with an Owner-only Cloudflare Access policy AND set `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` in the Worker so every request's `Cf-Access-Jwt-Assertion` signature, issuer, audience, and expiry are cryptographically verified against Cloudflare's JWKS (`/cdn-cgi/access/certs`). Do not rely on header presence alone; `ALLOW_UNVERIFIED_ACCESS_HEADER=true` is only for temporary rolling migration.
2. **Per-device WebSocket credentials**: `/relay/ws` authenticates paired devices with a 256-bit bearer token stored as a SHA-256 hash in Durable Object storage and compared in constant time.
3. **Hardened local gateway**: The local Streamable HTTP gateway binds to `127.0.0.1` only, validates loopback `Host` headers (preventing DNS rebinding), rejects browser `Origin` headers (preventing localhost CSRF), and requires a per-launch ephemeral Bearer token (`MCP_LOCAL_TOKEN`) shared only with the parent connector process.
4. **Local guardrails & DLP**:
   - The connector always blocks remote tool calls targeting its own `PrivateDesktopMCP` credential directory.
   - Outbound DLP redacts high-confidence secrets (private key PEM blocks, AWS/GitHub/OpenAI/Slack/Google tokens, and active device/gateway tokens) before responses leave the device.
   - Use `--readonly`, `--allow-dir`, `--allow-tools`, `--deny-tools`, or the per-device read-only lock in `/admin/devices` to apply least privilege.
   - Guardrails reduce accidental damage and unintended leakage; for untrusted or experimental workloads, run the connector inside an isolated VM or container.
5. **Audit & emergency revocation**: Metadata-only audit logs (timestamps, actor, device, method/tool name, HTTP status, duration — never file contents or command output) are recorded in Durable Object SQLite and visible in `/admin/devices`. Use **Revoke** or **Revoke All** in `/admin/devices` immediately if any device credential is suspected compromised.

## Secret hygiene

Never commit `device.json`, Cloudflare secrets, Access cookies, npm tokens, or admin session data. Do not register your personal remote-execution MCP in a public directory or share authenticated connections without deliberate review.
