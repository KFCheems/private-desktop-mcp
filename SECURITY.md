# Security policy

This is a private remote-execution tool, not a public unauthenticated MCP. The Worker **must** be protected by Cloudflare Access at the `/mcp` and `/admin/*` paths with an owner-only policy. WebSockets at `/relay/ws` use per-device bearer credentials issued only after code-based approval.

Never commit the device credentials in AppData, Cloudflare secrets, Access cookies, npm tokens, or admin session data.

Revoke any stolen device credential immediately through the authenticated admin page. The first-time pairing code and local device secret must not be shared.

Do not register your personal remote-execution MCP in a public directory or share authenticated connections without a deliberate review.
