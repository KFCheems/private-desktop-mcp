---
name: private-desktop-mcp
description: Operate and orchestrate remote Windows, macOS, and Linux desktops through Private Desktop MCP (Cloudflare Worker + Durable Object WebSocket relay + local Desktop Commander gateway). Use when the user wants to inspect or switch paired desktop devices, run cross-machine commands or file operations, configure MCP clients, diagnose relay/proxy connectivity, or manage read-only and DLP guardrails.
---

# Private Desktop MCP Skill

Use this skill when interacting with a **Private Desktop MCP** remote server (`/mcp`) or managing the local `@juexibobi/private-desktop-mcp` connector CLI.

## 1. Multi-Device Orchestration (Remote MCP Tools & Resources)

Private Desktop MCP can pair and keep multiple computers online simultaneously. Never assume which computer is active without checking first when multiple machines exist.

### Always-Available Edge Resources
Even when zero desktop devices are online, the Cloudflare Worker edge serves:
- `relay://devices` — JSON inventory of all paired devices (`id`, `name`, `online`, `platform`, `arch`, `cliVersion`, `clientMode`, `readOnly`, `selected`, `lastSeen`).
- `relay://status` — Worker version, protocol features, and Cloudflare Access JWT verification status.
- `relay://audit` — Recent metadata-only tool execution audit log.

### Built-In Edge Meta-Tools
- `relay_list_devices` — Call first in multi-machine workflows to inspect online devices and check which device is `selected`.
- `relay_select_device` — Switch the default target device by `device_id` or case-insensitive `device_name`.
- `relay_ping_device` — Measure end-to-end WebSocket RTT (`rttMs`) and verify the device's local MCP gateway (`gatewayReady: true`, `uptimeMs`, `mode`).
- `relay_set_device_policy` — Lock or unlock a device in edge read-only mode (`read_only: true | false`) or rename it (`new_name`).
- `relay_recent_activity` — Inspect recent sanitized tool call audit records (`ts`, `actor`, `deviceName`, `mcpName`, `status`, `durationMs`, `ok`).

### Per-Call Device Targeting (`_device`)
Every upstream tool (`read_file`, `list_directory`, `start_process`, `write_file`, `edit_block`, `start_search`, etc.) accepts an optional `_device` string argument:

```json
{
  "name": "read_file",
  "arguments": {
    "path": "C:\\Users\\Alice\\logs\\app.log",
    "_device": "WorkPC"
  }
}
```

- The Worker routes that single call to `WorkPC` and strips `_device` before forwarding to the local MCP server.
- Prefer `_device` over `relay_select_device` when comparing files, logs, or processes across two machines in the same turn so you don't mutate global selection state.

### Handling Self-Healing Tool Errors
When a `tools/call` fails with `errorCode: "NO_DEVICE_ONLINE"`, `"SELECTED_DEVICE_OFFLINE"`, or `"MULTIPLE_DEVICES_ONLINE"`:
1. Inspect `structuredContent.onlineDevices` and `structuredContent.nextActions` in the tool response.
2. If other devices are online, call `relay_select_device` or retry with `_device`.
3. If no device is online, give the user the exact connector command:
   ```powershell
   npx.cmd --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect
   ```

## 2. Local Connector CLI & Client Setup (Machine-Readable `--json`)

When running local shell commands on a machine to diagnose, pair, or configure Private Desktop MCP, always pass `--json`:

| Task | Command |
|---|---|
| End-to-end health & proxy check | `npx --yes @juexibobi/private-desktop-mcp@latest doctor --json` |
| Check local pairing & port state | `npx --yes @juexibobi/private-desktop-mcp@latest status --json` |
| Export sanitized diagnostic bundle | `npx --yes @juexibobi/private-desktop-mcp@latest report --json` |
| Preview client config (`--dry-run`) | `npx --yes @juexibobi/private-desktop-mcp@latest setup-client <client> --dry-run --json` |
| Apply client config | `npx --yes @juexibobi/private-desktop-mcp@latest setup-client <client> --json` |
| Connect in read-only jailed mode | `npx --yes @juexibobi/private-desktop-mcp@latest connect --readonly --allow-dir <dir> --json` |

Supported `<client>` targets for `setup-client`: `claude-code`, `claude-desktop`, `cursor`, `vscode`, `codex`, `gemini`, `windsurf`, `all`.

## 3. Safety & Guardrails

- **Least privilege**: When the user only needs code reading, log inspection, or diagnostics, recommend `--readonly` (or lock the device via `relay_set_device_policy` with `read_only: true`).
- **Credential boundary**: Never attempt to read or modify `PrivateDesktopMCP/device.json` via remote tools (the local policy engine blocks it automatically).
- **DLP redaction**: Outbound responses automatically redact PEM private keys, AWS/GitHub/OpenAI/Slack/Google tokens, and active relay tokens as `[REDACTED_BY_PCC_DLP]`. Never write `[REDACTED_BY_PCC_DLP]` back into user files when editing.
