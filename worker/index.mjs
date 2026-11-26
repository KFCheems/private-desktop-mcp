import { authenticateOwnerRequest } from "./auth.mjs";

export const WORKER_VERSION = "0.5.0";
export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const DEFAULT_SHARED_HOSTS = ["private-desktop-device-relay.ljx2043979076.workers.dev"];
const DEFAULT_OWNER_HOSTS = ["mcp.qqking.top"];
const DEFAULT_RELAY_HOSTS = ["relay.qqking.top"];

const OWNER_PATHS = new Set([
  "/mcp",
  "/admin/devices",
  "/admin/approve",
  "/admin/select",
  "/admin/revoke",
  "/admin/revoke-all",
  "/admin/rename",
  "/admin/readonly"
]);

const RELAY_PATHS = new Set([
  "/relay/status",
  "/relay/pair/start",
  "/relay/pair/poll",
  "/relay/ws",
  "/relay/diagnostic"
]);

const READONLY_UPSTREAM_TOOLS = new Set([
  "read_file",
  "read_multiple_files",
  "list_directory",
  "get_file_info",
  "start_search",
  "get_more_search_results",
  "list_searches",
  "stop_search",
  "list_processes",
  "list_sessions",
  "read_process_output",
  "get_config",
  "get_usage_stats",
  "get_recent_tool_calls",
  "get_prompts"
]);

export const RELAY_META_TOOLS = [
  {
    name: "relay_list_devices",
    description:
      "List all paired remote desktop devices, their online status, platform, version, read-only lock, and which device is currently selected.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "relay_select_device",
    description:
      "Select the active target desktop device for subsequent tool calls by exact device_id or unambiguous device_name.",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string", description: "Exact paired device UUID" },
        device_name: { type: "string", description: "Case-insensitive paired device name" }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "relay_ping_device",
    description:
      "Ping a paired online device over the relay WebSocket and return end-to-end RTT latency and local gateway health.",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string", description: "Optional target device UUID" },
        device_name: { type: "string", description: "Optional target device name" }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "relay_set_device_policy",
    description:
      "Configure edge governance on a paired device: toggle its read-only lock (blocking write/shell tools at the Cloudflare edge) or rename the device.",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string", description: "Target paired device UUID" },
        device_name: { type: "string", description: "Target paired device name" },
        read_only: { type: "boolean", description: "Set true to lock device to read-only tools at the edge, false to unlock" },
        new_name: { type: "string", description: "Optional new display name for the device (max 40 chars)" }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "relay_recent_activity",
    description:
      "View recent sanitized relay audit metadata (timestamps, actor, device, tool name, status, duration). Never exposes file contents or command output.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: 50, description: "Number of recent entries (default 20)" }
      },
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }
];

export const RELAY_RESOURCES = [
  {
    uri: "relay://devices",
    name: "Paired Desktop Devices",
    description: "Live inventory of paired desktop devices, online state, OS/arch, read-only locks, and current selection.",
    mimeType: "application/json"
  },
  {
    uri: "relay://status",
    name: "Relay & Security Posture",
    description: "Cloudflare Worker relay version, supported protocol features, Access verification mode, and online device count.",
    mimeType: "application/json"
  },
  {
    uri: "relay://audit",
    name: "Recent Sanitized Tool Audit Log",
    description: "Recent metadata-only tool call audit entries stored in Durable Object SQLite.",
    mimeType: "application/json"
  }
];

export const RELAY_PROMPTS = [
  {
    name: "multi-device-triage",
    description: "Inspect paired desktop devices, check online connectivity/latency, and route tasks across machines safely.",
    arguments: [
      { name: "task", description: "Optional goal or investigation to perform across paired devices", required: false }
    ]
  },
  {
    name: "safe-remote-maintenance",
    description: "Perform remote desktop file or shell maintenance with read-only preflight, explicit device targeting, and audit review.",
    arguments: [
      { name: "target_device", description: "Target paired device name or ID", required: false },
      { name: "operation", description: "Maintenance operation to execute", required: true }
    ]
  }
];

const RELAY_META_NAMES = new Set(RELAY_META_TOOLS.map((t) => t.name));
const RELAY_PROMPT_NAMES = new Set(RELAY_PROMPTS.map((p) => p.name));

const DEVICE_PARAM_SCHEMA = {
  type: "string",
  description: "Optional target paired device ID or name for this single call (overrides currently selected device)."
};

const json = (v, s = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(v), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extraHeaders }
  });

const html = (s) =>
  new Response(s, {
    headers: {
      "content-type": "text/html;charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none';style-src 'unsafe-inline';form-action 'self';frame-ancestors 'none'"
    }
  });

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const hex = (n) =>
  [...crypto.getRandomValues(new Uint8Array(n))].map((x) => x.toString(16).padStart(2, "0")).join("");

const sha256Hex = async (s) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

function constantTimeEqual(a, b) {
  const sa = String(a || "");
  const sb = String(b || "");
  if (sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) {
    diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  }
  return diff === 0;
}

function parseHostList(raw, fallback) {
  if (raw === undefined || raw === null || String(raw).trim() === "") return fallback;
  return String(raw)
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function sanitizeLabel(value, fallback = "Device", max = 48) {
  const cleaned = String(value || "")
    .replace(/[^a-zA-Z0-9_. -]/g, "")
    .trim()
    .slice(0, max);
  return cleaned || fallback;
}

function sanitizeShort(value, max = 32) {
  return String(value || "")
    .replace(/[^a-zA-Z0-9._+-]/g, "")
    .slice(0, max);
}

async function readBody(req) {
  const s = await req.text();
  if (s.length > 131072) throw Error("Body too large");
  return req.headers.get("content-type")?.includes("form-urlencoded")
    ? Object.fromEntries(new URLSearchParams(s))
    : JSON.parse(s || "{}");
}

function jsonRpcResult(id, payload, isError = false) {
  return json({
    jsonrpc: "2.0",
    id: id ?? null,
    result: {
      content: [{ type: "text", text: typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) }],
      ...(typeof payload === "object" && payload !== null ? { structuredContent: payload } : {}),
      isError
    }
  });
}

function buildRelayInstructions(devices = []) {
  const online = devices.filter((d) => d.online);
  const selected = devices.find((d) => d.selected);
  const deviceSummary = devices.length
    ? devices
        .map(
          (d) =>
            `${d.name} (${d.id.slice(0, 8)}…: ${d.online ? "ONLINE" : "offline"}, ${d.platform || "unknown"}${d.readOnly || d.clientMode === "READONLY" ? ", READONLY" : ""}${d.selected ? ", SELECTED" : ""})`
        )
        .join("; ")
    : "none paired yet";

  return (
    `[Private Desktop MCP Relay v${WORKER_VERSION}] ` +
    `Paired devices (${online.length}/${devices.length} online): ${deviceSummary}. ` +
    (selected ? `Active target: ${selected.name} (${selected.id}). ` : "") +
    "Multi-device controls: call `relay_list_devices` to inspect machines, `relay_select_device` to switch active target, `relay_ping_device` to test latency, `relay_set_device_policy` to toggle read-only locks, or pass `_device: \"<device_name_or_id>\"` on any tool call to target a specific machine without changing global selection. " +
    "Resources `relay://devices`, `relay://status`, and `relay://audit` are always available."
  );
}

function transformRpcJsonOrSse(bodyText, contentType, transformObj) {
  if (String(contentType || "").toLowerCase().includes("text/event-stream")) {
    let changed = false;
    const lines = String(bodyText || "").split(/\r?\n/);
    const updated = lines.map((line) => {
      if (!line.startsWith("data:")) return line;
      const raw = line.slice(5).trim();
      if (!raw || raw === "[DONE]") return line;
      try {
        const parsed = JSON.parse(raw);
        const merged = transformObj(parsed);
        if (merged) {
          changed = true;
          return "data: " + JSON.stringify(merged);
        }
      } catch {
        return line;
      }
      return line;
    });
    return changed ? updated.join("\n") : bodyText;
  }

  try {
    const parsed = JSON.parse(String(bodyText || ""));
    const merged = transformObj(parsed);
    return merged ? JSON.stringify(merged) : bodyText;
  } catch {
    return bodyText;
  }
}

function injectMetaToolsIntoBody(bodyText, contentType = "") {
  return transformRpcJsonOrSse(bodyText, contentType, (obj) => {
    if (!obj || typeof obj !== "object" || !Array.isArray(obj.result?.tools)) return null;
    const augmentedUpstream = obj.result.tools.map((tool) => {
      if (!tool || typeof tool !== "object" || RELAY_META_NAMES.has(tool.name)) return tool;
      const schema = tool.inputSchema && typeof tool.inputSchema === "object" ? tool.inputSchema : { type: "object", properties: {} };
      const props = schema.properties && typeof schema.properties === "object" ? schema.properties : {};
      if (Object.hasOwn(props, "_device")) return tool;
      return {
        ...tool,
        inputSchema: {
          ...schema,
          type: schema.type || "object",
          properties: {
            ...props,
            _device: DEVICE_PARAM_SCHEMA
          }
        }
      };
    });
    const existing = new Set(augmentedUpstream.map((t) => t?.name));
    const additions = RELAY_META_TOOLS.filter((t) => !existing.has(t.name));
    return {
      ...obj,
      result: {
        ...obj.result,
        tools: [...augmentedUpstream, ...additions]
      }
    };
  });
}

function enrichInitializeBody(bodyText, contentType = "", devices = []) {
  const relayNote = buildRelayInstructions(devices);
  return transformRpcJsonOrSse(bodyText, contentType, (obj) => {
    if (!obj || typeof obj !== "object" || !obj.result || typeof obj.result !== "object") return null;
    const prevInstructions = typeof obj.result.instructions === "string" ? obj.result.instructions.trim() : "";
    const capabilities = obj.result.capabilities && typeof obj.result.capabilities === "object" ? obj.result.capabilities : {};
    return {
      ...obj,
      result: {
        ...obj.result,
        capabilities: {
          ...capabilities,
          tools: capabilities.tools || {},
          resources: capabilities.resources || {},
          prompts: capabilities.prompts || {}
        },
        instructions: prevInstructions ? `${relayNote}\n\n${prevInstructions}` : relayNote
      }
    };
  });
}

function injectRelayResourcesIntoBody(bodyText, contentType = "") {
  return transformRpcJsonOrSse(bodyText, contentType, (obj) => {
    if (!obj || typeof obj !== "object" || !Array.isArray(obj.result?.resources)) return null;
    const existing = new Set(obj.result.resources.map((r) => r?.uri));
    const additions = RELAY_RESOURCES.filter((r) => !existing.has(r.uri));
    return {
      ...obj,
      result: {
        ...obj.result,
        resources: [...RELAY_RESOURCES, ...obj.result.resources.filter((r) => ! !r && !RELAY_RESOURCES.some((rr) => rr.uri === r.uri))]
      }
    };
  });
}

function injectRelayPromptsIntoBody(bodyText, contentType = "") {
  return transformRpcJsonOrSse(bodyText, contentType, (obj) => {
    if (!obj || typeof obj !== "object" || !Array.isArray(obj.result?.prompts)) return null;
    return {
      ...obj,
      result: {
        ...obj.result,
        prompts: [...RELAY_PROMPTS, ...obj.result.prompts.filter((p) => !!p && !RELAY_PROMPT_NAMES.has(p.name))]
      }
    };
  });
}

export function classifyRoute(url, env = {}) {
  const u = new URL(url);
  const h = u.hostname.toLowerCase();
  const p = u.pathname;
  const sharedHosts = parseHostList(env.SHARED_HOSTS, DEFAULT_SHARED_HOSTS);
  const ownerHosts = parseHostList(env.ALLOWED_OWNER_HOSTS, DEFAULT_OWNER_HOSTS);
  const relayHosts = parseHostList(env.ALLOWED_RELAY_HOSTS, DEFAULT_RELAY_HOSTS);

  const isShared = sharedHosts.includes(h);
  const isOwner = (ownerHosts.includes(h) || isShared) && OWNER_PATHS.has(p);
  const isRelay = (relayHosts.includes(h) || isShared) && RELAY_PATHS.has(p);
  return { hostname: h, pathname: p, isOwner, isRelay };
}

export default {
  async fetch(req, env = {}, ctx = null) {
    const { hostname, pathname, isOwner, isRelay } = classifyRoute(req.url, env);
    if (!isOwner && !isRelay) return new Response("No route", { status: 404 });

    let forwardedReq = req;
    if (isOwner) {
      const auth = await authenticateOwnerRequest(req, env, ctx);
      if (!auth.ok) {
        return json({ error: auth.error }, auth.status || 403);
      }
      if (pathname.startsWith("/admin/") && req.method === "POST") {
        const origin = req.headers.get("origin");
        let originHost = "";
        try {
          originHost = origin ? new URL(origin).hostname.toLowerCase() : "";
        } catch {
          originHost = "";
        }
        if (!originHost || originHost !== hostname) {
          return new Response("Origin rejected", { status: 403 });
        }
      }
      // Forward request with verified internal identity headers (stripping any untrusted client values)
      const contentLen = Number(req.headers.get("content-length") || 0);
      if (contentLen > 1048576) {
        return new Response("Too large", { status: 413 });
      }
      const headers = new Headers(req.headers);
      headers.set("x-pcc-actor", auth.actor || "access-user");
      headers.set("x-pcc-verified", auth.verified ? "1" : "0");
      const hasBody = req.method !== "GET" && req.method !== "HEAD";
      forwardedReq = new Request(req.url, {
        method: req.method,
        headers,
        ...(req.signal ? { signal: req.signal } : {}),
        ...(hasBody ? { body: await req.arrayBuffer() } : {})
      });
    }

    const hub = env.HUB.getByName ? env.HUB.getByName("owner-main") : env.HUB.get(env.HUB.idFromName("owner-main"));
    return hub.fetch(forwardedReq);
  }
};

export class DeviceHub {
  constructor(ctx, env = {}) {
    this.ctx = ctx;
    this.env = env;
    this.inflight = new Map();
    this.pings = new Map();
    this.auditInitialized = false;
    this.auditFallback = [];

    // Zero-cost WebSocket Hibernation heartbeat: DO stays hibernated on ping/pong
    if (
      typeof this.ctx?.setWebSocketAutoResponse === "function" &&
      typeof WebSocketRequestResponsePair === "function"
    ) {
      try {
        this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
      } catch {
        // Ignore in non-Workers test environments
      }
    }
  }

  ensureAuditSchema() {
    if (this.auditInitialized) return;
    this.auditInitialized = true;
    const sql = this.ctx?.storage?.sql;
    if (!sql || typeof sql.exec !== "function") return;
    try {
      sql.exec(
        "CREATE TABLE IF NOT EXISTS audit_logs (" +
          "id INTEGER PRIMARY KEY AUTOINCREMENT," +
          "ts TEXT NOT NULL," +
          "actor TEXT NOT NULL," +
          "device_id TEXT NOT NULL," +
          "device_name TEXT NOT NULL," +
          "mcp_method TEXT NOT NULL," +
          "mcp_name TEXT NOT NULL," +
          "status INTEGER NOT NULL," +
          "duration_ms INTEGER NOT NULL," +
          "ok INTEGER NOT NULL," +
          "error TEXT NOT NULL)"
      );
    } catch {
      // Fall back silently if storage.sql is unavailable
    }
  }

  recordAudit({ actor = "", deviceId = "", deviceName = "", mcpMethod = "", mcpName = "", status = 200, durationMs = 0, ok = true, error = "" }) {
    const entry = {
      ts: new Date().toISOString(),
      actor: String(actor || "unknown").slice(0, 120),
      deviceId: String(deviceId || "").slice(0, 64),
      deviceName: String(deviceName || "").slice(0, 64),
      mcpMethod: String(mcpMethod || "").slice(0, 80),
      mcpName: String(mcpName || "").slice(0, 80),
      status: Number(status) || 0,
      durationMs: Math.max(0, Math.round(Number(durationMs) || 0)),
      ok: ok ? 1 : 0,
      error: String(error || "").slice(0, 180)
    };
    this.ensureAuditSchema();
    const sql = this.ctx?.storage?.sql;
    if (sql && typeof sql.exec === "function") {
      try {
        sql.exec(
          "INSERT INTO audit_logs (ts, actor, device_id, device_name, mcp_method, mcp_name, status, duration_ms, ok, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          entry.ts,
          entry.actor,
          entry.deviceId,
          entry.deviceName,
          entry.mcpMethod,
          entry.mcpName,
          entry.status,
          entry.durationMs,
          entry.ok,
          entry.error
        );
        sql.exec("DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT 500)");
        return;
      } catch {
        // Fallback below
      }
    }
    this.auditFallback.unshift(entry);
    if (this.auditFallback.length > 200) this.auditFallback.length = 200;
  }

  listAudit(limit = 20) {
    const n = Math.min(50, Math.max(1, Number(limit) || 20));
    this.ensureAuditSchema();
    const sql = this.ctx?.storage?.sql;
    if (sql && typeof sql.exec === "function") {
      try {
        const cursor = sql.exec(
          "SELECT ts, actor, device_id, device_name, mcp_method, mcp_name, status, duration_ms, ok, error FROM audit_logs ORDER BY id DESC LIMIT ?",
          n
        );
        return [...cursor].map((r) => ({
          ts: r.ts,
          actor: r.actor,
          deviceId: r.device_id,
          deviceName: r.device_name,
          mcpMethod: r.mcp_method,
          mcpName: r.mcp_name,
          status: r.status,
          durationMs: r.duration_ms,
          ok: Boolean(r.ok),
          error: r.error || ""
        }));
      } catch {
        // Fallback below
      }
    }
    return this.auditFallback.slice(0, n).map((r) => ({ ...r, ok: Boolean(r.ok) }));
  }

  open() {
    const found = new Map();
    for (const w of this.ctx.getWebSockets()) {
      const a = w.deserializeAttachment();
      if (a?.deviceId && w.readyState === WebSocket.OPEN) {
        found.set(a.deviceId, { ws: w, meta: a });
      }
    }
    return found;
  }

  async list() {
    const r = await this.ctx.storage.list({ prefix: "device:" });
    const online = this.open();
    const selected = await this.ctx.storage.get("selected");
    return [...r.values()].map((d) => {
      const conn = online.get(d.id);
      return {
        id: d.id,
        name: d.name,
        approvedAt: d.approvedAt,
        lastSeen: conn ? new Date().toISOString() : d.lastSeen || d.approvedAt,
        platform: conn?.meta?.platform || d.platform || "unknown",
        arch: conn?.meta?.arch || d.arch || "",
        cliVersion: conn?.meta?.cliVersion || d.cliVersion || "",
        clientMode: conn?.meta?.clientMode || d.clientMode || "FULL",
        readOnly: Boolean(d.readOnly),
        online: Boolean(conn),
        selected: selected === d.id
      };
    });
  }

  async fetch(req) {
    const p = new URL(req.url).pathname;
    const m = req.method;
    try {
      if (p === "/relay/status" && m === "GET") {
        return json({
          ok: true,
          version: WORKER_VERSION,
          protocol: 3,
          features: [
            "heartbeat",
            "meta-tools",
            "device-targeting",
            "cancel",
            "audit",
            "readonly-lock",
            "agent-native-discovery",
            "mcp-resources",
            "mcp-prompts",
            "self-healing-errors"
          ]
        });
      }
      if (p === "/relay/pair/start" && m === "POST") return this.pairStart(req);
      if (p === "/relay/pair/poll" && m === "POST") return this.pairPoll(req);
      if (p === "/relay/ws" && m === "GET") return this.connect(req);
      if (p === "/relay/diagnostic" && m === "POST") return this.diagnostic(req);
      if (p === "/admin/devices" && m === "GET") return this.dashboard(req);
      if (p === "/admin/approve" && m === "POST") return this.approve(req);
      if (p === "/admin/select" && m === "POST") return this.select(req);
      if (p === "/admin/rename" && m === "POST") return this.rename(req);
      if (p === "/admin/readonly" && m === "POST") return this.toggleReadOnly(req);
      if (p === "/admin/revoke" && m === "POST") return this.revoke(req);
      if (p === "/admin/revoke-all" && m === "POST") return this.revokeAll(req);
      if (p === "/mcp" && (m === "POST" || m === "DELETE")) return this.proxy(req);
      if (p === "/mcp" && m === "GET") return new Response("POST/DELETE only", { status: 405, headers: { allow: "POST, DELETE" } });
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ error: String(e.message || e).slice(0, 180) }, 500);
    }
  }

  approvalBaseUrl(req) {
    if (this.env?.PUBLIC_BASE_URL) {
      return String(this.env.PUBLIC_BASE_URL).replace(/\/+$/, "");
    }
    const u = new URL(req.url);
    if (u.hostname.toLowerCase() === "relay.qqking.top") return "https://mcp.qqking.top";
    return u.origin;
  }

  async pairStart(req) {
    const d = await readBody(req);
    const name = sanitizeLabel(d.name, "Desktop", 40);
    const ip = req.headers.get("cf-connecting-ip") || "unknown";
    const key = "rate:" + ip;
    let limit = (await this.ctx.storage.get(key)) || { n: 0, until: 0 };
    if (Date.now() > limit.until) limit = { n: 0, until: Date.now() + 300000 };
    if (++limit.n > 5) return json({ error: "Pairing rate limit" }, 429);
    await this.ctx.storage.put(key, limit, { expirationTtl: 360 });

    const pending = await this.ctx.storage.list({ prefix: "pending:" });
    for (const [k, request] of pending) {
      if (request.expires < Date.now()) {
        await this.ctx.storage.delete(k);
        pending.delete(k);
      }
    }
    if (pending.size > 20) return json({ error: "Too many pending devices" }, 429);

    const id = crypto.randomUUID();
    const proof = hex(32);
    const code = hex(5).toUpperCase();
    await this.ctx.storage.put(
      "pending:" + id,
      { id, proof, code, name, expires: Date.now() + 3600000, approved: false },
      { expirationTtl: 4200 }
    );
    return json({
      pairId: id,
      proof,
      code,
      approvalUrl: `${this.approvalBaseUrl(req)}/admin/devices`,
      expiresIn: 3600
    });
  }

  async pairPoll(req) {
    const { pairId, proof } = await readBody(req);
    const r = await this.ctx.storage.get("pending:" + String(pairId || ""));
    if (!r || !constantTimeEqual(r.proof, String(proof || "")) || r.expires < Date.now()) {
      return json({ error: "Pairing expired" }, 404);
    }
    if (!r.approved) return json({ status: "pending" });
    await this.ctx.storage.delete("pending:" + r.id);
    return json({ status: "approved", deviceId: r.deviceId, token: r.token });
  }

  async authenticateDeviceHeaders(req) {
    const id = req.headers.get("x-device-id") || "";
    const a = req.headers.get("authorization") || "";
    if (!id || !/^Bearer [a-f0-9]{64}$/.test(a)) return null;
    const d = await this.ctx.storage.get("device:" + id);
    if (!d) return null;
    const expectedHash = await sha256Hex(a.slice(7));
    if (!constantTimeEqual(d.hash, expectedHash)) return null;
    return d;
  }

  async connect(req) {
    if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return new Response("WebSocket required", { status: 426 });
    }
    const device = await this.authenticateDeviceHeaders(req);
    if (!device) return new Response("Unauthorized", { status: 401 });

    const platform = sanitizeShort(req.headers.get("x-device-platform") || device.platform || "unknown", 24);
    const arch = sanitizeShort(req.headers.get("x-device-arch") || device.arch || "", 16);
    const nodeVersion = sanitizeShort(req.headers.get("x-device-node") || device.nodeVersion || "", 24);
    const cliVersion = sanitizeShort(req.headers.get("x-device-version") || device.cliVersion || "", 24);
    const clientMode = sanitizeShort(req.headers.get("x-device-mode") || device.clientMode || "FULL", 24);
    const nowIso = new Date().toISOString();

    await this.ctx.storage.put("device:" + device.id, {
      ...device,
      platform,
      arch,
      nodeVersion,
      cliVersion,
      clientMode,
      lastSeen: nowIso
    });

    for (const w of this.ctx.getWebSockets()) {
      if (w.deserializeAttachment()?.deviceId === device.id) {
        try {
          w.close(1000, "Reconnected");
        } catch {}
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({
      deviceId: device.id,
      name: device.name,
      platform,
      arch,
      cliVersion,
      clientMode,
      connectedAt: nowIso
    });
    return new Response(null, { status: 101, webSocket: client });
  }

  async dashboard(req) {
    const pending = await this.ctx.storage.list({ prefix: "pending:" });
    const devices = await this.list();
    const audits = this.listAudit(30);
    const verified = req.headers.get("x-pcc-verified") === "1";
    const actor = req.headers.get("x-pcc-actor") || "owner";

    const form = (act, id, label, extra = "") =>
      `<form action="/admin/${act}" method="post"><input type="hidden" name="id" value="${esc(id)}">${extra}<button>${esc(label)}</button></form>`;

    const pRows =
      [...pending.values()]
        .filter((x) => !x.approved && x.expires > Date.now())
        .map(
          (x) =>
            `<li><b>${esc(x.name)}</b> — 配对码 <code>${esc(x.code)}</code> ${form("approve", x.id, "批准设备")}</li>`
        )
        .join("") || "<li>暂无待批准的设备</li>";

    const dRows =
      devices
        .map((x) => {
          const badges = [
            x.online ? '<span class="b ok">在线</span>' : '<span class="b off">离线</span>',
            x.selected ? '<span class="b sel">当前选中</span>' : "",
            x.readOnly ? '<span class="b ro">边缘只读锁定</span>' : "",
            x.clientMode === "READONLY" ? '<span class="b ro">本地只读</span>' : ""
          ]
            .filter(Boolean)
            .join(" ");
          const meta = [x.platform, x.arch, x.cliVersion ? "v" + x.cliVersion : "", x.lastSeen ? "最近活跃 " + x.lastSeen.slice(0, 19).replace("T", " ") + "Z" : ""]
            .filter(Boolean)
            .join(" · ");
          return (
            `<li><div><b>${esc(x.name)}</b> ${badges}<div class="meta">${esc(x.id)} · ${esc(meta)}</div></div>` +
            `<div class="actions">` +
            form("select", x.id, "选择此设备") +
            form("readonly", x.id, x.readOnly ? "解除只读锁定" : "锁定为只读") +
            form("rename", x.id, "重命名", '<input name="name" placeholder="新名称" maxlength="40">') +
            form("revoke", x.id, "撤销授权") +
            `</div></li>`
          );
        })
        .join("") || "<li>暂无设备</li>";

    const aRows =
      audits
        .map(
          (a) =>
            `<tr><td>${esc(a.ts.slice(11, 19))}</td><td>${esc(a.deviceName || a.deviceId.slice(0, 8))}</td><td><code>${esc(a.mcpName || a.mcpMethod)}</code></td><td>${a.ok ? "OK" : "ERR"} (${esc(a.status)})</td><td>${esc(a.durationMs)}ms</td><td>${esc(a.actor)}</td></tr>`
        )
        .join("") || '<tr><td colspan="6">暂无审计记录</td></tr>';

    const banner = verified
      ? `<p class="banner ok">Access JWT 签名校验已启用 · 当前身份：${esc(actor)}</p>`
      : `<p class="banner warn">警告：当前处于兼容模式（未配置 CF_ACCESS_TEAM_DOMAIN / CF_ACCESS_AUD 签名校验），请尽快在 Worker 中配置。</p>`;

    const revokeAllForm =
      devices.length > 0
        ? `<form action="/admin/revoke-all" method="post" style="margin-top:1rem"><button class="danger">紧急熔断：撤销全部 ${devices.length} 台设备</button></form>`
        : "";

    return html(
      '<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
        "<title>Private Desktop MCP</title>" +
        "<style>" +
        "body{font:15px/1.5 system-ui;max-width:900px;margin:2rem auto;padding:1rem;background:#f6f7f9;color:#111}" +
        "ul{list-style:none;padding:0}li{margin:.8rem 0;padding:1rem;background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.06)}" +
        ".meta{color:#666;font-size:12px;margin-top:.2rem}.actions{margin-top:.6rem;display:flex;flex-wrap:wrap;gap:.4rem;align-items:center}" +
        "form{display:inline-flex;gap:.3rem;align-items:center}button{padding:.35rem .7rem;border-radius:6px;border:1px solid #ccc;background:#fff;cursor:pointer}" +
        "button.danger{background:#fee2e2;border-color:#ef4444;color:#991b1b}input{padding:.3rem .5rem;border:1px solid #ccc;border-radius:6px;width:120px}" +
        ".b{display:inline-block;padding:.1rem .45rem;border-radius:999px;font-size:12px;margin-left:.3rem}" +
        ".b.ok{background:#dcfce7;color:#166534}.b.off{background:#e5e7eb;color:#374151}.b.sel{background:#dbeafe;color:#1e40af}.b.ro{background:#fef3c7;color:#92400e}" +
        ".banner{padding:.6rem .9rem;border-radius:8px;font-size:13px}.banner.ok{background:#ecfdf5;color:#065f46}.banner.warn{background:#fef3c7;color:#92400e}" +
        "table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;font-size:13px}th,td{padding:.5rem .7rem;border-bottom:1px solid #eee;text-align:left}" +
        "</style>" +
        `<h1>Private Desktop MCP 设备管理 <small>v${esc(WORKER_VERSION)}</small></h1>` +
        banner +
        `<h2>待批准</h2><ul>${pRows}</ul>` +
        `<h2>已配对设备</h2><ul>${dRows}</ul>${revokeAllForm}` +
        `<h2>最近调用审计（仅元数据）</h2><table><thead><tr><th>UTC</th><th>设备</th><th>工具/方法</th><th>状态</th><th>耗时</th><th>操作者</th></tr></thead><tbody>${aRows}</tbody></table>` +
        '<p><a href="/admin/devices">刷新</a></p></html>'
    );
  }

  async approve(req) {
    const { id } = await readBody(req);
    const key = "pending:" + String(id || "");
    const p = await this.ctx.storage.get(key);
    if (!p || p.expires < Date.now() || p.approved) return new Response("Expired", { status: 400 });
    const deviceId = crypto.randomUUID();
    const token = hex(32);
    await this.ctx.storage.put("device:" + deviceId, {
      id: deviceId,
      name: p.name,
      hash: await sha256Hex(token),
      approvedAt: new Date().toISOString(),
      readOnly: false
    });
    await this.ctx.storage.put(
      key,
      { ...p, approved: true, deviceId, token, expires: Date.now() + 600000 },
      { expirationTtl: 600 }
    );
    return Response.redirect(new URL("/admin/devices", req.url).href, 303);
  }

  async select(req) {
    const { id } = await readBody(req);
    if (!(await this.ctx.storage.get("device:" + String(id || "")))) {
      return new Response("Unknown", { status: 404 });
    }
    await this.ctx.storage.put("selected", String(id));
    return Response.redirect(new URL("/admin/devices", req.url).href, 303);
  }

  async rename(req) {
    const { id, name } = await readBody(req);
    const key = "device:" + String(id || "");
    const existing = await this.ctx.storage.get(key);
    if (!existing) return new Response("Unknown", { status: 404 });
    const nextName = sanitizeLabel(name, existing.name, 40);
    await this.ctx.storage.put(key, { ...existing, name: nextName });
    return Response.redirect(new URL("/admin/devices", req.url).href, 303);
  }

  async toggleReadOnly(req) {
    const { id } = await readBody(req);
    const key = "device:" + String(id || "");
    const existing = await this.ctx.storage.get(key);
    if (!existing) return new Response("Unknown", { status: 404 });
    await this.ctx.storage.put(key, { ...existing, readOnly: !existing.readOnly });
    return Response.redirect(new URL("/admin/devices", req.url).href, 303);
  }

  async revoke(req) {
    const { id } = await readBody(req);
    const targetId = String(id || "");
    await this.ctx.storage.delete("device:" + targetId);
    if ((await this.ctx.storage.get("selected")) === targetId) {
      await this.ctx.storage.delete("selected");
    }
    for (const w of this.ctx.getWebSockets()) {
      if (w.deserializeAttachment()?.deviceId === targetId) {
        try {
          w.close(1008, "Revoked");
        } catch {}
      }
    }
    return Response.redirect(new URL("/admin/devices", req.url).href, 303);
  }

  async revokeAll(req) {
    const devices = await this.ctx.storage.list({ prefix: "device:" });
    for (const [k] of devices) await this.ctx.storage.delete(k);
    await this.ctx.storage.delete("selected");
    for (const w of this.ctx.getWebSockets()) {
      try {
        w.close(1008, "All devices revoked");
      } catch {}
    }
    return Response.redirect(new URL("/admin/devices", req.url).href, 303);
  }

  async diagnostic(req) {
    const device = await this.authenticateDeviceHeaders(req);
    if (!device) return json({ error: "Unauthorized" }, 401);
    const body = await req.text();
    if (body.length > 8192) return json({ error: "Body too large" }, 413);
    let msg;
    try {
      msg = JSON.parse(body);
    } catch {
      return json({ error: "Invalid JSON" }, 400);
    }
    // Strictly allow read-only MCP introspection methods only (no filesystem/shell tool calls)
    if (
      msg.jsonrpc !== "2.0" ||
      !["initialize", "notifications/initialized", "tools/list", "server/discover", "ping"].includes(msg.method)
    ) {
      return json({ error: "Diagnostic method denied" }, 403);
    }
    const h = new Headers({
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-pcc-actor": "device-diagnostic:" + device.id.slice(0, 8)
    });
    for (const k of ["mcp-session-id", "mcp-protocol-version"]) {
      if (req.headers.has(k)) h.set(k, req.headers.get(k));
    }
    return this.proxy(new Request(`${this.approvalBaseUrl(req)}/mcp`, { method: "POST", headers: h, body }), device.id);
  }

  async resolveDeviceQuery(query) {
    const q = String(query || "").trim();
    if (!q) return { error: "Empty device target", status: 400 };
    const devices = await this.list();
    const byId = devices.find((d) => d.id === q);
    if (byId) return { device: byId };
    const lower = q.toLowerCase();
    const matches = devices.filter((d) => d.name.toLowerCase() === lower);
    if (matches.length === 1) return { device: matches[0] };
    if (matches.length > 1) {
      return {
        error: `Ambiguous device name "${q}" matches ${matches.length} devices; specify device_id instead`,
        status: 409
      };
    }
    return { error: `Unknown device "${q}"`, status: 404 };
  }

  async pingDeviceWs(deviceId, ws, timeoutMs = 8000) {
    const pingId = crypto.randomUUID();
    const started = Date.now();
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pings.delete(pingId);
        resolve({ ok: false, deviceId, error: "Ping timed out", rttMs: Date.now() - started });
      }, timeoutMs);
      this.pings.set(pingId, {
        ws,
        resolve: (payload) => {
          clearTimeout(timer);
          resolve({ ok: true, deviceId, rttMs: Date.now() - started, ...payload });
        }
      });
      try {
        ws.send(JSON.stringify({ kind: "ping", id: pingId }));
      } catch {
        clearTimeout(timer);
        this.pings.delete(pingId);
        resolve({ ok: false, deviceId, error: "WebSocket send failed", rttMs: Date.now() - started });
      }
    });
  }

  async handleMetaToolCall(rpc, actor) {
    const started = Date.now();
    const name = rpc.params?.name;
    const args = rpc.params?.arguments && typeof rpc.params.arguments === "object" ? rpc.params.arguments : {};

    if (name === "relay_list_devices") {
      const devices = await this.list();
      const onlineCount = devices.filter((d) => d.online).length;
      const selected = devices.find((d) => d.selected)?.id || null;
      this.recordAudit({ actor, mcpMethod: "tools/call", mcpName: name, status: 200, durationMs: Date.now() - started, ok: true });
      return jsonRpcResult(rpc.id, {
        workerVersion: WORKER_VERSION,
        onlineCount,
        selectedDeviceId: selected,
        devices
      });
    }

    if (name === "relay_select_device") {
      const query = args.device_id || args.device_name || "";
      const resolved = await this.resolveDeviceQuery(query);
      if (resolved.error) {
        this.recordAudit({ actor, mcpMethod: "tools/call", mcpName: name, status: resolved.status, durationMs: Date.now() - started, ok: false, error: resolved.error });
        return jsonRpcResult(rpc.id, { error: resolved.error }, true);
      }
      await this.ctx.storage.put("selected", resolved.device.id);
      this.recordAudit({
        actor,
        deviceId: resolved.device.id,
        deviceName: resolved.device.name,
        mcpMethod: "tools/call",
        mcpName: name,
        status: 200,
        durationMs: Date.now() - started,
        ok: true
      });
      return jsonRpcResult(rpc.id, {
        selected: resolved.device.id,
        name: resolved.device.name,
        online: resolved.device.online,
        readOnly: resolved.device.readOnly
      });
    }

    if (name === "relay_ping_device") {
      const online = this.open();
      let targetId = "";
      if (args.device_id || args.device_name) {
        const resolved = await this.resolveDeviceQuery(args.device_id || args.device_name);
        if (resolved.error) return jsonRpcResult(rpc.id, { error: resolved.error }, true);
        targetId = resolved.device.id;
      } else {
        targetId = (await this.ctx.storage.get("selected")) || (online.size === 1 ? online.keys().next().value : "");
      }
      if (!targetId || !online.has(targetId)) {
        return jsonRpcResult(rpc.id, { ok: false, error: "Target device is offline or unselected" }, true);
      }
      const conn = online.get(targetId);
      const pingRes = await this.pingDeviceWs(targetId, conn.ws);
      this.recordAudit({
        actor,
        deviceId: targetId,
        deviceName: conn.meta?.name || "",
        mcpMethod: "tools/call",
        mcpName: name,
        status: pingRes.ok ? 200 : 504,
        durationMs: Date.now() - started,
        ok: pingRes.ok,
        error: pingRes.error || ""
      });
      return jsonRpcResult(rpc.id, pingRes, !pingRes.ok);
    }

    if (name === "relay_set_device_policy") {
      const query = args.device_id || args.device_name || (await this.ctx.storage.get("selected")) || "";
      const resolved = await this.resolveDeviceQuery(query);
      if (resolved.error) {
        this.recordAudit({ actor, mcpMethod: "tools/call", mcpName: name, status: resolved.status, durationMs: Date.now() - started, ok: false, error: resolved.error });
        return jsonRpcResult(rpc.id, { error: resolved.error }, true);
      }
      const key = "device:" + resolved.device.id;
      const stored = await this.ctx.storage.get(key);
      if (!stored) return jsonRpcResult(rpc.id, { error: "Unknown device" }, true);

      const updated = {
        ...stored,
        ...(typeof args.read_only === "boolean" ? { readOnly: args.read_only } : {}),
        ...(typeof args.new_name === "string" && args.new_name.trim() ? { name: sanitizeLabel(args.new_name, stored.name, 40) } : {})
      };
      await this.ctx.storage.put(key, updated);
      this.recordAudit({
        actor,
        deviceId: updated.id,
        deviceName: updated.name,
        mcpMethod: "tools/call",
        mcpName: name,
        status: 200,
        durationMs: Date.now() - started,
        ok: true
      });
      return jsonRpcResult(rpc.id, {
        deviceId: updated.id,
        name: updated.name,
        readOnly: Boolean(updated.readOnly),
        online: resolved.device.online
      });
    }

    if (name === "relay_recent_activity") {
      const entries = this.listAudit(args.limit ?? 20);
      this.recordAudit({ actor, mcpMethod: "tools/call", mcpName: name, status: 200, durationMs: Date.now() - started, ok: true });
      return jsonRpcResult(rpc.id, { count: entries.length, entries });
    }

    return jsonRpcResult(rpc.id, { error: "Unknown relay tool" }, true);
  }

  async handleRelayResourceRead(rpc, actor, verified = false) {
    const started = Date.now();
    const uri = String(rpc?.params?.uri || "");
    const devices = await this.list();
    let payload = null;

    if (uri === "relay://devices") {
      payload = {
        workerVersion: WORKER_VERSION,
        onlineCount: devices.filter((d) => d.online).length,
        selectedDeviceId: devices.find((d) => d.selected)?.id || null,
        devices
      };
    } else if (uri === "relay://status") {
      payload = {
        ok: true,
        workerVersion: WORKER_VERSION,
        protocol: 3,
        accessJwtVerified: verified,
        actor,
        onlineCount: devices.filter((d) => d.online).length,
        pairedCount: devices.length,
        selectedDeviceId: devices.find((d) => d.selected)?.id || null
      };
    } else if (uri === "relay://audit") {
      const entries = this.listAudit(30);
      payload = { count: entries.length, entries };
    } else {
      return null;
    }

    this.recordAudit({ actor, mcpMethod: "resources/read", mcpName: uri, status: 200, durationMs: Date.now() - started, ok: true });
    return json({
      jsonrpc: "2.0",
      id: rpc?.id ?? null,
      result: {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(payload, null, 2)
          }
        ]
      }
    });
  }

  async handleRelayPromptGet(rpc, actor) {
    const started = Date.now();
    const name = String(rpc?.params?.name || "");
    if (!RELAY_PROMPT_NAMES.has(name)) return null;
    const args = rpc?.params?.arguments && typeof rpc.params.arguments === "object" ? rpc.params.arguments : {};
    const devices = await this.list();
    const instructions = buildRelayInstructions(devices);

    let promptText = "";
    if (name === "multi-device-triage") {
      promptText =
        `${instructions}\n\n` +
        "Follow this multi-device triage workflow:\n" +
        "1. Call `relay_list_devices` to inspect all paired devices, their OS/platform, read-only state, and online status.\n" +
        "2. For each online device relevant to the user's goal, call `relay_ping_device` to verify WebSocket RTT and local gateway readiness.\n" +
        "3. Use `_device: \"<device_name_or_id>\"` on read-only tool calls (`read_file`, `list_directory`, `list_processes`) to compare or gather evidence across machines without mutating global selection.\n" +
        (args.task ? `\nUser task: ${args.task}` : "");
    } else if (name === "safe-remote-maintenance") {
      promptText =
        `${instructions}\n\n` +
        "Follow this safe remote maintenance workflow:\n" +
        `1. Confirm the target device (${args.target_device || "currently selected device"}) via \`relay_list_devices\` and verify it is online and not locked in read-only mode.\n` +
        "2. Run read-only discovery (`list_directory`, `read_file`, `get_file_info`, `list_processes`) before making any modification.\n" +
        "3. Present the exact paths or commands to the user if an operation is destructive.\n" +
        "4. After execution, verify the outcome and call `relay_recent_activity` to confirm a clean audit trail.\n" +
        (args.operation ? `\nRequested operation: ${args.operation}` : "");
    }

    this.recordAudit({ actor, mcpMethod: "prompts/get", mcpName: name, status: 200, durationMs: Date.now() - started, ok: true });
    return json({
      jsonrpc: "2.0",
      id: rpc?.id ?? null,
      result: {
        description: RELAY_PROMPTS.find((p) => p.name === name)?.description || name,
        messages: [
          {
            role: "user",
            content: { type: "text", text: promptText }
          }
        ]
      }
    });
  }

  async buildEdgeInitializeResponse(rpc) {
    const devices = await this.list();
    const requestedVersion = rpc?.params?.protocolVersion;
    const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requestedVersion)
      ? requestedVersion
      : SUPPORTED_PROTOCOL_VERSIONS[0];
    const result = {
      protocolVersion,
      capabilities: {
        tools: { listChanged: false },
        resources: {},
        prompts: {}
      },
      serverInfo: {
        name: "private-desktop-mcp-relay",
        version: WORKER_VERSION
      },
      instructions: buildRelayInstructions(devices)
    };
    return json({ jsonrpc: "2.0", id: rpc?.id ?? null, result });
  }

  async buildSelfHealingDeviceError(rpc, reasonCode, humanMessage, status) {
    const devices = await this.list();
    const onlineDevices = devices.filter((d) => d.online).map((d) => ({ id: d.id, name: d.name, platform: d.platform, readOnly: d.readOnly }));
    const selectedDeviceId = devices.find((d) => d.selected)?.id || null;
    const nextActions =
      onlineDevices.length > 1
        ? [
            `Call relay_select_device with one of the online devices: ${onlineDevices.map((d) => `${d.name} (${d.id})`).join(", ")}`,
            'Or pass `_device: "<device_name_or_id>"` in the tool call arguments to target a specific machine directly.'
          ]
        : onlineDevices.length === 1
          ? [
              `Call relay_select_device with device_id "${onlineDevices[0].id}" (${onlineDevices[0].name}), or pass \`_device: "${onlineDevices[0].name}"\`.`
            ]
          : [
              "No paired desktop device is currently online.",
              "Ask the user to start the connector on their computer: `npx.cmd --yes --prefer-online --package=@juexibobi/private-desktop-mcp@latest -- private-desktop-mcp connect`",
              "Call `relay_list_devices` to check when the device comes online."
            ];

    if (rpc && rpc.method === "tools/call") {
      return jsonRpcResult(
        rpc.id,
        {
          error: humanMessage,
          errorCode: reasonCode,
          httpStatus: status,
          selectedDeviceId,
          onlineDevices,
          pairedDevicesCount: devices.length,
          nextActions
        },
        true
      );
    }

    return json({ error: humanMessage, errorCode: reasonCode, onlineDevices, nextActions }, status);
  }

  async proxy(req, forcedId = null) {
    const started = Date.now();
    const actor = req.headers.get("x-pcc-actor") || "owner";
    const verified = req.headers.get("x-pcc-verified") === "1";
    const bodyText = req.method === "DELETE" ? "" : await req.text();
    if (bodyText.length > 1048576) return new Response("Too large", { status: 413 });

    let rpc = null;
    if (bodyText) {
      try {
        rpc = JSON.parse(bodyText);
      } catch {
        rpc = null;
      }
    }

    const mcpMethod = typeof rpc?.method === "string" ? rpc.method : req.headers.get("mcp-method") || req.method;
    const mcpName =
      mcpMethod === "tools/call" && typeof rpc?.params?.name === "string"
        ? rpc.params.name
        : req.headers.get("mcp-name") || "";

    // 1. Handle built-in relay management meta-tools, relay:// resources, and relay prompts directly at the edge
    if (mcpMethod === "tools/call" && RELAY_META_NAMES.has(mcpName)) {
      return this.handleMetaToolCall(rpc, actor);
    }
    if (mcpMethod === "resources/read" && String(rpc?.params?.uri || "").startsWith("relay://")) {
      const res = await this.handleRelayResourceRead(rpc, actor, verified);
      if (res) return res;
    }
    if (mcpMethod === "prompts/get" && RELAY_PROMPT_NAMES.has(String(rpc?.params?.name || ""))) {
      const res = await this.handleRelayPromptGet(rpc, actor);
      if (res) return res;
    }

    // 2. Resolve target device (supports explicit _device argument or X-Target-Device header)
    let forwardedBody = bodyText;
    let targetQuery = forcedId ? "" : req.headers.get("x-target-device") || "";
    if (
      !forcedId &&
      mcpMethod === "tools/call" &&
      rpc?.params?.arguments &&
      typeof rpc.params.arguments === "object" &&
      typeof rpc.params.arguments._device === "string"
    ) {
      targetQuery = rpc.params.arguments._device.trim();
      const cleanedArgs = { ...rpc.params.arguments };
      delete cleanedArgs._device;
      forwardedBody = JSON.stringify({
        ...rpc,
        params: { ...rpc.params, arguments: cleanedArgs }
      });
    }

    const online = this.open();
    const selected = await this.ctx.storage.get("selected");
    let id = forcedId || "";

    if (!id && targetQuery) {
      const resolved = await this.resolveDeviceQuery(targetQuery);
      if (resolved.error) {
        this.recordAudit({ actor, mcpMethod, mcpName, status: resolved.status, durationMs: Date.now() - started, ok: false, error: resolved.error });
        return this.buildSelfHealingDeviceError(rpc, "DEVICE_TARGET_ERROR", resolved.error, resolved.status);
      }
      id = resolved.device.id;
    }

    if (!id) {
      id = selected;
      if ((!id || !online.has(id)) && online.size === 1) id = online.keys().next().value;
    }

    // 3. Edge-native fallback for MCP lifecycle & discovery when no single target device is online/selected
    if (!id || !online.has(id)) {
      if (mcpMethod === "initialize" || mcpMethod === "server/discover") {
        this.recordAudit({ actor, mcpMethod, mcpName, status: 200, durationMs: Date.now() - started, ok: true });
        return this.buildEdgeInitializeResponse(rpc);
      }
      if (mcpMethod === "notifications/initialized") {
        this.recordAudit({ actor, mcpMethod, mcpName: "", status: 202, durationMs: Date.now() - started, ok: true });
        return new Response(null, { status: 202, headers: { "cache-control": "no-store" } });
      }
      if (mcpMethod === "ping") {
        return json({ jsonrpc: "2.0", id: rpc?.id ?? null, result: {} });
      }
      if (mcpMethod === "tools/list") {
        this.recordAudit({ actor, mcpMethod, mcpName, status: 200, durationMs: Date.now() - started, ok: true });
        return json({ jsonrpc: "2.0", id: rpc?.id ?? null, result: { tools: RELAY_META_TOOLS } });
      }
      if (mcpMethod === "resources/list") {
        this.recordAudit({ actor, mcpMethod, mcpName, status: 200, durationMs: Date.now() - started, ok: true });
        return json({ jsonrpc: "2.0", id: rpc?.id ?? null, result: { resources: RELAY_RESOURCES } });
      }
      if (mcpMethod === "prompts/list") {
        this.recordAudit({ actor, mcpMethod, mcpName, status: 200, durationMs: Date.now() - started, ok: true });
        return json({ jsonrpc: "2.0", id: rpc?.id ?? null, result: { prompts: RELAY_PROMPTS } });
      }
    }

    if (id && !online.has(id)) {
      this.recordAudit({ actor, deviceId: id, mcpMethod, mcpName, status: 503, durationMs: Date.now() - started, ok: false, error: "Selected device offline" });
      return this.buildSelfHealingDeviceError(
        rpc,
        "SELECTED_DEVICE_OFFLINE",
        "Selected device offline; call relay_list_devices or check /admin/devices",
        503
      );
    }
    if (!id) {
      if (!online.size) {
        this.recordAudit({ actor, mcpMethod, mcpName, status: 503, durationMs: Date.now() - started, ok: false, error: "No device online" });
        return this.buildSelfHealingDeviceError(rpc, "NO_DEVICE_ONLINE", "No device online", 503);
      }
      if (online.size > 1) {
        this.recordAudit({ actor, mcpMethod, mcpName, status: 409, durationMs: Date.now() - started, ok: false, error: "Multiple devices online" });
        return this.buildSelfHealingDeviceError(
          rpc,
          "MULTIPLE_DEVICES_ONLINE",
          "Multiple devices online; call relay_select_device, pass _device, or select at /admin/devices",
          409
        );
      }
      id = online.keys().next().value;
    }

    const storedDevice = await this.ctx.storage.get("device:" + id);
    const deviceName = storedDevice?.name || online.get(id)?.meta?.name || "";

    // 4. Edge read-only lock check before crossing WebSocket
    if (storedDevice?.readOnly && mcpMethod === "tools/call" && !READONLY_UPSTREAM_TOOLS.has(mcpName)) {
      const msg = `Blocked by relay: device "${deviceName || id}" is locked in read-only mode (call relay_set_device_policy or toggle at /admin/devices).`;
      this.recordAudit({ actor, deviceId: id, deviceName, mcpMethod, mcpName, status: 403, durationMs: Date.now() - started, ok: false, error: "Device read-only lock" });
      return jsonRpcResult(rpc?.id ?? null, msg, true);
    }

    const ws = online.get(id).ws;
    const headers = {};
    for (const k of ["accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id", "mcp-method", "mcp-name"]) {
      if (req.headers.get(k)) headers[k] = req.headers.get(k);
    }
    const requestId = crypto.randomUUID();
    const res = await new Promise((resolve) => {
      const cleanup = () => {
        clearTimeout(timer);
        this.inflight.delete(requestId);
        if (req.signal && onAbort) {
          try {
            req.signal.removeEventListener("abort", onAbort);
          } catch {}
        }
      };
      const timer = setTimeout(() => {
        cleanup();
        try {
          ws.send(JSON.stringify({ kind: "cancel", id: requestId }));
        } catch {}
        resolve({ status: 504, headers: { "content-type": "application/json" }, body: '{"error":"Timeout"}' });
      }, 75000);
      const onAbort = () => {
        cleanup();
        try {
          ws.send(JSON.stringify({ kind: "cancel", id: requestId }));
        } catch {}
        resolve({ status: 499, headers: { "content-type": "application/json" }, body: '{"error":"Client aborted"}' });
      };
      if (req.signal) {
        if (req.signal.aborted) {
          onAbort();
          return;
        }
        req.signal.addEventListener("abort", onAbort, { once: true });
      }
      this.inflight.set(requestId, {
        ws,
        resolve: (v) => {
          cleanup();
          resolve(v);
        }
      });
      try {
        ws.send(
          JSON.stringify({
            kind: "request",
            id: requestId,
            method: req.method,
            headers,
            body: forwardedBody
          })
        );
      } catch {
        cleanup();
        resolve({ status: 503, body: '{"error":"Disconnected"}', headers: { "content-type": "application/json" } });
      }
    });

    let responseBody = [202, 204].includes(res.status) ? null : String(res.body || "");
    const resContentType = res.headers?.["content-type"] || "";
    if (responseBody && res.status >= 200 && res.status < 300) {
      if (mcpMethod === "tools/list") {
        responseBody = injectMetaToolsIntoBody(responseBody, resContentType);
      } else if (mcpMethod === "initialize" || mcpMethod === "server/discover") {
        const devices = await this.list();
        responseBody = enrichInitializeBody(responseBody, resContentType, devices);
      } else if (mcpMethod === "resources/list") {
        responseBody = injectRelayResourcesIntoBody(responseBody, resContentType);
      } else if (mcpMethod === "prompts/list") {
        responseBody = injectRelayPromptsIntoBody(responseBody, resContentType);
      }
    }

    const ok = res.status >= 200 && res.status < 400;
    this.recordAudit({
      actor,
      deviceId: id,
      deviceName,
      mcpMethod,
      mcpName,
      status: res.status || 502,
      durationMs: Date.now() - started,
      ok,
      error: ok ? "" : `HTTP ${res.status || 502}`
    });

    const outHeaders = new Headers({ "cache-control": "no-store" });
    for (const key of ["content-type", "mcp-session-id", "mcp-protocol-version"]) {
      if (res.headers?.[key]) outHeaders.set(key, res.headers[key]);
    }
    return new Response(responseBody, { status: res.status || 502, headers: outHeaders });
  }

  async webSocketMessage(ws, message) {
    const raw = String(message);
    if (raw === "ping") {
      try {
        ws.send("pong");
      } catch {}
      return;
    }
    let d;
    try {
      d = JSON.parse(raw);
    } catch {
      return;
    }
    if (d?.kind === "ping") {
      try {
        ws.send(JSON.stringify({ kind: "pong", id: d.id, ts: Date.now() }));
      } catch {}
      return;
    }
    if (d?.kind === "pong" && d.id && this.pings.has(d.id)) {
      const slot = this.pings.get(d.id);
      if (slot.ws === ws) {
        this.pings.delete(d.id);
        slot.resolve({
          uptimeMs: d.uptimeMs,
          gatewayReady: d.gatewayReady,
          mode: d.mode,
          cliVersion: d.version
        });
      }
      return;
    }
    const slot = d?.id && this.inflight.get(d.id);
    if (d.kind === "response" && slot && slot.ws === ws) {
      this.inflight.delete(d.id);
      slot.resolve({
        status: Number(d.status) || 500,
        headers: d.headers || {},
        body: String(d.body || "")
      });
    }
  }

  async webSocketClose(ws) {
    const meta = ws.deserializeAttachment?.();
    if (meta?.deviceId) {
      try {
        const stored = await this.ctx.storage.get("device:" + meta.deviceId);
        if (stored) {
          await this.ctx.storage.put("device:" + meta.deviceId, { ...stored, lastSeen: new Date().toISOString() });
        }
      } catch {}
    }
    for (const [id, p] of this.inflight) {
      if (p.ws === ws) {
        this.inflight.delete(id);
        p.resolve({ status: 503, headers: { "content-type": "application/json" }, body: '{"error":"Device disconnected"}' });
      }
    }
    for (const [id, p] of this.pings) {
      if (p.ws === ws) {
        this.pings.delete(id);
        p.resolve({ ok: false, error: "Device disconnected" });
      }
    }
  }

  async webSocketError(ws) {
    return this.webSocketClose(ws);
  }
}
