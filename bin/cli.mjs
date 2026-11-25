#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { ProxyAgent } from "undici";
import { HttpsProxyAgent } from "https-proxy-agent";
import { resolveProxyForUrl } from "./proxy.mjs";
import { logLine, sanitizeText } from "./logging.mjs";
import {
  callInfo,
  requestBrief,
  requestDebug,
  responseBrief,
  safeTraceRequest,
  safeTraceOutput,
  shortCallId,
  formatElapsed,
  loggingOptions
} from "./activity.mjs";
import {
  createPolicy,
  evaluateToolCall,
  filterToolsListBody,
  redactOutboundResponse,
  buildPolicyBlockedResponse
} from "./policy.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PKG_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version || "0.4.0";
  } catch {
    return "0.4.0";
  }
})();

const DEFAULT_RELAY = "https://private-desktop-device-relay.ljx2043979076.workers.dev";
const HEARTBEAT_INTERVAL_MS = 25000;
const MAX_GATEWAY_LOG_BYTES = 5 * 1024 * 1024;

function parseArgs(argv) {
  let command = "";
  let relay = process.env.PCC_RELAY_URL || DEFAULT_RELAY;
  let port = Number(process.env.MCP_PORT || 8717);
  let deviceName = os.hostname();
  let readonly = /^(1|true|yes)$/i.test(String(process.env.PCC_READONLY || ""));
  let dlp = !/^(0|false|no)$/i.test(String(process.env.PCC_DLP || "true"));
  let autoOpen = true;
  let serversConfig = process.env.PCC_MCP_CONFIG || "";
  const allowDirs = String(process.env.PCC_ALLOW_DIRS || "")
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter(Boolean);
  const allowTools = String(process.env.PCC_ALLOW_TOOLS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const denyTools = String(process.env.PCC_DENY_TOOLS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("-")) {
      if (!command) command = arg;
      continue;
    }
    const eq = arg.indexOf("=");
    const flag = eq > 0 ? arg.slice(0, eq) : arg;
    const inlineVal = eq > 0 ? arg.slice(eq + 1) : null;
    const nextVal = () => (inlineVal !== null ? inlineVal : argv[++i] || "");

    if (flag === "--help" || flag === "-h") command = "help";
    else if (flag === "--relay") relay = nextVal().replace(/\/+$/, "");
    else if (flag === "--port") port = Number(nextVal());
    else if (flag === "--name") deviceName = nextVal();
    else if (flag === "--readonly") readonly = true;
    else if (flag === "--no-dlp") dlp = false;
    else if (flag === "--no-open") autoOpen = false;
    else if (flag === "--servers") serversConfig = nextVal();
    else if (flag === "--allow-dir") {
      const v = nextVal().trim();
      if (v) allowDirs.push(v);
    } else if (flag === "--allow-tools") {
      for (const item of nextVal().split(",")) if (item.trim()) allowTools.push(item.trim());
    } else if (flag === "--deny-tools") {
      for (const item of nextVal().split(",")) if (item.trim()) denyTools.push(item.trim());
    }
  }

  return {
    command: command || "connect",
    relay: relay.replace(/\/+$/, ""),
    port,
    deviceName: deviceName || "Desktop",
    readonly,
    dlp,
    autoOpen,
    serversConfig,
    allowDirs,
    allowTools,
    denyTools
  };
}

const opts = parseArgs(process.argv.slice(2));
const { trace, debug } = loggingOptions(process.argv.slice(2));
const configDir = path.join(process.env.APPDATA || path.join(os.homedir(), ".config"), "PrivateDesktopMCP");
const config = path.join(configDir, "device.json");
const gatewayLogDir = path.join(configDir, "logs");
const gatewayLogPath = path.join(gatewayLogDir, "gateway.log");
const localBaseUrl = `http://127.0.0.1:${opts.port}/mcp`;
const localGatewayToken = crypto.randomBytes(32).toString("hex");
const policy = createPolicy({
  readonly: opts.readonly,
  allowTools: opts.allowTools,
  denyTools: opts.denyTools,
  allowDirs: opts.allowDirs,
  protectedDirs: [configDir],
  dlp: opts.dlp
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let currentProxy = null;
let proxyCheckedAt = 0;
let lastProxyNotice = "";
const agents = new Map();

function remoteTransport() {
  if (!currentProxy || Date.now() - proxyCheckedAt > 10000) {
    currentProxy = resolveProxyForUrl(opts.relay);
    proxyCheckedAt = Date.now();
    if (currentProxy.mode === "unsupported") {
      throw Error(currentProxy.reason + " (use an HTTP/Mixed port via system settings or HTTPS_PROXY)");
    }
    const notice =
      currentProxy.mode === "proxy"
        ? "🌐 Proxy: " + currentProxy.source + " (" + currentProxy.description + ")"
        : currentProxy.mode === "unavailable"
          ? "⚠️ Proxy detection unavailable: " + currentProxy.reason + "; trying direct"
          : "🌐 Direct connection (" + currentProxy.source + ")";
    if (notice !== lastProxyNotice) {
      logLine(currentProxy.mode === "unavailable" ? "warn" : "info", notice);
      lastProxyNotice = notice;
    }
  }
  if (currentProxy.mode !== "proxy") return {};
  let transport = agents.get(currentProxy.url);
  if (!transport) {
    transport = { dispatcher: new ProxyAgent(currentProxy.url), wsAgent: new HttpsProxyAgent(currentProxy.url) };
    agents.set(currentProxy.url, transport);
  }
  return transport;
}

let stopping = false;
let child = null;
let gatewayHealthy = false;
let gatewayRestartCount = 0;
let gatewayRestartPromise = null;
let socket = null;
let activeCreds = null;
let connectionAttempt = 0;
let connectedSince = 0;
let sessionCalls = 0;
let sessionFails = 0;
let allCalls = 0;
let allFails = 0;
let lastError = "";
const inflightControllers = new Map();

function saved() {
  try {
    return JSON.parse(fs.readFileSync(config, "utf8"));
  } catch {
    return null;
  }
}

function store(x) {
  fs.mkdirSync(path.dirname(config), { recursive: true, mode: 0o700 });
  fs.writeFileSync(config, JSON.stringify(x, null, 2), { mode: 0o600 });
}

function forget() {
  try {
    fs.unlinkSync(config);
  } catch {}
}

function rotateLogIfNeeded(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  try {
    const stat = fs.statSync(filePath);
    if (stat.size >= MAX_GATEWAY_LOG_BYTES) {
      try {
        fs.unlinkSync(filePath + ".1");
      } catch {}
      fs.renameSync(filePath, filePath + ".1");
    }
  } catch {}
}

function tryOpenBrowser(url) {
  if (!opts.autoOpen || !process.stdout.isTTY || process.env.CI) return;
  try {
    let cmd;
    let args;
    if (process.platform === "win32") {
      cmd = "cmd.exe";
      args = ["/c", "start", "", url];
    } else if (process.platform === "darwin") {
      cmd = "open";
      args = [url];
    } else {
      cmd = "xdg-open";
      args = [url];
    }
    const p = spawn(cmd, args, { stdio: "ignore", detached: true, windowsHide: true });
    p.on("error", () => {});
    p.unref();
  } catch {}
}

function reportDevice(creds) {
  logLine("info", "━━━━━━━━━━━━━━━━ PCC DEVICE READY ━━━━━━━━━━━━━━━━");
  logLine("info", "Computer: " + opts.deviceName + " | User: " + os.userInfo().username + " | Node: " + process.version);
  logLine("info", "Device ID: " + creds.deviceId + " | Gateway PID: " + (child?.pid || "unknown"));
  logLine("info", "Relay: " + opts.relay + " | Local MCP: " + localBaseUrl + " (Bearer+Host protected)");
  logLine(
    "info",
    "Mode: " +
      (trace ? "TRACE" : debug ? "DEBUG" : "LIVE") +
      " | Policy: " +
      (policy.readonly ? "READONLY" : "FULL") +
      " | DLP: " +
      (policy.dlp ? "ON" : "OFF") +
      (policy.allowDirs.length ? " | AllowDirs: " + policy.allowDirs.length : "")
  );
  logLine("info", "Return to your AI client; keep this terminal running. Ctrl+C to disconnect.");
  logLine("info", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

async function post(route, data) {
  const { dispatcher } = remoteTransport();
  const r = await fetch(opts.relay + route, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(data),
    signal: AbortSignal.timeout(12000),
    ...(dispatcher ? { dispatcher } : {})
  });
  const j = await r.json();
  if (!r.ok) throw Error(j.error || "HTTP " + r.status);
  return j;
}

async function pair() {
  const v = await post("/relay/pair/start", { name: opts.deviceName });
  logLine("info", "🔑 New device pairing requested");
  console.log(
    "\nNEW DEVICE: " +
      opts.deviceName +
      "\nPAIRING CODE: " +
      v.code +
      "\nPlease visit " +
      v.approvalUrl +
      " and approve the matching code.\nWaiting for approval (60 minutes)...\n"
  );
  tryOpenBrowser(v.approvalUrl);
  for (let i = 0; i < 720 && !stopping; i++) {
    await sleep(5000);
    let r;
    try {
      r = await post("/relay/pair/poll", { pairId: v.pairId, proof: v.proof });
    } catch (e) {
      if (/expired|invalid/i.test(e.message)) throw e;
      continue;
    }
    if (r.status === "approved") {
      const credentials = { deviceId: r.deviceId, token: r.token };
      store(credentials);
      logLine("info", "✅ Device approved; credentials saved locally.");
      return credentials;
    }
  }
  throw Error("Pairing timed out. Re-run the command.");
}

async function portOpen(withToken = false) {
  if (withToken) {
    const r = await fetch(`http://127.0.0.1:${opts.port}/healthz`, {
      headers: { authorization: "Bearer " + localGatewayToken },
      signal: AbortSignal.timeout(1500)
    });
    return r.status === 200;
  }
  const r = await fetch(localBaseUrl, { signal: AbortSignal.timeout(1500) });
  return r.status > 0;
}

function abortAllInflight(reason) {
  for (const [id, controller] of inflightControllers) {
    inflightControllers.delete(id);
    try {
      controller.abort(new Error(reason));
    } catch {}
  }
}

async function startGateway({ checkOccupied = true } = {}) {
  if (!Number.isInteger(opts.port) || opts.port < 1024 || opts.port > 65535) {
    throw Error("Invalid port: " + opts.port);
  }
  if (checkOccupied) {
    try {
      if (await portOpen(false)) {
        throw Error(`Port ${opts.port} is already occupied. Stop the other MCP gateway or pass --port <port>.`);
      }
    } catch (e) {
      if (/occupied/.test(e.message)) throw e;
    }
  }

  logLine("info", "🚀 Starting local MCP gateway (Desktop Commander" + (opts.serversConfig ? " + extra servers" : "") + ")...");
  rotateLogIfNeeded(gatewayLogPath);
  const fd = fs.openSync(gatewayLogPath, "a", 0o600);
  const spawned = spawn(process.execPath, [path.join(root, "gateway.mjs")], {
    cwd: root,
    stdio: ["ignore", fd, fd],
    windowsHide: true,
    env: {
      ...process.env,
      MCP_PORT: String(opts.port),
      MCP_LOCAL_TOKEN: localGatewayToken,
      ...(opts.serversConfig ? { PCC_MCP_CONFIG: path.resolve(opts.serversConfig) } : {})
    }
  });
  fs.closeSync(fd);
  child = spawned;
  gatewayHealthy = false;
  logLine("info", "Gateway PID: " + spawned.pid + " | diagnostic log: " + gatewayLogPath);

  spawned.on("exit", (code, signal) => {
    if (child === spawned) child = null;
    const wasHealthy = gatewayHealthy;
    gatewayHealthy = false;
    abortAllInflight("Local MCP gateway exited unexpectedly");
    if (stopping) return;
    logLine("error", `⚠️ Local MCP gateway exited unexpectedly (code=${code ?? "null"}, signal=${signal ?? "none"})`);
    if (wasHealthy) scheduleGatewayRestart();
  });

  for (let i = 0; i < 40; i++) {
    if (spawned.exitCode !== null) {
      throw Error("Gateway exited unexpectedly. See " + gatewayLogPath);
    }
    try {
      if (await portOpen(true)) {
        gatewayHealthy = true;
        gatewayRestartCount = 0;
        logLine("info", `🔌 Local MCP gateway ready (127.0.0.1:${opts.port})`);
        return;
      }
    } catch {}
    await sleep(500);
  }
  throw Error(`Gateway failed to listen on port ${opts.port}.`);
}

function scheduleGatewayRestart() {
  if (stopping || gatewayRestartPromise) return;
  gatewayRestartCount++;
  const delayMs = Math.min(30000, 1000 * 2 ** Math.min(4, gatewayRestartCount - 1));
  logLine("warn", `🔄 Restarting local MCP gateway in ${Math.ceil(delayMs / 1000)}s (restart #${gatewayRestartCount})...`);
  gatewayRestartPromise = (async () => {
    await sleep(delayMs);
    if (stopping) return;
    try {
      await startGateway({ checkOccupied: false });
      logLine("info", "✅ Local MCP gateway recovered.");
    } catch (e) {
      logLine("error", "Local MCP gateway restart failed: " + sanitizeText(e.message, 200));
    } finally {
      gatewayRestartPromise = null;
      if (!stopping && !gatewayHealthy && !child) {
        scheduleGatewayRestart();
      }
    }
  })();
}

function stopGateway() {
  gatewayHealthy = false;
  abortAllInflight("Connector shutting down");
  if (child?.pid) {
    if (process.platform === "win32") {
      spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, timeout: 8000 });
    } else {
      try {
        child.kill("SIGTERM");
      } catch {}
    }
    child = null;
  }
}

async function respond(ws, msg) {
  const started = Date.now();
  const call = callInfo(msg.body, msg.id);
  const callId = shortCallId(call.requestId);
  const name = call.label;
  const isTool = call.method === "tools/call";
  allCalls++;
  sessionCalls++;

  logLine("info", "🔧 [" + callId + "] " + (isTool ? "Tool: " : "MCP: ") + name + " | " + requestBrief(call));
  if (debug) logLine("debug", "    ↳ Metadata: " + requestDebug(call));
  if (trace) logLine("warn", "    ↳ Trace args (locally visible): " + safeTraceRequest(call));

  let parsedRpc = null;
  try {
    parsedRpc = JSON.parse(String(msg.body || ""));
  } catch {
    parsedRpc = null;
  }

  // Enforce local tool policy before forwarding to gateway
  if (parsedRpc) {
    const verdict = evaluateToolCall(parsedRpc, policy);
    if (!verdict.allowed) {
      allFails++;
      sessionFails++;
      logLine("warn", "🛡️ [" + callId + "] Policy blocked " + name + ": " + verdict.reason);
      const blockedResp = {
        kind: "response",
        id: msg.id,
        status: 200,
        headers: { "content-type": "application/json" },
        body: buildPolicyBlockedResponse(parsedRpc.id, verdict.reason)
      };
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(blockedResp));
      return;
    }
  }

  if (!gatewayHealthy) {
    allFails++;
    sessionFails++;
    const unavailable = {
      kind: "response",
      id: msg.id,
      status: 503,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Local MCP gateway is currently restarting; retry shortly." })
    };
    logLine("error", "❌ [" + callId + "] " + name + " | Local gateway unavailable");
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(unavailable));
    return;
  }

  const headers = { authorization: "Bearer " + localGatewayToken };
  for (const k of ["accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id", "mcp-method", "mcp-name"]) {
    if (msg.headers?.[k]) headers[k] = msg.headers[k];
  }
  if (parsedRpc && typeof parsedRpc.method === "string") {
    headers["mcp-method"] = parsedRpc.method;
    if (parsedRpc.method === "tools/call" && typeof parsedRpc.params?.name === "string") {
      headers["mcp-name"] = parsedRpc.params.name;
    }
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("Local gateway timeout (70s)")), 70000);
  inflightControllers.set(msg.id, controller);

  let response;
  try {
    const fetchOpts = {
      method: msg.method || "POST",
      headers,
      signal: controller.signal
    };
    if (fetchOpts.method !== "DELETE" && fetchOpts.method !== "GET" && fetchOpts.method !== "HEAD") {
      fetchOpts.body = msg.body;
    }
    const r = await fetch(localBaseUrl, fetchOpts);
    let body = await r.text();
    const forward = {};
    for (const k of ["content-type", "mcp-session-id", "mcp-protocol-version"]) {
      if (r.headers.has(k)) forward[k] = r.headers.get(k);
    }
    const ct = forward["content-type"] || "";

    // Filter disallowed tools from tools/list responses
    if (call.method === "tools/list" && r.ok) {
      body = filterToolsListBody(body, ct, policy);
    }

    // Outbound DLP secret redaction
    const dlpResult = redactOutboundResponse(body, ct, {
      enabled: policy.dlp,
      extraSecrets: [activeCreds?.token || "", localGatewayToken]
    });
    if (dlpResult.redactedCount > 0) {
      logLine("warn", `🛡️ [${callId}] DLP redacted ${dlpResult.redactedCount} secret(s) before returning response to relay`);
      body = dlpResult.body;
    }

    response = { kind: "response", id: msg.id, status: r.status, headers: forward, body: body.slice(0, 8 * 1024 * 1024) };
  } catch (e) {
    const aborted = controller.signal.aborted;
    const reason = controller.signal.reason?.message || e.message || "Local gateway error";
    response = {
      kind: "response",
      id: msg.id,
      status: aborted && /client/i.test(reason) ? 499 : 502,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Local gateway error", message: String(reason).slice(0, 180) })
    };
  } finally {
    clearTimeout(timeout);
    inflightControllers.delete(msg.id);
  }

  const result = responseBrief(response.body, response.headers?.["content-type"] || "", response.status);
  const failed = result.failed;
  if (failed) {
    allFails++;
    sessionFails++;
  }
  logLine(
    failed ? "error" : "info",
    (failed ? "❌" : "✅") +
      " [" +
      callId +
      "] " +
      name +
      " | " +
      result.kind +
      " | HTTP " +
      response.status +
      " | " +
      formatElapsed(Date.now() - started)
  );
  logLine(failed ? "warn" : "info", "    ↳ " + result.summary);
  if (result.error) logLine("error", "    ↳ JSON-RPC: " + result.error);
  if (debug) logLine("debug", "    ↳ Response size: " + result.bytes + " bytes | Total calls: " + allCalls + " | Errors: " + allFails);
  if (trace) logLine("warn", "    ↳ Trace output (may contain private data): " + safeTraceOutput(result));
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(response));
  else logLine("warn", "    ↳ Response cannot be delivered: relay socket is not open");
}

async function connect(creds, { onHealthy } = {}) {
  return new Promise((resolve) => {
    const { wsAgent } = remoteTransport();
    const attempt = ++connectionAttempt;
    const opening = Date.now();
    logLine("info", "🌐 Connecting to Cloudflare relay (attempt #" + attempt + ")...");

    const ws = new WebSocket(opts.relay.replace(/^https:/, "wss:").replace(/^http:/, "ws:") + "/relay/ws", {
      headers: {
        Authorization: "Bearer " + creds.token,
        "X-Device-ID": creds.deviceId,
        "X-Device-Platform": process.platform,
        "X-Device-Arch": process.arch,
        "X-Device-Node": process.version,
        "X-Device-Version": PKG_VERSION,
        "X-Device-Mode": policy.readonly ? "READONLY" : "FULL"
      },
      handshakeTimeout: 15000,
      ...(wsAgent ? { agent: wsAgent } : {})
    });
    socket = ws;

    let status = 0;
    let awaitingPong = false;
    let heartbeatTimer = null;
    let healthyTimer = null;

    const clearTimers = () => {
      if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
        heartbeatTimer = null;
      }
      if (healthyTimer) {
        clearTimeout(healthyTimer);
        healthyTimer = null;
      }
    };

    ws.on("open", () => {
      connectedSince = Date.now();
      sessionCalls = 0;
      sessionFails = 0;
      lastError = "";
      awaitingPong = false;

      // Reset backoff retries once the connection proves stable for 10s
      healthyTimer = setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) onHealthy?.();
      }, 10000);
      healthyTimer.unref?.();

      // RFC 6455 control-frame heartbeat: answered at the Cloudflare edge without waking hibernated DOs,
      // and compatible with both legacy v0.3.x and v0.4.0 Workers.
      heartbeatTimer = setInterval(() => {
        if (ws.readyState !== WebSocket.OPEN) return;
        if (awaitingPong) {
          logLine("warn", "⚠️ Relay heartbeat timed out (half-open socket detected); forcing reconnect...");
          clearTimers();
          try {
            ws.terminate();
          } catch {}
          return;
        }
        awaitingPong = true;
        try {
          ws.ping();
        } catch {
          try {
            ws.terminate();
          } catch {}
        }
      }, HEARTBEAT_INTERVAL_MS);
      heartbeatTimer.unref?.();

      logLine("info", "✅ Cloudflare relay connected in " + formatElapsed(Date.now() - opening));
      reportDevice(creds);
      console.log("CONNECTED. Your AI client can now use this device. Ctrl+C to disconnect.");
    });

    ws.on("pong", () => {
      awaitingPong = false;
    });

    ws.on("unexpected-response", (_req, res) => {
      status = res.statusCode;
      res.resume();
      lastError = "HTTP " + status;
      logLine("error", "Relay handshake rejected: HTTP " + status);
    });

    ws.on("message", (data) => {
      awaitingPong = false;
      const text = String(data);
      if (text === "pong") {
        return;
      }
      let m;
      try {
        m = JSON.parse(text);
      } catch {
        if (debug) logLine("debug", "Ignored invalid relay JSON message");
        return;
      }
      if (m.kind === "pong") {
        awaitingPong = false;
        return;
      }
      if (m.kind === "ping") {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(
            JSON.stringify({
              kind: "pong",
              id: m.id,
              uptimeMs: connectedSince ? Date.now() - connectedSince : 0,
              gatewayReady: gatewayHealthy,
              mode: policy.readonly ? "READONLY" : "FULL",
              version: PKG_VERSION
            })
          );
        }
        return;
      }
      if (m.kind === "cancel" && m.id) {
        const ctrl = inflightControllers.get(m.id);
        if (ctrl) {
          logLine("warn", "🛑 [" + shortCallId(m.id) + "] Aborting in-flight call (client cancelled/timed out)");
          try {
            ctrl.abort(new Error("Cancelled by client"));
          } catch {}
        }
        return;
      }
      if (m.kind === "request") {
        respond(ws, m).catch((e) => logLine("error", "Request handler: " + sanitizeText(e.message, 240)));
      }
    });

    ws.on("error", (e) => {
      lastError = sanitizeText(e.message, 180);
      logLine("error", "Relay network error: " + lastError);
    });

    ws.on("close", (code, reason) => {
      clearTimers();
      socket = null;
      const uptime = connectedSince ? formatElapsed(Date.now() - connectedSince) : "not established";
      logLine(
        "warn",
        "🔌 Relay disconnected | code=" + code + " | session uptime=" + uptime + " | calls=" + sessionCalls + " | failures=" + sessionFails
      );
      if (lastError) logLine("warn", "    ↳ Last network error: " + lastError);
      if (reason?.length) logLine("warn", "    ↳ Close reason: " + sanitizeText(reason.toString(), 100));
      connectedSince = 0;
      resolve({ unauthorized: status === 401 || code === 1008 });
    });
  });
}

async function runDoctor() {
  let healthy = true;
  console.log(`Private Desktop MCP Doctor (v${PKG_VERSION})`);
  console.log("─".repeat(48));
  console.log("Node.js:", process.version, `(${process.platform}/${process.arch})`);
  console.log("Relay URL:", opts.relay);

  let transport = {};
  try {
    const p = resolveProxyForUrl(opts.relay);
    console.log("Proxy:", p.mode === "proxy" ? `${p.source} (${p.description})` : `${p.mode} (${p.source}${p.reason ? ": " + p.reason : ""})`);
    if (p.mode === "unsupported") healthy = false;
    else if (p.mode === "proxy") transport = { dispatcher: new ProxyAgent(p.url) };
  } catch (e) {
    console.log("Proxy: error -", e.message);
    healthy = false;
  }

  try {
    const t0 = Date.now();
    const res = await fetch(opts.relay + "/relay/status", {
      signal: AbortSignal.timeout(8000),
      ...transport
    });
    const body = await res.json();
    console.log(
      `Relay Status: OK (HTTP ${res.status}, ${Date.now() - t0}ms, worker v${body.version || "unknown"}, features: ${(body.features || []).join(",") || "legacy"})`
    );
  } catch (e) {
    console.log("Relay Status: UNREACHABLE -", sanitizeText(e.message, 140));
    healthy = false;
  }

  const creds = saved();
  console.log("Device Pairing:", creds ? `paired (id=${String(creds.deviceId || "").slice(0, 8)}…)` : "not paired");
  try {
    const st = (await fetch(localBaseUrl, { signal: AbortSignal.timeout(1500) })).status;
    console.log(`Local Port ${opts.port}: occupied (HTTP ${st})`);
  } catch {
    console.log(`Local Port ${opts.port}: free`);
  }
  console.log("Policy:", policy.readonly ? "READONLY" : "FULL", "| DLP:", policy.dlp ? "ON" : "OFF");
  if (!healthy) process.exitCode = 1;
}

function runReport() {
  const p = resolveProxyForUrl(opts.relay);
  const creds = saved();
  let gatewayLogTail = [];
  try {
    const raw = fs.readFileSync(gatewayLogPath, "utf8");
    gatewayLogTail = raw
      .split(/\r?\n/)
      .slice(-20)
      .filter(Boolean)
      .map((line) => sanitizeText(line, 240));
  } catch {}

  const report = {
    generatedAt: new Date().toISOString(),
    version: PKG_VERSION,
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    relay: opts.relay,
    port: opts.port,
    paired: Boolean(creds?.deviceId),
    proxy: {
      mode: p.mode,
      source: p.source,
      description: p.description || "",
      reason: p.reason || ""
    },
    policy: {
      readonly: policy.readonly,
      dlp: policy.dlp,
      allowToolsCount: policy.allowTools.size,
      denyToolsCount: policy.denyTools.size,
      allowDirsCount: policy.allowDirs.length
    },
    recentGatewayLogTail: gatewayLogTail
  };
  console.log(JSON.stringify(report, null, 2));
}

function stop() {
  if (stopping) return;
  stopping = true;
  logLine("info", "Disconnecting PCC...");
  try {
    socket?.close(1000, "Manual disconnect");
  } catch {}
  stopGateway();
  setTimeout(() => process.exit(0), 200).unref();
}

process.on("SIGINT", stop);
process.on("SIGTERM", stop);

if (opts.command === "help") {
  console.log(
    `Private Desktop MCP v${PKG_VERSION}: connect | status | doctor | report | reset\n` +
      "Options:\n" +
      "  --relay <url>          Custom Cloudflare Worker relay URL (env: PCC_RELAY_URL)\n" +
      "  --port <port>          Local MCP gateway port (default: 8717, env: MCP_PORT)\n" +
      "  --name <name>          Device display name when pairing (default: hostname)\n" +
      "  --readonly             Allow read-only tools only and hide mutating tools\n" +
      "  --allow-dir <dir>      Restrict file tool paths to allowed directories (repeatable)\n" +
      "  --allow-tools <csv>    Explicit allowlist of MCP tool names\n" +
      "  --deny-tools <csv>     Explicit denylist of MCP tool names\n" +
      "  --servers <file.json>  Aggregate additional local stdio MCP servers (env: PCC_MCP_CONFIG)\n" +
      "  --no-dlp               Disable outbound secret redaction on responses (enabled by default)\n" +
      "  --no-open              Do not auto-open browser during device pairing\n" +
      "  --safe | --debug | --trace  Terminal logging verbosity (default: TRACE)\n" +
      `Default relay: ${DEFAULT_RELAY}\n` +
      `Approval page: ${opts.relay}/admin/devices\n` +
      "Ctrl+C to disconnect. No automatic startup."
  );
} else if (opts.command === "status") {
  console.log("Paired:", !!saved());
  console.log("Relay:", opts.relay);
  try {
    console.log("Local HTTP:", (await fetch(localBaseUrl, { signal: AbortSignal.timeout(2000) })).status);
  } catch {
    console.log("Local MCP offline");
  }
} else if (opts.command === "doctor") {
  await runDoctor();
} else if (opts.command === "report") {
  runReport();
} else if (opts.command === "reset") {
  forget();
  console.log("Local credentials cleared. Revoke old credentials in the admin page too.");
} else if (opts.command === "connect") {
  logLine("info", `╔══════════════ PCC REMOTE v${PKG_VERSION} ══════════════╗`);
  logLine(
    "info",
    "Logging: " +
      (trace ? "TRACE" : debug ? "DEBUG" : "LIVE") +
      " | Policy: " +
      (policy.readonly ? "READONLY" : "FULL") +
      " | DLP: " +
      (policy.dlp ? "ON" : "OFF") +
      " | Gateway: Desktop Commander MCP"
  );
  if (trace) logLine("warn", "TRACE mode can display private user content in this terminal; do not share these logs.");
  logLine("info", "╚═══════════════════════════════════════════════╝");
  try {
    const existing = saved();
    const credentials = existing || (await pair());
    activeCreds = credentials;
    if (existing) logLine("info", "💾 Stored device pairing found");
    await startGateway();
    let retries = 0;
    while (!stopping) {
      const r = await connect(credentials, {
        onHealthy: () => {
          retries = 0;
        }
      });
      if (r.unauthorized) {
        forget();
        logLine("error", "Credentials revoked; run again to pair.");
        break;
      }
      if (stopping) break;
      retries++;
      const baseMs = Math.min(30000, 1500 * 2 ** Math.min(5, retries));
      const jitterMs = Math.round(baseMs * (0.75 + Math.random() * 0.5));
      logLine("warn", "Reconnecting in " + (jitterMs / 1000).toFixed(1) + "s");
      await sleep(jitterMs);
    }
  } catch (e) {
    logLine("error", "ERROR: " + sanitizeText(e.message, 250));
    process.exitCode = 1;
  } finally {
    stopGateway();
  }
} else {
  console.error("Unknown command. Use help");
  process.exitCode = 2;
}
