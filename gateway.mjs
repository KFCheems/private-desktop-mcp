import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Server } from "@modelcontextprotocol/server";
import { proxyServer, startHTTPServer } from "mcp-proxy";

const __filename = fileURLToPath(import.meta.url);

export function isAllowedLocalHost(hostHeader, port) {
  const host = String(hostHeader || "").trim().toLowerCase();
  if (!host) return false;
  const p = String(port);
  return host === `127.0.0.1:${p}` || host === `localhost:${p}` || host === `[::1]:${p}`;
}

export function constantTimeTokenEqual(actual, expected) {
  const a = Buffer.from(String(actual || ""), "utf8");
  const b = Buffer.from(String(expected || ""), "utf8");
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

/**
 * Local MCP HTTP security guard:
 * - Blocks DNS rebinding via strict Host header validation.
 * - Blocks browser CSRF by rejecting any Origin header.
 * - Enforces ephemeral per-launch Bearer token when MCP_LOCAL_TOKEN is set.
 */
export function createLocalAuthGuard({ port, localToken = "" }) {
  return async (req) => {
    if (!isAllowedLocalHost(req.headers?.host, port)) {
      throw new Response("Forbidden: invalid Host header", { status: 403 });
    }
    if (req.headers?.origin) {
      throw new Response("Forbidden: browser Origin not allowed on local gateway", { status: 403 });
    }
    if (localToken) {
      const auth = String(req.headers?.authorization || "");
      const prefix = "Bearer ";
      if (!auth.startsWith(prefix) || !constantTimeTokenEqual(auth.slice(prefix.length), localToken)) {
        return { authenticated: false, error: "Unauthorized: invalid local gateway token" };
      }
    }
    return { authenticated: true };
  };
}

export function loadExtraServersConfig(configPath) {
  if (!configPath) return [];
  const resolved = path.resolve(configPath);
  const raw = JSON.parse(fs.readFileSync(resolved, "utf8"));
  const map = raw?.mcpServers || raw?.servers || {};
  const entries = [];
  for (const [rawName, cfg] of Object.entries(map)) {
    const namespace = String(rawName)
      .replace(/[^a-zA-Z0-9_-]/g, "_")
      .slice(0, 32);
    if (!namespace || !cfg || typeof cfg.command !== "string" || !cfg.command.trim()) continue;
    entries.push({
      namespace,
      command: cfg.command.trim(),
      args: Array.isArray(cfg.args) ? cfg.args.map(String) : [],
      env: cfg.env && typeof cfg.env === "object" ? Object.fromEntries(Object.entries(cfg.env).map(([k, v]) => [k, String(v)])) : undefined,
      cwd: typeof cfg.cwd === "string" ? cfg.cwd : undefined
    });
  }
  return entries;
}

export function createAggregatedClient(primary, extras = []) {
  if (!extras.length) return primary;
  const byNamespace = new Map(extras.map((e) => [e.namespace, e.client]));

  return new Proxy(primary, {
    get(target, prop, receiver) {
      if (prop === "listTools") {
        return async (params, options) => {
          const base = await target.listTools(params, options);
          const merged = [...(base.tools || [])];
          for (const [ns, client] of byNamespace) {
            try {
              const extraRes = await client.listTools(undefined, options);
              for (const tool of extraRes.tools || []) {
                merged.push({
                  ...tool,
                  name: `${ns}__${tool.name}`,
                  description: `[${ns}] ${tool.description || ""}`.trim()
                });
              }
            } catch (e) {
              console.error(`Failed to list tools from extra MCP server "${ns}":`, e?.message || e);
            }
          }
          return { ...base, tools: merged };
        };
      }
      if (prop === "callTool") {
        return async (params, options) => {
          const name = String(params?.name || "");
          const sep = name.indexOf("__");
          if (sep > 0) {
            const ns = name.slice(0, sep);
            const rawTool = name.slice(sep + 2);
            const client = byNamespace.get(ns);
            if (client) {
              return client.callTool({ ...params, name: rawTool }, options);
            }
          }
          return target.callTool(params, options);
        };
      }
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
}

async function main() {
  if (process.platform === "win32" && !process.env.PUPPETEER_EXECUTABLE_PATH) {
    const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    if (fs.existsSync(edge)) process.env.PUPPETEER_EXECUTABLE_PATH = edge;
  }

  const port = Number(process.env.MCP_PORT || 8717);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw Error("Invalid MCP_PORT");
  const localToken = String(process.env.MCP_LOCAL_TOKEN || "");

  const require = createRequire(import.meta.url);
  const pkgFile = require.resolve("@wonderwhy-er/desktop-commander/package.json");
  const exe = path.join(path.dirname(pkgFile), "dist", "index.js");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [exe, "--no-onboarding"],
    stderr: "inherit"
  });
  const primary = new Client({ name: "private-mcp-gateway", version: "0.4.0" }, { capabilities: {} });
  await primary.connect(transport);

  const extras = [];
  if (process.env.PCC_MCP_CONFIG) {
    const configs = loadExtraServersConfig(process.env.PCC_MCP_CONFIG);
    for (const cfg of configs) {
      try {
        const extraTransport = new StdioClientTransport({
          command: cfg.command,
          args: cfg.args,
          env: cfg.env ? { ...process.env, ...cfg.env } : undefined,
          cwd: cfg.cwd,
          stderr: "inherit"
        });
        const extraClient = new Client({ name: `private-mcp-gateway-${cfg.namespace}`, version: "0.4.0" }, { capabilities: {} });
        await extraClient.connect(extraTransport);
        extras.push({ namespace: cfg.namespace, client: extraClient });
        console.log("Attached extra MCP server:", cfg.namespace);
      } catch (e) {
        console.error(`Skipping extra MCP server "${cfg.namespace}":`, e?.message || e);
      }
    }
  }

  const upstream = createAggregatedClient(primary, extras);
  const serverCapabilities = primary.getServerCapabilities();
  const serverInfo = primary.getServerVersion();
  const tools = await upstream.listTools();

  console.log(
    "MCP upstream ready:",
    serverInfo?.name,
    "tools:",
    tools.tools?.length,
    "extraServers:",
    extras.length,
    "localAuth:",
    localToken ? "bearer+host" : "host-only"
  );

  const localGuard = createLocalAuthGuard({ port, localToken });
  const { close } = await startHTTPServer({
    host: "127.0.0.1",
    port,
    streamEndpoint: "/mcp",
    sseEndpoint: null,
    cors: false,
    maxBodySize: 1048576,
    eventStoreMaxEvents: 100,
    authenticate: localGuard,
    onUnhandledRequest: async (req, res) => {
      if (req.method === "GET" && req.url === "/healthz") {
        try {
          const verdict = await localGuard(req);
          if (!verdict?.authenticated) {
            res.writeHead(401, { "content-type": "application/json" }).end('{"error":"Unauthorized"}');
            return;
          }
          res
            .writeHead(200, { "content-type": "application/json", "cache-control": "no-store" })
            .end(JSON.stringify({ ok: true, tools: tools.tools?.length || 0, extraServers: extras.length }));
          return;
        } catch (err) {
          const status = err instanceof Response ? err.status : 403;
          res.writeHead(status, { "content-type": "application/json" }).end('{"error":"Forbidden"}');
          return;
        }
      }
      res.writeHead(404).end();
    },
    createServer: async () => {
      const downstream = new Server(serverInfo, { capabilities: serverCapabilities });
      await proxyServer({ client: upstream, server: downstream, serverCapabilities });
      return downstream;
    }
  });

  console.log(`Local MCP gateway listening at http://127.0.0.1:${port}/mcp`);

  const stop = async () => {
    try {
      await close();
    } catch {}
    for (const extra of extras) {
      try {
        await extra.client.close();
      } catch {}
    }
    try {
      await primary.close();
    } catch {}
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main().catch((err) => {
    console.error("Local MCP gateway fatal error:", err?.message || err);
    process.exit(1);
  });
}
