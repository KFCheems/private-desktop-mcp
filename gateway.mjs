import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Server } from "@modelcontextprotocol/server";
import { proxyServer, startHTTPServer } from "mcp-proxy";

const root = path.dirname(fileURLToPath(import.meta.url));
if (process.platform === "win32" && !process.env.PUPPETEER_EXECUTABLE_PATH) {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (fs.existsSync(edge)) process.env.PUPPETEER_EXECUTABLE_PATH = edge;
}
const require = createRequire(import.meta.url);
const pkgFile = require.resolve("@wonderwhy-er/desktop-commander/package.json");
const exe = path.join(path.dirname(pkgFile), "dist", "index.js");
const transport = new StdioClientTransport({ command: process.execPath, args: [exe], stderr: "inherit" });
const upstream = new Client({ name: "private-mcp-gateway", version: "0.1.0" }, { capabilities: {} });
await upstream.connect(transport);
const serverCapabilities = upstream.getServerCapabilities();
const serverInfo = upstream.getServerVersion();
const tools = await upstream.listTools();
const port = Number(process.env.MCP_PORT || 8717);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw Error("Invalid MCP_PORT");
console.log("MCP upstream ready:", serverInfo?.name, "tools:", tools.tools?.length);
const { close } = await startHTTPServer({
  host: "127.0.0.1",
  port,
  streamEndpoint: "/mcp",
  sseEndpoint: null,
  cors: false,
  maxBodySize: 1048576,
  eventStoreMaxEvents: 100,
  createServer: async () => {
    const downstream = new Server(serverInfo, { capabilities: serverCapabilities });
    await proxyServer({ client: upstream, server: downstream, serverCapabilities });
    return downstream;
  }
});
console.log(`Local MCP gateway listening at http://127.0.0.1:${port}/mcp`);
const stop = async () => { await close(); await upstream.close(); process.exit(0); };
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
