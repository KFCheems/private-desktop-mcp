import test from "node:test";
import assert from "node:assert/strict";
import {
  isAllowedLocalHost,
  createLocalAuthGuard,
  createAggregatedClient,
  loadExtraServersConfig
} from "../gateway.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

test("isAllowedLocalHost permits loopback host:port only", () => {
  assert.equal(isAllowedLocalHost("127.0.0.1:8717", 8717), true);
  assert.equal(isAllowedLocalHost("localhost:8717", 8717), true);
  assert.equal(isAllowedLocalHost("[::1]:8717", 8717), true);
  assert.equal(isAllowedLocalHost("evil.attacker.com:8717", 8717), false);
  assert.equal(isAllowedLocalHost("127.0.0.1:9999", 8717), false);
  assert.equal(isAllowedLocalHost("", 8717), false);
});

test("createLocalAuthGuard blocks DNS rebinding, browser Origin CSRF, and invalid Bearer tokens", async () => {
  const guard = createLocalAuthGuard({ port: 8717, localToken: "s".repeat(64) });

  // Valid request
  const ok = await guard({
    headers: { host: "127.0.0.1:8717", authorization: "Bearer " + "s".repeat(64) }
  });
  assert.deepEqual(ok, { authenticated: true });

  // Invalid Host header -> throws 403 Response
  await assert.rejects(
    () => guard({ headers: { host: "rebind.evil:8717", authorization: "Bearer " + "s".repeat(64) } }),
    (err) => err instanceof Response && err.status === 403
  );

  // Browser Origin header -> throws 403 Response
  await assert.rejects(
    () =>
      guard({
        headers: {
          host: "127.0.0.1:8717",
          origin: "https://malicious.example",
          authorization: "Bearer " + "s".repeat(64)
        }
      }),
    (err) => err instanceof Response && err.status === 403
  );

  // Missing or wrong bearer token -> returns authenticated: false (401)
  const missing = await guard({ headers: { host: "127.0.0.1:8717" } });
  assert.equal(missing.authenticated, false);
  const wrong = await guard({ headers: { host: "127.0.0.1:8717", authorization: "Bearer " + "x".repeat(64) } });
  assert.equal(wrong.authenticated, false);
});

test("createAggregatedClient merges secondary MCP server tools under namespace prefix and routes calls", async () => {
  const calls = [];
  const primary = {
    async listTools() {
      return { tools: [{ name: "read_file", description: "Read local file" }] };
    },
    async callTool(params) {
      calls.push({ target: "primary", params });
      return { content: [{ type: "text", text: "from-primary" }] };
    }
  };
  const secondary = {
    async listTools() {
      return { tools: [{ name: "snapshot", description: "Take screenshot" }] };
    },
    async callTool(params) {
      calls.push({ target: "winremote", params });
      return { content: [{ type: "text", text: "from-winremote" }] };
    }
  };

  const agg = createAggregatedClient(primary, [{ namespace: "winremote", client: secondary }]);
  const listed = await agg.listTools();
  assert.deepEqual(
    listed.tools.map((t) => t.name),
    ["read_file", "winremote__snapshot"]
  );
  assert.equal(listed.tools[1].description, "[winremote] Take screenshot");

  const r1 = await agg.callTool({ name: "read_file", arguments: { path: "a" } });
  assert.equal(r1.content[0].text, "from-primary");
  const r2 = await agg.callTool({ name: "winremote__snapshot", arguments: { quality: 80 } });
  assert.equal(r2.content[0].text, "from-winremote");
  assert.deepEqual(calls[1], { target: "winremote", params: { name: "snapshot", arguments: { quality: 80 } } });
});

test("loadExtraServersConfig parses mcpServers JSON safely", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcc-cfg-"));
  const file = path.join(dir, "servers.json");
  fs.writeFileSync(
    file,
    JSON.stringify({
      mcpServers: {
        "win-remote": { command: "winremote-mcp", args: ["--transport", "stdio"], env: { FOO: "bar" } },
        invalid: { args: [] }
      }
    })
  );
  try {
    const parsed = loadExtraServersConfig(file);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0].namespace, "win-remote");
    assert.equal(parsed[0].command, "winremote-mcp");
    assert.deepEqual(parsed[0].args, ["--transport", "stdio"]);
    assert.deepEqual(parsed[0].env, { FOO: "bar" });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
