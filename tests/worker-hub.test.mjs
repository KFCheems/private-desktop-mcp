import test from "node:test";
import assert from "node:assert/strict";
import worker, { DeviceHub, RELAY_META_TOOLS } from "../worker/index.mjs";

class MockStorage {
  constructor() {
    this.map = new Map();
    this.auditRows = [];
    this.sql = {
      exec: (query, ...params) => {
        if (/^CREATE TABLE/i.test(query)) return [];
        if (/^INSERT INTO audit_logs/i.test(query)) {
          this.auditRows.push({
            id: this.auditRows.length + 1,
            ts: params[0],
            actor: params[1],
            device_id: params[2],
            device_name: params[3],
            mcp_method: params[4],
            mcp_name: params[5],
            status: params[6],
            duration_ms: params[7],
            ok: params[8],
            error: params[9]
          });
          return [];
        }
        if (/^DELETE FROM audit_logs/i.test(query)) {
          if (this.auditRows.length > 500) {
            this.auditRows = this.auditRows.slice(-500);
          }
          return [];
        }
        if (/^SELECT .* FROM audit_logs/i.test(query)) {
          const limit = params[0] || 20;
          return [...this.auditRows].reverse().slice(0, limit);
        }
        return [];
      }
    };
  }
  async get(k) {
    return this.map.get(k);
  }
  async put(k, v) {
    this.map.set(k, v);
  }
  async delete(k) {
    this.map.delete(k);
  }
  async list({ prefix = "" } = {}) {
    const out = new Map();
    for (const [k, v] of this.map) {
      if (k.startsWith(prefix)) out.set(k, v);
    }
    return out;
  }
}

class MockSocket {
  constructor() {
    this.readyState = 1; // OPEN
    this.attachment = null;
    this.sent = [];
    this.closed = null;
    this.onSend = null;
  }
  serializeAttachment(a) {
    this.attachment = a;
  }
  deserializeAttachment() {
    return this.attachment;
  }
  send(msg) {
    this.sent.push(msg);
    if (this.onSend) this.onSend(msg);
  }
  close(code, reason) {
    this.readyState = 3;
    this.closed = { code, reason };
  }
}

function createHubEnv() {
  const storage = new MockStorage();
  const sockets = new Set();
  const autoResponses = [];
  const ctx = {
    storage,
    setWebSocketAutoResponse(pair) {
      autoResponses.push(pair);
    },
    acceptWebSocket(ws) {
      sockets.add(ws);
    },
    getWebSockets() {
      return [...sockets].filter((w) => w.readyState === 1);
    }
  };
  const origPair = globalThis.WebSocketPair;
  const origAuto = globalThis.WebSocketRequestResponsePair;
  const origResponse = globalThis.Response;

  globalThis.WebSocketRequestResponsePair = class {
    constructor(req, res) {
      this.request = req;
      this.response = res;
    }
  };
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = new MockSocket();
      this[1] = new MockSocket();
    }
  };
  // Node.js Response disallows status 101; shim only for WebSocket upgrade responses in test
  globalThis.Response = class extends origResponse {
    constructor(body, init) {
      if (init?.status === 101 && init?.webSocket) {
        return { status: 101, webSocket: init.webSocket, headers: new Headers() };
      }
      super(body, init);
    }
  };

  const hub = new DeviceHub(ctx, {});
  const restore = () => {
    globalThis.WebSocketPair = origPair;
    globalThis.WebSocketRequestResponsePair = origAuto;
    globalThis.Response = origResponse;
  };
  return { hub, ctx, storage, sockets, autoResponses, restore };
}

async function pairAndConnect(hub, name, onMessage) {
  const base = "https://private-desktop-device-relay.ljx2043979076.workers.dev";
  const startRes = await hub.fetch(
    new Request(`${base}/relay/pair/start`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "1.2.3.4" },
      body: JSON.stringify({ name })
    })
  );
  assert.equal(startRes.status, 200);
  const started = await startRes.json();

  const approveRes = await hub.fetch(
    new Request(`${base}/admin/approve`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `id=${encodeURIComponent(started.pairId)}`
    })
  );
  assert.equal(approveRes.status, 303);

  const pollRes = await hub.fetch(
    new Request(`${base}/relay/pair/poll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pairId: started.pairId, proof: started.proof })
    })
  );
  const creds = await pollRes.json();
  assert.equal(creds.status, "approved");

  const wsRes = await hub.fetch(
    new Request(`${base}/relay/ws`, {
      method: "GET",
      headers: {
        upgrade: "websocket",
        authorization: `Bearer ${creds.token}`,
        "x-device-id": creds.deviceId,
        "x-device-platform": "win32",
        "x-device-arch": "x64",
        "x-device-version": "0.4.0",
        "x-device-mode": "FULL"
      }
    })
  );
  assert.equal(wsRes.status, 101);
  // Find server socket registered in hub
  const open = hub.open();
  const serverWs = open.get(creds.deviceId).ws;
  serverWs.onSend = (raw) => {
    if (onMessage) onMessage(raw, serverWs, creds);
  };
  return { creds, serverWs };
}

test("DeviceHub registers zero-cost WebSocket hibernation ping/pong auto-response", () => {
  const { autoResponses, restore } = createHubEnv();
  try {
    assert.equal(autoResponses.length, 1);
    assert.equal(autoResponses[0].request, "ping");
    assert.equal(autoResponses[0].response, "pong");
  } finally {
    restore();
  }
});

test("DeviceHub supports pairing, meta-tools, per-call _device targeting, edge readonly lock, audit log, and revoke-all", async () => {
  const { hub, restore } = createHubEnv();
  const base = "https://private-desktop-device-relay.ljx2043979076.workers.dev";
  try {
    // 1. Even with 0 devices online, tools/list returns built-in relay meta-tools
    const emptyList = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })
      })
    );
    assert.equal(emptyList.status, 200);
    const emptyJson = await emptyList.json();
    assert.equal(emptyJson.result.tools.length, RELAY_META_TOOLS.length);

    // 2. Pair and connect two devices
    const receivedByA = [];
    const receivedByB = [];
    const devA = await pairAndConnect(hub, "WorkPC", (raw, ws) => {
      const msg = JSON.parse(raw);
      receivedByA.push(msg);
      if (msg.kind === "ping") {
        hub.webSocketMessage(ws, JSON.stringify({ kind: "pong", id: msg.id, uptimeMs: 1200, gatewayReady: true, mode: "FULL", version: "0.4.0" }));
      } else if (msg.kind === "request") {
        const rpc = JSON.parse(msg.body || "{}");
        const reply =
          rpc.method === "tools/list"
            ? { jsonrpc: "2.0", id: rpc.id, result: { tools: [{ name: "read_file" }, { name: "write_file" }] } }
            : { jsonrpc: "2.0", id: rpc.id, result: { content: [{ type: "text", text: "from-WorkPC:" + JSON.stringify(rpc.params?.arguments || {}) }] } };
        hub.webSocketMessage(ws, JSON.stringify({ kind: "response", id: msg.id, status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(reply) }));
      }
    });
    const devB = await pairAndConnect(hub, "HomePC", (raw, ws) => {
      const msg = JSON.parse(raw);
      receivedByB.push(msg);
      if (msg.kind === "request") {
        const rpc = JSON.parse(msg.body || "{}");
        const reply = { jsonrpc: "2.0", id: rpc.id, result: { content: [{ type: "text", text: "from-HomePC:" + JSON.stringify(rpc.params?.arguments || {}) }] } };
        hub.webSocketMessage(ws, JSON.stringify({ kind: "response", id: msg.id, status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(reply) }));
      }
    });

    // 3. Call relay_list_devices in chat
    const listDevsRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "relay_list_devices", arguments: {} } })
      })
    );
    const listDevs = await listDevsRes.json();
    assert.equal(listDevs.result.structuredContent.onlineCount, 2);
    assert.equal(listDevs.result.structuredContent.devices.length, 2);

    // 4. Select WorkPC in chat via relay_select_device
    const selRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "relay_select_device", arguments: { device_name: "workpc" } } })
      })
    );
    const selJson = await selRes.json();
    assert.equal(selJson.result.structuredContent.selected, devA.creds.deviceId);

    // 5. tools/list against WorkPC appends RELAY_META_TOOLS to upstream tools
    const mergedToolsRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list" })
      })
    );
    const mergedTools = (await mergedToolsRes.json()).result.tools.map((t) => t.name);
    assert.ok(mergedTools.includes("read_file"));
    assert.ok(mergedTools.includes("relay_list_devices"));
    assert.ok(mergedTools.includes("relay_ping_device"));

    // 6. Per-call _device targeting routes to HomePC and strips _device before forwarding
    const targetedRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 5,
          method: "tools/call",
          params: { name: "read_file", arguments: { path: "README.md", _device: "HomePC" } }
        })
      })
    );
    const targetedJson = await targetedRes.json();
    assert.match(targetedJson.result.content[0].text, /^from-HomePC:/);
    assert.doesNotMatch(targetedJson.result.content[0].text, /_device/);

    // 7. Live ping via relay_ping_device
    const pingRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "relay_ping_device", arguments: { device_name: "WorkPC" } } })
      })
    );
    const pingJson = await pingRes.json();
    assert.equal(pingJson.result.structuredContent.ok, true);
    assert.equal(pingJson.result.structuredContent.gatewayReady, true);

    // 8. Lock WorkPC to read-only via /admin/readonly -> blocks write_file at edge without crossing WS
    await hub.fetch(
      new Request(`${base}/admin/readonly`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `id=${encodeURIComponent(devA.creds.deviceId)}`
      })
    );
    const beforeCount = receivedByA.length;
    const blockedWriteRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "write_file", arguments: { path: "a.txt", content: "x" } } })
      })
    );
    const blockedWrite = await blockedWriteRes.json();
    assert.equal(blockedWrite.result.isError, true);
    assert.match(blockedWrite.result.content[0].text, /read-only/i);
    assert.equal(receivedByA.length, beforeCount); // never sent over WebSocket

    // 9. Audit log via relay_recent_activity
    const auditRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "alice@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "relay_recent_activity", arguments: { limit: 10 } } })
      })
    );
    const auditJson = await auditRes.json();
    assert.ok(auditJson.result.structuredContent.count >= 5);
    assert.equal(auditJson.result.structuredContent.entries[0].actor, "alice@example.com");

    // 10. Diagnostic endpoint rejects tools/call (removed hardcoded path backdoor)
    const badDiag = await hub.fetch(
      new Request(`${base}/relay/diagnostic`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${devA.creds.token}`,
          "x-device-id": devA.creds.deviceId
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "read_file", arguments: { path: "C:\\workspace\\private-desktop-device-relay\\package.json" } } })
      })
    );
    assert.equal(badDiag.status, 403);

    // 11. Emergency revoke-all disconnects all devices
    const revokeAllRes = await hub.fetch(new Request(`${base}/admin/revoke-all`, { method: "POST" }));
    assert.equal(revokeAllRes.status, 303);
    assert.equal((await hub.list()).length, 0);
    assert.equal(devA.serverWs.closed?.code, 1008);
    assert.equal(devB.serverWs.closed?.code, 1008);
  } finally {
    restore();
  }
});

test("DeviceHub forwards DELETE /mcp and sends cancel frame on client AbortSignal", async () => {
  const { hub, restore } = createHubEnv();
  const base = "https://private-desktop-device-relay.ljx2043979076.workers.dev";
  try {
    const frames = [];
    await pairAndConnect(hub, "CancelPC", (raw, ws) => {
      const msg = JSON.parse(raw);
      frames.push(msg);
      if (msg.kind === "request" && msg.method === "DELETE") {
        hub.webSocketMessage(ws, JSON.stringify({ kind: "response", id: msg.id, status: 204, headers: {}, body: "" }));
      }
      // Deliberately do not respond to POST so abort triggers cancel frame
    });

    const delRes = await hub.fetch(
      new Request(`${base}/mcp`, { method: "DELETE", headers: { "mcp-session-id": "sess-1" } })
    );
    assert.equal(delRes.status, 204);
    assert.equal(frames[0].method, "DELETE");

    const ac = new AbortController();
    const pending = hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 10, method: "tools/call", params: { name: "start_process", arguments: { command: "sleep 60" } } }),
        signal: ac.signal
      })
    );
    await new Promise((r) => setTimeout(r, 15));
    ac.abort();
    const abortedRes = await pending;
    assert.equal(abortedRes.status, 499);
    assert.ok(frames.some((f) => f.kind === "cancel"));
  } finally {
    restore();
  }
});

test("Worker router enforces Access auth and Origin CSRF checks on /admin POST", async () => {
  const base = "https://private-desktop-device-relay.ljx2043979076.workers.dev";
  let hubCalled = false;
  const mockEnv = {
    ALLOW_UNVERIFIED_ACCESS_HEADER: "true",
    HUB: {
      getByName: () => ({
        fetch: async () => {
          hubCalled = true;
          return new Response("ok");
        }
      })
    }
  };

  // Missing header rejected
  const unauth = await worker.fetch(new Request(`${base}/mcp`, { method: "POST", body: "{}" }), mockEnv);
  assert.equal(unauth.status, 403);
  assert.equal(hubCalled, false);

  // Cross-origin POST /admin/revoke rejected even with Access header
  const fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6Im93bmVyQGV4YW1wbGUuY29tIn0.sig";
  const csrf = await worker.fetch(
    new Request(`${base}/admin/revoke`, {
      method: "POST",
      headers: {
        "cf-access-jwt-assertion": fakeJwt,
        origin: "https://evil.example"
      },
      body: "id=123"
    }),
    mockEnv
  );
  assert.equal(csrf.status, 403);
  assert.equal(hubCalled, false);
});

test("DeviceHub provides agent-native edge initialize, resources, prompts, _device schema injection, relay_set_device_policy, and self-healing tool errors", async () => {
  const { hub, restore } = createHubEnv();
  const base = "https://private-desktop-device-relay.ljx2043979076.workers.dev";
  try {
    // 1. Edge initialize succeeds even when 0 devices are online
    const initEmptyRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "agent@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 100, method: "initialize", params: { protocolVersion: "2025-03-26" } })
      })
    );
    assert.equal(initEmptyRes.status, 200);
    const initEmpty = await initEmptyRes.json();
    assert.equal(initEmpty.result.protocolVersion, "2025-03-26");
    assert.match(initEmpty.result.instructions, /Private Desktop MCP Relay/);

    // 2. Self-healing structured tool error when 0 devices are online
    const offlineCallRes = await hub.fetch(
      new Request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-pcc-actor": "agent@example.com" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 101, method: "tools/call", params: { name: "read_file", arguments: { path: "a.txt" } } })
      })
    );
    assert.equal(offlineCallRes.status, 200);
    const offlineCall = await offlineCallRes.json();
    assert.equal(offlineCall.result.isError, true);
    assert.equal(offlineCall.result.structuredContent.errorCode, "NO_DEVICE_ONLINE");
    assert.ok(Array.isArray(offlineCall.result.structuredContent.nextActions));

    // 3. Edge resources/list, resources/read (relay://devices, relay://status, relay://audit), prompts/list, prompts/get
    const resList = await (
      await hub.fetch(
        new Request(`${base}/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 102, method: "resources/list" })
        })
      )
    ).json();
    assert.ok(resList.result.resources.some((r) => r.uri === "relay://devices"));

    const resRead = await (
      await hub.fetch(
        new Request(`${base}/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-pcc-actor": "agent@example.com", "x-pcc-verified": "1" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 103, method: "resources/read", params: { uri: "relay://status" } })
        })
      )
    ).json();
    const statusResource = JSON.parse(resRead.result.contents[0].text);
    assert.equal(statusResource.accessJwtVerified, true);

    const promptGet = await (
      await hub.fetch(
        new Request(`${base}/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 104, method: "prompts/get", params: { name: "multi-device-triage", arguments: { task: "Check disk space" } } })
        })
      )
    ).json();
    assert.match(promptGet.result.messages[0].content.text, /Check disk space/);

    // 4. Pair a device, verify _device schema injection on tools/list, and test relay_set_device_policy
    const dev = await pairAndConnect(hub, "LabPC", (raw, ws) => {
      const msg = JSON.parse(raw);
      if (msg.kind === "request") {
        const rpc = JSON.parse(msg.body || "{}");
        const reply =
          rpc.method === "tools/list"
            ? {
                jsonrpc: "2.0",
                id: rpc.id,
                result: {
                  tools: [
                    {
                      name: "read_file",
                      description: "Read file",
                      inputSchema: { type: "object", properties: { path: { type: "string" } } }
                    }
                  ]
                }
              }
            : { jsonrpc: "2.0", id: rpc.id, result: { content: [{ type: "text", text: "ok" }] } };
        hub.webSocketMessage(ws, JSON.stringify({ kind: "response", id: msg.id, status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(reply) }));
      }
    });

    const toolsJson = await (
      await hub.fetch(
        new Request(`${base}/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 105, method: "tools/list" })
        })
      )
    ).json();
    const readFileTool = toolsJson.result.tools.find((t) => t.name === "read_file");
    assert.equal(readFileTool.inputSchema.properties._device.type, "string");

    // Lock and rename LabPC via relay_set_device_policy meta-tool
    const policyRes = await (
      await hub.fetch(
        new Request(`${base}/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 106,
            method: "tools/call",
            params: { name: "relay_set_device_policy", arguments: { device_id: dev.creds.deviceId, read_only: true, new_name: "LabPC-RO" } }
          })
        })
      )
    ).json();
    assert.equal(policyRes.result.structuredContent.readOnly, true);
    assert.equal(policyRes.result.structuredContent.name, "LabPC-RO");
  } finally {
    restore();
  }
});
