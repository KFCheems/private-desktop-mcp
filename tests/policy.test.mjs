import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  createPolicy,
  evaluateToolCall,
  filterToolsListBody,
  redactOutboundResponse
} from "../bin/policy.mjs";

const call = (name, args = {}) => ({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name, arguments: args }
});

test("readonly mode allows read-only tools and blocks writes and shell execution", () => {
  const policy = createPolicy({ readonly: true });
  assert.equal(evaluateToolCall(call("read_file", { path: "/tmp/a.txt" }), policy).allowed, true);
  assert.equal(evaluateToolCall(call("list_directory", { path: "/tmp" }), policy).allowed, true);
  assert.equal(evaluateToolCall(call("write_file", { path: "/tmp/a.txt", content: "hi" }), policy).allowed, false);
  assert.equal(evaluateToolCall(call("start_process", { command: "whoami" }), policy).allowed, false);
});

test("allow-tools and deny-tools enforce explicit tool lists", () => {
  const allowOnly = createPolicy({ allowTools: ["read_file", "list_directory"] });
  assert.equal(evaluateToolCall(call("read_file"), allowOnly).allowed, true);
  assert.equal(evaluateToolCall(call("start_search"), allowOnly).allowed, false);

  const deny = createPolicy({ denyTools: ["start_process", "kill_process"] });
  assert.equal(evaluateToolCall(call("read_file"), deny).allowed, true);
  assert.equal(evaluateToolCall(call("start_process", { command: "dir" }), deny).allowed, false);
});

test("allow-dir restricts paths, prevents traversal, prefix tricks, and symlink escape", () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "pcc-policy-"));
  const allowedDir = path.join(tmpBase, "allowed");
  const siblingDir = path.join(tmpBase, "allowed-evil");
  fs.mkdirSync(allowedDir);
  fs.mkdirSync(siblingDir);
  const insideFile = path.join(allowedDir, "ok.txt");
  const outsideFile = path.join(siblingDir, "secret.txt");
  fs.writeFileSync(insideFile, "ok");
  fs.writeFileSync(outsideFile, "secret");
  const escapeLink = path.join(allowedDir, "escape.txt");
  fs.symlinkSync(outsideFile, escapeLink);

  try {
    const policy = createPolicy({ allowDirs: [allowedDir] });
    assert.equal(evaluateToolCall(call("read_file", { path: insideFile }), policy).allowed, true);
    assert.equal(evaluateToolCall(call("read_file", { path: path.join(allowedDir, "..", "allowed-evil", "secret.txt") }), policy).allowed, false);
    assert.equal(evaluateToolCall(call("read_file", { path: outsideFile }), policy).allowed, false);
    assert.equal(evaluateToolCall(call("read_file", { path: escapeLink }), policy).allowed, false);
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test("protected connector credential directory is always blocked even in full mode", () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "pcc-cred-"));
  const credDir = path.join(tmpBase, "PrivateDesktopMCP");
  fs.mkdirSync(credDir);
  const credFile = path.join(credDir, "device.json");
  fs.writeFileSync(credFile, '{"token":"abc"}');

  try {
    const policy = createPolicy({ protectedDirs: [credDir] });
    assert.equal(evaluateToolCall(call("read_file", { path: credFile }), policy).allowed, false);
    assert.equal(
      evaluateToolCall(call("start_process", { command: "cat ~/.config/PrivateDesktopMCP/device.json" }), policy).allowed,
      false
    );
    assert.equal(evaluateToolCall(call("read_file", { path: path.join(tmpBase, "other.txt") }), policy).allowed, true);
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test("filterToolsListBody removes disallowed tools in JSON and SSE and respects readOnlyHint annotations", () => {
  const policy = createPolicy({ readonly: true });
  const tools = [
    { name: "read_file" },
    { name: "write_file" },
    { name: "winremote__snapshot", annotations: { readOnlyHint: true, destructiveHint: false } },
    { name: "winremote__shell", annotations: { readOnlyHint: false, destructiveHint: true } }
  ];

  const jsonBody = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools } });
  const filteredJson = JSON.parse(filterToolsListBody(jsonBody, "application/json", policy));
  assert.deepEqual(
    filteredJson.result.tools.map((t) => t.name),
    ["read_file", "winremote__snapshot"]
  );
  // Learned readOnlyHint tools must remain callable in --readonly mode
  assert.equal(evaluateToolCall(call("winremote__snapshot"), policy).allowed, true);
  assert.equal(evaluateToolCall(call("winremote__shell"), policy).allowed, false);

  const sseBody = `event: message\ndata: ${jsonBody}\n\n`;
  const filteredSse = filterToolsListBody(sseBody, "text/event-stream", policy);
  assert.match(filteredSse, /winremote__snapshot/);
  assert.doesNotMatch(filteredSse, /write_file|winremote__shell/);
});

test("redactOutboundResponse strips high-confidence secrets and runtime tokens while preserving normal code", () => {
  const deviceToken = "a".repeat(64);
  const fakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
  const fakeGhToken = "ghp_" + "1234567890abcdef1234567890abcdef1234";
  const fakePem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtoken\n-----END RSA PRIVATE KEY-----";
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 2,
    result: {
      content: [
        {
          type: "text",
          text: `const x = 42;\naws=${fakeAwsKey}\ngh=${fakeGhToken}\n${fakePem}\ntok=${deviceToken}`
        }
      ]
    }
  });

  const { body: redacted, redactedCount } = redactOutboundResponse(body, "application/json", {
    enabled: true,
    extraSecrets: [deviceToken]
  });
  assert.equal(redactedCount, 4);
  const parsed = JSON.parse(redacted);
  const text = parsed.result.content[0].text;
  assert.match(text, /const x = 42;/);
  assert.doesNotMatch(text, new RegExp(fakeAwsKey));
  assert.doesNotMatch(text, new RegExp(fakeGhToken));
  assert.doesNotMatch(text, /MIIEpAIBAAKCAQEA/);
  assert.doesNotMatch(text, new RegExp(deviceToken));
  assert.match(text, /\[REDACTED_BY_PCC_DLP\]/);
});

test("redactOutboundResponse redacts secrets inside result.structuredContent", () => {
  const fakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
  const deviceToken = "b".repeat(64);
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 3,
    result: {
      content: [{ type: "text", text: "ok" }],
      structuredContent: {
        nested: { token: fakeAwsKey, items: ["clean", `key=${deviceToken}`] },
        count: 2
      }
    }
  });

  const { body: redacted, redactedCount } = redactOutboundResponse(body, "application/json", {
    enabled: true,
    extraSecrets: [deviceToken]
  });
  assert.equal(redactedCount, 2);
  const parsed = JSON.parse(redacted);
  // structuredContent must no longer carry the secrets
  assert.equal(JSON.stringify(parsed).includes(fakeAwsKey), false);
  assert.equal(JSON.stringify(parsed).includes(deviceToken), false);
  // non-secret structured values are preserved
  assert.equal(parsed.result.structuredContent.count, 2);
  assert.equal(parsed.result.structuredContent.nested.items[0], "clean");
  assert.match(JSON.stringify(parsed), /\[REDACTED_BY_PCC_DLP\]/);
});

test("allow-dir jail recognizes snake_case file_path used by Desktop Commander edit_block", () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "pcc-filepath-"));
  const allowedDir = path.join(tmpBase, "allowed");
  const outsideDir = path.join(tmpBase, "outside");
  fs.mkdirSync(allowedDir);
  fs.mkdirSync(outsideDir);
  const insideFile = path.join(allowedDir, "ok.txt");
  const outsideFile = path.join(outsideDir, "secret.txt");
  fs.writeFileSync(insideFile, "ok");
  fs.writeFileSync(outsideFile, "secret");

  try {
    const policy = createPolicy({ allowDirs: [allowedDir] });
    assert.equal(evaluateToolCall(call("edit_block", { file_path: insideFile }), policy).allowed, true);
    assert.equal(evaluateToolCall(call("edit_block", { file_path: outsideFile }), policy).allowed, false);
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test("readonly mode authorizes callable tools via client-supplied readOnlyHint annotations", () => {
  const policy = createPolicy({ readonly: true });
  const annotatedCall = {
    jsonrpc: "2.0",
    id: 9,
    method: "tools/call",
    params: {
      name: "winremote__snapshot",
      arguments: {},
      _meta: { annotations: { readOnlyHint: true, destructiveHint: false } }
    }
  };
  assert.equal(evaluateToolCall(annotatedCall, policy).allowed, true);
  // A tool with no annotation and not in the static set stays blocked
  assert.equal(evaluateToolCall(call("winremote__shell"), policy).allowed, false);
  // A destructive annotation is not honored as read-only
  const destructive = {
    jsonrpc: "2.0",
    id: 10,
    method: "tools/call",
    params: { name: "winremote__wipe", arguments: {}, _meta: { annotations: { readOnlyHint: true, destructiveHint: true } } }
  };
  assert.equal(evaluateToolCall(destructive, policy).allowed, false);
});

test("readonly mode authorizes a call against annotations learned from tools/list", () => {
  const policy = createPolicy({ readonly: true });
  const listBody = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: "winremote__snapshot", annotations: { readOnlyHint: true, destructiveHint: false } }] }
  });
  filterToolsListBody(listBody, "application/json", policy);
  // Call carries NO _meta annotations; must still be allowed from learned annotations
  assert.equal(evaluateToolCall(call("winremote__snapshot"), policy).allowed, true);
});