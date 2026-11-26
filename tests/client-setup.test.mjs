import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { SUPPORTED_CLIENTS, configureMcpClient, resolveClientConfigPath } from "../bin/client-setup.mjs";

const relay = "https://private-desktop-device-relay.ljx2043979076.workers.dev";

test("resolveClientConfigPath maps all supported clients across platforms", () => {
  for (const client of SUPPORTED_CLIENTS) {
    const pWin = resolveClientConfigPath(client, { platform: "win32", homedir: "C:\\Users\\Alice", env: { APPDATA: "C:\\Users\\Alice\\AppData\\Roaming" }, cwd: "C:\\work" });
    const pMac = resolveClientConfigPath(client, { platform: "darwin", homedir: "/Users/alice", env: {}, cwd: "/Users/alice/work" });
    assert.ok(pWin.length > 0);
    assert.ok(pMac.length > 0);
  }
});

test("configureMcpClient supports dry-run and non-destructively merges JSON and TOML configs", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pcc-client-setup-"));
  try {
    // 1. Dry-run does not create file on disk
    const cursorFile = path.join(tmpDir, "cursor-mcp.json");
    const dryRes = configureMcpClient({
      client: "cursor",
      relayUrl: relay,
      configPath: cursorFile,
      dryRun: true
    });
    assert.equal(dryRes.ok, true);
    assert.equal(dryRes.action, "create");
    assert.equal(dryRes.changed, true);
    assert.equal(fs.existsSync(cursorFile), false);

    // 2. Existing JSON config preserves other MCP servers when merging
    fs.writeFileSync(
      cursorFile,
      JSON.stringify({ mcpServers: { github: { url: "https://api.githubcopilot.com/mcp/" } } }, null, 2)
    );
    const updateRes = configureMcpClient({
      client: "cursor",
      relayUrl: relay,
      configPath: cursorFile,
      dryRun: false
    });
    assert.equal(updateRes.action, "update");
    const mergedCursor = JSON.parse(fs.readFileSync(cursorFile, "utf8"));
    assert.equal(mergedCursor.mcpServers.github.url, "https://api.githubcopilot.com/mcp/");
    assert.equal(mergedCursor.mcpServers["private-desktop"].url, `${relay}/mcp`);

    // 3. Re-running on identical config reports unchanged
    const unchangedRes = configureMcpClient({
      client: "cursor",
      relayUrl: relay,
      configPath: cursorFile,
      dryRun: false
    });
    assert.equal(unchangedRes.action, "unchanged");
    assert.equal(unchangedRes.changed, false);

    // 4. VS Code uses root.servers with type: http
    const vscodeFile = path.join(tmpDir, "vscode-mcp.json");
    configureMcpClient({ client: "vscode", relayUrl: relay, configPath: vscodeFile });
    const vscodeJson = JSON.parse(fs.readFileSync(vscodeFile, "utf8"));
    assert.deepEqual(vscodeJson.servers["private-desktop"], { type: "http", url: `${relay}/mcp` });

    // 5. Gemini uses httpUrl + oauth.enabled
    const geminiFile = path.join(tmpDir, "gemini.json");
    configureMcpClient({ client: "gemini", relayUrl: relay, configPath: geminiFile });
    const geminiJson = JSON.parse(fs.readFileSync(geminiFile, "utf8"));
    assert.deepEqual(geminiJson.mcpServers["private-desktop"], { httpUrl: `${relay}/mcp`, oauth: { enabled: true } });

    // 6. Codex TOML non-destructively merges section
    const codexFile = path.join(tmpDir, "config.toml");
    fs.writeFileSync(codexFile, 'model = "gpt-5"\n\n[mcp_servers.other]\nurl = "https://other.example/mcp"\n');
    configureMcpClient({ client: "codex", relayUrl: relay, configPath: codexFile });
    const toml = fs.readFileSync(codexFile, "utf8");
    assert.match(toml, /model = "gpt-5"/);
    assert.match(toml, /\[mcp_servers\.other\]/);
    assert.match(toml, /\[mcp_servers\.private_desktop\]\nurl = "https:\/\/private-desktop-device-relay\.ljx2043979076\.workers\.dev\/mcp"/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI setup-client --dry-run --json and status --json emit machine-readable JSON", () => {
  const setupRes = spawnSync(
    process.execPath,
    ["bin/cli.mjs", "setup-client", "claude-code", "--dry-run", "--json"],
    { encoding: "utf8" }
  );
  assert.equal(setupRes.status, 0, setupRes.stderr);
  const setupPayload = JSON.parse(setupRes.stdout);
  assert.equal(setupPayload.ok, true);
  assert.equal(setupPayload.client, "claude-code");
  assert.equal(setupPayload.dryRun, true);
  assert.match(setupPayload.mcpUrl, /\/mcp$/);

  const statusRes = spawnSync(process.execPath, ["bin/cli.mjs", "status", "--json"], { encoding: "utf8" });
  assert.equal(statusRes.status, 0, statusRes.stderr);
  const statusPayload = JSON.parse(statusRes.stdout);
  assert.equal(statusPayload.ok, true);
  assert.equal(typeof statusPayload.paired, "boolean");
});
