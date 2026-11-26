import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const SUPPORTED_CLIENTS = [
  "claude-code",
  "claude-desktop",
  "cursor",
  "vscode",
  "codex",
  "gemini",
  "windsurf"
];

export function resolveClientConfigPath(
  client,
  { platform = process.platform, homedir = os.homedir(), env = process.env, cwd = process.cwd() } = {}
) {
  const c = String(client || "").toLowerCase().trim();
  const appData = env.APPDATA || path.join(homedir, "AppData", "Roaming");

  switch (c) {
    case "claude-code":
      return path.join(cwd, ".mcp.json");
    case "claude-desktop":
      if (platform === "win32") return path.join(appData, "Claude", "claude_desktop_config.json");
      if (platform === "darwin") {
        return path.join(homedir, "Library", "Application Support", "Claude", "claude_desktop_config.json");
      }
      return path.join(env.XDG_CONFIG_HOME || path.join(homedir, ".config"), "Claude", "claude_desktop_config.json");
    case "cursor":
      return path.join(homedir, ".cursor", "mcp.json");
    case "vscode":
      return path.join(cwd, ".vscode", "mcp.json");
    case "codex":
      return path.join(homedir, ".codex", "config.toml");
    case "gemini":
      return path.join(homedir, ".gemini", "settings.json");
    case "windsurf":
      return path.join(homedir, ".codeium", "windsurf", "mcp_config.json");
    default:
      throw new Error(`Unsupported client "${client}". Supported clients: ${SUPPORTED_CLIENTS.join(", ")}`);
  }
}

export function normalizeMcpEndpointUrl(relayUrl) {
  const trimmed = String(relayUrl || "").trim().replace(/\/+$/, "");
  if (!trimmed) throw new Error("Empty relay URL");
  return trimmed.endsWith("/mcp") ? trimmed : `${trimmed}/mcp`;
}

function mergeJsonClientConfig(client, existingText, mcpUrl, serverName = "private-desktop") {
  let root = {};
  if (String(existingText || "").trim()) {
    const parsed = JSON.parse(existingText);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      root = { ...parsed };
    }
  }

  if (client === "vscode") {
    const servers = root.servers && typeof root.servers === "object" ? { ...root.servers } : {};
    servers[serverName] = { type: "http", url: mcpUrl };
    root.servers = servers;
  } else if (client === "gemini") {
    const mcpServers = root.mcpServers && typeof root.mcpServers === "object" ? { ...root.mcpServers } : {};
    mcpServers[serverName] = { httpUrl: mcpUrl, oauth: { enabled: true } };
    root.mcpServers = mcpServers;
  } else if (client === "cursor" || client === "windsurf") {
    const mcpServers = root.mcpServers && typeof root.mcpServers === "object" ? { ...root.mcpServers } : {};
    mcpServers[serverName] = { url: mcpUrl };
    root.mcpServers = mcpServers;
  } else {
    // claude-code, claude-desktop, standard mcpServers
    const mcpServers = root.mcpServers && typeof root.mcpServers === "object" ? { ...root.mcpServers } : {};
    mcpServers[serverName] = { type: "http", url: mcpUrl };
    root.mcpServers = mcpServers;
  }

  return JSON.stringify(root, null, 2) + "\n";
}

function mergeCodexTomlConfig(existingText, mcpUrl, serverName = "private_desktop") {
  const sectionHeader = `[mcp_servers.${serverName}]`;
  const block = `${sectionHeader}\nurl = "${mcpUrl}"\n`;
  const raw = String(existingText || "");
  if (!raw.trim()) return block;

  const escapedHeader = sectionHeader.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const sectionRegex = new RegExp(`(^|\\r?\\n)${escapedHeader}\\r?\\n[\\s\\S]*?(?=(\\r?\\n\\[[^\\]]+\\])|$)`);
  if (sectionRegex.test(raw)) {
    return raw.replace(sectionRegex, `$1${block.trimEnd()}`).replace(/\s*$/, "\n");
  }
  return raw.replace(/\s*$/, "\n\n") + block;
}

export function configureMcpClient({
  client,
  relayUrl,
  serverName,
  configPath,
  dryRun = false,
  platform = process.platform,
  homedir = os.homedir(),
  env = process.env,
  cwd = process.cwd()
} = {}) {
  const normalizedClient = String(client || "").toLowerCase().trim();
  if (!SUPPORTED_CLIENTS.includes(normalizedClient)) {
    throw new Error(`Unsupported client "${client}". Supported clients: ${SUPPORTED_CLIENTS.join(", ")}`);
  }

  const mcpUrl = normalizeMcpEndpointUrl(relayUrl);
  const targetPath = configPath
    ? path.resolve(configPath)
    : resolveClientConfigPath(normalizedClient, { platform, homedir, env, cwd });

  let existingText = "";
  let existed = false;
  try {
    existingText = fs.readFileSync(targetPath, "utf8");
    existed = true;
  } catch {
    existingText = "";
    existed = false;
  }

  const nextContent =
    normalizedClient === "codex"
      ? mergeCodexTomlConfig(existingText, mcpUrl, serverName ? serverName.replace(/-/g, "_") : "private_desktop")
      : mergeJsonClientConfig(normalizedClient, existingText, mcpUrl, serverName || "private-desktop");

  const changed = nextContent !== existingText;
  const action = !existed ? "create" : changed ? "update" : "unchanged";

  if (!dryRun && changed) {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, nextContent, "utf8");
  }

  return {
    ok: true,
    client: normalizedClient,
    path: targetPath,
    mcpUrl,
    action,
    changed,
    dryRun: Boolean(dryRun),
    preview: nextContent
  };
}
