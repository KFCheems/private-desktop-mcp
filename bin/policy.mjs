import fs from "node:fs";
import path from "node:path";

export const READONLY_TOOLS = new Set([
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

const PATH_ARG_KEYS = [
  "path",
  "paths",
  "source",
  "destination",
  "cwd",
  "workingDirectory",
  "filePath",
  "directory",
  "dir"
];

const HIGH_CONFIDENCE_SECRET_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  /\bsk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{24,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g
];

const DLP_MARKER = "[REDACTED_BY_PCC_DLP]";

function normalizeForComparison(p, platform = process.platform) {
  const resolved = path.resolve(String(p));
  return platform === "win32" ? resolved.toLowerCase() : resolved;
}

function resolveWithSymlinks(targetPath) {
  const resolved = path.resolve(String(targetPath));
  try {
    return fs.realpathSync(resolved);
  } catch {
    // Walk up until an existing parent is found to catch symlinked parent directories
    let current = resolved;
    const tail = [];
    while (true) {
      const parent = path.dirname(current);
      if (parent === current) return resolved;
      tail.unshift(path.basename(current));
      current = parent;
      try {
        const realParent = fs.realpathSync(current);
        return path.join(realParent, ...tail);
      } catch {
        continue;
      }
    }
  }
}

export function isPathInside(candidatePath, rootDir, platform = process.platform) {
  const realCandidate = normalizeForComparison(resolveWithSymlinks(candidatePath), platform);
  const realRoot = normalizeForComparison(resolveWithSymlinks(rootDir), platform);
  const rel = path.relative(realRoot, realCandidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function extractPathArgs(args) {
  const paths = [];
  if (!args || typeof args !== "object") return paths;
  for (const key of PATH_ARG_KEYS) {
    const val = args[key];
    if (typeof val === "string" && val.trim()) {
      paths.push({ key, value: val.trim() });
    } else if (Array.isArray(val)) {
      for (const item of val) {
        if (typeof item === "string" && item.trim()) {
          paths.push({ key, value: item.trim() });
        }
      }
    }
  }
  return paths;
}

export function createPolicy({
  readonly = false,
  allowTools = [],
  denyTools = [],
  allowDirs = [],
  protectedDirs = [],
  dlp = true
} = {}) {
  return {
    readonly: Boolean(readonly),
    allowTools: new Set(allowTools.map((s) => String(s).trim()).filter(Boolean)),
    denyTools: new Set(denyTools.map((s) => String(s).trim()).filter(Boolean)),
    allowDirs: allowDirs.map((d) => path.resolve(String(d).trim())).filter(Boolean),
    protectedDirs: protectedDirs.map((d) => path.resolve(String(d).trim())).filter(Boolean),
    dlp: Boolean(dlp)
  };
}

export function isToolAllowedByName(toolName, policy, annotations = null) {
  if (!toolName) return false;
  if (policy.denyTools.has(toolName)) return false;
  if (policy.allowTools.size > 0 && !policy.allowTools.has(toolName)) return false;
  if (policy.readonly) {
    if (READONLY_TOOLS.has(toolName)) return true;
    if (annotations && annotations.readOnlyHint === true && annotations.destructiveHint !== true) return true;
    return false;
  }
  return true;
}

export function evaluateToolCall(rpc, policy, { platform = process.platform } = {}) {
  if (!rpc || rpc.method !== "tools/call") return { allowed: true };
  const toolName = typeof rpc.params?.name === "string" ? rpc.params.name : "";
  const args = rpc.params?.arguments && typeof rpc.params.arguments === "object" ? rpc.params.arguments : {};

  if (!isToolAllowedByName(toolName, policy)) {
    const modeReason = policy.readonly ? "connector is running in --readonly mode" : "tool is disallowed by local policy";
    return { allowed: false, reason: `Blocked locally: "${toolName}" is not permitted (${modeReason}).` };
  }

  const candidatePaths = extractPathArgs(args);

  // Always block access to PCC's own credential/config directory
  for (const dir of policy.protectedDirs) {
    for (const entry of candidatePaths) {
      if (isPathInside(entry.value, dir, platform)) {
        return {
          allowed: false,
          reason: `Blocked locally: access to protected connector directory via "${entry.key}" is forbidden.`
        };
      }
    }
    if (typeof args.command === "string") {
      const cmdLower = args.command.toLowerCase();
      if (cmdLower.includes("privatedesktopmcp") && cmdLower.includes("device.json")) {
        return {
          allowed: false,
          reason: "Blocked locally: reading or modifying connector device credentials via shell is forbidden."
        };
      }
    }
  }

  // Optional allow-dir jail
  if (policy.allowDirs.length > 0) {
    for (const entry of candidatePaths) {
      const permitted = policy.allowDirs.some((root) => isPathInside(entry.value, root, platform));
      if (!permitted) {
        return {
          allowed: false,
          reason: `Blocked locally: "${entry.key}" is outside allowed directories (--allow-dir).`
        };
      }
    }
  }

  return { allowed: true };
}

function transformRpcPayload(bodyText, contentType, transformObj) {
  if (String(contentType || "").toLowerCase().includes("text/event-stream")) {
    let changed = false;
    const lines = String(bodyText || "").split(/\r?\n/);
    const out = lines.map((line) => {
      if (!line.startsWith("data:")) return line;
      const raw = line.slice(5).trim();
      if (!raw || raw === "[DONE]") return line;
      try {
        const parsed = JSON.parse(raw);
        const next = transformObj(parsed);
        if (next) {
          changed = true;
          return "data: " + JSON.stringify(next);
        }
      } catch {
        return line;
      }
      return line;
    });
    return changed ? out.join("\n") : bodyText;
  }
  try {
    const parsed = JSON.parse(String(bodyText || ""));
    const next = transformObj(parsed);
    return next ? JSON.stringify(next) : bodyText;
  } catch {
    return bodyText;
  }
}

export function filterToolsListBody(bodyText, contentType, policy) {
  if (!policy.readonly && policy.allowTools.size === 0 && policy.denyTools.size === 0) {
    return bodyText;
  }
  return transformRpcPayload(bodyText, contentType, (obj) => {
    if (!Array.isArray(obj?.result?.tools)) return null;
    const filtered = obj.result.tools.filter((tool) =>
      isToolAllowedByName(tool?.name, policy, tool?.annotations || null)
    );
    return {
      ...obj,
      result: {
        ...obj.result,
        tools: filtered
      }
    };
  });
}

export function redactSecretsInText(text, extraSecrets = []) {
  let out = String(text ?? "");
  let count = 0;

  for (const secret of extraSecrets) {
    const s = String(secret || "");
    if (s.length >= 16 && out.includes(s)) {
      const parts = out.split(s);
      count += parts.length - 1;
      out = parts.join(DLP_MARKER);
    }
  }

  for (const pattern of HIGH_CONFIDENCE_SECRET_PATTERNS) {
    out = out.replace(pattern, () => {
      count++;
      return DLP_MARKER;
    });
  }

  return { text: out, redactedCount: count };
}

export function redactOutboundResponse(bodyText, contentType = "", { enabled = true, extraSecrets = [] } = {}) {
  if (!enabled || !bodyText) return { body: bodyText, redactedCount: 0 };
  let total = 0;
  const body = transformRpcPayload(bodyText, contentType, (obj) => {
    if (!Array.isArray(obj?.result?.content)) return null;
    let modified = false;
    const content = obj.result.content.map((block) => {
      if (block?.type === "text" && typeof block.text === "string") {
        const res = redactSecretsInText(block.text, extraSecrets);
        if (res.redactedCount > 0) {
          total += res.redactedCount;
          modified = true;
          return { ...block, text: res.text };
        }
      }
      return block;
    });
    return modified ? { ...obj, result: { ...obj.result, content } } : null;
  });
  return { body, redactedCount: total };
}

export function buildPolicyBlockedResponse(rpcId, reason) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: rpcId ?? null,
    result: {
      isError: true,
      content: [{ type: "text", text: reason }]
    }
  });
}
