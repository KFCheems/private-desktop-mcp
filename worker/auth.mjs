const JWKS_TTL_MS = 10 * 60 * 1000;
const CLOCK_SKEW_SEC = 60;
const jwksCache = new Map();

function base64UrlToBytes(input) {
  const normalized = String(input || "").replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJsonSegment(segment) {
  const bytes = base64UrlToBytes(segment);
  return JSON.parse(new TextDecoder().decode(bytes));
}

export function normalizeTeamDomain(raw) {
  const value = String(raw || "").trim().replace(/\/+$/, "");
  if (!value) return "";
  if (/^https?:\/\//i.test(value)) {
    const u = new URL(value);
    return u.origin;
  }
  return `https://${value}`;
}

export function parseAllowedAuds(raw) {
  return String(raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function clearJwksCache() {
  jwksCache.clear();
}

async function fetchJwks(teamOrigin, { fetcher = fetch, now = Date.now(), forceRefresh = false } = {}) {
  const cached = jwksCache.get(teamOrigin);
  if (!forceRefresh && cached && cached.expiresAt > now) {
    return cached.keys;
  }
  const certsUrl = `${teamOrigin}/cdn-cgi/access/certs`;
  const res = await fetcher(certsUrl, {
    headers: { accept: "application/json" }
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch Access JWKS (HTTP ${res.status})`);
  }
  const body = await res.json();
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  jwksCache.set(teamOrigin, { keys, expiresAt: now + JWKS_TTL_MS });
  return keys;
}

export async function verifyAccessJwt(token, {
  teamDomain,
  aud,
  fetcher = fetch,
  nowSec = Math.floor(Date.now() / 1000)
} = {}) {
  const rawToken = String(token || "").trim();
  const parts = rawToken.split(".");
  if (parts.length !== 3 || parts.some((p) => !p)) {
    return { ok: false, status: 403, error: "Malformed Cloudflare Access JWT" };
  }

  let header;
  let payload;
  try {
    header = decodeJsonSegment(parts[0]);
    payload = decodeJsonSegment(parts[1]);
  } catch {
    return { ok: false, status: 403, error: "Unparseable Cloudflare Access JWT" };
  }

  if (header?.alg !== "RS256" || typeof header?.kid !== "string" || !header.kid) {
    return { ok: false, status: 403, error: "Unsupported JWT algorithm or missing kid" };
  }

  const teamOrigin = normalizeTeamDomain(teamDomain);
  const allowedAuds = Array.isArray(aud) ? aud.filter(Boolean) : parseAllowedAuds(aud);
  if (!teamOrigin || allowedAuds.length === 0) {
    return {
      ok: false,
      status: 503,
      error: "Access JWT verifier not configured (set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD)"
    };
  }

  // Validate issuer before hitting signature verification
  const expectedIss = teamOrigin;
  const actualIss = typeof payload?.iss === "string" ? payload.iss.replace(/\/+$/, "") : "";
  if (actualIss !== expectedIss) {
    return { ok: false, status: 403, error: "JWT issuer mismatch" };
  }

  // Validate audience
  const tokenAuds = Array.isArray(payload?.aud)
    ? payload.aud
    : typeof payload?.aud === "string"
      ? [payload.aud]
      : [];
  if (!tokenAuds.some((a) => allowedAuds.includes(a))) {
    return { ok: false, status: 403, error: "JWT audience mismatch" };
  }

  // Validate expiry / not-before
  if (typeof payload?.exp !== "number" || nowSec > payload.exp + CLOCK_SKEW_SEC) {
    return { ok: false, status: 403, error: "JWT expired" };
  }
  if (typeof payload?.nbf === "number" && nowSec + CLOCK_SKEW_SEC < payload.nbf) {
    return { ok: false, status: 403, error: "JWT not yet valid" };
  }

  const nowMs = nowSec * 1000;
  let keys;
  try {
    keys = await fetchJwks(teamOrigin, { fetcher, now: nowMs, forceRefresh: false });
  } catch (e) {
    return { ok: false, status: 503, error: String(e?.message || e) };
  }

  let jwk = keys.find((k) => k?.kid === header.kid && k?.kty === "RSA");
  if (!jwk) {
    // Key rotation: retry once with fresh JWKS
    try {
      keys = await fetchJwks(teamOrigin, { fetcher, now: nowMs, forceRefresh: true });
      jwk = keys.find((k) => k?.kid === header.kid && k?.kty === "RSA");
    } catch (e) {
      return { ok: false, status: 503, error: String(e?.message || e) };
    }
  }
  if (!jwk) {
    return { ok: false, status: 403, error: "Unknown JWT signing key (kid)" };
  }

  try {
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = base64UrlToBytes(parts[2]);
    const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      sigBytes,
      signingInput
    );
    if (!valid) {
      return { ok: false, status: 403, error: "Invalid JWT signature" };
    }
  } catch {
    return { ok: false, status: 403, error: "JWT cryptographic verification failed" };
  }

  const actor = String(payload.email || payload.common_name || payload.sub || "access-user").slice(0, 120);
  return { ok: true, verified: true, actor, claims: payload };
}

/**
 * Authenticates an owner request arriving at the Worker edge.
 * Priority:
 * 1. Cryptographic RS256 JWT verification when CF_ACCESS_TEAM_DOMAIN & CF_ACCESS_AUD are set.
 * 2. Cloudflare Workers native `ctx.access` assertion if available.
 * 3. Explicit legacy opt-in (`ALLOW_UNVERIFIED_ACCESS_HEADER === "true"`) for staged migration.
 * 4. Otherwise fail-closed with 503 telling the operator what to configure.
 */
export async function authenticateOwnerRequest(req, env = {}, ctx = null, opts = {}) {
  const jwtHeader = req.headers.get("cf-access-jwt-assertion") || "";
  const hasVerifierConfig = Boolean(
    normalizeTeamDomain(env.CF_ACCESS_TEAM_DOMAIN) && parseAllowedAuds(env.CF_ACCESS_AUD).length > 0
  );

  if (hasVerifierConfig) {
    if (!jwtHeader) {
      return { ok: false, status: 403, error: "Cloudflare Access JWT required" };
    }
    return verifyAccessJwt(jwtHeader, {
      teamDomain: env.CF_ACCESS_TEAM_DOMAIN,
      aud: env.CF_ACCESS_AUD,
      fetcher: opts.fetcher || fetch,
      nowSec: opts.nowSec
    });
  }

  // Cloudflare Workers native Access context (when bound via Workers Access)
  if (ctx?.access && (ctx.access.email || ctx.access.sub || ctx.access.serviceTokenId)) {
    const actor = String(ctx.access.email || ctx.access.serviceTokenId || ctx.access.sub).slice(0, 120);
    return { ok: true, verified: true, actor, claims: ctx.access };
  }

  // Explicit legacy opt-in during rolling migration before secrets are added
  if (String(env.ALLOW_UNVERIFIED_ACCESS_HEADER || "").toLowerCase() === "true") {
    if (!jwtHeader) {
      return { ok: false, status: 403, error: "Cloudflare Access required" };
    }
    const parts = jwtHeader.trim().split(".");
    if (parts.length !== 3 || parts.some((p) => !p)) {
      return { ok: false, status: 403, error: "Malformed Cloudflare Access JWT" };
    }
    let actor = "unverified-access-header";
    try {
      const payload = decodeJsonSegment(parts[1]);
      actor = String(payload.email || payload.common_name || payload.sub || actor).slice(0, 120);
    } catch {
      return { ok: false, status: 403, error: "Malformed Cloudflare Access JWT" };
    }
    return { ok: true, verified: false, actor, warning: "Unverified Access header mode enabled" };
  }

  return {
    ok: false,
    status: 503,
    error: "Access JWT verification not configured. Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD (or ALLOW_UNVERIFIED_ACCESS_HEADER=true during migration)."
  };
}
