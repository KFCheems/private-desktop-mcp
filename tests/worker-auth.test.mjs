import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { verifyAccessJwt, authenticateOwnerRequest, clearJwksCache } from "../worker/auth.mjs";

function makeRsaJwkPair(kid) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" };
  return { jwk, privateKey };
}

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function signRs256(header, payload, privateKey) {
  const head = b64url(JSON.stringify(header));
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.sign("RSA-SHA256", Buffer.from(`${head}.${body}`), privateKey);
  return `${head}.${body}.${b64url(sig)}`;
}

test("verifyAccessJwt accepts a valid RS256 Cloudflare Access JWT", async () => {
  clearJwksCache();
  const { jwk, privateKey } = makeRsaJwkPair("k1");
  const now = 1_800_000_000;
  const token = signRs256(
    { alg: "RS256", kid: "k1", typ: "JWT" },
    {
      iss: "https://myteam.cloudflareaccess.com",
      aud: ["aud-tag-123"],
      email: "owner@example.com",
      exp: now + 300,
      nbf: now - 10
    },
    privateKey
  );

  let fetches = 0;
  const fetcher = async (url) => {
    fetches++;
    assert.equal(url, "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs");
    return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
  };

  const res = await verifyAccessJwt(token, {
    teamDomain: "myteam.cloudflareaccess.com",
    aud: "aud-tag-123",
    fetcher,
    nowSec: now
  });
  assert.equal(res.ok, true);
  assert.equal(res.verified, true);
  assert.equal(res.actor, "owner@example.com");
  assert.equal(fetches, 1);

  // Second call hits JWKS cache without refetching
  const res2 = await verifyAccessJwt(token, {
    teamDomain: "https://myteam.cloudflareaccess.com",
    aud: "other-aud, aud-tag-123",
    fetcher,
    nowSec: now
  });
  assert.equal(res2.ok, true);
  assert.equal(fetches, 1);
});

test("verifyAccessJwt rejects forged signature, expired token, wrong aud, and wrong iss", async () => {
  clearJwksCache();
  const keyA = makeRsaJwkPair("ka");
  const keyB = makeRsaJwkPair("kb");
  const now = 1_800_000_000;
  const fetcher = async () => new Response(JSON.stringify({ keys: [keyA.jwk] }), { status: 200 });
  const baseClaims = {
    iss: "https://team.cloudflareaccess.com",
    aud: ["expected-aud"],
    email: "owner@example.com",
    exp: now + 300
  };

  // Signed with wrong private key
  const forged = signRs256({ alg: "RS256", kid: "ka" }, baseClaims, keyB.privateKey);
  const rForged = await verifyAccessJwt(forged, { teamDomain: "team.cloudflareaccess.com", aud: "expected-aud", fetcher, nowSec: now });
  assert.equal(rForged.ok, false);
  assert.equal(rForged.status, 403);

  // Expired beyond clock skew
  const expired = signRs256({ alg: "RS256", kid: "ka" }, { ...baseClaims, exp: now - 120 }, keyA.privateKey);
  const rExpired = await verifyAccessJwt(expired, { teamDomain: "team.cloudflareaccess.com", aud: "expected-aud", fetcher, nowSec: now });
  assert.equal(rExpired.ok, false);
  assert.match(rExpired.error, /expired/i);

  // Wrong audience
  const wrongAud = signRs256({ alg: "RS256", kid: "ka" }, { ...baseClaims, aud: ["wrong-aud"] }, keyA.privateKey);
  const rAud = await verifyAccessJwt(wrongAud, { teamDomain: "team.cloudflareaccess.com", aud: "expected-aud", fetcher, nowSec: now });
  assert.equal(rAud.ok, false);
  assert.match(rAud.error, /audience/i);

  // Wrong issuer
  const wrongIss = signRs256({ alg: "RS256", kid: "ka" }, { ...baseClaims, iss: "https://evil.cloudflareaccess.com" }, keyA.privateKey);
  const rIss = await verifyAccessJwt(wrongIss, { teamDomain: "team.cloudflareaccess.com", aud: "expected-aud", fetcher, nowSec: now });
  assert.equal(rIss.ok, false);
  assert.match(rIss.error, /issuer/i);
});

test("verifyAccessJwt refreshes cached JWKS automatically on key rotation (unknown kid)", async () => {
  clearJwksCache();
  const oldKey = makeRsaJwkPair("old-kid");
  const rotatedKey = makeRsaJwkPair("new-kid");
  const now = 1_800_000_000;

  let callCount = 0;
  const fetcher = async () => {
    callCount++;
    return new Response(JSON.stringify({ keys: callCount === 1 ? [oldKey.jwk] : [oldKey.jwk, rotatedKey.jwk] }), { status: 200 });
  };

  const t1 = signRs256(
    { alg: "RS256", kid: "old-kid" },
    { iss: "https://rot.cloudflareaccess.com", aud: ["aud1"], sub: "u1", exp: now + 600 },
    oldKey.privateKey
  );
  assert.equal((await verifyAccessJwt(t1, { teamDomain: "rot.cloudflareaccess.com", aud: "aud1", fetcher, nowSec: now })).ok, true);
  assert.equal(callCount, 1);

  const t2 = signRs256(
    { alg: "RS256", kid: "new-kid" },
    { iss: "https://rot.cloudflareaccess.com", aud: ["aud1"], sub: "u1", exp: now + 600 },
    rotatedKey.privateKey
  );
  const res2 = await verifyAccessJwt(t2, { teamDomain: "rot.cloudflareaccess.com", aud: "aud1", fetcher, nowSec: now });
  assert.equal(res2.ok, true);
  assert.equal(callCount, 2);
});

test("authenticateOwnerRequest fails closed without verifier config unless ctx.access or legacy opt-in is set", async () => {
  const reqWithHeader = new Request("https://example.workers.dev/mcp", {
    headers: { "cf-access-jwt-assertion": "a." + b64url(JSON.stringify({ email: "legacy@example.com" })) + ".c" }
  });

  // Fail closed when unconfigured
  const failClosed = await authenticateOwnerRequest(reqWithHeader, {});
  assert.equal(failClosed.ok, false);
  assert.equal(failClosed.status, 503);

  // Native ctx.access succeeds
  const nativeCtx = await authenticateOwnerRequest(new Request("https://example.workers.dev/mcp"), {}, {
    access: { email: "native@example.com" }
  });
  assert.equal(nativeCtx.ok, true);
  assert.equal(nativeCtx.verified, true);
  assert.equal(nativeCtx.actor, "native@example.com");

  // Explicit legacy opt-in works for well-formed 3-part JWT and rejects garbage
  const legacyOk = await authenticateOwnerRequest(reqWithHeader, { ALLOW_UNVERIFIED_ACCESS_HEADER: "true" });
  assert.equal(legacyOk.ok, true);
  assert.equal(legacyOk.verified, false);
  assert.equal(legacyOk.actor, "legacy@example.com");

  const legacyBad = await authenticateOwnerRequest(
    new Request("https://example.workers.dev/mcp", { headers: { "cf-access-jwt-assertion": "not-a-jwt" } }),
    { ALLOW_UNVERIFIED_ACCESS_HEADER: "true" }
  );
  assert.equal(legacyBad.ok, false);
  assert.equal(legacyBad.status, 403);
});
