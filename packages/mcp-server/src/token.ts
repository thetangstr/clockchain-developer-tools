import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Self-serve testnet tokens — stateless, HMAC-signed, no database.
 *
 * A token is `cc_<base64url(payload)>.<base64url(hmac)>` where the payload is a
 * small JSON object ({ v, tier, iat, exp }) and the hmac is HMAC-SHA256 over the
 * payload segment, keyed by a server secret (MCP_TOKEN_SIGNING_SECRET). The
 * server can therefore mint and verify tokens with no storage: validity is just
 * a signature check plus an expiry check.
 *
 * These grant the DELEGATED (shared testnet) key — they let a brand-new user try
 * the hosted server without their own Clockchain key. They are NOT a Clockchain
 * credential and never touch the gateway directly.
 */

const PREFIX = "cc_";

export interface TokenPayload {
  v: 1;
  tier: "demo";
  iat: number; // issued-at, unix seconds
  exp: number; // expiry, unix seconds
}

const b64url = (buf: Buffer): string =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const b64urlDecode = (s: string): Buffer =>
  Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

const sign = (payloadSeg: string, secret: string): string =>
  b64url(createHmac("sha256", secret).update(payloadSeg).digest());

/**
 * Mint a signed self-serve token. `ttlSeconds` defaults to 7 days. `nowSec` is
 * injectable for tests.
 */
export function mintToken(
  secret: string,
  ttlSeconds = 7 * 24 * 60 * 60,
  nowSec: number = Math.floor(Date.now() / 1000),
): { token: string; payload: TokenPayload } {
  const payload: TokenPayload = { v: 1, tier: "demo", iat: nowSec, exp: nowSec + ttlSeconds };
  const seg = b64url(Buffer.from(JSON.stringify(payload), "utf8"));
  return { token: `${PREFIX}${seg}.${sign(seg, secret)}`, payload };
}

/**
 * Verify a self-serve token: correct shape, valid signature (constant-time), and
 * not expired. Returns the payload when valid, else a reason. Never throws.
 */
export function verifyToken(
  secret: string,
  token: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): { valid: true; payload: TokenPayload } | { valid: false; reason: string } {
  if (!secret) return { valid: false, reason: "signing disabled" };
  if (typeof token !== "string" || !token.startsWith(PREFIX)) {
    return { valid: false, reason: "bad prefix" };
  }
  const body = token.slice(PREFIX.length);
  const dot = body.indexOf(".");
  if (dot < 0) return { valid: false, reason: "malformed" };
  const seg = body.slice(0, dot);
  const sig = body.slice(dot + 1);
  const expected = sign(seg, secret);
  // Constant-time compare; lengths must match for timingSafeEqual.
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { valid: false, reason: "bad signature" };
  }
  let payload: TokenPayload;
  try {
    payload = JSON.parse(b64urlDecode(seg).toString("utf8")) as TokenPayload;
  } catch {
    return { valid: false, reason: "bad payload" };
  }
  if (payload.v !== 1) return { valid: false, reason: "bad version" };
  if (typeof payload.exp !== "number" || nowSec >= payload.exp) {
    return { valid: false, reason: "expired" };
  }
  return { valid: true, payload };
}

/** True iff the token is a structurally-self-serve token (cheap pre-check). */
export const looksLikeSelfServe = (token: string): boolean =>
  typeof token === "string" && token.startsWith(PREFIX) && token.includes(".");
