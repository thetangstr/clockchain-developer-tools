import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

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
  /**
   * Unique token id (per-user auth). Makes every minted token distinct — even two
   * minted in the same second — so the per-request rate limiter can bucket each
   * token independently instead of collapsing a shared-egress public app's
   * traffic into one IP bucket. Optional in the type for backward-compatible
   * verification of older tokens; always set by `mintToken`.
   */
  jti?: string;
  /**
   * Optional subject (per-user auth): a NON-AUTHORITATIVE label for the principal this
   * token is intended for. It is supplied on the UNAUTHENTICATED mint endpoint,
   * so it is NOT trusted and does NOT isolate rate-limit buckets or budgets — the
   * per-request limiter keys on `jti` (per token), never on `sub`. `sub` becomes
   * a safe per-user key only once it derives from an authenticated identity.
   * MEDIUM-TERM follow-up (not in this change): real per-user auth + mapping
   * `sub` to a distinct delegated sub-key / credit bucket at the gateway instead
   * of the single shared delegated key every demo token uses today.
   */
  sub?: string;
}

const b64url = (buf: Buffer): string =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const b64urlDecode = (s: string): Buffer =>
  Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

const sign = (payloadSeg: string, secret: string): string =>
  b64url(createHmac("sha256", secret).update(payloadSeg).digest());

/**
 * Mint a signed self-serve token. `ttlSeconds` defaults to 7 days. Each token
 * gets a unique `jti` so it is independently rate-limitable (per-user auth). `sub` is
 * an optional NON-AUTHORITATIVE label only (see {@link TokenPayload.sub}); it
 * never affects bucketing. Callers should sanitize `sub` before passing it.
 * `nowSec` and `jti` are injectable for tests.
 */
export function mintToken(
  secret: string,
  ttlSeconds = 7 * 24 * 60 * 60,
  nowSec: number = Math.floor(Date.now() / 1000),
  sub?: string,
  jti: string = randomUUID(),
): { token: string; payload: TokenPayload } {
  const payload: TokenPayload = { v: 1, tier: "demo", iat: nowSec, exp: nowSec + ttlSeconds, jti };
  if (sub) payload.sub = sub;
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
