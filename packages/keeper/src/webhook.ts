/**
 * Standard-Webhooks-style signed delivery with retry / backoff / dead-letter.
 *
 * Signing follows the Standard Webhooks spec (https://www.standardwebhooks.com):
 *   - `webhook-id`        : unique message id; ALSO the idempotency key. Stable
 *                           across retries AND across a keeper restart re-fire, so
 *                           the receiver can dedupe a fire it already processed.
 *   - `webhook-timestamp` : unix seconds, to bound replay windows.
 *   - `webhook-signature` : `v1,<base64(HMAC-SHA256(secret, "id.timestamp.body"))>`.
 *   - `idempotency-key`   : mirror of webhook-id, for receivers keyed on it.
 *
 * The secret may be given as a raw string or in Standard-Webhooks `whsec_<base64>`
 * form (the base64 part is decoded before HMAC, per spec).
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { resolvePinnedAddress, type Resolver, type SsrfOptions } from "./ssrf.js";

/** Result of a single POST attempt. */
export interface DeliverResult {
  ok: boolean;
  status: number | null;
  error: string | null;
}

/** A function that performs one HTTP POST. Injectable so tests avoid the network. */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ status: number }>;

/**
 * The production deliverer: DNS-pinned. Resolves the target host, range-checks every
 * address, then opens the connection to that exact address via node:http(s) with a
 * `lookup` that returns only the vetted address — so a DNS flip between check and
 * connect cannot redirect the POST. TLS still verifies against the hostname (SNI /
 * servername), and the Host header is the hostname. Redirects are never followed.
 */
export function pinnedFetch(opts: SsrfOptions & { resolver?: Resolver; timeoutMs?: number } = {}): FetchLike {
  return async (url, init) => {
    const u = new URL(url);
    const pinned = await resolvePinnedAddress(u.hostname, opts);
    const isHttps = u.protocol === "https:";
    const mod = isHttps ? https : http;
    return new Promise<{ status: number }>((resolve, reject) => {
      const req = mod.request(
        {
          protocol: u.protocol,
          hostname: u.hostname,
          port: u.port || (isHttps ? 443 : 80),
          path: `${u.pathname}${u.search}`,
          method: init.method,
          headers: { ...init.headers, host: u.host, "content-length": String(Buffer.byteLength(init.body)) },
          servername: isHttps ? u.hostname : undefined,
          // The pin: every connect for this request goes to the address that passed the
          // check. Node may ask with `all: true` (happy-eyeballs) or for a single address.
          lookup: ((_host: string, o: { all?: boolean }, cb: (...a: unknown[]) => void) =>
            o?.all
              ? cb(null, [{ address: pinned.address, family: pinned.family }])
              : cb(null, pinned.address, pinned.family)) as unknown as http.RequestOptions["lookup"],
          timeout: opts.timeoutMs ?? 10_000,
        },
        (res) => {
          res.resume(); // drain; the body is irrelevant to delivery success
          resolve({ status: res.statusCode ?? 0 });
        },
      );
      req.on("timeout", () => req.destroy(new Error("webhook delivery timed out")));
      req.on("error", reject);
      req.end(init.body);
    });
  };
}

const defaultFetch: FetchLike = pinnedFetch();

/**
 * Per-owner webhook secret derived from the server secret: `whsec_` +
 * base64(HMAC-SHA256(serverSecret, owner)). Each owner verifies their own fires with
 * a secret only they were shown, and the server secret itself is never disclosed.
 */
export function deriveOwnerSecret(serverSecret: string, owner: string): string {
  return "whsec_" + createHmac("sha256", decodeSecret(serverSecret)).update(owner, "utf8").digest("base64");
}

/** Decode a Standard-Webhooks secret to the raw key bytes used for HMAC. */
export function decodeSecret(secret: string): Buffer {
  if (secret.startsWith("whsec_")) {
    return Buffer.from(secret.slice("whsec_".length), "base64");
  }
  return Buffer.from(secret, "utf8");
}

/** Compute the `webhook-signature` header value for a message. */
export function signWebhook(args: {
  id: string;
  timestampSec: number;
  body: string;
  secret: string;
}): string {
  const signedContent = `${args.id}.${args.timestampSec}.${args.body}`;
  const sig = createHmac("sha256", decodeSecret(args.secret))
    .update(signedContent)
    .digest("base64");
  return `v1,${sig}`;
}

/**
 * Verify a `webhook-signature` header (constant-time). Exported so receivers (and
 * tests) can validate what the keeper sent. Accepts the space-delimited multi-sig
 * header form and returns true if ANY `v1,` entry matches.
 */
export function verifyWebhook(args: {
  id: string;
  timestampSec: number;
  body: string;
  secret: string;
  signatureHeader: string;
}): boolean {
  const expected = signWebhook({
    id: args.id,
    timestampSec: args.timestampSec,
    body: args.body,
    secret: args.secret,
  });
  const expectedBuf = Buffer.from(expected);
  for (const part of args.signatureHeader.split(" ")) {
    const candidate = part.trim();
    if (!candidate.startsWith("v1,")) continue;
    const candBuf = Buffer.from(candidate);
    if (
      candBuf.length === expectedBuf.length &&
      timingSafeEqual(candBuf, expectedBuf)
    ) {
      return true;
    }
  }
  return false;
}

/** Build the outbound headers for a signed webhook POST. */
export function buildHeaders(args: {
  id: string;
  timestampSec: number;
  body: string;
  secret: string;
}): Record<string, string> {
  return {
    "content-type": "application/json",
    "webhook-id": args.id,
    "webhook-timestamp": String(args.timestampSec),
    "webhook-signature": signWebhook(args),
    "idempotency-key": args.id,
    "user-agent": "clockchain-keeper/0.1",
  };
}

/**
 * Deliver one signed POST. `idempotencyKey` is the Standard-Webhooks `webhook-id`
 * and is REUSED unchanged on every retry (that is what makes retries safe).
 */
export async function deliverWebhook(args: {
  target: string;
  body: unknown;
  secret: string;
  idempotencyKey: string;
  nowSec: number;
  fetchFn?: FetchLike;
  /** SSRF policy for the default (DNS-pinned) deliverer. */
  ssrf?: SsrfOptions;
}): Promise<DeliverResult> {
  const fetchFn = args.fetchFn ?? (args.ssrf ? pinnedFetch(args.ssrf) : defaultFetch);
  const body = JSON.stringify(args.body ?? null);
  const headers = buildHeaders({
    id: args.idempotencyKey,
    timestampSec: args.nowSec,
    body,
    secret: args.secret,
  });
  try {
    const { status } = await fetchFn(args.target, { method: "POST", headers, body });
    return { ok: status >= 200 && status < 300, status, error: null };
  } catch (err) {
    return { ok: false, status: null, error: err instanceof Error ? err.message : String(err) };
  }
}

export interface RetryOptions {
  /** Total attempts before dead-lettering. Default 5. */
  maxAttempts?: number;
  /** Base backoff, ms. Delay = base * 2^(attempt-1), capped at maxDelayMs. */
  baseDelayMs?: number;
  /** Backoff cap, ms. Default 30_000. */
  maxDelayMs?: number;
  /** Sleep impl, injectable so tests don't wait. Default real setTimeout. */
  sleep?: (ms: number) => Promise<void>;
  /** Called once per attempt with 1-based attempt index and the result. */
  onAttempt?: (attempt: number, result: DeliverResult) => void;
}

export interface RetryResult {
  ok: boolean;
  attempts: number;
  lastStatus: number | null;
  lastError: string | null;
  /** True when every attempt failed -> the caller should dead-letter. */
  deadLettered: boolean;
}

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Exponential backoff for the delay BEFORE attempt N (1-based). */
export function backoffDelayMs(
  attempt: number,
  baseDelayMs: number,
  maxDelayMs: number,
): number {
  if (attempt <= 1) return 0;
  return Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 2));
}

/**
 * Run `deliver` with retries + exponential backoff. The same idempotency key must
 * be used inside `deliver` on each call (the caller closes over it). Returns the
 * final outcome; `deadLettered` is true when all attempts were exhausted.
 */
export async function deliverWithRetry(
  deliver: () => Promise<DeliverResult>,
  opts: RetryOptions = {},
): Promise<RetryResult> {
  const maxAttempts = opts.maxAttempts ?? 5;
  const baseDelayMs = opts.baseDelayMs ?? 500;
  const maxDelayMs = opts.maxDelayMs ?? 30_000;
  const sleep = opts.sleep ?? realSleep;

  let last: DeliverResult = { ok: false, status: null, error: "not attempted" };
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const delay = backoffDelayMs(attempt, baseDelayMs, maxDelayMs);
    if (delay > 0) await sleep(delay);
    last = await deliver();
    opts.onAttempt?.(attempt, last);
    if (last.ok) {
      return { ok: true, attempts: attempt, lastStatus: last.status, lastError: null, deadLettered: false };
    }
  }
  return {
    ok: false,
    attempts: maxAttempts,
    lastStatus: last.status,
    lastError: last.error,
    deadLettered: true,
  };
}
