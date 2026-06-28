/**
 * Typed errors for the Clockchain client.
 *
 * Core never retries automatically — these errors are surfaced so the caller
 * can decide whether to back off, retry, or fail.
 */

/** Generic API error (non-2xx response that does not match a more specific case). */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** Gateway rate limiting: HTTP 429 or body containing "Rate limit exceeded". */
export class RateLimitError extends ApiError {
  /**
   * Seconds to wait before retrying, parsed from the upstream gateway's
   * `Retry-After` header when present (AGE-194). `undefined` when the gateway
   * gave no hint. Surfaced to MCP callers so an agent can back off correctly.
   */
  readonly retryAfter?: number;

  constructor(
    message = "Rate limit exceeded",
    status = 429,
    body?: unknown,
    retryAfter?: number,
  ) {
    super(message, status, body);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

/**
 * Parse an HTTP `Retry-After` header into seconds. The header is either a
 * non-negative integer count of seconds or an HTTP-date; both are supported.
 * Returns `undefined` for a missing / empty / unparseable value. `nowMs` is
 * injectable for tests.
 */
export function parseRetryAfter(
  value: string | null | undefined,
  nowMs: number = Date.now(),
): number | undefined {
  if (value == null) return undefined;
  const trimmed = value.trim();
  if (trimmed === "") return undefined;
  if (/^\d+$/.test(trimmed)) return Number(trimmed); // delta-seconds form
  const when = Date.parse(trimmed); // HTTP-date form
  if (Number.isNaN(when)) return undefined;
  return Math.max(0, Math.ceil((when - nowMs) / 1000));
}

/** Logging credit exhaustion: "No enough tokens to facilitate this logging". */
export class InsufficientCreditsError extends ApiError {
  constructor(
    message = "No enough tokens to facilitate this logging",
    status = 402,
    body?: unknown,
  ) {
    super(message, status, body);
    this.name = "InsufficientCreditsError";
  }
}

/** Authentication failure: HTTP 401 (bad or missing x-api-key). */
export class AuthError extends ApiError {
  constructor(message = "Authentication failed", status = 401, body?: unknown) {
    super(message, status, body);
    this.name = "AuthError";
  }
}

/**
 * Node pool degraded (AGE-193): 0% node participation, so a write may not
 * anchor. Raised by the pool-health guard to refuse a write that would likely
 * report success without anchoring, unless the caller explicitly opts in.
 */
export class PoolDegradedError extends ApiError {
  constructor(
    message = "Node pool degraded (0% participation): a write may not anchor.",
    status = 503,
    body?: unknown,
  ) {
    super(message, status, body);
    this.name = "PoolDegradedError";
  }
}

/**
 * A write was submitted but is not yet anchored on-chain (AGE-193). Surfaced so
 * a pending write is never silently reported as confirmed success; the caller
 * should poll (get_log_entry / complete_attestation) until it anchors.
 */
export class NotAnchoredError extends ApiError {
  constructor(
    message = "Not anchored yet: submitted but no blockHeight — poll to confirm.",
    status = 202,
    body?: unknown,
  ) {
    super(message, status, body);
    this.name = "NotAnchoredError";
  }
}
