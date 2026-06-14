/**
 * Upstream resilience for the Clockchain gateway (node.clockchain.network).
 *
 * Wraps a single `fetch` call with three independent safeguards so a flaky or
 * slow gateway degrades gracefully — clear errors — instead of hanging or
 * cascading:
 *
 *  - Timeout: every attempt is bounded by an AbortController. A hung socket
 *    surfaces a {@link TimeoutError} instead of blocking the caller forever.
 *  - Bounded retries: idempotent reads (GET) retry on a network error or HTTP
 *    5xx with a small backoff. Writes (non-GET) get ONE attempt — re-POSTing an
 *    anchor could double-anchor, so we never auto-retry them.
 *  - Circuit-breaker: a module-level (per-process) counter of consecutive
 *    failures. After {@link DEFAULT_BREAKER_THRESHOLD} failures the breaker
 *    OPENS for a cooldown and every call fails fast with a clear "upstream
 *    unavailable (circuit open)" error. After the cooldown it goes HALF-OPEN:
 *    the next call probes; success closes it, failure re-opens it.
 *
 * Dependency-free and fully testable: `fetchImpl`, `sleep`, and `now` are
 * injectable so tests never sleep or touch the network. {@link __resetBreaker}
 * clears breaker state between tests.
 */
import { ApiError } from "./errors.js";

/** Default per-attempt timeout in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 12_000;
/** Default maximum number of RETRIES (additional attempts) for idempotent reads. */
export const DEFAULT_MAX_RETRIES = 2;
/** Default backoff schedule (ms) indexed by retry number. */
export const DEFAULT_BACKOFF_MS = [200, 500];
/** Consecutive failures that trip the breaker open. */
export const DEFAULT_BREAKER_THRESHOLD = 5;
/** How long (ms) the breaker stays open before going half-open. */
export const DEFAULT_BREAKER_COOLDOWN_MS = 30_000;

/** Raised when an attempt exceeds its timeout. Subclass of ApiError (status 0). */
export class TimeoutError extends ApiError {
  constructor(message = "Clockchain request timed out", body?: unknown) {
    super(message, 0, body);
    this.name = "TimeoutError";
  }
}

/** Raised when the circuit-breaker is open and the call fails fast. */
export class CircuitOpenError extends ApiError {
  constructor(
    message = "Clockchain upstream unavailable (circuit open)",
    body?: unknown,
  ) {
    super(message, 0, body);
    this.name = "CircuitOpenError";
  }
}

/** Injectable dependencies + tunables for {@link resilientFetch}. */
export interface ResilientFetchOptions {
  /** HTTP method (drives the retry decision). Defaults to GET. */
  method?: string;
  /** Per-attempt timeout in ms. Defaults to {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** Max retries for idempotent reads. Defaults to {@link DEFAULT_MAX_RETRIES}. */
  maxRetries?: number;
  /** Backoff schedule (ms). Defaults to {@link DEFAULT_BACKOFF_MS}. */
  backoffMs?: number[];
  /** Breaker trip threshold. Defaults to {@link DEFAULT_BREAKER_THRESHOLD}. */
  breakerThreshold?: number;
  /** Breaker cooldown in ms. Defaults to {@link DEFAULT_BREAKER_COOLDOWN_MS}. */
  breakerCooldownMs?: number;
  /** Fetch implementation. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Sleep implementation. Defaults to a real setTimeout-based sleep. */
  sleep?: (ms: number) => Promise<void>;
  /** Clock. Defaults to Date.now. */
  now?: () => number;
}

/** Module-level (per-process) circuit-breaker state. */
interface BreakerState {
  consecutiveFailures: number;
  /** Epoch ms when the breaker may probe again; 0 means closed. */
  openUntil: number;
}

const breaker: BreakerState = { consecutiveFailures: 0, openUntil: 0 };

/** Test hook: reset the per-process breaker to its closed/initial state. */
export function __resetBreaker(): void {
  breaker.consecutiveFailures = 0;
  breaker.openUntil = 0;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** An AbortError-shaped rejection (DOMException or any { name: "AbortError" }). */
function isAbortError(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "name" in err &&
    (err as { name?: unknown }).name === "AbortError"
  );
}

/** Run one fetch attempt bounded by an AbortController timeout. */
async function attempt(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  fetchImpl: typeof fetch,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } catch (err) {
    if (isAbortError(err)) {
      throw new TimeoutError(`Clockchain request timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch `url` with timeout, bounded retries (GET only), and a shared circuit
 * breaker. Returns the {@link Response} so callers keep their existing
 * `res.ok` / `res.json()` handling. Throws {@link TimeoutError},
 * {@link CircuitOpenError}, or the underlying network error on exhaustion.
 */
export async function resilientFetch(
  url: string,
  init: RequestInit = {},
  opts: ResilientFetchOptions = {},
): Promise<Response> {
  const method = (opts.method ?? init.method ?? "GET").toUpperCase();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
  const backoffMs = opts.backoffMs ?? DEFAULT_BACKOFF_MS;
  const breakerThreshold = opts.breakerThreshold ?? DEFAULT_BREAKER_THRESHOLD;
  const breakerCooldownMs =
    opts.breakerCooldownMs ?? DEFAULT_BREAKER_COOLDOWN_MS;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const sleep = opts.sleep ?? defaultSleep;
  const now = opts.now ?? Date.now;

  // Circuit-breaker gate: fail fast while open (before the cooldown elapses).
  if (breaker.openUntil > 0 && now() < breaker.openUntil) {
    throw new CircuitOpenError();
  }

  // Only idempotent reads may retry; writes get exactly one attempt.
  const retriesAllowed = method === "GET" ? maxRetries : 0;

  const onSuccess = () => {
    breaker.consecutiveFailures = 0;
    breaker.openUntil = 0;
  };
  const onFailure = () => {
    breaker.consecutiveFailures += 1;
    if (breaker.consecutiveFailures >= breakerThreshold) {
      breaker.openUntil = now() + breakerCooldownMs;
    }
  };

  let lastError: unknown;
  for (let i = 0; i <= retriesAllowed; i += 1) {
    try {
      const res = await attempt(url, init, timeoutMs, fetchImpl);
      // Retry idempotent reads on transient server errors (5xx).
      if (res.status >= 500 && i < retriesAllowed) {
        onFailure();
        await sleep(backoffMs[i] ?? backoffMs[backoffMs.length - 1] ?? 0);
        continue;
      }
      onSuccess();
      return res;
    } catch (err) {
      lastError = err;
      onFailure();
      // A tripped breaker fails the rest of this call fast too.
      if (breaker.openUntil > 0 && now() < breaker.openUntil) {
        throw new CircuitOpenError();
      }
      if (i < retriesAllowed) {
        await sleep(backoffMs[i] ?? backoffMs[backoffMs.length - 1] ?? 0);
        continue;
      }
      throw err;
    }
  }

  // Unreachable in practice (loop either returns or throws), but keeps TS happy.
  throw lastError ?? new ApiError("Clockchain request failed", 0);
}
