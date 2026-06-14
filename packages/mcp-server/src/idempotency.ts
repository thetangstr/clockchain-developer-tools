/**
 * Optional idempotency for write tools.
 *
 * A write tool retried with the same `idempotency_key` must return the ORIGINAL
 * result instead of re-running its work — re-anchoring would spend a duplicate
 * log credit and create a duplicate on-chain record. The cache is process-local
 * (a bounded Map) and keyed by the caller-supplied key.
 *
 * Only SUCCESSES are cached: if the work throws, nothing is cached so the call
 * stays retryable (a failed write spends no credit and should be safe to redo).
 */

/** Max distinct keys retained; oldest are evicted past this cap. */
const MAX_ENTRIES = 1000;

/** Process-local cache of successful results, keyed by idempotency key. */
const cache = new Map<string, unknown>();

/**
 * Run `work` at most once per `key`. With no key, `work` always runs (no
 * caching). With a key: a cache hit returns the original result without
 * re-running `work`; a cache miss runs `work` and, on success, caches the
 * result. A thrown error is NOT cached so the call remains retryable.
 */
export async function idempotent<T>(
  key: string | undefined,
  work: () => Promise<T>,
): Promise<T> {
  if (!key) return work();
  if (cache.has(key)) return cache.get(key) as T;
  const result = await work();
  // Bound the cache: evict the oldest entry (Map preserves insertion order).
  if (cache.size >= MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, result);
  return result;
}

/** Test-only: clear the process-wide idempotency cache. */
export function __resetIdempotency(): void {
  cache.clear();
}
