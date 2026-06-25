/**
 * Gateway time parsing/formatting for the verified-time SDK.
 *
 * The Clockchain gateway emits two DD-MM-YYYY time shapes, both UTC:
 *   - get_time / get_timestamp:  "DD-MM-YYYY_HH:MM:SS:mmm"  (e.g. "24-06-2026_22:49:40:092")
 *   - log createdTimestamp:      "DD-MM-YYYY HH:MM:SS:mmm UTC" (e.g. "24-06-2026 22:49:48:434 UTC")
 *
 * These MUST be pattern-matched BEFORE Date.parse: V8 leniently mis-parses them
 * month-first (Nov 6 instead of Jun 11). Mirrors core's parseClockTime ordering
 * (gateway regex -> Date.parse(ISO) -> numeric epoch), kept local so the SDK's
 * time math has no hidden coupling to core internals.
 */

/** The single regex that matches BOTH gateway shapes (separator `_` or ` `, optional ` UTC`). */
const GATEWAY_TIME_RE =
  /^(\d{2})-(\d{2})-(\d{4})[_ ](\d{2}):(\d{2}):(\d{2}):(\d{3})(?: UTC)?$/;

/**
 * Parse a Clockchain gateway timestamp to epoch milliseconds, treating it as UTC.
 *
 * Accepts both gateway shapes plus, as a fallback, ISO 8601 strings and raw
 * numeric epochs (ms or s). Returns NaN when the input cannot be parsed.
 */
export function parseGatewayTime(value: unknown): number {
  const s = String(value ?? "");
  const m = s.match(GATEWAY_TIME_RE);
  if (m) {
    return Date.UTC(+m[3], +m[2] - 1, +m[1], +m[4], +m[5], +m[6], +m[7]);
  }
  const iso = Date.parse(s);
  if (!Number.isNaN(iso)) return iso;
  const n = Number(s);
  if (!Number.isNaN(n) && n > 0) return n > 1e12 ? n : n * 1000; // epoch ms or s
  return NaN;
}

/** True when a string matches one of the gateway's DD-MM-YYYY time shapes. */
export function isGatewayTime(value: unknown): boolean {
  return GATEWAY_TIME_RE.test(String(value ?? ""));
}

/**
 * Format epoch milliseconds (UTC) into the gateway's `DD-MM-YYYY HH:MM:SS:mmm UTC`
 * shape. Round-trips with {@link parseGatewayTime}. Throws on a non-finite input
 * so callers never silently produce "NaN-NaN-NaN".
 */
export function formatGatewayTime(epochMs: number): string {
  if (!Number.isFinite(epochMs)) {
    throw new RangeError(`formatGatewayTime: epochMs must be finite, got ${epochMs}`);
  }
  const d = new Date(epochMs);
  const p2 = (n: number) => String(n).padStart(2, "0");
  const p3 = (n: number) => String(n).padStart(3, "0");
  const dd = p2(d.getUTCDate());
  const mm = p2(d.getUTCMonth() + 1);
  const yyyy = String(d.getUTCFullYear()).padStart(4, "0");
  const hh = p2(d.getUTCHours());
  const min = p2(d.getUTCMinutes());
  const ss = p2(d.getUTCSeconds());
  const ms = p3(d.getUTCMilliseconds());
  return `${dd}-${mm}-${yyyy} ${hh}:${min}:${ss}:${ms} UTC`;
}
