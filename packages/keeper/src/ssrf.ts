/**
 * Basic SSRF guard for webhook targets.
 *
 * A keeper makes outbound POSTs to caller-supplied URLs, so an attacker could try
 * to point a target at internal infrastructure (cloud metadata, localhost admin
 * ports, private RFC-1918 ranges). This guard rejects those at REGISTRATION time
 * (keeper_schedule) and again before each delivery.
 *
 * Scope of THIS increment (honest TODOs below):
 *   - Enforces http/https only.
 *   - Blocks literal private / loopback / link-local / metadata IP hosts.
 *   - Optional host-suffix allow-list (KEEPER_WEBHOOK_ALLOWLIST) — when set, only
 *     matching hosts are permitted (deny-by-default).
 *   - `allowLoopback` opt-in so local dev / tests can target 127.0.0.1.
 *
 * TODO (deferred, important for prod):
 *   - DNS resolution + re-check at connect time to defeat DNS-rebinding (a public
 *     hostname that resolves to a private IP, or flips between the registration
 *     check and the delivery connect — a TOCTOU). Today only LITERAL IP hosts are
 *     range-checked; hostnames are checked only against the allow-list. Production
 *     should resolve, pin the resolved IP, and connect to that pinned IP.
 *   - Block redirects to private ranges (follow-redirect off, or re-validate each
 *     hop). The deliverer here does not follow redirects, which sidesteps this.
 */

export interface SsrfOptions {
  /** Allow loopback / private targets (local dev, tests). Default false. */
  allowLoopback?: boolean;
  /**
   * Host-suffix allow-list. When non-empty, a target host must equal or end with
   * (".suffix") one of these, else it is rejected (deny-by-default).
   */
  allowlist?: string[];
}

/** Read SSRF options from the environment. */
export function ssrfOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): SsrfOptions {
  const allowlist = (env.KEEPER_WEBHOOK_ALLOWLIST ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
  return {
    allowLoopback: env.KEEPER_ALLOW_LOOPBACK === "1",
    allowlist,
  };
}

/** Thrown when a webhook target is rejected by the SSRF guard. */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

/**
 * Validate a webhook URL. Throws {@link SsrfError} if it must be rejected;
 * returns the parsed URL on success.
 */
export function assertSafeWebhookUrl(target: string, opts: SsrfOptions = {}): URL {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new SsrfError(`Invalid webhook URL: ${target}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfError(`Webhook URL must be http(s), got ${url.protocol}`);
  }

  const host = url.hostname.toLowerCase();

  // Deny-by-default allow-list, when configured.
  if (opts.allowlist && opts.allowlist.length > 0) {
    const ok = opts.allowlist.some(
      (suffix) => host === suffix || host.endsWith(`.${suffix}`),
    );
    if (!ok) {
      throw new SsrfError(
        `Webhook host "${host}" is not in KEEPER_WEBHOOK_ALLOWLIST.`,
      );
    }
  }

  if (opts.allowLoopback) return url;

  if (isBlockedHost(host)) {
    throw new SsrfError(
      `Webhook host "${host}" resolves to a private/loopback/metadata address and is blocked.`,
    );
  }
  return url;
}

/** True if a host literal is a loopback / private / link-local / metadata address. */
export function isBlockedHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, ""); // strip IPv6 brackets

  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "metadata.google.internal") return true;

  // IPv6 loopback / unique-local / link-local.
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // fc00::/7 ULA
  if (h.startsWith("fe80")) return true; // link-local

  // IPv4 literal?
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const octets = m.slice(1, 5).map((n) => Number(n));
    if (octets.some((o) => o > 255)) return true; // malformed -> block
    const [a, b] = octets;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
    return false;
  }
  // A non-IP hostname: not range-checkable without DNS (see TODO). Allowed here
  // unless the allow-list (above) constrained it.
  return false;
}
