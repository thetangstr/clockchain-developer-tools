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
 *   - Blocks literal private / loopback / link-local / metadata IP hosts, INCLUDING
 *     IPv4-mapped IPv6 forms (`::ffff:169.254.169.254`, `::ffff:7f00:1`) and the
 *     unspecified address (`::`).
 *   - Host-suffix allow-list. `requireAllowlist` (prod/HTTP mode) makes it
 *     MANDATORY: a host not on the list is refused even if it looks public, and an
 *     empty list refuses everything (forces operators to configure egress).
 *   - `allowLoopback` opt-in so local dev / tests can target 127.0.0.1.
 *
 * TODO (deferred, important for prod):
 *   - DNS resolution + re-check at connect time to defeat DNS-rebinding (a public
 *     hostname that resolves to a private IP, or flips between the registration
 *     check and the delivery connect — a TOCTOU). Today only LITERAL IP hosts are
 *     range-checked; hostnames are checked only against the allow-list. Production
 *     should resolve, pin the resolved IP, and connect to that pinned IP. Until
 *     then, set `requireAllowlist` so only known hosts are reachable.
 *   - Block redirects to private ranges. The deliverer sends `redirect: "manual"`,
 *     so a 30x is treated as a non-2xx failure rather than being followed.
 */

export interface SsrfOptions {
  /** Allow loopback / private targets (local dev, tests). Default false. */
  allowLoopback?: boolean;
  /**
   * Host-suffix allow-list. When non-empty (or when `requireAllowlist`), a target
   * host must equal or end with (".suffix") one of these, else it is rejected.
   */
  allowlist?: string[];
  /**
   * Enforce the allow-list even when empty (deny-by-default egress). Intended for
   * HTTP/prod mode where untrusted callers register targets. Default false.
   */
  requireAllowlist?: boolean;
}

/**
 * Read SSRF options from the environment.
 *
 * `requireAllowlist` is ON when `KEEPER_REQUIRE_ALLOWLIST=1`, OR implicitly in
 * HTTP mode (`MCP_TRANSPORT=http`) unless `KEEPER_ALLOW_ANY_HOST=1` — so a hosted,
 * multi-caller keeper refuses to deliver to a non-allowlisted host by default.
 */
export function ssrfOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): SsrfOptions {
  const allowlist = (env.KEEPER_WEBHOOK_ALLOWLIST ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
  const httpMode = (env.MCP_TRANSPORT ?? "").toLowerCase() === "http";
  return {
    allowLoopback: env.KEEPER_ALLOW_LOOPBACK === "1",
    allowlist,
    requireAllowlist:
      env.KEEPER_REQUIRE_ALLOWLIST === "1" ||
      (httpMode && env.KEEPER_ALLOW_ANY_HOST !== "1"),
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
  const allowlist = opts.allowlist ?? [];

  // Allow-list: deny-by-default when configured or when mandatory (prod/HTTP).
  if (opts.requireAllowlist || allowlist.length > 0) {
    const ok = allowlist.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
    if (!ok) {
      throw new SsrfError(
        allowlist.length === 0
          ? `Webhook host "${host}" rejected: no KEEPER_WEBHOOK_ALLOWLIST configured (deny-by-default).`
          : `Webhook host "${host}" is not in KEEPER_WEBHOOK_ALLOWLIST.`,
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
  const h = host.replace(/^\[|\]$/g, "").toLowerCase(); // strip IPv6 brackets

  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "metadata.google.internal") return true;

  // IPv6 loopback / unspecified / unique-local / link-local.
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (h === "::" || h === "::0" || /^(0:){7}0$/.test(h)) return true; // unspecified
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // fc00::/7 ULA
  if (h.startsWith("fe80")) return true; // link-local

  // IPv4-mapped IPv6 (::ffff:a.b.c.d  or  ::ffff:hhhh:hhhh) — unwrap and range-check
  // the embedded IPv4, so [::ffff:169.254.169.254] / [::ffff:7f00:1] can't bypass.
  const mapped = mappedIpv4Octets(h);
  if (mapped) return blockedIpv4(mapped);

  // Dotted IPv4 literal.
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) return blockedIpv4(m.slice(1, 5).map(Number));

  // A non-IP hostname: not range-checkable without DNS (see TODO). Allowed here
  // unless the allow-list (above) constrained it.
  return false;
}

/** Extract the embedded IPv4 octets from an IPv4-mapped IPv6 literal, or null. */
function mappedIpv4Octets(h: string): number[] | null {
  let m = /^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) return m.slice(1, 5).map(Number);
  m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (m) {
    const hi = parseInt(m[1], 16);
    const lo = parseInt(m[2], 16);
    return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
  }
  return null;
}

/** Range-check IPv4 octets against blocked ranges. */
function blockedIpv4(octets: number[]): boolean {
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    return true; // malformed -> block
  }
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
