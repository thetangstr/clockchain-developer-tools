import { createHash, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ClockchainClient, readConfigFromEnv, type ClockchainConfig } from "@clockchain/core";
import { buildServer } from "./server.js";
import { LANDING_HTML, INSTALL_TXT, MCP_MANIFEST } from "./landing.js";
import { CLOCK_TOOLS_HTML, CLOCK_TOOLS_TXT } from "./clock-tools-page.js";
import { HANDSHAKE_SOP_HTML, HANDSHAKE_SOP_TXT } from "./handshake-sop-page.js";
import {
  mintToken,
  verifyToken,
  verifyTrialToken,
  mintTrialToken,
  mintClaim,
  looksLikeSelfServe,
  verifyHandshakeSessionToken,
  type HandshakeSessionTokenPayload,
  type TokenPayload,
  type TrialTokenPayload,
} from "./token.js";
import { getRuntimeAgentHandshakeInvitationService } from "./agent-handshake/invitation-store.js";
import { createStore, type Store } from "./store.js";
import {
  getOrCreateSession,
  newEphemeralDid,
  normalizeChannel,
  claimTtlSeconds,
  hashClaim,
} from "./session.js";
import {
  buildKeeperGate,
  type Entitlement,
  type KeeperGate,
} from "./entitlement.js";
import { runPromote } from "./promote.js";
import {
  createV2PublicHttpHandler,
} from "./agent-handshake/v2/public-server.js";
import {
  buildV2Manifest,
  readV2ReleasePin,
} from "./agent-handshake/v2/instructions.js";
import { createRuntimeV2Coordinator } from "./agent-handshake/v2/coordinator.js";
import { buildStandaloneDiscovery, createStandaloneHttpHandler, limiter as keyedWindowLimiter } from "./standalone-handshake/public-server.js";
import { createRuntimeStandaloneCoordinator } from "./standalone-handshake/coordinator.js";
import { normalizeRelayBaseUrl } from "./handshake/relay.js";
import { MetricsRegistry, bounded } from "./metrics.js";
import { createStatusCache, type StatusDeps } from "./status.js";
import { renderStatusPage } from "./status-page.js";
import { V2_PUBLIC_TOOL_NAMES } from "./agent-handshake/v2/public-tools.js";
import { V2RoleAccessError } from "./agent-handshake/v2/access.js";

/**
 * HTTP entry point (secondary; stdio is primary).
 *
 * Serves MCP over StreamableHTTPServerTransport at POST/GET/DELETE on the MCP
 * endpoint. A simple bearer check is applied when MCP_AUTH_TOKENS is set
 * (comma-separated list of accepted tokens). When unset, auth is open — only
 * intended for local/trusted use.
 *
 * This uses stateless transports (one per request) for simplicity.
 */
/** Parse a comma-separated MCP_AUTH_TOKENS value into a token list. */
export function parseTokens(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

const firstHeader = (h: string | string[] | undefined): string =>
  (Array.isArray(h) ? h[0] : h) ?? "";

/** Path portion of a request URL, without the query string. */
export const pathOf = (url: string | undefined): string => (url ?? "").split("?")[0];

/**
 * Best-effort client IP for rate limiting. Behind the GCP load balancer / Cloud
 * Run, the socket's remote address is a Google proxy IP (identical for every
 * caller), so keying limits on it would create a single global bucket. The real
 * client is the first entry of `X-Forwarded-For`. This is for abuse mitigation,
 * not auth — XFF is client-spoofable, but spoofing only rotates the rate-limit
 * key, and actual tool usage is independently capped per token + at the gateway.
 */
export function clientIp(
  headers: Record<string, string | string[] | undefined>,
  remoteAddr: string | undefined,
): string {
  const xff = firstHeader(headers["x-forwarded-for"]);
  const first = xff.split(",")[0]?.trim();
  return first || remoteAddr || "unknown";
}

/**
 * Bring-your-own-key: if the caller presents their own Clockchain credentials as
 * request headers, return them as a config override so the per-request server
 * uses THEIR key (their credits). Returns undefined when no `x-clockchain-api-key`
 * is present, in which case the server uses the delegated (env) key. The endpoint
 * is fixed server-side (callers cannot redirect it).
 *
 * RECOMMENDED per-user production path (per-user auth): BYO key gives each user their
 * own identity, credit budget, and rate-limit bucket. The self-serve `/token`
 * mint is a SHARED testnet pool for quick trials only. MEDIUM-TERM TODO: map a
 * token's `sub` to a distinct delegated sub-key / credit bucket so `/token` can
 * offer per-user isolation without the user supplying their own key.
 */
export function clockchainOverrides(
  headers: Record<string, string | string[] | undefined>,
): Partial<ClockchainConfig> | undefined {
  const apiKey = firstHeader(headers["x-clockchain-api-key"]).trim();
  if (!apiKey) return undefined;
  const o: Partial<ClockchainConfig> = { apiKey };
  const clientId = firstHeader(headers["x-clockchain-client-id"]).trim();
  const walletId = firstHeader(headers["x-clockchain-wallet-id"]).trim();
  if (clientId) o.clientId = clientId;
  if (walletId) o.walletId = walletId;
  return o;
}

/**
 * Authorize a request against the token list. When no tokens are configured,
 * auth is open (local/trusted use). A token is accepted via either
 * `Authorization: Bearer <token>` or `x-api-key: <token>` - both are documented
 * for testers, so supporting both avoids a 401 from picking the "wrong" header.
 *
 * Pure and exported so it can be unit-tested without binding a port.
 */
export function isAuthorized(
  headers: { authorization?: string | string[]; "x-api-key"?: string | string[] },
  tokens: string[],
): boolean {
  if (tokens.length === 0) return true;
  const bearer = /^Bearer\s+(.+)$/i.exec(firstHeader(headers.authorization));
  if (bearer && tokens.includes(bearer[1].trim())) return true;
  const apiKey = firstHeader(headers["x-api-key"]).trim();
  return apiKey.length > 0 && tokens.includes(apiKey);
}

/**
 * The credential the caller presented as an MCP token — the `x-api-key` value or
 * the `Authorization: Bearer <token>` value (x-api-key wins if both are set).
 * Empty string when neither is present. Used by the forgiving auth fallback.
 */
export function presentedApiKey(
  headers: { authorization?: string | string[]; "x-api-key"?: string | string[] },
): string {
  const apiKey = firstHeader(headers["x-api-key"]).trim();
  if (apiKey) return apiKey;
  const bearer = /^Bearer\s+(.+)$/i.exec(firstHeader(headers.authorization));
  return bearer ? bearer[1].trim() : "";
}

/**
 * Forgiving fallback: build a BYO override from a key presented in the MCP-token
 * slot. A Clockchain API key pasted into `x-api-key` (the #1 install mistake) is
 * not a valid MCP token, so instead of a 401 we treat it as a Clockchain key and
 * let the gateway be the real gate — an invalid key fails on the first tool call
 * with the gateway's own error, not an opaque 401 here. Picks up client/wallet id
 * from the x-clockchain-* headers if the caller also set those.
 */
export function clockchainOverridesFromKey(
  apiKey: string,
  headers: Record<string, string | string[] | undefined>,
): Partial<ClockchainConfig> {
  const o: Partial<ClockchainConfig> = { apiKey };
  const clientId = firstHeader(headers["x-clockchain-client-id"]).trim();
  const walletId = firstHeader(headers["x-clockchain-wallet-id"]).trim();
  if (clientId) o.clientId = clientId;
  if (walletId) o.walletId = walletId;
  return o;
}

/** True for the unauthenticated health-probe routes (GET /health|/healthz). */
export function isHealthCheck(
  method: string | undefined,
  url: string | undefined,
): boolean {
  return method === "GET" && (url === "/health" || url === "/healthz");
}

/**
 * Identify the caller for rate-limiting: the presented token if any, else the
 * remote IP. Tokens are already validated by the time this is used, so keying on
 * the token gives a per-tester limit; the IP fallback covers health/edge cases.
 *
 * `selfServeJti` is the `jti` of an ALREADY-VERIFIED self-serve token (verified
 * once by the auth step, threaded in to avoid a second HMAC verify per request).
 * When present we key on `jti:<jti>` so each minted token gets its own bucket —
 * a shared-egress public app that mints many tokens isn't collapsed into one IP
 * bucket (per-user auth).
 *
 * SECURITY: we deliberately do NOT key on a token's `sub`. `sub` is supplied on
 * the unauthenticated mint endpoint, so an attacker could mint `sub=<victim>` and
 * burn the victim's bucket (targeted DoS), or rotate `sub` to escape limits.
 * `sub` only becomes a safe bucketing key once it derives from an authenticated
 * principal (medium-term: BYO-key-derived identity / real per-user auth).
 */
export function callerKey(
  headers: {
    authorization?: string | string[];
    "x-api-key"?: string | string[];
    "x-clockchain-api-key"?: string | string[];
  },
  remoteAddr: string | undefined,
  selfServeJti?: string,
): string {
  // jti is unforgeable (it comes from a signature-verified token) and unique per
  // mint, so it is a safe per-token bucket.
  if (selfServeJti) return `jti:${selfServeJti}`;
  const bearer = /^Bearer\s+(.+)$/i.exec(firstHeader(headers.authorization));
  const token = bearer ? bearer[1].trim() : firstHeader(headers["x-api-key"]).trim();
  if (token) return `tok:${token}`;
  // Bring-your-own-key requests carry no MCP token; key them by their own
  // Clockchain key so the per-caller rate limit still applies. This IS an
  // authenticated per-principal bucket (the key proves the identity).
  const cck = firstHeader(headers["x-clockchain-api-key"]).trim();
  if (cck) return `cck:${cck}`;
  return `ip:${remoteAddr ?? "unknown"}`;
}

/**
 * Stable caller-state key without retaining an MCP token or Clockchain API key.
 * The raw credential-derived caller key remains confined to the current request.
 */
export function principalIdForCallerKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

/**
 * One opaque caller id for every stateful per-caller subsystem. A BYO key from
 * the resolved auth branch takes precedence over any co-present token headers;
 * otherwise {@link callerKey} preserves credential-kind separation before hashing.
 */
export function callerPrincipalId(
  headers: IncomingHttpHeaders,
  remoteAddr?: string,
  selfServeJti?: string,
  resolvedByoApiKey?: string,
): string {
  const key = resolvedByoApiKey
    ? `cck:${resolvedByoApiKey}`
    : callerKey(headers, remoteAddr, selfServeJti);
  return principalIdForCallerKey(key);
}

/**
 * Sanitize a caller-supplied `sub` before it is logged or embedded in a token.
 * Strips control chars, restricts to a conservative identifier charset, and caps
 * the length — defends against log injection and token/Map bloat (per-user auth). The
 * value is a non-authoritative LABEL only; it never affects rate-limit bucketing.
 */
export function sanitizeSub(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  // Allow letters, digits, and a few email/id-safe punctuation chars; drop the
  // rest (including all control chars). Cap at 128 chars.
  const cleaned = raw.replace(/[^A-Za-z0-9._@:+-]/g, "").slice(0, 128);
  return cleaned.length > 0 ? cleaned : undefined;
}

/**
 * Outcome of a rate-limit check. Carries the data needed to set standard
 * `X-RateLimit-*` (and, when blocked, `Retry-After`) response headers — per-user auth.
 */
export interface RateLimitResult {
  /** True if the request is allowed; false if the key is over its limit. */
  allowed: boolean;
  /** The window's request ceiling (0 when the limiter is disabled). */
  limit: number;
  /** Requests left in the current window (never negative). */
  remaining: number;
  /** Epoch milliseconds when the current window resets. */
  resetAt: number;
}

/**
 * Fixed-window per-key rate limiter. Disabled (always allows) when perMin <= 0.
 * `windowMs` defaults to one minute; pass a larger window (e.g. one hour) to cap
 * a slower action like token minting. Pure and injectable (`now`) for tests.
 *
 * `allow()` returns a {@link RateLimitResult} (not a bare boolean) so callers
 * can emit `X-RateLimit-*` / `Retry-After` headers on both 429 and success.
 *
 * Memory is bounded (per-user auth): the per-key `hits` map is pruned of expired
 * windows opportunistically (the stale entry for a missed key is overwritten)
 * and via a periodic full sweep, so an attacker rotating keys (e.g. a fresh
 * `jti`/IP per request) cannot grow the map without bound.
 */
export function createRateLimiter(perMin: number, windowMs = 60_000) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  // Full sweep at most once per window; also force a sweep if the map grows past
  // this many live keys (defends against a burst of distinct keys within one
  // window before the time-based sweep would fire).
  const PRUNE_INTERVAL = windowMs;
  const MAX_KEYS = 50_000;
  let lastPrune = 0;
  const prune = (now: number): void => {
    for (const [k, v] of hits) {
      if (now >= v.resetAt) hits.delete(k);
    }
    lastPrune = now;
  };
  return {
    enabled: perMin > 0,
    /** Number of tracked keys (exposed for tests/observability). */
    size(): number {
      return hits.size;
    },
    allow(key: string, now: number = Date.now()): RateLimitResult {
      if (perMin <= 0) {
        return { allowed: true, limit: 0, remaining: 0, resetAt: now };
      }
      if (now - lastPrune >= PRUNE_INTERVAL || hits.size > MAX_KEYS) {
        prune(now);
      }
      let e = hits.get(key);
      if (!e || now >= e.resetAt) {
        e = { count: 1, resetAt: now + windowMs };
        hits.set(key, e);
        return { allowed: true, limit: perMin, remaining: perMin - 1, resetAt: e.resetAt };
      }
      if (e.count >= perMin) {
        return { allowed: false, limit: perMin, remaining: 0, resetAt: e.resetAt };
      }
      e.count++;
      return { allowed: true, limit: perMin, remaining: perMin - e.count, resetAt: e.resetAt };
    },
  };
}

/**
 * Build standard rate-limit response headers from a {@link RateLimitResult}.
 * Always sets `X-RateLimit-Limit/Remaining/Reset` (Reset as a unix-seconds
 * timestamp); adds `Retry-After` (seconds) only when the request was blocked.
 * `now` is injectable for tests.
 */
export function rateLimitHeaders(
  r: RateLimitResult,
  now: number = Date.now(),
): Record<string, string> {
  const headers: Record<string, string> = {
    "X-RateLimit-Limit": String(r.limit),
    "X-RateLimit-Remaining": String(Math.max(0, r.remaining)),
    "X-RateLimit-Reset": String(Math.ceil(r.resetAt / 1000)),
  };
  if (!r.allowed) {
    headers["Retry-After"] = String(Math.max(0, Math.ceil((r.resetAt - now) / 1000)));
  }
  return headers;
}

/**
 * Read and JSON-parse a request body, capped at 1 MB (the MCP transport reads its
 * own body; this is only for our small JSON control endpoints like /promote).
 * Rejects on invalid JSON or an over-size body.
 */
/**
 * JSON-RPC methods every MCP client sends just to attach — initialize, the
 * initialized notification, ping, and the list_* discovery calls. They are cheap
 * (no Clockchain call behind them) and they are exactly what a fresh session does
 * first, so they are exempt from the per-caller rate limit: a client that reaches
 * the limit while polling must still be able to open its next session, and the
 * 30/min demo budget should be spent on tool calls, not on handshakes. Only
 * `tools/call` (and any unknown method) counts. Auth still applies.
 */
export const RATE_LIMIT_EXEMPT_METHODS: ReadonlySet<string> = new Set([
  "initialize",
  "notifications/initialized",
  "ping",
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
]);

/** True when a parsed JSON-RPC body (single message or batch) is lifecycle/discovery only. */
export function isRateLimitExempt(body: unknown): boolean {
  const msgs = Array.isArray(body) ? body : [body];
  if (msgs.length === 0) return false;
  return msgs.every(
    (m) => !!m && typeof m === "object" && typeof (m as { method?: unknown }).method === "string" &&
      RATE_LIMIT_EXEMPT_METHODS.has((m as { method: string }).method),
  );
}

export function readJsonBody(req: IncomingMessage, maxBytes = 1_000_000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let data = "";
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      data += chunk.toString("utf8");
    });
    req.on("end", () => {
      try {
        resolve(data.trim() ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

export async function runHttp(): Promise<void> {
  // PORT is injected by Cloud Run / most PaaS hosts (8080); MCP_PORT is our own
  // override; 3000 is the local default. Honor them in that order.
  const port = Number(process.env.PORT ?? process.env.MCP_PORT ?? "3000");
  const tokens = parseTokens(process.env.MCP_AUTH_TOKENS);

  // Footgun guard: for a delegated/hosted deploy, set MCP_REQUIRE_AUTH=1 so the
  // server refuses to start without tokens (otherwise auth is open by design).
  if (tokens.length === 0) {
    if (/^(1|true|yes)$/i.test(process.env.MCP_REQUIRE_AUTH ?? "")) {
      console.error(
        "[clockchain-mcp] FATAL: MCP_REQUIRE_AUTH is set but MCP_AUTH_TOKENS is " +
          "empty. Refusing to start an open, credential-holding HTTP endpoint.",
      );
      process.exit(1);
    }
    console.error(
      "[clockchain-mcp] WARNING: no MCP_AUTH_TOKENS set - the HTTP endpoint is " +
        "OPEN (no auth). Only do this for local/trusted use. Set MCP_AUTH_TOKENS " +
        "(and MCP_REQUIRE_AUTH=1) for any networked/delegated deploy.",
    );
  }

  const perMin = Number(process.env.MCP_RATE_PER_MIN ?? "0");
  const limiter = createRateLimiter(Number.isFinite(perMin) ? perMin : 0);

  // Self-serve testnet tokens (instant, signed, no DB). Enabled only when a
  // signing secret is configured; otherwise /token is off and no signed token
  // validates. Minting is ALWAYS capped by a per-IP abuse ceiling (default
  // 10/hour) — this is the only guard on the shared delegated-key budget, so it
  // must never be bypassable. `sub` is NOT used to bucket mints: it is supplied
  // unauthenticated, so keying on it would let an attacker rotate `sub` to escape
  // the ceiling and drain the shared budget (per-user auth).
  const signingSecret = process.env.MCP_TOKEN_SIGNING_SECRET ?? "";
  const selfServeEnabled = signingSecret.length > 0;
  const mintPerHour = Number(process.env.MCP_TOKEN_MINT_PER_HOUR ?? "10");
  const mintLimiter = createRateLimiter(
    Number.isFinite(mintPerHour) ? mintPerHour : 10,
    60 * 60_000,
  );
  const tokenTtlDays = Number(process.env.MCP_TOKEN_TTL_DAYS ?? "7");

  // Session + entitlement layer (LLD §4.1 A1/A8). The store is process-wide (each
  // request builds a fresh MCP server, so a per-request store would never
  // accumulate). Claim tokens use a DISTINCT secret (LLD §16); fall back to the
  // signing secret in demo mode so the layer still runs without extra config.
  const store: Store = createStore();
  const promoteSecret = process.env.MCP_PROMOTE_SECRET || signingSecret;

  let publicHandshakeHandler: ReturnType<typeof createV2PublicHttpHandler> | undefined;
  let publicHandshakeCoordinator: ReturnType<typeof createRuntimeV2Coordinator> | undefined;
  const getPublicHandshakeHandler = () => {
    if (publicHandshakeHandler) return publicHandshakeHandler;
    const pin = readV2ReleasePin(process.env);
    publicHandshakeCoordinator ??= createRuntimeV2Coordinator(process.env);
    publicHandshakeHandler = createV2PublicHttpHandler({
      pin,
      trustedProxy: process.env.AGENT_HANDSHAKE_TRUSTED_PROXY,
      invitePerHour: Number(process.env.AGENT_HANDSHAKE_INVITES_PER_HOUR ?? "5"),
      callsPerMinute: Number(process.env.AGENT_HANDSHAKE_CALLS_PER_MINUTE ?? "120"),
      invoke: (name, args) => instrumentedInvoke(name, args as Record<string, unknown>, (n, a) => publicHandshakeCoordinator!.invoke(n, a as Record<string, never>)),
      onRateLimited: (surface) => rlEvents.inc({ surface: bounded(surface, RL_SURFACES) }),
    });
    return publicHandshakeHandler;
  };

  // Keyless chain-verify route state: a shared client for the public
  // /connect/verify route plus a per-IP limiter and an immutable-block cache.
  let chainVerifyClient: ClockchainClient | undefined;
  const getChainVerifyClient = () => (chainVerifyClient ??= new ClockchainClient(readConfigFromEnv(process.env)));
  const chainVerifyCache = new Map<string, unknown>();
  const allowChainVerify = keyedWindowLimiter(Number(process.env.STANDALONE_HANDSHAKE_VERIFY_PER_MINUTE ?? "60"), 60_000, Date.now);

  let standaloneHandshakeHandler: ReturnType<typeof createStandaloneHttpHandler> | undefined;
  let standaloneHandshakeCoordinator: ReturnType<typeof createRuntimeStandaloneCoordinator> | undefined;
  const getStandaloneHandshakeHandler = () => {
    if (standaloneHandshakeHandler) return standaloneHandshakeHandler;
    standaloneHandshakeCoordinator ??= createRuntimeStandaloneCoordinator(process.env);
    standaloneHandshakeHandler = createStandaloneHttpHandler({
      trustedProxy: process.env.STANDALONE_HANDSHAKE_TRUSTED_PROXY,
      invitesPerHour: Number(process.env.STANDALONE_HANDSHAKE_INVITES_PER_HOUR ?? "5"),
      callsPerMinute: Number(process.env.STANDALONE_HANDSHAKE_CALLS_PER_MINUTE ?? "120"),
      invoke: (name, args) => standaloneHandshakeCoordinator!.invoke(name, args),
    });
    return standaloneHandshakeHandler;
  };

  // ---- Status + operational metrics -------------------------------------
  // Bounded label vocabularies: every label value funnels through `bounded()`
  // so a surprise value collapses to "other" instead of minting a series.
  // Session ids, role-access handles, keys, addresses, digests, statements,
  // and raw error text are never labels.
  const metrics = new MetricsRegistry();
  const ROUTE_CLASSES = [
    "health", "status", "status_json", "readyz", "metrics", "clock_tools", "sop",
    "llms", "manifest", "handshake_manifest", "standalone_manifest", "connect_verify",
    "connect_mcp", "handshake_mcp", "invitation_exchange", "token", "promote",
    "landing", "mcp_rpc", "keeper", "other",
  ] as const;
  const STATUS_CLASSES = ["2xx", "3xx", "4xx", "5xx"] as const;
  const RESULT_KINDS = ["ok", "fail_closed", "error", "rate_limited"] as const;
  const FAIL_REASONS = [
    "unavailable", "role_access", "rate_limited", "bad_request", "internal",
  ] as const;
  const HANDSHAKE_STAGES = [
    "invited", "joined", "identity_claimed", "awaiting_funding",
    "awaiting_identity_registration", "awaiting_counterpart", "awaiting_proposal",
    "party_ready", "sign_proposal", "proposal_checkpoint_submitted",
    "proposal_submitted", "sign_acceptance", "acceptance_checkpoint_submitted",
    "acceptance_submitted", "awaiting_descriptor", "awaiting_anchors",
    "sign_evidence", "evidence_submitted", "certificate_available",
  ] as const;
  const DEP_NAMES = ["relay_discovery", "relay_result", "gateway_pool", "evm_rpc"] as const;
  const RL_SURFACES = ["handshake_call", "handshake_invite", "token_mint", "chain_verify", "mcp_call"] as const;

  const httpRequests = metrics.counter("clockchain_http_requests_total", "HTTP requests by route class and status class.");
  const httpDuration = metrics.histogram("clockchain_http_request_duration_seconds", "HTTP request duration by route class.");
  const toolCalls = metrics.counter("clockchain_handshake_tool_calls_total", "Agent-handshake tool invocations by tool and result kind.");
  const toolDuration = metrics.histogram("clockchain_handshake_tool_duration_seconds", "Agent-handshake tool invocation duration by tool.");
  const stageCounter = metrics.counter("clockchain_handshake_stage_total", "Handshake stage observations by stage name.");
  const failCounter = metrics.counter("clockchain_handshake_failures_total", "Handshake tool failures by bounded reason.");
  const completedCounter = metrics.counter("clockchain_handshake_completed_total", "Completed handshakes by outcome.");
  const inflightGauge = metrics.gauge("clockchain_handshake_inflight", "Handshake sessions currently in flight (not yet terminal).");
  const httpActiveGauge = metrics.gauge("clockchain_http_requests_active", "HTTP requests currently being served.");
  const toolActiveGauge = metrics.gauge("clockchain_handshake_tool_active", "Handshake tool invocations currently in flight.");
  const depUp = metrics.gauge("clockchain_dependency_up", "Dependency probe result: 1 up, 0 down.");
  const depDuration = metrics.histogram("clockchain_dependency_probe_seconds", "Dependency probe latency by probe.");
  const rlEvents = metrics.counter("clockchain_rate_limit_events_total", "Rate-limit rejections by surface.");
  const uptimeGauge = metrics.gauge("process_uptime_seconds", "Process uptime in seconds.");

  function classifyRoute(method: string | undefined, url: string | undefined, accept: string): string {
    const p = pathOf(url);
    if (method === "GET" && (p === "/health" || p === "/healthz")) return "health";
    if (method === "GET" && p === "/status") return "status";
    if (method === "GET" && p === "/status.json") return "status_json";
    if (method === "GET" && p === "/readyz") return "readyz";
    if (method === "GET" && p === "/metrics") return "metrics";
    if (method === "GET" && (p === "/clock-tools" || p === "/clock-tools.txt")) return "clock_tools";
    if (method === "GET" && (p === "/handshake/sop" || p === "/handshake/sop.txt")) return "sop";
    if (method === "GET" && (p === "/llms.txt" || p === "/install.txt")) return "llms";
    if (method === "GET" && p === "/.well-known/mcp.json") return "manifest";
    if (method === "GET" && p === "/.well-known/agent-handshake.json") return "handshake_manifest";
    if (method === "GET" && p === "/.well-known/standalone-handshake.json") return "standalone_manifest";
    if (method === "GET" && p === "/connect/verify") return "connect_verify";
    if (p === "/connect/mcp") return "connect_mcp";
    if (p === "/handshake/mcp") return "handshake_mcp";
    if (p === "/handshake/invitations/exchange") return "invitation_exchange";
    if (method === "POST" && p === "/token") return "token";
    if (method === "POST" && p === "/promote") return "promote";
    if (p === "/keeper" || p.startsWith("/keeper/")) return "keeper";
    if (method === "GET" && accept.includes("text/html")) return "landing";
    if (p === "/mcp") return "mcp_rpc";
    return "other";
  }

  function statusClass(code: number): string {
    return bounded(`${Math.floor(code / 100)}xx`, STATUS_CLASSES, "5xx");
  }

  // In-flight handshake sessions: sessionId -> expiry. Session ids live only
  // inside this map (never as labels); entries drop on terminal stage or when
  // the session deadline passes.
  const inflight = new Map<string, number>();
  const counted = new Map<string, number>();
  function trackSession(sessionId: unknown, deadlineMs: unknown, nowMs: number): void {
    if (typeof sessionId !== "string") return;
    for (const [id, exp] of inflight) if (nowMs >= exp) inflight.delete(id);
    for (const [id, exp] of counted) if (nowMs >= exp) counted.delete(id);
    if (!inflight.has(sessionId)) {
      inflight.set(sessionId, typeof deadlineMs === "string" ? Number(deadlineMs) || nowMs + 600_000 : nowMs + 600_000);
    }
    inflightGauge.set({}, inflight.size);
  }
  function completeSession(sessionId: unknown, nowMs: number): void {
    if (typeof sessionId !== "string" || counted.has(sessionId)) return;
    counted.set(sessionId, inflight.get(sessionId) ?? nowMs + 600_000);
    if (inflight.delete(sessionId)) inflightGauge.set({}, inflight.size);
    completedCounter.inc({ outcome: "verified" });
  }

  async function instrumentedInvoke(name: string, args: Record<string, unknown>, invoke: (n: string, a: unknown) => Promise<unknown>) {
    const tool = bounded(name, V2_PUBLIC_TOOL_NAMES as readonly string[], "other");
    const started = Date.now();
    toolActiveGauge.inc();
    try {
      const result = await invoke(name, args);
      toolDuration.observe({ tool }, (Date.now() - started) / 1000);
      const r = (result && typeof result === "object" && !Array.isArray(result) ? result : {}) as Record<string, unknown>;
      trackSession(r.sessionId, r.sessionDeadlineMs ?? r.invitationExpiresAtMs, started);
      if (typeof r.error === "string") {
        toolCalls.inc({ tool, result: bounded("fail_closed", RESULT_KINDS) });
        failCounter.inc({ reason: bounded(r.error === "HANDSHAKE_UNAVAILABLE" ? "unavailable" : undefined, FAIL_REASONS) });
        return result;
      }
      toolCalls.inc({ tool, result: bounded("ok", RESULT_KINDS) });
      if (typeof r.stage === "string") stageCounter.inc({ stage: bounded(r.stage, HANDSHAKE_STAGES) });
      if (r.stage === "certificate_available" || r.certificateSummary) {
        completeSession(r.sessionId, started);
      }
      return result;
    } catch (err) {
      toolDuration.observe({ tool }, (Date.now() - started) / 1000);
      const reason = err instanceof V2RoleAccessError ? "role_access"
        : /rate_limit/i.test(String((err as Error)?.message ?? "")) ? "rate_limited"
        : "internal";
      toolCalls.inc({ tool, result: bounded(reason === "rate_limited" ? "rate_limited" : "error", RESULT_KINDS) });
      failCounter.inc({ reason: bounded(reason, FAIL_REASONS) });
      throw err;
    } finally {
      toolActiveGauge.dec();
    }
  }

  // Live dependency probes for /status + /readyz. Each probe also feeds the
  // dependency metrics — probe latency and up/down are operational signals too.
  const processStartedAtMs = Date.now();
  async function fetchJsonTimed(url: string, timeoutMs: number): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { headers: { accept: "application/json" }, signal: controller.signal });
      if (!response.ok) throw Object.assign(new Error(`http_${response.status}`), { httpStatus: response.status });
      return await response.json();
    } finally {
      clearTimeout(timer);
    }
  }
  const statusDeps: StatusDeps = {
    now: () => Date.now(),
    fetchJson: async (url, timeoutMs) => {
      const dep = bounded(url.includes("/v1/discovery/") ? "relay_discovery" : "relay_result", DEP_NAMES);
      const started = Date.now();
      try {
        const out = await fetchJsonTimed(url, timeoutMs);
        depDuration.observe({ dep }, (Date.now() - started) / 1000);
        depUp.set({ dep }, 1);
        return out;
      } catch (e) {
        depDuration.observe({ dep }, (Date.now() - started) / 1000);
        depUp.set({ dep }, 0);
        throw e;
      }
    },
    fetchEvmChainId: async (timeoutMs) => {
      const started = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(process.env.EVM_RPC_URL ?? process.env.SEPOLIA_RPC_URL ?? "", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
          signal: controller.signal,
        });
        const json = await response.json() as { result?: unknown };
        depDuration.observe({ dep: bounded("evm_rpc", DEP_NAMES) }, (Date.now() - started) / 1000);
        depUp.set({ dep: bounded("evm_rpc", DEP_NAMES) }, 1);
        return String(json.result ?? "");
      } catch (e) {
        depDuration.observe({ dep: bounded("evm_rpc", DEP_NAMES) }, (Date.now() - started) / 1000);
        depUp.set({ dep: bounded("evm_rpc", DEP_NAMES) }, 0);
        throw e;
      } finally {
        clearTimeout(timer);
      }
    },
    fetchPoolParticipation: async (timeoutMs) => {
      const started = Date.now();
      void timeoutMs; // the gateway client carries its own timeout
      try {
        // getTimestamp resolves whenever the gateway answers; participation
        // is read rename-tolerantly ("nodeParticipation%" vs "nodeParticipation",
        // same as getPoolHealth) but a missing field yields undefined — gateway
        // reachable yet pool state unreported, not "unreachable".
        const ts = await getChainVerifyClient().getTimestamp();
        depDuration.observe({ dep: bounded("gateway_pool", DEP_NAMES) }, (Date.now() - started) / 1000);
        depUp.set({ dep: bounded("gateway_pool", DEP_NAMES) }, 1);
        const raw = ts["nodeParticipation%"] ?? ts.nodeParticipation;
        const parsed = raw == null ? undefined : Number(raw);
        return {
          totalNodes: Number(ts.totalNodes ?? 0) || 0,
          nodeParticipationPct: parsed === undefined || Number.isNaN(parsed) ? undefined : parsed,
        };
      } catch (e) {
        depDuration.observe({ dep: bounded("gateway_pool", DEP_NAMES) }, (Date.now() - started) / 1000);
        depUp.set({ dep: bounded("gateway_pool", DEP_NAMES) }, 0);
        throw e;
      }
    },
    relayBaseUrl: (() => { try { return normalizeRelayBaseUrl(process.env.HANDSHAKE_RELAY ?? ""); } catch { return ""; } })(),
    probeTimeoutMs: Number(process.env.STATUS_PROBE_TIMEOUT_MS ?? "2000"),
    sessionStaleAfterMs: Number(process.env.STATUS_SESSION_STALE_MS ?? "1200000"),
    evidenceStaleAfterMs: Number(process.env.STATUS_EVIDENCE_STALE_MS ?? "1200000"),
    processStartedAtMs,
    serviceVersion: "0.1.0",
  };
  const statusCache = createStatusCache(statusDeps, Number(process.env.STATUS_CACHE_MS ?? "15000"));

  const metricsToken = (process.env.MCP_METRICS_TOKEN ?? "").trim();
  // Constant-time compare on fixed-size SHA-256 digests — never leaks token
  // length or a partial-match prefix through timing.
  const metricsTokenDigest = metricsToken ? createHash("sha256").update(metricsToken).digest() : undefined;
  function metricsAuthorized(req: IncomingMessage): boolean {
    if (!metricsTokenDigest) return false;
    const bearer = /^Bearer\s+(.+)$/i.exec(firstHeader(req.headers.authorization));
    if (!bearer) return false;
    const presented = createHash("sha256").update(bearer[1].trim()).digest();
    return timingSafeEqual(presented, metricsTokenDigest);
  }

  // A request is authorized if it carries a valid static MCP token OR a valid
  // self-serve signed token (v:1 demo or v:2 trial). Static tokens and v:1 demo
  // tokens resolve to AUTHENTICATED and bypass the trial/keeper layer (LLD §13);
  // a v:2 trial token marks the request as an ANONYMOUS TRIAL and carries the
  // ephemeral DID + channel. Returns the verified payload (when that is how auth
  // passed) so the caller can rate-limit on the token's `jti` WITHOUT re-verifying.
  type AuthOutcome =
    | { ok: false }
    | { ok: true; reason: "static_token" }
    | { ok: true; reason: "demo_token_v1"; payload: TokenPayload }
    | { ok: true; scope: HandshakeSessionTokenPayload }
    | { ok: true; trial: TrialTokenPayload };
  const checkAuth = (req: IncomingMessage): AuthOutcome => {
    if (isAuthorized(req.headers, tokens)) return { ok: true, reason: "static_token" };
    if (!selfServeEnabled) return { ok: false };
    const presented = presentedApiKey(req.headers);
    if (!looksLikeSelfServe(presented)) return { ok: false };
    const v1 = verifyToken(signingSecret, presented);
    if (v1.valid) return { ok: true, reason: "demo_token_v1", payload: v1.payload };
    const v2 = verifyTrialToken(signingSecret, presented);
    if (v2.valid) return { ok: true, trial: v2.payload };
    const v3 = verifyHandshakeSessionToken(signingSecret, presented);
    if (v3.valid) return { ok: true, scope: v3.payload };
    return { ok: false };
  };

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const requestStarted = Date.now();
    const routeClass = bounded(classifyRoute(req.method, req.url, firstHeader(req.headers.accept)), ROUTE_CLASSES, "other");
    httpActiveGauge.inc();
    // "close" fires exactly once per response — including client aborts, which
    // "finish" misses — so the active gauge can never drift positive.
    res.on("close", () => httpActiveGauge.dec());
    res.on("finish", () => {
      httpRequests.inc({ route: routeClass, status: statusClass(res.statusCode) });
      httpDuration.observe({ route: routeClass }, (Date.now() - requestStarted) / 1000);
    });
    // Unauthenticated, lightweight health check for the Mac mini runbook and the
    // AWS ALB / GCP Cloud Run health probes. Must be before auth (probes send no
    // token) and must not touch the gateway.
    if (isHealthCheck(req.method, req.url)) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    // Plain-text connect guide for agents/LLMs, served for ANY Accept header
    // (no browser, no auth). An agent that fetches the bare endpoint with a
    // default Accept gets a 401; this gives it a header-agnostic place to read
    // exactly how to connect. Public, before auth — like the health probe.
    // The clock-tools guide: HTML for a browser, plain text for everything else (an
    // agent fetching the bare URL gets the guide, not markup). /clock-tools.txt is
    // always text. Public, like the landing page.
    if (req.method === "GET" && (pathOf(req.url) === "/clock-tools" || pathOf(req.url) === "/clock-tools.txt")) {
      const wantsHtml = pathOf(req.url) === "/clock-tools" && firstHeader(req.headers.accept).includes("text/html");
      res.writeHead(200, {
        "content-type": wantsHtml ? "text/html; charset=utf-8" : "text/plain; charset=utf-8",
        "cache-control": "public, max-age=300",
      });
      res.end(wantsHtml ? CLOCK_TOOLS_HTML : CLOCK_TOOLS_TXT);
      return;
    }
    // The Agent Handshake operator SOP: HTML for a browser, plain text for
    // everything else. /handshake/sop.txt is always text. Public — the SOP
    // carries no credentials, only the endpoint, the eight-tool surface, and
    // the pinned-helper discipline.
    if (req.method === "GET" && (pathOf(req.url) === "/handshake/sop" || pathOf(req.url) === "/handshake/sop.txt")) {
      const wantsHtml = pathOf(req.url) === "/handshake/sop" && firstHeader(req.headers.accept).includes("text/html");
      res.writeHead(200, {
        "content-type": wantsHtml ? "text/html; charset=utf-8" : "text/plain; charset=utf-8",
        "cache-control": "public, max-age=300",
      });
      res.end(wantsHtml ? HANDSHAKE_SOP_HTML : HANDSHAKE_SOP_TXT);
      return;
    }

    // Public operational status. /status serves HTML to browsers and JSON to
    // everything else; /status.json is always JSON. Both are computed from
    // live dependency probes (TTL-cached) and carry freshness labels — a
    // failed probe reports down/degraded, never a remembered "healthy".
    if (req.method === "GET" && (pathOf(req.url) === "/status" || pathOf(req.url) === "/status.json")) {
      try {
        const report = await statusCache();
        const wantsHtml = pathOf(req.url) === "/status" && firstHeader(req.headers.accept).includes("text/html");
        res.writeHead(200, {
          "content-type": wantsHtml ? "text/html; charset=utf-8" : "application/json; charset=utf-8",
          "cache-control": "no-store",
        });
        res.end(wantsHtml ? renderStatusPage(report) : JSON.stringify(report, null, 2));
      } catch {
        res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "status_unavailable" }));
      }
      return;
    }

    // Readiness — the dependency-gated complement to the /health liveness
    // probe. 200 when no hard dependency is down (a degraded dependency still
    // counts as ready: the handshake surface fails closed by design in that
    // state, which is serving, not down). 503 otherwise.
    if (req.method === "GET" && pathOf(req.url) === "/readyz") {
      try {
        const report = await statusCache();
        const ready = report.overall !== "outage";
        res.writeHead(ready ? 200 : 503, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({
          status: ready ? "ready" : "not_ready",
          overall: report.overall,
          components: Object.fromEntries(Object.entries(report.components).map(([k, v]) => [k, v.state])),
        }));
      } catch {
        res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ status: "not_ready", error: "status_unavailable" }));
      }
      return;
    }

    // Operational metrics (Prometheus text exposition). Private: requires
    // Authorization: Bearer ${MCP_METRICS_TOKEN}. When the token is unset the
    // route doesn't exist (404) rather than serving or failing open.
    if (req.method === "GET" && pathOf(req.url) === "/metrics") {
      if (!metricsAuthorized(req)) {
        res.writeHead(metricsTokenDigest ? 401 : 404, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: metricsTokenDigest ? "unauthorized" : "not_found" }));
        return;
      }
      uptimeGauge.set({}, (Date.now() - processStartedAtMs) / 1000);
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8", "cache-control": "no-store" });
      res.end(metrics.collect());
      return;
    }

    if (req.method === "GET" && (pathOf(req.url) === "/llms.txt" || pathOf(req.url) === "/install.txt")) {
      res.writeHead(200, {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "public, max-age=300",
      });
      res.end(INSTALL_TXT);
      return;
    }

    // Machine-readable manifest, served for ANY Accept header (no auth). An agent
    // handed only the bare URL can GET this to self-configure (endpoint, transport,
    // x-api-key) so the user just pastes a token — no "which client?", no package hunt.
    if (req.method === "GET" && pathOf(req.url) === "/.well-known/mcp.json") {
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "public, max-age=300",
      });
      res.end(JSON.stringify(MCP_MANIFEST, null, 2));
      return;
    }

    if (req.method === "GET" && pathOf(req.url) === "/.well-known/agent-handshake.json") {
      try {
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "public, max-age=300",
        });
        res.end(JSON.stringify(buildV2Manifest(readV2ReleasePin(process.env)), null, 2));
      } catch {
        res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "agent_handshake_unavailable" }));
      }
      return;
    }

    if (req.method === "GET" && pathOf(req.url) === "/.well-known/standalone-handshake.json") {
      // The advertised endpoint must match the address the caller actually used:
      // behind a prefixed mount (e.g. Caddy `handle_path /staging/*`) the app never
      // sees the prefix, so it arrives as X-Forwarded-Prefix. An explicit env
      // override wins; absent both, the public production endpoint is the default.
      const configured = (process.env.STANDALONE_PUBLIC_ENDPOINT ?? "").trim();
      const prefix = firstHeader(req.headers["x-forwarded-prefix"]).trim().replace(/\/+$/, "");
      const host = (firstHeader(req.headers["x-forwarded-host"]) || firstHeader(req.headers.host)).trim();
      const endpoint = configured || (host ? `https://${host}${prefix}/connect/mcp` : undefined);
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "public, max-age=300",
      });
      res.end(JSON.stringify(buildStandaloneDiscovery(endpoint), null, 2));
      return;
    }

    if (req.method === "GET" && pathOf(req.url) === "/connect/verify") {
      // Keyless receipt verification for anyone: the check reads the immutable
      // on-chain block upstream (no API key on that read), so a counterparty —
      // or a curious browser — can confirm a handshake anchor without an
      // account. Public like the handshake endpoint; per-IP limited and briefly
      // cached (an anchored block is immutable).
      const q = new URL(req.url ?? "/", "http://localhost").searchParams;
      const ledgerId = (q.get("ledgerId") ?? "").trim();
      const blockHeight = (q.get("blockHeight") ?? "").trim();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(ledgerId) || !/^\d{1,10}$/.test(blockHeight)) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "bad_request" }));
        return;
      }
      const ip = clientIp(req.headers, req.socket.remoteAddress);
      if (!allowChainVerify(`chainverify:${ip}`)) {
        rlEvents.inc({ surface: bounded("chain_verify", RL_SURFACES) });
        res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "rate_limited" }));
        return;
      }
      const cacheKey = `${blockHeight}:${ledgerId.toLowerCase()}`;
      const cached = chainVerifyCache.get(cacheKey);
      try {
        const result = cached ?? (await getChainVerifyClient().verifyOnChain(ledgerId, blockHeight));
        // Only confirmed positives are immutable; a "none" (pending anchor) must be re-checkable.
        if (!cached && (result as { verifiedAgainst?: string }).verifiedAgainst === "on-chain block") {
          chainVerifyCache.set(cacheKey, result);
          if (chainVerifyCache.size > 10_000) chainVerifyCache.delete(chainVerifyCache.keys().next().value as string);
        }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "public, max-age=60" });
        res.end(JSON.stringify(result));
      } catch {
        res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "verification_unavailable" }));
      }
      return;
    }

    if (pathOf(req.url) === "/connect/mcp") {
      try {
        await getStandaloneHandshakeHandler()(req, res);
      } catch {
        console.warn(JSON.stringify({ event: "standalone_handshake_route_failure" }));
        if (!res.headersSent) {
          res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
          res.end(JSON.stringify({ error: "standalone_handshake_unavailable" }));
        }
      }
      return;
    }

    if (pathOf(req.url) === "/handshake/mcp") {
      try {
        await getPublicHandshakeHandler()(req, res);
      } catch {
        if (!res.headersSent) {
          res.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
          res.end(JSON.stringify({ error: "agent_handshake_unavailable" }));
        }
      }
      return;
    }

    // A Responder exchanges the URL-fragment capability exactly once. The
    // capability is never sent in a query string and the response is never
    // cacheable. All public failures intentionally collapse to one code.
    if (req.method === "POST" && pathOf(req.url) === "/handshake/invitations/exchange") {
      let body: unknown;
      try {
        body = await readJsonBody(req, 16 * 1024);
        if (
          body === null || typeof body !== "object" || Array.isArray(body) ||
          Object.keys(body).length !== 1 || typeof (body as { capability?: unknown }).capability !== "string"
        ) throw new Error("invalid");
        const result = await getRuntimeAgentHandshakeInvitationService().exchange(
          (body as { capability: string }).capability,
        );
        res.writeHead(200, {
          "content-type": "application/json",
          "cache-control": "no-store",
        });
        res.end(JSON.stringify(result));
      } catch {
        res.writeHead(409, {
          "content-type": "application/json",
          "cache-control": "no-store",
        });
        res.end(JSON.stringify({ error: "INVITATION_UNAVAILABLE" }));
      }
      return;
    }

    // Self-serve token minting (public, before auth). Mints a signed testnet
    // token that grants the shared delegated key, so a brand-new user can connect
    // without their own Clockchain key. Off if no signing secret.
    if (req.method === "POST" && pathOf(req.url) === "/token") {
      if (!selfServeEnabled) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({
          error: "self_serve_disabled",
          message:
            "Self-serve tokens aren't enabled here. Ask the team for a token, or " +
            "bring your own Clockchain key via x-clockchain-api-key.",
          docs: "https://mcp.clockchain.network/llms.txt",
        }));
        return;
      }
      const ip = clientIp(req.headers, req.socket.remoteAddress);
      // ALWAYS enforce the per-IP abuse ceiling. This is the only guard on the
      // shared delegated-key budget, so it must be unconditional and never keyed
      // on attacker-controlled input. `sub` is NOT used here: rotating `sub` must
      // not let a caller escape this ceiling and drain the shared budget (per-user auth).
      const mintCheck = mintLimiter.enabled ? mintLimiter.allow(`mint:ip:${ip}`) : null;
      if (mintCheck && !mintCheck.allowed) {
        rlEvents.inc({ surface: bounded("token_mint", RL_SURFACES) });
        const headers = rateLimitHeaders(mintCheck);
        res.writeHead(429, { "content-type": "application/json", ...headers });
        res.end(JSON.stringify({
          error: "rate_limited",
          message: "Too many tokens minted from this address. Try again later.",
          retry_after_seconds: Number(headers["Retry-After"]),
        }));
        return;
      }
      // Optional subject from the x-clockchain-sub header or a ?sub= query param.
      // Sanitized, and embedded as a NON-AUTHORITATIVE LABEL only — it is supplied
      // unauthenticated, so it does NOT isolate budgets or rate-limit buckets.
      // Real per-user isolation needs authenticated identity (medium-term TODO).
      const reqUrl = new URL(req.url ?? "/", "http://localhost");
      const sub = sanitizeSub(
        firstHeader(req.headers["x-clockchain-sub"]).trim() ||
          reqUrl.searchParams.get("sub")?.trim() ||
          undefined,
      );

      // Trial mode (LLD §6.4): `POST /token?mode=trial` mints a v:2 TRIAL token
      // carrying a fresh ephemeral DID + channel. Used as a transport credential
      // (x-api-key) like a demo token, but it marks the request as an anonymous
      // trial so the keeper gate engages. Default mode is unchanged (v:1 demo) so
      // existing callers are byte-for-byte unaffected (backward compat).
      if (reqUrl.searchParams.get("mode") === "trial") {
        const channel = normalizeChannel(
          firstHeader(req.headers["x-clockchain-channel"]).trim() ||
            reqUrl.searchParams.get("channel")?.trim() ||
            undefined,
        );
        const eph = newEphemeralDid();
        const { token: trialToken, payload: trialPayload } = mintTrialToken(
          signingSecret,
          { eph, ch: channel },
          tokenTtlDays * 24 * 60 * 60,
        );
        console.error(
          `[clockchain-mcp] minted self-serve TRIAL token (channel=${channel}, ip=${ip})`,
        );
        res.writeHead(200, {
          "content-type": "application/json",
          "cache-control": "no-store",
          ...(mintCheck ? rateLimitHeaders(mintCheck) : {}),
        });
        res.end(JSON.stringify({
          token: trialToken,
          tier: trialPayload.tier,
          channel,
          ephemeral_did: eph,
          expires_at: new Date(trialPayload.exp * 1000).toISOString(),
          endpoint: "https://mcp.clockchain.network/mcp",
          usage: "Add header  x-api-key: <token>  to your MCP client config (anonymous testnet trial).",
        }));
        return;
      }

      const { token, payload } = mintToken(
        signingSecret,
        tokenTtlDays * 24 * 60 * 60,
        undefined, // nowSec: use default (real clock)
        sub,
      );
      // Observability: log mint volume (never the token value) so abuse is visible.
      // `sub` is sanitized above, so this line is safe from log injection.
      console.error(
        `[clockchain-mcp] minted self-serve token (tier=${payload.tier}, sub=${sub ?? "-"}, ip=${ip})`,
      );
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
        ...(mintCheck ? rateLimitHeaders(mintCheck) : {}),
      });
      res.end(JSON.stringify({
        token,
        tier: payload.tier,
        sub: payload.sub,
        expires_at: new Date(payload.exp * 1000).toISOString(),
        endpoint: "https://mcp.clockchain.network/mcp",
        usage: "Add header  x-api-key: <token>  to your MCP client config (testnet).",
      }));
      return;
    }

    // Promote-in-place (LLD §4.1 A6, §6.5). Web-origin: the billing callback POSTs
    // { claim, accountId } after checkout to bind the ephemeral session to the
    // account. Idempotent on `claim`. STUB binding (manual entitlement flip) until
    // Network B2 lands (LLD §12).
    //
    // SECURITY TODO (A7/B6): restrict this to the web/billing origin (shared
    // secret or allowlist) before production — anyone with a valid claim can flip
    // an account in demo mode. Off entirely when self-serve is disabled.
    if (req.method === "POST" && pathOf(req.url) === "/promote") {
      if (!selfServeEnabled) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({
          error: "self_serve_disabled",
          message: "Promote is unavailable: no signing secret configured.",
        }));
        return;
      }
      let body: unknown;
      try {
        body = await readJsonBody(req);
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "bad_request", message: "Invalid JSON body." }));
        return;
      }
      const b = (body ?? {}) as { claim?: unknown; accountId?: unknown; plan?: unknown };
      const outcome = await runPromote(store, promoteSecret, b);
      res.writeHead(outcome.status, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      res.end(JSON.stringify(outcome.body));
      return;
    }

    // A human browsing to the endpoint (GET with an HTML Accept) gets the
    // marketing landing page — at "/" and "/mcp" alike. Agents POST JSON-RPC and
    // MCP's own SSE GETs send Accept: text/event-stream, so the agent endpoint is
    // untouched. Public (before auth), like the health probe.
    if (req.method === "GET" && firstHeader(req.headers.accept).includes("text/html")) {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "public, max-age=300",
      });
      res.end(LANDING_HTML);
      return;
    }

    // Resolve the per-request credential, in priority order:
    //   1. Explicit BYO headers (x-clockchain-api-key)      -> their Clockchain key
    //   2. Valid MCP token (x-api-key / Bearer in allowlist) -> delegated env key
    //   3. Forgiving fallback: any key presented in x-api-key but NOT a valid MCP
    //      token -> treat it as a Clockchain key (the #1 install mistake — a
    //      Clockchain key pasted into x-api-key — now just works; the gateway is
    //      the real gate and rejects a bad key on the first tool call).
    //   4. No credential at all -> self-documenting 401.
    let byo = clockchainOverrides(req.headers);
    // Verify auth ONCE here; reuse the verified self-serve payload below for the
    // rate-limit key so we don't HMAC-verify the token twice per request.
    const auth: AuthOutcome = byo ? { ok: true, reason: "static_token" } : checkAuth(req);
    if (!byo && !auth.ok) {
      const presented = presentedApiKey(req.headers);
      // A malformed or expired signed-token-shaped credential must never fall
      // through as BYO: that would erase its session/role/tool restrictions.
      if (presented && !looksLikeSelfServe(presented)) {
        byo = clockchainOverridesFromKey(presented, req.headers);
      } else {
        // No credential presented — return actionable guidance, not a dead end.
        res.writeHead(401, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "unauthorized",
          message:
            "Clockchain MCP — a hosted MCP server (no package to install). " +
            "Authenticate with EITHER an MCP token (header x-api-key) OR your " +
            "own Clockchain API key (header x-clockchain-api-key + client/wallet " +
            "id), then point an MCP client at the endpoint below.",
          endpoint: "https://mcp.clockchain.network/mcp",
          transport: "http",
          auth: {
            // Two co-equal credential types — using the wrong header is the #1
            // cause of a 401 here (a Clockchain key sent as x-api-key is rejected).
            mcpToken: {
              header: "x-api-key",
              getToken: "POST https://mcp.clockchain.network/token",
              note: "instant self-serve testnet token (shared pool) — POST /token to mint one",
            },
            bringYourOwnKey: {
              headers: ["x-clockchain-api-key", "x-clockchain-client-id", "x-clockchain-wallet-id"],
              note:
                "your own Clockchain API key (writes spend your credits) — " +
                "RECOMMENDED for production / per-user usage: each user gets their " +
                "own identity, credit budget, and rate-limit bucket",
            },
          },
          // For production or per-user usage, bring your own Clockchain key so
          // each user is isolated. The self-serve MCP token is a shared testnet
          // pool for quick trials. (per-user auth medium-term: a `sub`-scoped delegated
          // sub-key/credit bucket will give /token per-user isolation too.)
          recommendation:
            "For production or per-user usage, bring your own Clockchain key " +
            "(x-clockchain-api-key). The self-serve MCP token is a shared testnet pool.",
          manifest: "https://mcp.clockchain.network/.well-known/mcp.json",
          install: "https://mcp.clockchain.network/llms.txt",
          docs: "https://github.com/thetangstr/clockchain-developer-tools/blob/main/INSTALL.md",
        }),
        );
        return;
      }
    }

    // Per-tester rate limit (after auth so the key is the validated token). For a
    // self-serve token the key is its (already-verified) jti, so distinct tokens
    // get distinct buckets and a shared-egress public app isn't throttled as one
    // IP. We pass the jti only for a NON-byo request, so a BYO key is bucketed by
    // its own (authenticated) key, not by a co-presented token's jti.
    // jti for rate-limit bucketing: present on a v:1 demo token (auth.payload) or
    // a v:2 trial token (auth.trial); absent for static-token / BYO callers.
    const selfServeJti = byo || !auth.ok
      ? undefined
      : "payload" in auth
        ? auth.payload.jti
        : "trial" in auth
          ? auth.trial.jti
          : "scope" in auth
            ? auth.scope.jti
          : undefined;
    const effectiveCallerId = callerPrincipalId(
      req.headers,
      clientIp(req.headers, req.socket.remoteAddress),
      selfServeJti,
      byo?.apiKey,
    );
    // Read the JSON-RPC body once here (the transport accepts a pre-parsed body) so
    // the rate limiter can wave lifecycle/discovery through — see RATE_LIMIT_EXEMPT_METHODS.
    let parsedBody: unknown;
    if (req.method === "POST") {
      try {
        parsedBody = await readJsonBody(req, 4_000_000);
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_json_body" }));
        return;
      }
    }
    const rl = limiter.enabled && !(parsedBody !== undefined && isRateLimitExempt(parsedBody))
      ? limiter.allow(
          effectiveCallerId,
        )
      : null;
    if (rl && !rl.allowed) {
      rlEvents.inc({ surface: bounded("mcp_call", RL_SURFACES) });
      const headers = rateLimitHeaders(rl);
      res.writeHead(429, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify({
        error: "rate_limited",
        retry_after_seconds: Number(headers["Retry-After"]),
      }));
      return;
    }

    try {
      // Surface the standard rate-limit headers on success too, so clients can
      // see their remaining budget before they hit the limit (per-user auth).
      if (rl) {
        for (const [k, v] of Object.entries(rateLimitHeaders(rl))) {
          res.setHeader(k, v);
        }
      }

      // Resolve entitlement -> keeper gate (LLD §4.1 A1/A4). Only an anonymous
      // TRIAL (v:2 trial token) gets a gate; BYO / static-token / v:1-demo
      // callers are AUTHENTICATED and bypass the trial/keeper layer (LLD §13).
      let gate: KeeperGate | undefined;
      if (!byo && auth.ok && "trial" in auth) {
        const eph = auth.trial.eph;
        const channel = normalizeChannel(auth.trial.ch);
        // Lazily open the ephemeral session on first trial call (LLD §6.4).
        const session = await getOrCreateSession(store, eph, channel);
        const entitlement: Entitlement = {
          kind: "anonymous_trial",
          sessionId: session.sessionId,
          ephemeralDid: eph,
          channel,
          plan: "trial",
        };
        gate = buildKeeperGate(entitlement, async () => {
          // Forwardable claim for the 402 (LLD §6.2). Minted with the promote
          // secret; only its hash is persisted on the session (LLD §5.3).
          const { token } = mintClaim(
            promoteSecret,
            { eph, ch: channel },
            claimTtlSeconds(),
          );
          // FIX 5a: AWAIT the session write before returning the claim — do not
          // hand out a claim whose session row (claim hash + keeper_blocked
          // status) never persisted. A write failure is logged, not thrown, so
          // the caller still receives a usable claim.
          await store
            .putSession({
              ...session,
              claimTokenHash: hashClaim(token),
              status: "keeper_blocked",
            })
            .catch((e) => {
              console.error(
                "[clockchain-mcp] failed to persist keeper_blocked session:",
                e,
              );
            });
          return token;
        });
      }
      const server = buildServer(
        byo,
        gate,
        effectiveCallerId,
        !byo && auth.ok && "scope" in auth ? auth.scope : undefined,
      );
      const transport = new StreamableHTTPServerTransport({
        // Stateless: no session id generation.
        sessionIdGenerator: undefined,
      });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, parsedBody);
    } catch (err) {
      console.error("[clockchain-mcp] http request error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    }
  });

  httpServer.listen(port, () => {
    console.error(`[clockchain-mcp] http server listening on :${port}`);
    console.error(
      `[clockchain-mcp] self-serve tokens: ${
        selfServeEnabled
          ? `ENABLED (POST /token, ${mintPerHour}/hour/IP, ${tokenTtlDays}d TTL)`
          : "DISABLED (set MCP_TOKEN_SIGNING_SECRET to enable POST /token)"
      }`,
    );
  });
}
