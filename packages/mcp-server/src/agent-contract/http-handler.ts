import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { limiter as keyedWindowLimiter } from "../standalone-handshake/public-server.js";
import { buildContractServer } from "./server.js";
import type { CertificateResolver } from "./certificate-resolver.js";
import type { TelemetryLanes } from "./telemetry-lanes.js";
import { receiptClientInfoSchema } from "./receipts.js";
import type { ContractPrincipal, ContractService, ContractSide } from "./service.js";
import type { ContractSigner } from "./envelope.js";
import type { HostRootPin } from "./certificate.js";
import type { ContractRole } from "./schemas.js";

/**
 * HTTP transport for `/contract/mcp` (LLD §3). Mirrors the v2 public
 * handshake handler: a per-principal call bucket and auth that fails closed.
 *
 * Auth (C2, orchestrator decision): `CONTRACT_AUTH_TOKENS` provisions one
 * `token:role:keyId:agentId:side` entry per principal. The token digest map
 * is a flat array compared with `timingSafeEqual` — never a plain-object
 * lookup, so `Bearer constructor`/`__proto__` can never resolve to a
 * principal. No anonymous mode: an empty token set refuses every request.
 *
 * `sourceIp` is the socket peer, or the LAST X-Forwarded-For hop (the one
 * appended by our own proxy) — and only when `CONTRACT_TRUST_PROXY=1` was
 * set, since a client-supplied XFF is otherwise pure spoof. Values are
 * sanitized to printable ASCII and truncated to the receipt schema's 64.
 *
 * Sessions (M2, LLD §9 R8 evidence): the transport is STATEFUL — the SDK's
 * session support issues `mcp-session-id` on `initialize` and every later
 * request must carry it (spec: 400 missing, 404 unknown/expired). Sessions
 * expire after `sessionTtlMs` idle and are bound to the principal that
 * initialized them — a different token on a live session is refused. The
 * session id and `clientInfo` ride every receipt as EVIDENCE (R9), never
 * proof: the server cannot tell a real MCP client from a well-formed script.
 */

const CONTRACT_PATH = "/contract/mcp";
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const DEFAULT_SESSION_TTL_MS = 30 * 60_000;
const MAX_INITIALIZE_BODY = 64 * 1024;

export interface ContractTokenEntry {
  /** sha256 of the raw bearer token — the token itself is never retained. */
  readonly digest: Buffer;
  readonly principal: ContractPrincipal;
}

/**
 * Parse `CONTRACT_AUTH_TOKENS`: comma-separated `token:role:keyId:agentId:side`
 * entries. `agentId` may be `*` (N4b-7 late binding): the principal's agentId
 * is then taken from the certificate's party on its side at contract_bind and
 * pinned write-once, instead of being provisioned in the token. Throws on
 * malformed entries, duplicate tokens, or tokens containing `:` — bad config
 * must fail loudly at startup, not lazily on traffic.
 */
export function parseContractTokens(raw: string | undefined): ContractTokenEntry[] {
  const out: ContractTokenEntry[] = [];
  const seen = new Set<string>();
  for (const entry of (raw ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const parts = entry.split(":").map((p) => p.trim());
    if (parts.length !== 5 || parts.some((p) => p.length === 0)) {
      throw new Error(`malformed CONTRACT_AUTH_TOKENS entry (want token:role:keyId:agentId:side)`);
    }
    const [token, role, keyId, agentId, side] = parts as [string, string, string, string, string];
    if (role !== "buyer" && role !== "provider") {
      throw new Error(`CONTRACT_AUTH_TOKENS: unknown role "${role}"`);
    }
    if (side !== "initiator" && side !== "responder") {
      throw new Error(`CONTRACT_AUTH_TOKENS: unknown side "${side}"`);
    }
    // N4: role≡side is pinned at parse time — buyer≡initiator,
    // provider≡responder; a mismatch is a startup (config) error.
    if ((role === "buyer") !== (side === "initiator")) {
      throw new Error(`CONTRACT_AUTH_TOKENS: role "${role}" cannot be pinned to side "${side}"`);
    }
    if (agentId !== "*" && !DECIMAL.test(agentId)) {
      throw new Error(`CONTRACT_AUTH_TOKENS: agentId "${agentId}" is not a decimal ERC-8004 id (or "*" for late binding)`);
    }
    if (seen.has(token)) {
      throw new Error(`CONTRACT_AUTH_TOKENS: duplicate token`);
    }
    seen.add(token);
    out.push({
      digest: createHash("sha256").update(token, "utf8").digest(),
      principal: { keyId, role: role as ContractRole, agentId, side: side as ContractSide },
    });
  }
  return out;
}

/**
 * Bearer-token authenticate over sha256 digests with `timingSafeEqual` — the
 * loop runs every entry so lookup time doesn't leak which token matched.
 */
export function tokenAuthenticator(
  tokens: readonly ContractTokenEntry[],
): (headers: IncomingHttpHeaders) => ContractPrincipal | null {
  return (headers) => {
    const raw = headers.authorization;
    const header = (Array.isArray(raw) ? raw[0] : raw) ?? "";
    const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
    if (match === null) return null;
    const candidate = createHash("sha256").update(match[1], "utf8").digest();
    for (const entry of tokens) {
      if (timingSafeEqual(candidate, entry.digest)) return entry.principal;
    }
    return null;
  };
}

function clientIp(
  headers: IncomingHttpHeaders,
  remoteAddress: string | undefined,
  trustProxy: boolean,
): string {
  let ip = remoteAddress ?? "";
  if (trustProxy) {
    const xff = (Array.isArray(headers["x-forwarded-for"]) ? headers["x-forwarded-for"][0] : headers["x-forwarded-for"]) ?? "";
    // The LAST hop is the one our own proxy appended; earlier hops are
    // attacker-controlled input the proxy merely forwards.
    const hops = xff.split(",").map((h) => h.trim()).filter(Boolean);
    if (hops.length > 0) ip = hops[hops.length - 1];
  }
  const clean = ip.replace(/[^\x21-\x7e]/g, "").slice(0, 64);
  return clean || "unknown";
}

function firstHeader(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

/** JSON-RPC error body matching the SDK transport's refusal shape. */
function jsonRpcError(code: number, message: string): Record<string, unknown> {
  return { jsonrpc: "2.0", error: { code, message }, id: null };
}

interface ContractSession {
  readonly transport: StreamableHTTPServerTransport;
  readonly ctx: {
    id?: string;
    clientInfo?: { name: string; version: string };
    /** Per-REQUEST peer IP — refreshed before every call (evidence). */
    sourceIp?: string;
  };
  readonly principalKeyId: string;
  lastSeenMs: number;
}

/** Read a bounded JSON body; returns undefined on parse failure/over-cap. */
async function readJsonBody(req: IncomingMessage, cap: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > cap) return undefined;
    chunks.push(buf);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return undefined;
  }
}

export function createContractHttpHandler(options: {
  authenticate: (headers: IncomingHttpHeaders) => ContractPrincipal | null;
  hostRoots: readonly HostRootPin[];
  signer: ContractSigner;
  service: ContractService;
  /** contract_bind by reference (handshakeSessionId → closing certificate). */
  resolveCertificate?: CertificateResolver;
  /** O-1: the adapter's `telemetry_open` (sealed lane) — absent = tool not served. */
  telemetryLanes?: TelemetryLanes;
  callsPerMinute?: number;
  /** N4b-3: per-principal polling-tool rate limit (rendezvous_inbox, contract_status). */
  pollsPerMinute?: number;
  /** CDT-SEC M2: per-principal contract_register_policy limit (default 6/min). */
  registrationsPerMinute?: number;
  trustProxy?: boolean;
  /** Idle-session TTL (M2); default 30 min. */
  sessionTtlMs?: number;
  /** N4b-3: live sessions per principal (default 4) and globally (512). */
  maxSessionsPerPrincipal?: number;
  maxSessions?: number;
  now?: () => number;
  onRateLimited?: () => void;
}) {
  const now = options.now ?? Date.now;
  const service = options.service;
  const sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  const maxSessionsPerPrincipal = options.maxSessionsPerPrincipal ?? 4;
  const maxSessions = options.maxSessions ?? 512;
  const allowCall = keyedWindowLimiter(options.callsPerMinute ?? 120, 60_000, now);
  // N4b-4: ONE poll limiter for the whole handler — keyed by principal, so a
  // fresh session can never reset a principal's polling budget.
  const pollGate = keyedWindowLimiter(options.pollsPerMinute ?? 60, 60_000, now);
  // CDT-SEC M2: one registration limiter per handler, keyed by principal.
  const registerGate = keyedWindowLimiter(options.registrationsPerMinute ?? 6, 60_000, now);
  const sessions = new Map<string, ContractSession>();

  /**
   * N4b-3: idle sessions are swept on EVERY request AND on a background
   * timer — a swept session frees its per-principal and global slots.
   */
  function sweepIdleSessions(): void {
    const t = now();
    for (const [id, sess] of sessions) {
      if (t - sess.lastSeenMs > sessionTtlMs) dropSession(id, sess);
    }
  }
  const sweepTimer = setInterval(sweepIdleSessions, Math.max(1_000, Math.min(sessionTtlMs, 60_000)));
  sweepTimer.unref?.();

  /**
   * Forget a session record — CDT-SEC M3: and tell the service once, so its
   * per-session pre-bind state is evicted (closed, DELETEd or idle-swept).
   */
  function forgetSession(sessionId: string): void {
    const sess = sessions.get(sessionId);
    if (sess === undefined) return;
    sessions.delete(sessionId);
    try { service.sessionDropped?.(sess.principalKeyId, sessionId); } catch { /* eviction must never break the transport */ }
  }

  /** Drop a session — closed transport, forgotten record. */
  function dropSession(sessionId: string, sess: ContractSession): void {
    forgetSession(sessionId);
    void sess.transport.close().catch(() => {});
  }

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = (req.url ?? "").split("?")[0];
    if (path !== CONTRACT_PATH) {
      writeJson(res, 404, { error: "not_found" });
      return;
    }
    const principal = options.authenticate(req.headers);
    if (principal === null) {
      writeJson(res, 401, { error: "unauthorized" });
      return;
    }
    if (!allowCall(`call:${principal.keyId}`)) {
      options.onRateLimited?.();
      writeJson(res, 429, { error: "rate_limited" });
      return;
    }

    sweepIdleSessions(); // N4b-3: idle sessions free slots on every request
    const sessionId = firstHeader(req.headers["mcp-session-id"]).trim();
    if (sessionId.length > 0) {
      const sess = sessions.get(sessionId);
      if (sess !== undefined && now() - sess.lastSeenMs > sessionTtlMs) {
        dropSession(sessionId, sess);
      } else if (sess !== undefined) {
        // A session is bound to the principal that initialized it — a
        // different token on a live session id is refused (M2).
        if (sess.principalKeyId !== principal.keyId) {
          writeJson(res, 403, { error: "forbidden" });
          return;
        }
        sess.lastSeenMs = now();
        sess.ctx.sourceIp = clientIp(req.headers, req.socket.remoteAddress, options.trustProxy === true);
        try {
          await sess.transport.handleRequest(req, res);
        } catch {
          if (!res.headersSent) writeJson(res, 500, { error: "internal_error" });
        }
        return;
      }
      // Spec: an unknown/expired session id is 404.
      writeJson(res, 404, jsonRpcError(-32001, "Session not found"));
      return;
    }

    // No session header: the only legal request is `initialize`.
    if (req.method !== "POST") {
      writeJson(res, 400, jsonRpcError(-32000, "Bad Request: Mcp-Session-Id header is required"));
      return;
    }
    const body = await readJsonBody(req, MAX_INITIALIZE_BODY);
    if (body === undefined) {
      writeJson(res, 400, jsonRpcError(-32700, "Parse error: Invalid JSON"));
      return;
    }
    const isInitialize =
      typeof body === "object" && body !== null && !Array.isArray(body) &&
      (body as { method?: unknown }).method === "initialize";
    if (!isInitialize) {
      // Spec: a non-initialization request without a session id is 400.
      writeJson(res, 400, jsonRpcError(-32000, "Bad Request: Mcp-Session-Id header is required"));
      return;
    }

    // N4b-3 receipts-first: a `clientInfo` the receipt schema would reject is
    // REFUSED at initialize — it could otherwise poison every receipt for
    // the session (probe N4b3-3: settlement committed with no receipt).
    const clientInfo = (body as { params?: { clientInfo?: unknown } }).params?.clientInfo;
    if (clientInfo !== undefined && !receiptClientInfoSchema.safeParse(clientInfo).success) {
      writeJson(res, 400, jsonRpcError(-32602, "Invalid params"));
      return;
    }

    // N4b-3 session caps: per-principal and global, after the sweep — the
    // 5th concurrent session for one principal is refused.
    if (sessions.size >= maxSessions) {
      options.onRateLimited?.();
      writeJson(res, 429, { error: "rate_limited" });
      return;
    }
    let principalSessions = 0;
    for (const s of sessions.values()) {
      if (s.principalKeyId === principal.keyId) principalSessions += 1;
    }
    if (principalSessions >= maxSessionsPerPrincipal) {
      options.onRateLimited?.();
      writeJson(res, 429, { error: "rate_limited" });
      return;
    }

    const ctx: ContractSession["ctx"] = {};
    if (clientInfo !== undefined) {
      ctx.clientInfo = clientInfo as { name: string; version: string };
    }

    const server = buildContractServer({
      principal,
      service,
      ...(options.resolveCertificate !== undefined ? { resolveCertificate: options.resolveCertificate } : {}),
      ...(options.telemetryLanes !== undefined ? { telemetryLanes: options.telemetryLanes } : {}),
      session: ctx,
      pollGate,
      registerGate,
      now,
    });
    ctx.sourceIp = clientIp(req.headers, req.socket.remoteAddress, options.trustProxy === true);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        ctx.id = id;
        sessions.set(id, {
          transport,
          ctx,
          principalKeyId: principal.keyId,
          lastSeenMs: now(),
        });
      },
      onsessionclosed: (id) => { forgetSession(id); },
    });
    transport.onclose = () => { if (ctx.id !== undefined) forgetSession(ctx.id); };
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch {
      if (!res.headersSent) writeJson(res, 500, { error: "internal_error" });
    }
  };
}
