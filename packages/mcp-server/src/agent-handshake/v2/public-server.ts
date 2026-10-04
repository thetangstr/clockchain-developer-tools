import { join } from "node:path";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { V2_HELPER_VERSION, buildV2Instructions, type V2ReleasePin } from "./instructions.js";
import { isV2RetryableToolError, registerV2PublicTools, V2_PUBLIC_TOOL_NAMES, type V2PublicInvoke } from "./public-tools.js";
import { readV2RoleAccessPayload, V2RoleAccessError } from "./access.js";
import { handshakeStateDir } from "../../handshake-core/durable-store.js";
import { createHandleMap } from "../../handshake-core/handle-map.js";
import { AsyncLocalStorage } from "node:async_hooks";
import { HANDSHAKE_RECEIPT_META_KEY, type HandshakeReceiptEcho, type HandshakeReceiptRecorder, type RawInvokeHook } from "./receipts.js";

export { V2_PUBLIC_TOOL_NAMES } from "./public-tools.js";

function firstHeader(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

// A listener bound to `::` (Node's default for listen(port)) reports IPv4 peers
// in mapped form ("::ffff:172.30.0.3"), which never string-equals the configured
// proxy address — collapsing every client into one rate-limit bucket. Normalize
// both sides before comparing.
function normalizePeerAddress(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(value.trim());
  return mapped ? mapped[1] : value;
}

export function v2PublicClientIp(headers: IncomingHttpHeaders, remoteAddress: string | undefined, trustedProxy?: string): string {
  const peer = normalizePeerAddress(remoteAddress);
  if (trustedProxy && peer === normalizePeerAddress(trustedProxy)) {
    const forwarded = firstHeader(headers["x-forwarded-for"]).split(",")[0]?.trim();
    if (forwarded) return forwarded;
  }
  return peer ?? "unknown";
}

function limiter(limit: number, windowMs: number, now: () => number) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return {
    acquire(key: string): boolean {
      const current = now();
      const prior = hits.get(key);
      if (!prior || current >= prior.resetAt) {
        hits.set(key, { count: 1, resetAt: current + windowMs });
        return true;
      }
      if (prior.count >= limit) return false;
      prior.count += 1;
      return true;
    },
    release(key: string): void {
      const prior = hits.get(key);
      if (prior && prior.count > 0) prior.count -= 1;
    },
    retryAfterMs(key: string): number {
      const prior = hits.get(key);
      return prior ? Math.max(prior.resetAt - now(), 1) : 1;
    },
  };
}

// Rate limiting is a quota condition, not a handshake failure — it carries the
// real bucket reset so a caller can back off for the actual duration instead of
// hot-retrying into the wall.
export class V2RateLimitedError extends Error {
  readonly retryAfterMs: number;
  constructor(retryAfterMs: number) {
    super("rate_limited");
    this.name = "V2RateLimitedError";
    this.retryAfterMs = retryAfterMs;
  }
}

const ROLE_ACCESS_HANDLE = /^ccra_[A-Za-z0-9_-]{22}$/;
const ROLE_ACCESS_HANDLE_LIMIT = 10_000;
const ROLE_SCOPED_TOOLS = new Set([
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit_checkpoint",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new V2RoleAccessError();
  return value as Record<string, unknown>;
}

// Handles live in a HandleMap (handshake-core/handle-map.ts): durable across restarts when
// HANDSHAKE_STATE_DIR is set, sealed at rest. Behaviour is otherwise unchanged: a handle
// lives until its role token expires, one handle per token, the same cap.
function createRoleAccessBroker(
  inner: V2PublicInvoke,
  now: () => number,
  stateDir: string | undefined,
): (name: string, args: Record<string, unknown>, hook?: RawInvokeHook) => Promise<unknown> {
  const handles = createHandleMap({
    label: "v2/ccra",
    prefix: "ccra_",
    limit: ROLE_ACCESS_HANDLE_LIMIT,
    now,
    ...(stateDir === undefined ? {} : { path: join(stateDir, "role-handles.json") }),
  });

  function issue(access: unknown): string {
    if (typeof access !== "string" || access.length < 80 || access.length > 4096) throw new V2RoleAccessError();
    const current = now();
    const expiresAt = Number(readV2RoleAccessPayload(access).expMs);
    if (!Number.isSafeInteger(expiresAt) || current >= expiresAt) throw new V2RoleAccessError();
    const handle = handles.issue(access, expiresAt);
    if (handle === undefined) throw new V2RoleAccessError();
    return handle;
  }

  function resolve(value: unknown): { clientAccess: string; signedAccess: string } {
    if (typeof value !== "string") throw new V2RoleAccessError();
    if (!ROLE_ACCESS_HANDLE.test(value)) {
      const expiresAt = Number(readV2RoleAccessPayload(value).expMs);
      if (!Number.isSafeInteger(expiresAt) || now() >= expiresAt) throw new V2RoleAccessError();
      return { clientAccess: "", signedAccess: value };
    }
    const access = handles.resolve(value);
    if (access === undefined) throw new V2RoleAccessError();
    return { clientAccess: value, signedAccess: access };
  }

  return async (name, args, hook) => {
    // Receipts (opt-in): the hook observes the RAW coordinator call and returns/throws
    // exactly what it does. Without a hook this is the original `inner` call.
    const invoke: V2PublicInvoke = hook === undefined ? inner : (n, a) => hook(n, a, inner);
    if (ROLE_SCOPED_TOOLS.has(name)) {
      const resolved = resolve(args.access);
      const result = object(await invoke(name, { ...args, access: resolved.signedAccess }));
      const roleAccess = resolved.clientAccess || issue(resolved.signedAccess);
      const { initiatorAccess: _initiator, responderAccess: _responder, ...publicResult } = result;
      return { ...publicResult, roleAccess };
    }
    const result = object(await invoke(name, args));
    if (name === "agent_handshake_invite") {
      const roleAccess = issue(result.initiatorAccess);
      const { initiatorAccess: _initiator, responderAccess: _responder, ...publicResult } = result;
      return { ...publicResult, roleAccess };
    }
    if (name === "agent_handshake_accept_invitation") {
      const roleAccess = issue(result.responderAccess);
      const { initiatorAccess: _initiator, responderAccess: _responder, ...publicResult } = result;
      return { ...publicResult, roleAccess };
    }
    return result;
  };
}

export function buildV2PublicServer(options: { pin: V2ReleasePin; invoke: V2PublicInvoke; metaFor?: () => Record<string, unknown> | undefined; scope?: <T>(run: () => Promise<T>) => Promise<T> }): McpServer {
  const server = new McpServer({ name: "clockchain-agent-handshake", version: V2_HELPER_VERSION }, {
    instructions: buildV2Instructions(options.pin),
  });
  registerV2PublicTools(server, options.invoke, options.metaFor, options.scope);
  return server;
}

export function createV2PublicHttpHandler(options: {
  pin: V2ReleasePin;
  invoke: V2PublicInvoke;
  trustedProxy?: string;
  invitePerHour?: number;
  callsPerMinute?: number;
  now?: () => number;
  onRateLimited?: (surface: "handshake_call" | "handshake_invite") => void;
  localActionCommand?: (commandSha256: string) => string | null;
  /** Durable state directory for ccra_ handles; defaults to HANDSHAKE_STATE_DIR/agent-handshake-v2. */
  stateDir?: string;
  /** Opt-in per-call signed receipts + their feed routes; absent = behaviour unchanged. */
  receipts?: HandshakeReceiptRecorder;
}) {
  const now = options.now ?? Date.now;
  const allowInvite = limiter(options.invitePerHour ?? 5, 60 * 60_000, now);
  const allowCall = limiter(options.callsPerMinute ?? 120, 60_000, now);
  const invoke = createRoleAccessBroker(options.invoke, now, options.stateDir ?? handshakeStateDir("agent-handshake-v2"));
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = (req.url ?? "").split("?")[0];
    // Digest-addressed fetch for verbatim helperStep commands: the 256-bit
    // commandSha256 is the capability, the body is the exact already-issued
    // shellCommand bytes, and the response is uncacheable. Exempt from the
    // per-minute call bucket — it is a static read, not a handshake call.
    if (path === "/handshake/local-action" || path.startsWith("/handshake/local-action/")) {
      const match = /^\/handshake\/local-action\/([0-9a-f]{64})$/.exec(path);
      const command = req.method === "GET" && match ? options.localActionCommand?.(match[1]) : null;
      if (!command) {
        res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "not_found" }));
        return;
      }
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end(command);
      return;
    }
    if (path !== "/handshake/mcp") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    const ip = v2PublicClientIp(req.headers, req.socket.remoteAddress, options.trustedProxy);
    if (!allowCall.acquire(`call:${ip}`)) {
      options.onRateLimited?.("handshake_call");
      res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    // Opt-in nonce echo: only when the request carries x-clockchain-receipt: 1 AND recording is on.
    // The echo lives in a per-tool-call async scope, so concurrent calls on one request (a JSON-RPC batch)
    // can never read each other's receipt.
    const echoScope = new AsyncLocalStorage<{ echo?: HandshakeReceiptEcho }>();
    const receiptHook = options.receipts?.hookFor({
      headers: req.headers,
      ip,
      onEcho: (e) => { const store = echoScope.getStore(); if (store !== undefined) store.echo = e; },
    });
    const server = buildV2PublicServer({
      pin: options.pin,
      scope: (run) => echoScope.run({}, run),
      metaFor: () => {
        const echo = echoScope.getStore()?.echo;
        return echo === undefined ? undefined : { [HANDSHAKE_RECEIPT_META_KEY]: { ...echo } };
      },
      invoke: async (name, args) => {
        if (name === "agent_handshake_invite") {
          const inviteKey = `invite:${ip}`;
          if (!allowInvite.acquire(inviteKey)) {
            options.onRateLimited?.("handshake_invite");
            throw new V2RateLimitedError(allowInvite.retryAfterMs(inviteKey));
          }
          try {
            return await invoke(name, args, receiptHook);
          } catch (error) {
            // Session-state transient rejections (consumed session, insufficient
            // invitation runway, dependency breaker) mint nothing — refund the
            // hourly budget so SOP-documented retry polling cannot self-lockout.
            if (isV2RetryableToolError(error)) allowInvite.release(inviteKey);
            throw error;
          }
        }
        return invoke(name, args, receiptHook);
      },
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { void transport.close(); void server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    }
  };
}
