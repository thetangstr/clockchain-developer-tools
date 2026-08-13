import { randomBytes } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { buildV2Instructions, type V2ReleasePin } from "./instructions.js";
import { registerV2PublicTools, V2_PUBLIC_TOOL_NAMES, type V2PublicInvoke } from "./public-tools.js";
import { V2RoleAccessError } from "./access.js";

export { V2_PUBLIC_TOOL_NAMES } from "./public-tools.js";

function firstHeader(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

export function v2PublicClientIp(headers: IncomingHttpHeaders, remoteAddress: string | undefined, trustedProxy?: string): string {
  if (trustedProxy && remoteAddress === trustedProxy) {
    const forwarded = firstHeader(headers["x-forwarded-for"]).split(",")[0]?.trim();
    if (forwarded) return forwarded;
  }
  return remoteAddress ?? "unknown";
}

function limiter(limit: number, windowMs: number, now: () => number) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return (key: string): boolean => {
    const current = now();
    const prior = hits.get(key);
    if (!prior || current >= prior.resetAt) {
      hits.set(key, { count: 1, resetAt: current + windowMs });
      return true;
    }
    if (prior.count >= limit) return false;
    prior.count += 1;
    return true;
  };
}

function quota(limit: number, windowMs: number, now: () => number) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return (key: string): (() => void) | null => {
    const current = now();
    let entry = hits.get(key);
    if (!entry || current >= entry.resetAt) {
      entry = { count: 0, resetAt: current + windowMs };
      hits.set(key, entry);
    }
    if (entry.count >= limit) return null;
    entry.count += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (hits.get(key) === entry && entry.count > 0) entry.count -= 1;
    };
  };
}

const ROLE_ACCESS_HANDLE = /^ccra_[A-Za-z0-9_-]{22}$/;
const ROLE_ACCESS_HANDLE_TTL_MS = 60 * 60_000;
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

function createRoleAccessBroker(invoke: V2PublicInvoke, now: () => number): V2PublicInvoke {
  const handles = new Map<string, { access: string; expiresAt: number }>();

  function prune(): void {
    const current = now();
    for (const [handle, entry] of handles) {
      if (current >= entry.expiresAt) handles.delete(handle);
    }
  }

  function issue(access: unknown): string {
    if (typeof access !== "string" || access.length < 80 || access.length > 4096) throw new V2RoleAccessError();
    prune();
    if (handles.size >= ROLE_ACCESS_HANDLE_LIMIT) throw new V2RoleAccessError();
    let handle: string;
    do { handle = `ccra_${randomBytes(16).toString("base64url")}`; } while (handles.has(handle));
    handles.set(handle, { access, expiresAt: now() + ROLE_ACCESS_HANDLE_TTL_MS });
    return handle;
  }

  function resolve(value: unknown): { clientAccess: string; signedAccess: string } {
    if (typeof value !== "string") throw new V2RoleAccessError();
    if (!ROLE_ACCESS_HANDLE.test(value)) return { clientAccess: "", signedAccess: value };
    prune();
    const entry = handles.get(value);
    if (!entry) throw new V2RoleAccessError();
    return { clientAccess: value, signedAccess: entry.access };
  }

  return async (name, args) => {
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

export function buildV2PublicServer(options: { pin: V2ReleasePin; invoke: V2PublicInvoke }): McpServer {
  const server = new McpServer({ name: "clockchain-agent-handshake", version: "2.1.3" }, {
    instructions: buildV2Instructions(options.pin),
  });
  registerV2PublicTools(server, options.invoke);
  return server;
}

export function createV2PublicHttpHandler(options: {
  pin: V2ReleasePin;
  invoke: V2PublicInvoke;
  trustedProxy?: string;
  invitePerHour?: number;
  callsPerMinute?: number;
  now?: () => number;
}) {
  const now = options.now ?? Date.now;
  const reserveInvite = quota(options.invitePerHour ?? 5, 60 * 60_000, now);
  const allowCall = limiter(options.callsPerMinute ?? 120, 60_000, now);
  const invoke = createRoleAccessBroker(options.invoke, now);
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if ((req.url ?? "").split("?")[0] !== "/handshake/mcp") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    const ip = v2PublicClientIp(req.headers, req.socket.remoteAddress, options.trustedProxy);
    if (!allowCall(`call:${ip}`)) {
      res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    const server = buildV2PublicServer({
      pin: options.pin,
      invoke: async (name, args) => {
        const releaseInvite = name === "agent_handshake_invite" ? reserveInvite(`invite:${ip}`) : undefined;
        if (releaseInvite === null) throw new Error("rate_limited");
        try {
          return await invoke(name, args);
        } catch (error) {
          releaseInvite?.();
          throw error;
        }
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
