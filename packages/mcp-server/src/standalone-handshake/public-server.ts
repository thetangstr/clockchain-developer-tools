import { randomBytes } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { STANDALONE_HANDSHAKE_PROTOCOL } from "./protocol.js";
import { STANDALONE_ROLE_SCOPED_TOOLS, STANDALONE_TOOL_NAMES, registerStandaloneTools } from "./tools.js";

export { STANDALONE_TOOL_NAMES } from "./tools.js";

const STANDALONE_ENDPOINT = "https://mcp.clockchain.network/connect/mcp";
const ROLE_ACCESS_HANDLE = /^csha_[A-Za-z0-9_-]{22}$/;
const ROLE_ACCESS_HANDLE_TTL_MS = 60 * 60_000;
const ROLE_ACCESS_HANDLE_LIMIT = 10_000;

export function buildStandaloneInstructions(): string {
  return [
    "Clockchain Standalone Handshake — the pre-negotiation, mutually authenticated gateway for two agents.",
    "",
    `Protocol ${STANDALONE_HANDSHAKE_PROTOCOL}. LOCAL SIGNING REQUIRED: this server never holds a private key and never signs for either party. consent_sign expects an EIP-191 signature over the exact canonical consent bytes returned in handshake_status; submit only that signature.`,
    "",
    "Flow: handshake_invite → the Responder runs handshake_accept_invitation with their readiness package → the deterministic checklist (identity, authority, capability manifest) must pass → both roles consent_sign the same digest → channel_open anchors the witnessed opening receipt → channel_send / channel_read within the consented scope until expiry, channel_close, or channel_revoke.",
    "",
    "Consent covers communication only. Opening the channel authorizes no external business action, accepts no proposal, and moves no funds. The server records what was checked and consented to; it does not guarantee truthfulness of either party.",
  ].join("\n");
}

export function buildStandaloneDiscovery(): Record<string, unknown> {
  return {
    name: "clockchain-standalone-handshake",
    protocol: STANDALONE_HANDSHAKE_PROTOCOL,
    endpoint: STANDALONE_ENDPOINT,
    tools: [...STANDALONE_TOOL_NAMES],
    localSigningRequired: true,
    externalBusinessActionsAllowed: false,
  };
}

function firstHeader(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

export function standaloneClientIp(headers: IncomingHttpHeaders, remoteAddress: string | undefined, trustedProxy?: string): string {
  if (trustedProxy && remoteAddress === trustedProxy) {
    return firstHeader(headers["x-forwarded-for"]).split(",")[0]?.trim() || remoteAddress || "unknown";
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

class StandaloneRoleAccessError extends Error {
  constructor() {
    super("standalone role access refused");
    this.name = "StandaloneRoleAccessError";
  }
}

function createRoleAccessBroker(invoke: (name: string, args: Record<string, unknown>) => Promise<unknown>, now: () => number) {
  const handles = new Map<string, { access: string; expiresAt: number }>();

  function prune(): void {
    const current = now();
    for (const [handle, entry] of handles) if (current >= entry.expiresAt) handles.delete(handle);
  }

  function issue(access: unknown): string {
    if (typeof access !== "string" || access.length < 20 || access.length > 4096) throw new StandaloneRoleAccessError();
    prune();
    if (handles.size >= ROLE_ACCESS_HANDLE_LIMIT) throw new StandaloneRoleAccessError();
    let handle: string;
    do {
      handle = `csha_${randomBytes(16).toString("base64url")}`;
    } while (handles.has(handle));
    handles.set(handle, { access, expiresAt: now() + ROLE_ACCESS_HANDLE_TTL_MS });
    return handle;
  }

  function resolve(value: unknown): { clientHandle: string | undefined; signedAccess: string } {
    if (typeof value !== "string") throw new StandaloneRoleAccessError();
    if (!ROLE_ACCESS_HANDLE.test(value)) return { clientHandle: undefined, signedAccess: value };
    prune();
    const entry = handles.get(value);
    if (!entry) throw new StandaloneRoleAccessError();
    return { clientHandle: value, signedAccess: entry.access };
  }

  return async (name: string, args: Record<string, unknown>) => {
    if (STANDALONE_ROLE_SCOPED_TOOLS.includes(name as never)) {
      const resolved = resolve(args.access);
      const result = (await invoke(name, { ...args, access: resolved.signedAccess })) as Record<string, unknown>;
      return { ...result, roleAccess: resolved.clientHandle ?? issue(resolved.signedAccess) };
    }
    const result = (await invoke(name, args)) as Record<string, unknown>;
    if (name === "handshake_invite") return { ...withoutAccessKeys(result), roleAccess: issue(result.initiatorAccess) };
    if (name === "handshake_accept_invitation") return { ...withoutAccessKeys(result), roleAccess: issue(result.responderAccess) };
    return result;
  };
}

function withoutAccessKeys(result: Record<string, unknown>): Record<string, unknown> {
  const { initiatorAccess: _i, responderAccess: _r, ...rest } = result;
  return rest;
}

export function buildStandalonePublicServer(options: { invoke: (name: string, args: Record<string, unknown>) => Promise<unknown> }): McpServer {
  const server = new McpServer({ name: "clockchain-standalone-handshake", version: "0.1.0" }, {
    instructions: buildStandaloneInstructions(),
  });
  registerStandaloneTools(server, options.invoke as never);
  return server;
}

export function createStandaloneHttpHandler(options: {
  invoke: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  trustedProxy?: string;
  invitesPerHour?: number;
  callsPerMinute?: number;
  now?: () => number;
}) {
  const now = options.now ?? Date.now;
  const allowInvite = limiter(options.invitesPerHour ?? 5, 60 * 60_000, now);
  const allowCall = limiter(options.callsPerMinute ?? 120, 60_000, now);
  const invoke = createRoleAccessBroker(options.invoke, now);
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if ((req.url ?? "").split("?")[0] !== "/connect/mcp") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    const ip = standaloneClientIp(req.headers, req.socket.remoteAddress, options.trustedProxy);
    if (!allowCall(`call:${ip}`)) {
      res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    const server = buildStandalonePublicServer({
      invoke: async (name, args) => {
        if (name === "handshake_invite" && !allowInvite(`invite:${ip}`)) throw new Error("rate_limited");
        return invoke(name, args);
      },
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
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
