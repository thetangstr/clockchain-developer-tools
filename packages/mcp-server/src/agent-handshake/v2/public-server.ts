import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { buildV2Instructions, type V2ReleasePin } from "./instructions.js";
import { registerV2PublicTools, V2_PUBLIC_TOOL_NAMES, type V2PublicInvoke } from "./public-tools.js";

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

export function buildV2PublicServer(options: { pin: V2ReleasePin; invoke: V2PublicInvoke }): McpServer {
  const server = new McpServer({ name: "clockchain-agent-handshake", version: "2.1.1" }, {
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
  const allowInvite = limiter(options.invitePerHour ?? 5, 60 * 60_000, now);
  const allowCall = limiter(options.callsPerMinute ?? 120, 60_000, now);
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
        if (name === "agent_handshake_invite" && !allowInvite(`invite:${ip}`)) throw new Error("rate_limited");
        return options.invoke(name, args);
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
