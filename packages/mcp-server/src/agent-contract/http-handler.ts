import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { limiter as keyedWindowLimiter } from "../standalone-handshake/public-server.js";
import { buildContractServer } from "./server.js";
import { createContractService, type ContractPrincipal, type ContractService } from "./service.js";
import type { ContractSigner } from "./envelope.js";
import type { HostRootPin } from "./certificate.js";
import type { ContractRole } from "./schemas.js";

/**
 * HTTP transport for `/contract/mcp` (LLD §3). Mirrors the v2 public
 * handshake handler: stateless StreamableHTTP transports, a per-principal
 * call bucket, and auth that fails closed.
 *
 * Auth is bearer-token based: the harness provisions one token per role
 * (LLD §8 — credential sets are disjoint per role). `authenticate` maps a
 * request's Authorization header to `{keyId, role}`; a null return is a 401.
 * There is no anonymous mode — a contract surface without tokens refuses
 * every request.
 */

const CONTRACT_PATH = "/contract/mcp";

/**
 * Parse `CONTRACT_AUTH_TOKENS`: comma-separated `token:role:keyId` entries.
 * Tokens may not contain `:` or whitespace; role is buyer|provider. Throws on
 * malformed entries — bad config must fail loudly at startup, not silently
 * drop an entry.
 */
export function parseContractTokens(raw: string | undefined): Record<string, ContractPrincipal> {
  const out: Record<string, ContractPrincipal> = {};
  for (const entry of (raw ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const parts = entry.split(":").map((p) => p.trim());
    if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
      throw new Error(`malformed CONTRACT_AUTH_TOKENS entry (want token:role:keyId)`);
    }
    const [token, role, keyId] = parts as [string, string, string];
    if (role !== "buyer" && role !== "provider") {
      throw new Error(`CONTRACT_AUTH_TOKENS: unknown role "${role}"`);
    }
    out[token] = { keyId, role: role as ContractRole };
  }
  return out;
}

/** Bearer-token authenticate over a parsed token map. */
export function tokenAuthenticator(
  tokens: Readonly<Record<string, ContractPrincipal>>,
): (headers: IncomingHttpHeaders) => ContractPrincipal | null {
  return (headers) => {
    const raw = headers.authorization;
    const header = (Array.isArray(raw) ? raw[0] : raw) ?? "";
    const match = /^Bearer\s+(.+)$/i.exec(header);
    if (match === null) return null;
    return tokens[match[1].trim()] ?? null;
  };
}

function clientIp(headers: IncomingHttpHeaders, remoteAddress: string | undefined): string {
  const xff = (Array.isArray(headers["x-forwarded-for"]) ? headers["x-forwarded-for"][0] : headers["x-forwarded-for"]) ?? "";
  const first = xff.split(",")[0]?.trim();
  return first || remoteAddress || "unknown";
}

export function createContractHttpHandler(options: {
  authenticate: (headers: IncomingHttpHeaders) => ContractPrincipal | null;
  hostRoots: readonly HostRootPin[];
  signer: ContractSigner;
  service?: ContractService;
  callsPerMinute?: number;
  now?: () => number;
  onRateLimited?: () => void;
}) {
  const now = options.now ?? Date.now;
  const service = options.service ?? createContractService({
    hostRoots: options.hostRoots,
    signer: options.signer,
    now,
  });
  const allowCall = keyedWindowLimiter(options.callsPerMinute ?? 120, 60_000, now);

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = (req.url ?? "").split("?")[0];
    if (path !== CONTRACT_PATH) {
      res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    const principal = options.authenticate(req.headers);
    if (principal === null) {
      res.writeHead(401, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (!allowCall(`call:${principal.keyId}`)) {
      options.onRateLimited?.();
      res.writeHead(429, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    const server = buildContractServer({
      principal,
      service,
      sourceIp: clientIp(req.headers, req.socket.remoteAddress),
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
