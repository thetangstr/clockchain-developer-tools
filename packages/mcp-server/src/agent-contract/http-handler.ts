import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { limiter as keyedWindowLimiter } from "../standalone-handshake/public-server.js";
import { buildContractServer } from "./server.js";
import { createContractService, type ContractPrincipal, type ContractService, type ContractSide } from "./service.js";
import type { ContractSigner } from "./envelope.js";
import type { HostRootPin } from "./certificate.js";
import type { ContractRole } from "./schemas.js";

/**
 * HTTP transport for `/contract/mcp` (LLD §3). Mirrors the v2 public
 * handshake handler: stateless StreamableHTTP transports, a per-principal
 * call bucket, and auth that fails closed.
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
 */

const CONTRACT_PATH = "/contract/mcp";
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

export interface ContractTokenEntry {
  /** sha256 of the raw bearer token — the token itself is never retained. */
  readonly digest: Buffer;
  readonly principal: ContractPrincipal;
}

/**
 * Parse `CONTRACT_AUTH_TOKENS`: comma-separated `token:role:keyId:agentId:side`
 * entries. Throws on malformed entries, duplicate tokens, or tokens containing
 * `:` — bad config must fail loudly at startup, not lazily on traffic.
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
    if (!DECIMAL.test(agentId)) {
      throw new Error(`CONTRACT_AUTH_TOKENS: agentId "${agentId}" is not a decimal ERC-8004 id`);
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

export function createContractHttpHandler(options: {
  authenticate: (headers: IncomingHttpHeaders) => ContractPrincipal | null;
  hostRoots: readonly HostRootPin[];
  signer: ContractSigner;
  service?: ContractService;
  callsPerMinute?: number;
  trustProxy?: boolean;
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
      sourceIp: clientIp(req.headers, req.socket.remoteAddress, options.trustProxy === true),
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
