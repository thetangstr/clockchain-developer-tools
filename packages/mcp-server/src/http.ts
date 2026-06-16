import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { type ClockchainConfig } from "@clockchain/core";
import { buildServer } from "./server.js";
import { LANDING_HTML, INSTALL_TXT, MCP_MANIFEST } from "./landing.js";

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
 * Bring-your-own-key: if the caller presents their own Clockchain credentials as
 * request headers, return them as a config override so the per-request server
 * uses THEIR key (their credits). Returns undefined when no `x-clockchain-api-key`
 * is present, in which case the server uses the delegated (env) key. The endpoint
 * is fixed server-side (callers cannot redirect it).
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
 */
export function callerKey(
  headers: {
    authorization?: string | string[];
    "x-api-key"?: string | string[];
    "x-clockchain-api-key"?: string | string[];
  },
  remoteAddr: string | undefined,
): string {
  const bearer = /^Bearer\s+(.+)$/i.exec(firstHeader(headers.authorization));
  if (bearer) return `tok:${bearer[1].trim()}`;
  const apiKey = firstHeader(headers["x-api-key"]).trim();
  if (apiKey) return `tok:${apiKey}`;
  // Bring-your-own-key requests carry no MCP token; key them by their own
  // Clockchain key so the per-caller rate limit still applies.
  const cck = firstHeader(headers["x-clockchain-api-key"]).trim();
  if (cck) return `cck:${cck}`;
  return `ip:${remoteAddr ?? "unknown"}`;
}

/**
 * Fixed-window per-key rate limiter. Disabled (always allows) when perMin <= 0.
 * Pure and injectable (`now`) so it can be unit-tested without timers.
 */
export function createRateLimiter(perMin: number) {
  const windowMs = 60_000;
  const hits = new Map<string, { count: number; resetAt: number }>();
  return {
    enabled: perMin > 0,
    /** True if the request is allowed; false if the key is over its limit. */
    allow(key: string, now: number = Date.now()): boolean {
      if (perMin <= 0) return true;
      const e = hits.get(key);
      if (!e || now >= e.resetAt) {
        hits.set(key, { count: 1, resetAt: now + windowMs });
        return true;
      }
      if (e.count >= perMin) return false;
      e.count++;
      return true;
    },
  };
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

  const checkAuth = (req: IncomingMessage): boolean =>
    isAuthorized(req.headers, tokens);

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
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
    if (!byo && !checkAuth(req)) {
      const presented = presentedApiKey(req.headers);
      if (presented) {
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
              note: "per-user MCP token from the team (shared testnet pool)",
            },
            bringYourOwnKey: {
              headers: ["x-clockchain-api-key", "x-clockchain-client-id", "x-clockchain-wallet-id"],
              note: "your own Clockchain API key (writes spend your credits)",
            },
          },
          manifest: "https://mcp.clockchain.network/.well-known/mcp.json",
          install: "https://mcp.clockchain.network/llms.txt",
          docs: "https://github.com/thetangstr/clockchain-developer-tools/blob/main/INSTALL.md",
        }),
        );
        return;
      }
    }

    // Per-tester rate limit (after auth so the key is the validated token).
    if (limiter.enabled && !limiter.allow(callerKey(req.headers, req.socket.remoteAddress))) {
      res.writeHead(429, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }

    try {
      const server = buildServer(byo);
      const transport = new StreamableHTTPServerTransport({
        // Stateless: no session id generation.
        sessionIdGenerator: undefined,
      });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
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
  });
}
