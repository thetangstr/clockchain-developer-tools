import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildServer } from "./server.js";

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

export async function runHttp(): Promise<void> {
  const port = Number(process.env.MCP_PORT ?? "3000");
  const tokens = parseTokens(process.env.MCP_AUTH_TOKENS);

  const checkAuth = (req: IncomingMessage): boolean =>
    isAuthorized(req.headers, tokens);

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (!checkAuth(req)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }

    try {
      const server = buildServer();
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
