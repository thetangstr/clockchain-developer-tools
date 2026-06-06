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
export async function runHttp(): Promise<void> {
  const port = Number(process.env.MCP_PORT ?? "3000");
  const tokens = (process.env.MCP_AUTH_TOKENS ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const checkAuth = (req: IncomingMessage): boolean => {
    if (tokens.length === 0) return true;
    const header = req.headers["authorization"] ?? "";
    const match = /^Bearer\s+(.+)$/i.exec(Array.isArray(header) ? header[0] : header);
    return match != null && tokens.includes(match[1].trim());
  };

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
