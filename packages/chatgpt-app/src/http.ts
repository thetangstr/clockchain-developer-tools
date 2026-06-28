import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { ClockchainConfig } from "@clockchain/core";
import { buildServer } from "./server.js";

/**
 * HTTP entry point for the ChatGPT dev-mode connector.
 *
 * Dev-mode auth = a per-tester `x-api-key` header (NO OAuth in this milestone).
 * Two accepted shapes, in priority order:
 *   1. Allowlisted tester key (CHATGPT_APP_TESTER_KEYS) -> uses the delegated
 *      (env) Clockchain key; the tester's header is just an access gate.
 *   2. Any other x-api-key -> treated as the caller's own Clockchain key (BYO);
 *      writes spend their credits. The gateway is the real gate.
 * No key -> a self-documenting 401.
 *
 * Stateless StreamableHTTP: one transport + server per request (matches the main
 * MCP server's wiring and ChatGPT's connector expectations).
 *
 * Public listing later requires OAuth 2.1 (AGE-194) — see the README + launch plan.
 */

const firstHeader = (h: string | string[] | undefined): string =>
  (Array.isArray(h) ? h[0] : h) ?? "";

export const pathOf = (url: string | undefined): string => (url ?? "").split("?")[0];

/** Parse a comma-separated allowlist of tester keys. */
export function parseTesterKeys(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

/**
 * Resolve the per-request Clockchain config override from the x-api-key header.
 * Returns:
 *   - `{}`        when the key is an allowlisted tester key (use delegated env key)
 *   - `{apiKey}`  when it is some other key (BYO; also picks up x-clockchain-* ids)
 *   - `null`      when no key was presented (-> 401)
 */
export function resolveOverride(
  headers: Record<string, string | string[] | undefined>,
  testerKeys: string[],
): Partial<ClockchainConfig> | null {
  const apiKey = firstHeader(headers["x-api-key"]).trim();
  if (!apiKey) return null;
  if (testerKeys.includes(apiKey)) return {};
  const o: Partial<ClockchainConfig> = { apiKey };
  const clientId = firstHeader(headers["x-clockchain-client-id"]).trim();
  const walletId = firstHeader(headers["x-clockchain-wallet-id"]).trim();
  if (clientId) o.clientId = clientId;
  if (walletId) o.walletId = walletId;
  return o;
}

export function isHealthCheck(method: string | undefined, url: string | undefined): boolean {
  return method === "GET" && (pathOf(url) === "/health" || pathOf(url) === "/healthz");
}

export async function runHttp(): Promise<void> {
  const port = Number(process.env.PORT ?? process.env.MCP_PORT ?? "3000");
  const testerKeys = parseTesterKeys(process.env.CHATGPT_APP_TESTER_KEYS);

  if (testerKeys.length === 0) {
    console.error(
      "[clockchain-chatgpt-app] WARNING: CHATGPT_APP_TESTER_KEYS is empty. Every " +
        "request must bring its own Clockchain key via x-api-key; no allowlisted " +
        "tester key will work. Set CHATGPT_APP_TESTER_KEYS for the dev connector.",
    );
  }

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (isHealthCheck(req.method, req.url)) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    // Friendly dev info page for a human hitting the endpoint in a browser.
    if (req.method === "GET" && firstHeader(req.headers.accept).includes("text/html")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        "<!doctype html><meta charset=utf-8><title>Clockchain ChatGPT app</title>" +
          "<body style='font-family:system-ui;max-width:640px;margin:40px auto'>" +
          "<h1>Clockchain ChatGPT app (dev mode)</h1>" +
          "<p>This is an OpenAI Apps SDK (MCP) endpoint. Add it as a ChatGPT " +
          "developer-mode connector and authenticate with an <code>x-api-key</code> header.</p>" +
          "<p>See the package README for the exact connector steps.</p>",
      );
      return;
    }

    const override = resolveOverride(req.headers, testerKeys);
    if (override === null) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "unauthorized",
          message:
            "Clockchain ChatGPT app (dev mode). Authenticate with an x-api-key header: " +
            "either an allowlisted tester key, or your own Clockchain API key " +
            "(optionally with x-clockchain-client-id / x-clockchain-wallet-id).",
          transport: "http",
        }),
      );
      return;
    }

    try {
      const server = buildServer(override);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch (err) {
      console.error("[clockchain-chatgpt-app] http request error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    }
  });

  httpServer.listen(port, () => {
    console.error(`[clockchain-chatgpt-app] http server listening on :${port}`);
    console.error(
      `[clockchain-chatgpt-app] tester keys: ${
        testerKeys.length > 0 ? `${testerKeys.length} allowlisted` : "none (BYO key only)"
      }`,
    );
  });
}
