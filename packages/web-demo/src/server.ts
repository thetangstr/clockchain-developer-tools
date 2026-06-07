import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  ApiError,
  AuthError,
  ClockchainClient,
  InsufficientCreditsError,
  RateLimitError,
  computeHash,
  readConfigFromEnv,
} from "@clockchain/core";
import { PAGE } from "./page.js";

/**
 * Zero-install browser demo for the Clockchain notarization workflow.
 *
 * Humans hit a web page; the Clockchain API key stays server-side (read from
 * env, never sent to the browser). Deploy this BEHIND Cloudflare Access (or
 * equivalent identity gate) - it has no token auth of its own, so the access
 * layer is what keeps "just anyone" out. A spend cap (MCP_LOG_BUDGET) limits
 * how many notarizations the demo can make.
 */
const config = readConfigFromEnv();
const client = new ClockchainClient(config);

const cap = Number(process.env.MCP_LOG_BUDGET ?? "0");
let used = 0;

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

/** Map core errors to a friendly message + status for the browser. */
function errorFor(err: unknown): { status: number; message: string } {
  if (err instanceof RateLimitError) return { status: 429, message: "The network is rate-limiting us. Wait a moment and retry." };
  if (err instanceof InsufficientCreditsError) return { status: 402, message: "Out of log credits on the test account." };
  if (err instanceof AuthError) return { status: 500, message: "Server is misconfigured (Clockchain API key)." };
  if (err instanceof ApiError) return { status: 502, message: `Clockchain API error (${err.status}).` };
  return { status: 500, message: err instanceof Error ? err.message : String(err) };
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {};
  return JSON.parse(raw) as Record<string, unknown>;
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(PAGE);
      return;
    }
    if (req.method === "GET" && (req.url === "/health" || req.url === "/healthz")) {
      return send(res, 200, { status: "ok" });
    }
    if (req.method === "POST" && req.url === "/api/time") {
      return send(res, 200, await client.getTime());
    }
    if (req.method === "POST" && req.url === "/api/notarize") {
      const { text } = await readJson(req);
      if (typeof text !== "string" || text.length === 0) {
        return send(res, 400, { error: "text is required" });
      }
      if (cap > 0 && used >= cap) {
        return send(res, 429, { error: "Demo notarization budget reached. Restart to reset." });
      }
      const hash = computeHash(text);
      const assetReferenceId = `webdemo-${Date.now()}`;
      const result = await client.log({ assetHash: hash, assetReferenceId, additionalInfo: "clockchain web demo" });
      if (cap > 0) used++;
      let confirmed = result;
      try {
        confirmed = await client.waitForConfirmation(result.ledgerId, 12000);
      } catch {
        // keep the pending record; the page shows "pending"
      }
      return send(res, 200, {
        ledgerId: confirmed.ledgerId,
        blockHeight: confirmed.blockHeight,
        hash,
        assetReferenceId,
      });
    }
    if (req.method === "POST" && req.url === "/api/verify") {
      const { ledgerId, text } = await readJson(req);
      if (typeof ledgerId !== "string" || typeof text !== "string") {
        return send(res, 400, { error: "ledgerId and text are required" });
      }
      const record = await client.getLedgerEntry(ledgerId);
      const hash = computeHash(text);
      return send(res, 200, {
        match: record.assetHash === hash,
        anchoredHash: record.assetHash,
        currentHash: hash,
        blockHeight: record.blockHeight,
      });
    }
    return send(res, 404, { error: "not found" });
  } catch (err) {
    const { status, message } = errorFor(err);
    if (!res.headersSent) send(res, status, { error: message });
  }
});

const port = Number(process.env.WEB_PORT ?? process.env.PORT ?? "8080");
server.listen(port, () => {
  console.error(`[clockchain-web-demo] listening on :${port}`);
  if (cap > 0) console.error(`[clockchain-web-demo] notarization budget: ${cap}`);
  console.error("[clockchain-web-demo] deploy BEHIND an identity gate (Cloudflare Access); no token auth of its own.");
});
