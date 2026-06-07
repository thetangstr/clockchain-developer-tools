import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  ApiError,
  AuthError,
  ClockchainClient,
  InsufficientCreditsError,
  RateLimitError,
  buildReceipt,
  computeHash,
  eventHashOf,
  readConfigFromEnv,
  type BlockResponse,
  type ValidationBlock,
} from "@clockchain/core";
import { randomUUID } from "node:crypto";
import { PAGE } from "./page.js";
import { runTurn, llmConfigured } from "./agent.js";

/** A visible "behind the scenes" step with the real time it took. */
type Step = { label: string; ms: number; detail?: string };
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** In-memory chat sessions: sessionId -> running LLM message history. */
const sessions = new Map<string, unknown[]>();
import { buildFeedbackRecord } from "./feedback.js";

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

const FEEDBACK_FILE = resolve(process.env.FEEDBACK_FILE ?? "feedback.jsonl");

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
    if (req.method === "GET" && req.url === "/api/config") {
      return send(res, 200, { agent: llmConfigured() });
    }
    if (req.method === "POST" && req.url === "/api/agent") {
      if (!llmConfigured()) {
        return send(res, 503, { error: "The agent (LLM) is not configured on this host." });
      }
      const { sessionId, message } = await readJson(req);
      if (typeof message !== "string" || message.trim().length === 0) {
        return send(res, 400, { error: "message is required" });
      }
      if (cap > 0 && used >= cap) {
        return send(res, 429, { error: "Demo budget reached. Restart to reset." });
      }
      const sid = typeof sessionId === "string" && sessions.has(sessionId) ? sessionId : randomUUID();
      const history = sessions.get(sid) ?? [];
      const { events, receipt } = await runTurn(history as unknown[], message.trim());
      sessions.set(sid, history);
      if (cap > 0 && events.some((e) => e.type === "tool_result" && /ledgerId/.test(e.content))) used++;
      return send(res, 200, { sessionId: sid, events, receipt });
    }
    if (req.method === "POST" && req.url === "/api/time") {
      const t = Date.now();
      const time = await client.getTime();
      const steps: Step[] = [
        { label: "Query the Clockchain gateway for the latest consented block", ms: Date.now() - t, detail: `GET node.clockchain.network/api/time` },
        { label: "Network returns the Marzullo consensus time (agreed by the validator set, not one server's clock)", ms: 0, detail: `block ${time.latestBlockHeight}` },
      ];
      return send(res, 200, { ...time, steps });
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
    if (req.method === "POST" && req.url === "/api/attest") {
      const { agentId, action, inputs, outputs } = await readJson(req);
      if (typeof agentId !== "string" || typeof action !== "string") {
        return send(res, 400, { error: "agentId and action are required" });
      }
      if (cap > 0 && used >= cap) {
        return send(res, 429, { error: "Demo budget reached. Restart to reset." });
      }

      // Orchestrate the attestation step-by-step so the page can show the real
      // (fast) on-chain work happening behind the scenes. No LLM is involved on
      // this path - it is a direct SDK integration.
      const steps: Step[] = [];
      const input = { agentId, action, inputs, outputs };

      let t = Date.now();
      const eventHash = eventHashOf(input);
      steps.push({ label: "Canonicalize the agent's inputs + outputs (sorted JSON) and compute the SHA-256 event fingerprint", ms: Date.now() - t, detail: eventHash });

      t = Date.now();
      const assetReferenceId = `${agentId}:${action}:${Date.now()}`;
      const log = await client.log({ assetHash: eventHash, assetReferenceId, additionalInfo: "agent attested receipt" });
      if (cap > 0) used++;
      steps.push({ label: "Anchor the fingerprint on-chain (POST /log -> node.clockchain.network)", ms: Date.now() - t, detail: `ledgerId ${log.ledgerId}` });

      t = Date.now();
      const confirmed = await client.waitForConfirmation(log.ledgerId, 12000);
      steps.push({ label: "Wait for the validator network to write it into a consensus block", ms: Date.now() - t, detail: confirmed.blockHeight ? `block ${confirmed.blockHeight}` : "still pending" });

      let block: BlockResponse | null = null;
      let validation: ValidationBlock | null = null;
      if (confirmed.blockHeight != null) {
        // Retry briefly: the block-detail endpoint can lag a beat behind the height.
        t = Date.now();
        for (let i = 0; i < 4 && !block?.blockTime; i++) {
          block = await client.getBlock(confirmed.blockHeight).catch(() => null);
          if (!block?.blockTime) await delay(400);
        }
        steps.push({ label: "Read the block's consensus timestamp (Marzullo time, multi-source at mainnet)", ms: Date.now() - t, detail: block?.blockTime ?? "n/a" });

        t = Date.now();
        validation = await client.getValidationBlock(confirmed.blockHeight).catch(() => null);
        const votes = validation ? (validation.positiveVotes ?? 0) : 0;
        steps.push({ label: "Read the validator attestation for that block", ms: Date.now() - t, detail: `${votes} validator vote(s) - single-validator on testnet` });
      }

      const receipt = buildReceipt({ input, eventHash, network: "testnet", log: confirmed, block, validation, identity: null });
      steps.push({ label: "Assemble the Agent Attested Receipt", ms: 0, detail: "self-verifying artifact" });
      return send(res, 200, { ...receipt, steps });
    }
    if (req.method === "POST" && req.url === "/api/verify-receipt") {
      const { receipt } = await readJson(req);
      if (!receipt || typeof receipt !== "object") {
        return send(res, 400, { error: "receipt is required" });
      }
      const r = receipt as { agentId: string; action: string; payload?: { inputs?: unknown; outputs?: unknown }; anchor?: { ledgerId?: string } };
      const steps: Step[] = [];
      let t = Date.now();
      const recomputed = eventHashOf({ agentId: r.agentId, action: r.action, inputs: r.payload?.inputs, outputs: r.payload?.outputs });
      steps.push({ label: "Recompute the SHA-256 fingerprint from the receipt's own payload (no trust in us required)", ms: Date.now() - t, detail: recomputed });
      t = Date.now();
      const result = await client.verifyReceipt(receipt as never);
      steps.push({ label: "Fetch the hash anchored on-chain at this ledgerId and compare", ms: Date.now() - t, detail: `anchored ${result.anchoredHash}` });
      steps.push({ label: result.match ? "Fingerprints match - the receipt is genuine and unaltered" : "Fingerprints differ - the record was altered", ms: 0 });
      return send(res, 200, { ...result, steps });
    }
    if (req.method === "POST" && req.url === "/api/feedback") {
      const body = await readJson(req);
      const { record, error } = buildFeedbackRecord(body, req.headers, Date.now());
      if (error) return send(res, 400, { error });
      await mkdir(dirname(FEEDBACK_FILE), { recursive: true });
      await appendFile(FEEDBACK_FILE, JSON.stringify(record) + "\n", "utf8");
      console.error(
        `[clockchain-web-demo] feedback: rating=${record!.rating} from=${record!.email || record!.role || "anon"}`,
      );
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: "not found" });
  } catch (err) {
    const { status, message } = errorFor(err);
    if (!res.headersSent) send(res, status, { error: message });
  }
});

const port = Number(process.env.WEB_PORT ?? process.env.PORT ?? "8080");
// Optional bind host. Set WEB_HOST to a specific interface (e.g. the tailnet IP)
// to restrict reach to that network; unset binds all interfaces.
const host = process.env.WEB_HOST || undefined;
server.listen(port, host, () => {
  console.error(`[clockchain-web-demo] listening on ${host ?? "*"}:${port}`);
  if (cap > 0) console.error(`[clockchain-web-demo] notarization budget: ${cap}`);
  console.error(`[clockchain-web-demo] feedback -> ${FEEDBACK_FILE}`);
  console.error("[clockchain-web-demo] deploy BEHIND an identity gate (Cloudflare Access); no token auth of its own.");
});
