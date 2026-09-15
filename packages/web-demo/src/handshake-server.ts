import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { runHandshake, type DemoEvent, type DemoRunResult, type FaultFlags } from "./handshake/orchestrator.js";
import { HANDSHAKE_PAGE } from "./handshake/page.js";

/**
 * Standalone Handshake theater — a self-contained demo server that drives two
 * unconnected agent personas (fresh ephemeral Sepolia keypairs, local EIP-191
 * signing) through a real handshake against the staging endpoint, and streams
 * every beat to a three-pane page over SSE. Anchors are verified KEYLESSLY
 * (GET /searchAssetFromChain — no API key) so the witness pane proves the same
 * thing an outside counterparty could check themselves.
 *
 *   HANDSHAKE_ENDPOINT  staging MCP endpoint (default below)
 *   PORT / HOST         listen address (default 5001 / 127.0.0.1)
 */
const ENDPOINT = process.env.HANDSHAKE_ENDPOINT ?? "https://mcp.clockchain.network/staging/connect/mcp";
// The public keyless-verification route is a sibling of the handshake endpoint —
// anyone can GET it with no account and confirm an anchor against the immutable
// on-chain block.
const VERIFY_ROUTE = ENDPOINT.replace(/\/connect\/mcp\/?$/, "/connect/verify");
const PORT = Number(process.env.PORT ?? "5001");
const HOST = process.env.HOST ?? "127.0.0.1";

// --- live event bus: every subscriber gets every beat -----------------------
const subscribers = new Set<ServerResponse>();
const emit = (e: DemoEvent) => {
  const line = `data: ${JSON.stringify(e)}\n\n`;
  for (const res of subscribers) res.write(line);
};

// --- run registry (in-memory; replay reads the stored event log) ------------
interface StoredRun {
  id: string;
  label: string;
  result: DemoRunResult;
  at: string;
}
const runs = new Map<string, StoredRun>();
let running = false;
let lastRunId: string | undefined;

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

const send = (res: ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
};

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  try {
    const path = (req.url ?? "").split("?")[0];

    if (req.method === "GET" && (path === "/" || path === "/handshake")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(HANDSHAKE_PAGE);
      return;
    }

    if (req.method === "GET" && path === "/handshake/events") {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
        connection: "keep-alive",
        "x-accel-buffering": "no",
      });
      res.write(`data: ${JSON.stringify({ ts: Date.now(), pane: "control", kind: "info", label: "connected", detail: `endpoint ${ENDPOINT}` })}\n\n`);
      subscribers.add(res);
      req.on("close", () => subscribers.delete(res));
      return;
    }

    if (req.method === "POST" && path === "/handshake/api/run") {
      if (running) return send(res, 409, { error: "a run is already in progress" });
      const { faults } = await readJson(req);
      running = true;
      const id = `run-${Date.now().toString(36)}`;
      void (async () => {
        try {
          const result = await runHandshake({ endpoint: ENDPOINT, faults: faults as FaultFlags, emit });
          const label = `${new Date().toISOString().slice(11, 19)} · ${result.sessionId?.slice(0, 8) ?? "no-session"}`;
          runs.set(id, { id, label, result, at: new Date().toISOString() });
          lastRunId = id;
          while (runs.size > 25) runs.delete(runs.keys().next().value as string);
          emit({ ts: Date.now(), pane: "control", kind: "info", label: "run complete", detail: `${result.refusals.length} refusal(s)` });
        } catch (e) {
          emit({ ts: Date.now(), pane: "control", kind: "error", label: "run failed", detail: String((e as Error).message).slice(0, 200) });
          emit({ ts: Date.now(), pane: "control", kind: "info", label: "run complete", detail: "aborted" });
        } finally {
          running = false;
        }
      })();
      return send(res, 202, { runId: id });
    }

    if (req.method === "POST" && path === "/handshake/api/verify") {
      const run = lastRunId ? runs.get(lastRunId) : undefined;
      const receipt = run?.result.openingReceipt;
      const anchors = [
        ...((receipt?.anchors as { kind: string; ledgerId: string; blockHeight: string; digest: string }[] | undefined) ?? []),
        ...(run?.result.closureReceipt?.closureAnchor
          ? [run.result.closureReceipt.closureAnchor as { ledgerId: string; blockHeight: string; digest: string }]
          : []),
      ];
      const results = await Promise.all(
        anchors.map(async (a) => {
          const url = `${VERIFY_ROUTE}?ledgerId=${encodeURIComponent(a.ledgerId)}&blockHeight=${encodeURIComponent(a.blockHeight)}`;
          try {
            const res = await fetch(url);
            const body = (await res.json()) as Record<string, unknown>;
            return { ...body, url };
          } catch (e) {
            return { verifiedAgainst: "none", ledgerId: a.ledgerId, blockHeight: a.blockHeight, note: String((e as Error).message).slice(0, 160), url };
          }
        }),
      );
      return send(res, 200, { results });
    }

    if (req.method === "GET" && path === "/handshake/api/runs") {
      return send(res, 200, { runs: [...runs.values()].map((r) => ({ id: r.id, label: r.label, at: r.at })).reverse() });
    }

    const replay = path.match(/^\/handshake\/api\/runs\/([\w-]+)$/);
    if (req.method === "GET" && replay) {
      const run = runs.get(replay[1] as string);
      if (!run) return send(res, 404, { error: "unknown run" });
      return send(res, 200, { events: run.result.events, sessionId: run.result.sessionId });
    }

    send(res, 404, { error: "not_found" });
  } catch (e) {
    send(res, 500, { error: String((e as Error).message).slice(0, 200) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`handshake theater: http://${HOST}:${PORT}/  (endpoint: ${ENDPOINT})`);
});
