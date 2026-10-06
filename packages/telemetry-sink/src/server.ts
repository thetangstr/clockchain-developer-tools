import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import type { LaneService } from "./lanes.js";
import type { SinkRefusalCode, TelemetrySink } from "./sink.js";
import type { SinkKeysDoc } from "./sink-key.js";
import type { TokenStore } from "./tokens.js";

/**
 * HTTP surface for the telemetry sink (N4c).
 *
 * The surface is split over THREE listeners (N4C-CHANGES-3/4) so pf can keep
 * each plane reachable only by its own uid:
 *
 *   write listener  (services uids — the forwarders):
 *     POST /v1/traces  |  POST /v1/logs     — OTLP/JSON ingest, Bearer ingest token
 *     GET  /v1/health                       — liveness, unauthenticated
 *   read listener   (harness / verifier uids):
 *     GET  /v1/runs/:runId/records          — paged records + head + annex + advisory, Bearer query/global-query token
 *     GET  /v1/runs/:runId/head             — signed head + annex + advisory, Bearer query/global-query token
 *     GET  /v1/health                       — liveness, unauthenticated
 *     GET  /v1/runs/:runId/receipt          — the accepted terminal receipt (v1 or v2), same gate (O-1)
 *   close listener  (contract-server uid/address ONLY — N4C-CHANGES-4):
 *     POST /v1/runs/:runId/close            — body = signed contract-server terminal receipt
 *                                           (no bearer — the receipt IS the authority)
 *     POST /v1/lanes/open                   — body = contract-signed ac-lane-open/v1 (O-1; only when lanes are wired)
 *     POST /v1/runs/:runId/link             — body = contract-signed ac-run-link/v1 (O-1; only when lanes are wired)
 *
 * Auth is capability-separated: ingest writes (never reads), query reads one
 * run (never writes/closes), and "global-query" — an explicit separate kind —
 * reads across runs. Close authority belongs to the SINK: only a terminal
 * receipt signed by a pinned contract-server key (or window expiry) closes a
 * run — no bearer token can. Unknown or revoked tokens get a bare 401 and
 * write nothing; a post-close ingest returns 409 only AFTER the token kind
 * check, so non-ingest holders learn nothing (no closed-run oracle).
 *
 * OTLP is `application/json` ONLY — no protobuf decoder exists in this
 * workspace, so exporters must be configured `OTEL_EXPORTER_OTLP_PROTOCOL=
 * http/json`. Chain verification in query responses is `advisory` with
 * `evidentiary: false` — the evidence is the records + signed head; callers
 * must re-verify offline.
 *
 * There is deliberately NO public mint endpoint: tokens are minted in-process
 * by the sink owner and delivered sealed. The one in-band mint is
 * /v1/lanes/open on the close listener (O-1): it requires a contract-server
 * signature, names a keyId the sink admin ENROLLED, and seals only to that
 * enrolled key — it never accepts a public key from the request, and its
 * response carries ciphertext only.
 *
 * Query scope for a linked run (O-1): a `query` token for contract runId R
 * also reads every lane linked to R; a lane's own laneId is never a query
 * token scope (lanes are not query-mintable before they are used).
 */

const MAX_BODY_BYTES = 4 * 1024 * 1024;
const BODY_READ_TIMEOUT_MS = 15_000;
const DEFAULT_PAGE = 500;
const MAX_PAGE = 1000;

const json = (res: ServerResponse, status: number, payload: unknown): void => {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
};

const bearerToken = (req: IncomingMessage): string | undefined => {
  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return undefined;
  return header.slice("Bearer ".length).trim() || undefined;
};

const REFUSAL_STATUS: Record<SinkRefusalCode, number> = {
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  REQUEST_INVALID: 400,
  PAYLOAD_TOO_LARGE: 413,
  RUN_FULL: 429,
  RUN_CLOSED: 409,
  ANCHOR_NOT_CONFIGURED: 503,
  ANCHOR_FAILED: 502,
  RECEIPT_INVALID: 403,
  RECEIPT_STALE: 403,
  RUN_EMPTY: 409,
  RUN_LOST: 410,
  NOT_ENROLLED: 404,
  LANE_REUSED: 409,
  LANE_LIMIT: 429,
  LINK_INVALID: 409,
  LINK_CONFLICT: 409,
};

function readBody(req: IncomingMessage): Promise<Buffer | "too_large" | "timeout"> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const timer = setTimeout(() => {
      req.destroy();
      resolve("timeout");
    }, BODY_READ_TIMEOUT_MS);
    req.on("data", (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > MAX_BODY_BYTES) {
        clearTimeout(timer);
        resolve("too_large");
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });
    req.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * The sink exposes three listeners: `write` (ingest), `read` (queries), and
 * `close` (contract-server terminal receipts only — the write port 404s
 * /close so a compromised forwarder can never deliver one).
 */
export interface TelemetrySinkServers {
  write: Server;
  read: Server;
  close: Server;
}

export function createTelemetrySinkServer(options: {
  sink: TelemetrySink;
  tokens: TokenStore;
  /** Published unauthenticated at GET /v1/keys on the read listener (N7a /telemetry/keys). */
  keys?: () => SinkKeysDoc;
  /** O-1 lane registry — enables /v1/lanes/open and /v1/runs/:runId/link on the close listener. */
  lanes?: LaneService;
}): TelemetrySinkServers {
  const { sink, tokens } = options;

  const write = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://loopback.invalid");
      const path = url.pathname;

      if (req.method === "GET" && path === "/v1/health") {
        json(res, 200, { ok: true });
        return;
      }

      // ---- ingest (write-only capability) ----
      if (req.method === "POST" && (path === "/v1/traces" || path === "/v1/logs")) {
        const token = bearerToken(req);
        const peeked = token === undefined ? undefined : tokens.peek(token);
        if (peeked === undefined) {
          json(res, 401, { error: "unauthorized" });
          return;
        }
        // Kind BEFORE closed state (no oracle): a query/global-query holder
        // gets 403 whether or not the run is closed. The actual closed check
        // happens inside sink.ingest so the refused-after-close counter bumps.
        if (peeked.kind !== "ingest") {
          json(res, 403, { error: "forbidden" });
          return;
        }
        const contentType = (req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
        if (contentType !== "application/json" && contentType !== "application/x-otel+json") {
          // Protobuf is not decodable here — exporters must use OTLP/HTTP+JSON.
          json(res, 415, { error: "unsupported_media_type", accept: ["application/json"] });
          return;
        }
        const body = await readBody(req);
        if (body === "too_large") {
          json(res, 413, { error: "payload_too_large" });
          return;
        }
        if (body === "timeout") {
          json(res, 408, { error: "request_timeout" });
          return;
        }
        const out = sink.ingest({
          token,
          kind: path === "/v1/traces" ? "traces" : "logs",
          body,
          contentType,
        });
        if (!out.ok) {
          json(res, REFUSAL_STATUS[out.code], { error: out.code.toLowerCase() });
          return;
        }
        json(res, 200, { accepted: true, runId: out.record.runId, seq: out.record.seq });
        return;
      }

      json(res, 404, { error: "not_found" });
    } catch {
      // Never leak internals (or tokens) through an error response.
      json(res, 500, { error: "internal_error" });
    }
  });

  // Close-only listener for the contract server (N4C-CHANGES-4). Serves
  // exactly one route — no ingest, no queries, not even health — so the only
  // credential it needs is the receipt's signature under the pinned key.
  const close = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://loopback.invalid");
      const closeMatch = /^\/v1\/runs\/([^/]+)\/close$/.exec(url.pathname);
      const linkMatch = /^\/v1\/runs\/([^/]+)\/link$/.exec(url.pathname);
      const laneOpen = url.pathname === "/v1/lanes/open";
      const lanes = options.lanes;
      if (req.method !== "POST"
        || (closeMatch === null && ((linkMatch === null && !laneOpen) || lanes === undefined))) {
        json(res, 404, { error: "not_found" });
        return;
      }
      const body = await readBody(req);
      if (body === "too_large") {
        json(res, 413, { error: "payload_too_large" });
        return;
      }
      if (body === "timeout") {
        json(res, 408, { error: "request_timeout" });
        return;
      }
      let receipt: unknown;
      try {
        receipt = JSON.parse(body.toString("utf8"));
      } catch {
        json(res, 400, { error: "request_invalid" });
        return;
      }
      if (lanes !== undefined && laneOpen) {
        // The response is the laneId plus CIPHERTEXT sealed to the enrolled
        // key — the plaintext token never crosses this listener.
        const opened = await lanes.open(receipt);
        if (!opened.ok) {
          json(res, REFUSAL_STATUS[opened.code], { error: opened.code.toLowerCase() });
          return;
        }
        json(res, 200, {
          laneId: opened.laneId,
          role: opened.role,
          keyId: opened.keyId,
          mcpSessionId: opened.mcpSessionId,
          sealedBox: opened.sealedBox,
        });
        return;
      }
      if (lanes !== undefined && linkMatch !== null) {
        const linked = await lanes.link(linkMatch[1], receipt);
        if (!linked.ok) {
          json(res, REFUSAL_STATUS[linked.code], { error: linked.code.toLowerCase() });
          return;
        }
        json(res, 200, { linked: true, runId: linked.runId, linkDigest: linked.linkDigest, created: linked.created });
        return;
      }
      const runId = (closeMatch as RegExpExecArray)[1];
      const out = await sink.closeRun({ runId, receipt });
      if (!out.ok) {
        json(res, REFUSAL_STATUS[out.code], { error: out.code.toLowerCase() });
        return;
      }
      if (out.head === null) {
        // Receipt accepted — the run seals at the deterministic boundary.
        json(res, 200, { closed: false, pending: true, closedAt: out.pendingClosedAt });
        return;
      }
      json(res, 200, { closed: true, head: out.head });
    } catch {
      json(res, 500, { error: "internal_error" });
    }
  });

  const read = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://loopback.invalid");
      const path = url.pathname;

      if (req.method === "GET" && path === "/v1/health") {
        json(res, 200, { ok: true });
        return;
      }

      // The sink's PUBLIC signing key — no bearer. Only key material that is
      // already public ever leaves this route; the private JWK stays on the
      // volume and never crosses this listener (or any listener).
      if (req.method === "GET" && path === "/v1/keys") {
        if (options.keys === undefined) {
          json(res, 404, { error: "not_found" });
          return;
        }
        json(res, 200, options.keys());
        return;
      }

      // ---- query (read-only capability) ----
      const match = /^\/v1\/runs\/([^/]+)\/(records|head|receipt)$/.exec(path);
      if (req.method === "GET" && match !== null) {
        const [, runId, what] = match;
        const record = tokens.resolve(bearerToken(req) ?? "");
        if (record === undefined) {
          json(res, 401, { error: "unauthorized" });
          return;
        }
        // O-1: a run's query token also reads the lanes linked to that run.
        const linkedTo = options.lanes?.lane(runId)?.runId ?? null;
        const canRead =
          record.kind === "global-query" ||
          (record.kind === "query" && record.runId === runId) ||
          (record.kind === "query" && linkedTo !== null && linkedTo === record.runId);
        if (!canRead) {
          json(res, 403, { error: "forbidden" });
          return;
        }
        if (what === "receipt") {
          const accepted = sink.receipt(runId);
          if (accepted === null) {
            json(res, 404, { error: "not_found" });
            return;
          }
          json(res, 200, { runId, receipt: accepted });
          return;
        }
        const head = sink.head(runId);
        const annex = sink.annex(runId); // the verifier fetches the LATEST annex itself
        const advisory = { evidentiary: false, result: sink.verifyRun(runId) };
        // O-1: a linked contract runId has no chain of its own — the run is
        // its ordered lane heads. Additive field; absent for unlinked runs.
        const runSet = sink.runSet(runId);
        const linked = runSet === null ? {} : { runSet };
        if (what === "head") {
          json(res, 200, { runId, head, annex, advisory, ...linked });
          return;
        }
        const cursorParam = url.searchParams.get("cursor");
        const limitParam = url.searchParams.get("limit");
        const cursor = cursorParam === null ? 0 : Number.parseInt(cursorParam, 10);
        const limit = Math.min(
          MAX_PAGE,
          limitParam === null ? DEFAULT_PAGE : Math.max(1, Number.parseInt(limitParam, 10) || DEFAULT_PAGE),
        );
        if (!Number.isSafeInteger(cursor) || cursor < 0) {
          json(res, 400, { error: "bad_cursor" });
          return;
        }
        const all = sink.exportRecords(runId);
        const slice = all.slice(cursor, cursor + limit);
        const nextCursor = cursor + limit < all.length ? cursor + limit : null;
        json(res, 200, {
          runId,
          records: slice.map(({ record: r, body }) => ({ ...r, body })),
          nextCursor,
          head,
          annex,
          advisory,
          ...linked,
        });
        return;
      }

      json(res, 404, { error: "not_found" });
    } catch {
      // Never leak internals (or tokens) through an error response.
      json(res, 500, { error: "internal_error" });
    }
  });
  write.requestTimeout = 30_000;
  read.requestTimeout = 30_000;
  close.requestTimeout = 30_000;
  return { write, read, close };
}
