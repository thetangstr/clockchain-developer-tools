import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomBytes, timingSafeEqual, type JsonWebKey } from "node:crypto";
import { closeSync, fsyncSync, openSync, rmSync, writeSync } from "node:fs";

import { openSealJwk, type SealedBox } from "./seal.js";
import type { ContractRole } from "./tokens.js";

/**
 * `ac-otlp-forward` (N4c, E12): the per-role local OTLP forwarder run by the
 * local-services uid. The agent's OTel exporter points here with NO token;
 * the forwarder unseals the ingest token with the services key (kept only in
 * this process's memory), attaches `Authorization: Bearer`, and relays the
 * request body BYTE-FOR-BYTE to the sink — it adds nothing and alters
 * nothing, so the digest the sink records is the digest of what the runtime
 * emitted.
 *
 * The listener accepts only the literal loopback addresses `127.0.0.1` and
 * `::1` — no `localhost`, no IPv4-mapped forms, no wildcards (post-review
 * LOW). No runtime can export to a Unix socket, and pf restricts which agent
 * uid may reach which role's port.
 *
 * The sealed token is bound to (runId, role) in its AAD (M4): the forwarder
 * must be told its own runId+role to unseal at all, and it cross-checks the
 * runId in every sink reply against its own — a reply naming another run is
 * not relayed.
 */

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1"]);
const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024;

export function createForwarder(options: {
  listen: { host: string; port: number };
  targetBaseUrl: string;
  sealedToken: SealedBox;
  servicesPrivateKeyJwk: JsonWebKey;
  runId: string;
  role: ContractRole;
  maxBodyBytes?: number;
}): Server {
  if (!LOOPBACK_HOSTS.has(options.listen.host)) {
    throw new Error(
      `ac-otlp-forward refuses a non-loopback bind (got ${options.listen.host}); ` +
        "the forwarder must listen on the literal 127.0.0.1 or ::1 only",
    );
  }
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  // Unseal once, at startup, under this forwarder's declared (runId, role).
  // The plaintext lives only in this closure — never in a response or log.
  const token = openSealJwk(options.servicesPrivateKeyJwk, options.sealedToken, {
    runId: options.runId,
    role: options.role,
  });
  const target = options.targetBaseUrl.replace(/\/$/, "");

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? "/", "http://loopback.invalid");
      if (req.method !== "POST" || !url.pathname.startsWith("/v1/")) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not_found" }));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      let tooLarge = false;
      for await (const chunk of req) {
        size += (chunk as Buffer).byteLength;
        if (size > maxBody) { tooLarge = true; break; }
        chunks.push(chunk as Buffer);
      }
      if (tooLarge) {
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "payload_too_large" }));
        return;
      }
      const body = Buffer.concat(chunks);

      const upstream = await fetch(`${target}${url.pathname}`, {
        method: "POST",
        headers: {
          "content-type": req.headers["content-type"] ?? "application/json",
          authorization: `Bearer ${token}`,
        },
        body,
      });
      const upstreamBody = Buffer.from(await upstream.arrayBuffer());

      // M4: the sink's reply must name OUR run. A reply for another run is
      // not evidence of our write and is not relayed.
      try {
        const reply = JSON.parse(upstreamBody.toString("utf8")) as { runId?: unknown };
        if (typeof reply.runId === "string" && reply.runId !== options.runId) {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "runid_mismatch" }));
          return;
        }
      } catch { /* non-JSON upstream replies are relayed untouched */ }

      res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      res.end(upstreamBody);
    } catch {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "upstream_unreachable" }));
    }
  });
}

/**
 * O-1 lane mode: the forwarder starts WITHOUT a token. The local adapter (not
 * the model) calls `telemetry_open` at MCP session start and hands the
 * returned `{laneId, sealedBox}` to `deliverLaneToken`.
 *
 *   - Fail closed until the token arrives: nothing is ever sent upstream
 *     without it. Requests are held IN ORDER in a bounded in-memory queue and
 *     answered 202 `{buffered: true}`; past the bound the answer is 503 (the
 *     exporter retries) and nothing is queued.
 *   - Delivery is write-once and must open under this forwarder's services key
 *     bound to (laneId, role) — a box for another lane, role, or recipient
 *     throws and leaves the forwarder token-less.
 *   - After delivery the backlog drains first, then live requests, through
 *     one serialized chain — bodies are relayed byte-for-byte, so every span
 *     emitted before the handshake lands in the lane chain under its own
 *     digest and is covered by the lane's final head.
 *
 * The `control` listener (optional, loopback-only, a SEPARATE port from the
 * OTLP port so the agent uid's pf rule never reaches it) accepts
 * `POST /v1/lane-token` `{laneId, sealedBox}` once.
 */
export interface LaneForwarderStatus {
  laneId: string | null;
  tokenDelivered: boolean;
  queued: number;
  queuedBytes: number;
  forwarded: number;
  /** buffered requests the sink refused after delivery (they had been answered 202). */
  droppedAfterDelivery: number;
  /** requests refused 503 because the pre-token queue was full. */
  rejectedQueueFull: number;
}

export interface LaneForwarder {
  server: Server;
  control: Server | null;
  /**
   * CDT-SEC L8: the per-start random secret the control listener requires
   * as `Authorization: Bearer <secret>` (null without a control listener).
   * The bin writes it to AC_CONTROL_SECRET_FILE (0600) for the adapter.
   */
  controlSecret: string | null;
  deliverLaneToken(laneId: string, sealedBox: unknown): void;
  status(): LaneForwarderStatus;
  /** resolves once every queued request has been relayed (or dropped). */
  idle(): Promise<void>;
}

const LANE_ID = /^lane:[0-9a-f]{32}$/;
const DEFAULT_MAX_QUEUED_REQUESTS = 512;
const DEFAULT_MAX_QUEUED_BYTES = 16 * 1024 * 1024;
const DRAIN_RETRY_MS = 1_000;

interface Queued {
  path: string;
  contentType: string;
  body: Buffer;
  /** live request waiting on its own relay result; undefined for a buffered (already-202) one. */
  respond?: (status: number, contentType: string, body: Buffer) => void;
}

async function readCapped(req: IncomingMessage, maxBody: number): Promise<Buffer | "too_large"> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).byteLength;
    if (size > maxBody) return "too_large";
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * CDT-SEC L8: write the control secret owner-only. Any existing file is
 * removed first and the new one is created exclusively at 0600, so a stale
 * or looser-mode file (or a planted symlink) is never written through.
 */
export function writeControlSecretFile(file: string, secret: string): void {
  rmSync(file, { force: true });
  const fd = openSync(file, "wx", 0o600);
  try {
    writeSync(fd, `${secret}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

const sha256 = (v: string): Buffer => createHash("sha256").update(v, "utf8").digest();

function send(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(payload));
}

// A refusal sent before the request body is read: drain the body and close the
// connection, so the client sees the status instead of a reset socket.
function refuse(req: IncomingMessage, res: ServerResponse, status: number, payload: unknown): void {
  req.resume();
  res.setHeader("connection", "close");
  send(res, status, payload);
}

export function createLaneForwarder(options: {
  listen: { host: string; port: number };
  control?: { host: string; port: number };
  targetBaseUrl: string;
  servicesPrivateKeyJwk: JsonWebKey;
  role: ContractRole;
  maxBodyBytes?: number;
  maxQueuedRequests?: number;
  maxQueuedBytes?: number;
  fetchImpl?: typeof fetch;
}): LaneForwarder {
  for (const l of [options.listen, options.control]) {
    if (l !== undefined && !LOOPBACK_HOSTS.has(l.host)) {
      throw new Error(
        `ac-otlp-forward refuses a non-loopback bind (got ${l.host}); ` +
          "the forwarder must listen on the literal 127.0.0.1 or ::1 only",
      );
    }
  }
  if (options.control !== undefined && options.control.port !== 0 && options.control.port === options.listen.port) {
    throw new Error("the lane-token control listener must not share the OTLP port");
  }
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const maxQueued = options.maxQueuedRequests ?? DEFAULT_MAX_QUEUED_REQUESTS;
  const maxQueuedBytes = options.maxQueuedBytes ?? DEFAULT_MAX_QUEUED_BYTES;
  const doFetch = options.fetchImpl ?? fetch;
  const target = options.targetBaseUrl.replace(/\/$/, "");

  // The plaintext lives only in this closure — never in a response or log.
  let token: string | null = null;
  let laneId: string | null = null;
  const queue: Queued[] = [];
  let queuedBytes = 0;
  let forwarded = 0;
  let droppedAfterDelivery = 0;
  let rejectedQueueFull = 0;
  let draining = false;
  let retryTimer: NodeJS.Timeout | null = null;
  let idleWaiters: (() => void)[] = [];

  const settleIdle = (): void => {
    if (queue.length > 0) return;
    const waiters = idleWaiters;
    idleWaiters = [];
    for (const w of waiters) w();
  };

  async function relay(item: Queued): Promise<{ status: number; contentType: string; body: Buffer }> {
    const upstream = await doFetch(`${target}${item.path}`, {
      method: "POST",
      headers: { "content-type": item.contentType, authorization: `Bearer ${token as string}` },
      body: item.body,
    });
    const upstreamBody = Buffer.from(await upstream.arrayBuffer());
    // M4: the sink's reply must name OUR lane.
    try {
      const reply = JSON.parse(upstreamBody.toString("utf8")) as { runId?: unknown };
      if (typeof reply.runId === "string" && reply.runId !== laneId) {
        return { status: 502, contentType: "application/json", body: Buffer.from(JSON.stringify({ error: "runid_mismatch" })) };
      }
    } catch { /* non-JSON upstream replies are relayed untouched */ }
    return { status: upstream.status, contentType: upstream.headers.get("content-type") ?? "application/json", body: upstreamBody };
  }

  /** One serialized drain — order is queue order, buffered backlog first. */
  async function drain(): Promise<void> {
    if (draining || token === null) return;
    draining = true;
    try {
      while (queue.length > 0) {
        const item = queue[0];
        let result: { status: number; contentType: string; body: Buffer };
        try {
          result = await relay(item);
        } catch {
          if (item.respond !== undefined) {
            queue.shift();
            queuedBytes -= item.body.byteLength;
            item.respond(502, "application/json", Buffer.from(JSON.stringify({ error: "upstream_unreachable" })));
            continue;
          }
          // A buffered item was already answered 202 — keep it at the head
          // and retry later rather than lose it.
          if (retryTimer === null) {
            retryTimer = setTimeout(() => { retryTimer = null; void drain(); }, DRAIN_RETRY_MS);
            retryTimer.unref();
          }
          return;
        }
        queue.shift();
        queuedBytes -= item.body.byteLength;
        if (result.status >= 200 && result.status < 300) forwarded += 1;
        else if (item.respond === undefined) droppedAfterDelivery += 1;
        item.respond?.(result.status, result.contentType, result.body);
      }
    } finally {
      draining = false;
      settleIdle();
    }
  }

  function deliverLaneToken(id: string, sealedBox: unknown): void {
    if (token !== null) throw new Error("lane token already delivered");
    if (typeof id !== "string" || !LANE_ID.test(id)) throw new Error("laneId must be lane:<32 hex>");
    // Throws SealError unless the box opens under OUR key bound to (laneId, role).
    const opened = openSealJwk(options.servicesPrivateKeyJwk, sealedBox, { runId: id, role: options.role });
    laneId = id;
    token = opened;
    void drain();
  }

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? "/", "http://loopback.invalid");
      if (req.method !== "POST" || !url.pathname.startsWith("/v1/")) {
        send(res, 404, { error: "not_found" });
        return;
      }
      const body = await readCapped(req, maxBody);
      if (body === "too_large") {
        send(res, 413, { error: "payload_too_large" });
        return;
      }
      const item: Queued = {
        path: url.pathname,
        contentType: req.headers["content-type"] ?? "application/json",
        body,
      };
      if (token === null) {
        // Fail closed: no token, nothing upstream. Hold in order, bounded.
        if (queue.length >= maxQueued || queuedBytes + body.byteLength > maxQueuedBytes) {
          rejectedQueueFull += 1;
          send(res, 503, { error: "lane_not_ready" });
          return;
        }
        queue.push(item);
        queuedBytes += body.byteLength;
        send(res, 202, { accepted: false, buffered: true, queued: queue.length });
        return;
      }
      await new Promise<void>((resolve) => {
        item.respond = (status, contentType, out) => {
          res.writeHead(status, { "content-type": contentType });
          res.end(out);
          resolve();
        };
        queue.push(item);
        queuedBytes += body.byteLength;
        void drain();
      });
    } catch {
      if (!res.headersSent) send(res, 502, { error: "upstream_unreachable" });
    }
  });

  let control: Server | null = null;
  const controlSecret = options.control === undefined ? null : randomBytes(32).toString("hex");
  if (options.control !== undefined) {
    const expected = sha256(controlSecret as string);
    control = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      try {
        const url = new URL(req.url ?? "/", "http://loopback.invalid");
        if (req.method !== "POST" || url.pathname !== "/v1/lane-token") {
          refuse(req, res, 404, { error: "not_found" });
          return;
        }
        // L8: only the holder of this start's secret file may deliver — the
        // first local writer no longer wins. Checked before anything else so
        // an unauthenticated caller learns nothing (not even delivery state).
        const auth = req.headers.authorization ?? "";
        const presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
        if (!timingSafeEqual(sha256(presented), expected)) {
          refuse(req, res, 401, { error: "unauthorized" });
          return;
        }
        if (token !== null) {
          refuse(req, res, 409, { error: "already_delivered" });
          return;
        }
        const raw = await readCapped(req, 64 * 1024);
        if (raw === "too_large") {
          send(res, 413, { error: "payload_too_large" });
          return;
        }
        let doc: { laneId?: unknown; sealedBox?: unknown };
        try {
          doc = JSON.parse(raw.toString("utf8")) as typeof doc;
        } catch {
          send(res, 400, { error: "request_invalid" });
          return;
        }
        try {
          deliverLaneToken(doc.laneId as string, doc.sealedBox);
        } catch {
          // Detail-free: which part failed is attacker aid.
          send(res, 400, { error: "lane_token_refused" });
          return;
        }
        send(res, 200, { delivered: true, laneId: laneId, queued: queue.length });
      } catch {
        if (!res.headersSent) send(res, 500, { error: "internal_error" });
      }
    });
  }

  return {
    server,
    control,
    controlSecret,
    deliverLaneToken,
    status: () => ({
      laneId,
      tokenDelivered: token !== null,
      queued: queue.length,
      queuedBytes,
      forwarded,
      droppedAfterDelivery,
      rejectedQueueFull,
    }),
    idle: () => (queue.length === 0 && !draining
      ? Promise.resolve()
      : new Promise<void>((resolve) => { idleWaiters.push(resolve); })),
  };
}
