// Owned Clockchain anchoring gateway (AC Express).
//
// A SEPARATE service/process that implements the exact ledger-API subset the MCP coordinator's
// ClockchainClient calls during handshake anchoring, so CLOCKCHAIN_ENDPOINT can point here instead of the
// unowned, currently-down node.clockchain.network. It never runs inside the MCP process.
//
// Contract implemented (verified against packages/core/src/client.ts on the MCP host):
//   POST /log                              -> LogResponse (blockHeight null = pending, set once sealed)
//   GET  /ledger/{ledgerId}                -> LedgerRecord (= LogResponse) | {success:false,error}
//   GET  /searchAsset?clientId&assetReferenceId -> LedgerRecord[]  (exact match; idempotency lookup)
//   GET  /getTime                          -> {success,data:{blockHeight,madMarzulloTime,totalNodes,nodeParticipation,votes}}
//   GET  /api/time/block?height=H          -> {success,data:{blockHeight:number,proposerAddress,blockTime}}
//   GET  /searchAssetFromChain?blockHeight=H (keyless) -> {blockHeight,proposerAddress,blockTime,transactions:[...]}
//   GET  /healthz                          -> liveness/state (own health check)
//   GET  /metrics                          -> Prometheus-style counters (own observability)
//
// Durability: append-only event log (fsync'd) + full in-memory index rebuilt on start (restart recovery).
// Honest pending: an entry is pending (blockHeight null) until a block seal makes it durable, then anchored.
// Idempotency: (clientId|assetReferenceId|assetHash) collapses duplicate submissions to one ledgerId.
// Fail-closed: strict validation; malformed writes are rejected; the process never mutates trust material.
// Authenticated: every route above except /healthz and /metrics requires a payload-bound HMAC signature from the
// MCP coordinator (x-cc-key-id/-timestamp/-nonce/-signature; replay + tamper protection; see verifySignature).
// With no signing key configured the gateway refuses all protected routes (503) — there is no unauthenticated mode.

import http from "node:http";
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PORT = Number(process.env.GATEWAY_PORT || 8090);
const HOST = process.env.GATEWAY_HOST || "0.0.0.0";
const DATA_DIR = process.env.GATEWAY_DATA_DIR || "/data";
const SEAL_INTERVAL_MS = Number(process.env.GATEWAY_SEAL_INTERVAL_MS || 750);
// Synchronous seal: seal the entry into a durable block INSIDE the /log call, before acknowledging, so the
// coordinator's immediate getLedgerEntry always sees an anchored (durable, fsync'd) record. Still honest — the
// block is fsync'd before the response — it just removes the async pending window. Set 0 for async pending
// (paired with the coordinator's pending-tolerant patch). Default on for compatibility with today's coordinator.
const SYNC_SEAL = (process.env.GATEWAY_SYNC_SEAL ?? "1") === "1";
// A stable, owned proposer identity for sealed blocks. mapPublicBlock only requires a non-empty printable
// string; a 0x-address keeps it shaped like the upstream gateway. Overridable, never a secret.
const PROPOSER = process.env.GATEWAY_PROPOSER_ADDRESS || "0xACE00000000000000000000000000000A11C0DE0";
const MAX_BODY = 256 * 1024;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

// ---- request authentication (payload-bound signed requests: replay + tamper protection) --------------
// Every protected call (the write path POST /log and all ledger/enumeration reads) must carry a payload-bound
// HMAC signature from the MCP coordinator; the gateway verifies it before doing any work. This closes the
// unauthenticated public write/enumeration exposure. Scheme is shared verbatim with the signer
// (packages/core/src/client.ts):
//   canonical  = METHOD "\n" PATH+QUERY "\n" TIMESTAMP "\n" NONCE "\n" sha256hex(body)
//   signature  = base64( HMAC_SHA256(secret, canonical) )
// Headers: x-cc-key-id, x-cc-timestamp (unix seconds), x-cc-nonce (32 lowercase hex = 128 bits), x-cc-signature.
// Fail-closed: with NO signing key configured the gateway REFUSES every protected route (503) — there is no
// unauthenticated mode and no bypass flag. Replay: the timestamp must be within +/-SIG_SKEW_MS and each nonce is
// single-use within 2*SIG_SKEW_MS. Only /healthz and /metrics are open (liveness + counters, no trust material).
const SIG_SKEW_MS = Number(process.env.GATEWAY_SIGNATURE_SKEW_MS || 300_000);
const SIGNING_KEYS = parseSigningKeys(process.env.GATEWAY_SIGNING_KEYS ?? process.env.GATEWAY_SIGNING_SECRET ?? "");
const seenNonces = new Map(); // nonce -> expiryMs (single-use within the replay window)

function parseSigningKeys(raw) {
  // "keyId:secret,keyId2:secret2" (comma-separated, supports rotation) OR a bare secret (implicit keyId "default").
  const keys = new Map();
  const trimmed = String(raw).trim();
  if (!trimmed) return keys;
  if (!trimmed.includes(":")) { keys.set("default", trimmed); return keys; }
  for (const pair of trimmed.split(",")) {
    const idx = pair.indexOf(":");
    if (idx <= 0) continue;
    const id = pair.slice(0, idx).trim();
    const secret = pair.slice(idx + 1).trim();
    if (id && secret) keys.set(id, secret);
  }
  return keys;
}
function sha256hex(s) { return createHash("sha256").update(s, "utf8").digest("hex"); }
function canonicalRequest(method, pathWithQuery, timestamp, nonce, bodyHashHex) {
  return `${String(method).toUpperCase()}\n${pathWithQuery}\n${timestamp}\n${nonce}\n${bodyHashHex}`;
}
function pruneNonces(now) {
  if (seenNonces.size < 8192) return; // opportunistic bound so the replay cache cannot grow without limit
  for (const [n, exp] of seenNonces) if (exp <= now) seenNonces.delete(n);
}
// Verify a payload-bound signature. Returns { ok:true } or { ok:false, status, code }. Order matters: the
// signature is validated (with a known key) BEFORE the nonce is recorded, so an attacker without the secret can
// neither forge a request nor poison the replay cache.
function verifySignature(req, method, pathWithQuery, rawBody) {
  if (SIGNING_KEYS.size === 0) return { ok: false, status: 503, code: "signing_not_configured" };
  const keyId = req.headers["x-cc-key-id"];
  const tsRaw = req.headers["x-cc-timestamp"];
  const nonce = req.headers["x-cc-nonce"];
  const sig = req.headers["x-cc-signature"];
  if (typeof keyId !== "string" || typeof tsRaw !== "string" || typeof nonce !== "string" || typeof sig !== "string") {
    return { ok: false, status: 401, code: "unauthenticated" };
  }
  const secret = SIGNING_KEYS.get(keyId);
  if (!secret) return { ok: false, status: 401, code: "unknown_key" };
  if (!/^[0-9a-f]{32}$/.test(nonce)) return { ok: false, status: 401, code: "bad_nonce" };
  const ts = Number(tsRaw);
  if (!Number.isFinite(ts) || !/^\d{1,15}$/.test(tsRaw)) return { ok: false, status: 401, code: "bad_timestamp" };
  const now = Date.now();
  if (Math.abs(now - ts * 1000) > SIG_SKEW_MS) return { ok: false, status: 401, code: "stale" };
  const expected = createHmac("sha256", secret)
    .update(canonicalRequest(method, pathWithQuery, tsRaw, nonce, sha256hex(rawBody)), "utf8")
    .digest();
  let provided;
  try { provided = Buffer.from(sig, "base64"); } catch { return { ok: false, status: 401, code: "bad_signature" }; }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return { ok: false, status: 401, code: "bad_signature" };
  }
  pruneNonces(now);
  if (seenNonces.has(nonce)) return { ok: false, status: 401, code: "replay" };
  // Retain the nonce for the FULL replay window plus a small margin, so a request accepted at the near edge of
  // the skew window cannot be replayed at the far edge after its cache entry was pruned on the same tick.
  seenNonces.set(nonce, now + 2 * SIG_SKEW_MS + 5_000);
  return { ok: true };
}

const LOG_PATH = path.join(DATA_DIR, "anchor-events.jsonl");

// ---- durable event log -------------------------------------------------------------------------------
// Two event kinds, append-only: {k:"log", ...entry} and {k:"seal", blockHeight, blockTime, ledgerIds:[...]}.
let logFd = null;
function openLog() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  logFd = fs.openSync(LOG_PATH, "a");
}
function appendDurable(event) {
  const line = JSON.stringify(event) + "\n";
  fs.writeSync(logFd, line);
  fs.fsyncSync(logFd); // durable before we acknowledge
}

// ---- in-memory index ---------------------------------------------------------------------------------
const byLedgerId = new Map();        // ledgerId -> entry
const byIdemKey = new Map();         // clientId|assetReferenceId|assetHash -> ledgerId
const byReference = new Map();       // clientId|assetReferenceId -> Set(ledgerId)
const blocks = new Map();            // blockHeight(number) -> {blockHeight, blockTime, proposerAddress, ledgerIds:[]}
let latestBlockHeight = 0;           // 0 = genesis / none sealed yet
let latestBlockTime = null;
const metrics = { logs: 0, idempotentHits: 0, seals: 0, sealedEntries: 0, notFound: 0, badRequests: 0, authOk: 0, authFailures: 0 };

function idemKey(clientId, assetReferenceId, assetHash) {
  return `${clientId} ${assetReferenceId} ${assetHash}`;
}
function refKey(clientId, assetReferenceId) {
  return `${clientId} ${assetReferenceId}`;
}
function indexEntry(entry) {
  byLedgerId.set(entry.ledgerId, entry);
  byIdemKey.set(idemKey(entry.clientId, entry.assetReferenceId, entry.assetHash), entry.ledgerId);
  const rk = refKey(entry.clientId, entry.assetReferenceId);
  if (!byReference.has(rk)) byReference.set(rk, new Set());
  byReference.get(rk).add(entry.ledgerId);
}
function applySeal(seal) {
  blocks.set(seal.blockHeight, seal);
  for (const id of seal.ledgerIds) {
    const e = byLedgerId.get(id);
    if (e) {
      e.blockHeight = String(seal.blockHeight);
      e.updatedTimestamp = seal.blockTime;
    }
  }
  if (seal.blockHeight > latestBlockHeight) {
    latestBlockHeight = seal.blockHeight;
    latestBlockTime = seal.blockTime;
  }
}

// ---- recovery: replay the durable log on start -------------------------------------------------------
function recover() {
  if (!fs.existsSync(LOG_PATH)) return;
  const raw = fs.readFileSync(LOG_PATH, "utf8");
  let logCount = 0, sealCount = 0, truncatedTail = false;
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line) continue;
    let ev;
    try { ev = JSON.parse(line); }
    catch { // only the final line may be a torn write; anything earlier is corruption -> fail closed
      if (i === lines.length - 1 || (i === lines.length - 2 && lines[lines.length - 1] === "")) { truncatedTail = true; continue; }
      throw new Error(`anchor log corrupt at line ${i + 1}`);
    }
    if (ev.k === "log") { indexEntry(ev.entry); logCount += 1; }
    else if (ev.k === "seal") { applySeal(ev.seal); sealCount += 1; }
  }
  console.log(JSON.stringify({ event: "gateway_recovered", logs: logCount, seals: sealCount, latestBlockHeight, truncatedTail }));
}

// ---- block sealing loop ------------------------------------------------------------------------------
function pendingLedgerIds() {
  const ids = [];
  for (const [id, e] of byLedgerId) if (e.blockHeight === null) ids.push(id);
  return ids;
}
function sealPending() {
  const ids = pendingLedgerIds();
  if (ids.length === 0) return;
  const height = latestBlockHeight + 1;
  const blockTime = new Date().toISOString();
  const seal = { blockHeight: height, blockTime, proposerAddress: PROPOSER, ledgerIds: ids };
  appendDurable({ k: "seal", seal });
  applySeal(seal);
  metrics.seals += 1;
  metrics.sealedEntries += ids.length;
}

// ---- request helpers ---------------------------------------------------------------------------------
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { "content-type": "application/json", "content-length": body.length, "cache-control": "no-store" });
  res.end(body);
}
function recordShape(e) {
  return {
    clientId: e.clientId, walletId: e.walletId, assetReferenceId: e.assetReferenceId, assetHash: e.assetHash,
    hashType: e.hashType, versionNumber: e.versionNumber, additionalInfo: e.additionalInfo,
    ledgerId: e.ledgerId, blockHeight: e.blockHeight, createdTimestamp: e.createdTimestamp,
    updatedTimestamp: e.updatedTimestamp, assetName: e.assetName, type: e.type,
  };
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// ---- handlers ----------------------------------------------------------------------------------------
function handleGetTime(res) {
  sendJson(res, 200, {
    success: true,
    data: {
      blockHeight: String(latestBlockHeight),
      madMarzulloTime: latestBlockTime || new Date().toISOString(),
      totalNodes: 1, nodeParticipation: 100, votes: 1,
    },
  });
}
async function handleLog(res, rawBody) {
  let body;
  try { body = JSON.parse(rawBody); } catch { metrics.badRequests += 1; return sendJson(res, 400, { success: false, error: { message: "invalid JSON" } }); }
  const { clientId, walletId, assetReferenceId, assetHash } = body || {};
  if (![clientId, walletId, assetReferenceId, assetHash].every((v) => typeof v === "string" && v.length > 0 && v.length < 4096)) {
    metrics.badRequests += 1;
    return sendJson(res, 400, { success: false, error: { message: "clientId, walletId, assetReferenceId, assetHash are required strings" } });
  }
  // idempotency: same (clientId, reference, hash) returns the existing ledgerId, never a duplicate.
  const existingId = byIdemKey.get(idemKey(clientId, assetReferenceId, assetHash));
  if (existingId) { metrics.idempotentHits += 1; return sendJson(res, 200, recordShape(byLedgerId.get(existingId))); }
  const now = new Date().toISOString();
  const entry = {
    clientId, walletId, assetReferenceId, assetHash,
    hashType: typeof body.hashType === "string" ? body.hashType : "SHA-256",
    versionNumber: Number.isInteger(body.versionNumber) ? body.versionNumber : 1,
    additionalInfo: typeof body.additionalInfo === "string" ? body.additionalInfo : "",
    ledgerId: randomUUID(), blockHeight: null, createdTimestamp: now, updatedTimestamp: null,
    assetName: null, type: null,
  };
  appendDurable({ k: "log", entry }); // durable (fsync) BEFORE acknowledging
  indexEntry(entry);
  metrics.logs += 1;
  if (SYNC_SEAL) sealPending(); // durable block (fsync'd) before we return — record comes back anchored, honestly
  sendJson(res, 200, recordShape(entry)); // anchored if SYNC_SEAL, else pending (blockHeight null)
}
function handleGetLedger(res, ledgerId) {
  const e = byLedgerId.get(ledgerId);
  if (!e) { metrics.notFound += 1; return sendJson(res, 404, { success: false, error: { message: "ledger entry not found" } }); }
  sendJson(res, 200, recordShape(e));
}
function handleSearchAsset(res, url) {
  const clientId = url.searchParams.get("clientId");
  const assetReferenceId = url.searchParams.get("assetReferenceId");
  if (!clientId || !assetReferenceId) { metrics.badRequests += 1; return sendJson(res, 400, { success: false, error: { message: "clientId and assetReferenceId required" } }); }
  const ids = byReference.get(refKey(clientId, assetReferenceId));
  const out = ids ? [...ids].map((id) => recordShape(byLedgerId.get(id))) : [];
  sendJson(res, 200, out); // bare array (contract)
}
function handleApiTimeBlock(res, url) {
  const h = Number(url.searchParams.get("height"));
  if (!Number.isSafeInteger(h) || h < 1) { metrics.badRequests += 1; return sendJson(res, 400, { success: false, error: { message: "height must be a positive integer" } }); }
  const b = blocks.get(h);
  if (!b) { metrics.notFound += 1; return sendJson(res, 404, { success: false, error: { message: "block not found" } }); }
  sendJson(res, 200, { success: true, data: { blockHeight: h, proposerAddress: b.proposerAddress, blockTime: b.blockTime } });
}
function handleSearchAssetFromChain(res, url) {
  const hs = url.searchParams.get("blockHeight");
  const h = Number(hs);
  if (!Number.isSafeInteger(h) || h < 1) { metrics.badRequests += 1; return sendJson(res, 400, { success: false, error: { message: "blockHeight must be a positive integer" } }); }
  const b = blocks.get(h);
  if (!b) { metrics.notFound += 1; return sendJson(res, 404, { success: false, error: { message: "block not found" } }); }
  const transactions = b.ledgerIds.map((id) => {
    const e = byLedgerId.get(id);
    return `ledgerId=${e.ledgerId},assetHash=${e.assetHash},assetReferenceId=${e.assetReferenceId}`;
  });
  sendJson(res, 200, { blockHeight: String(h), proposerAddress: b.proposerAddress, blockTime: b.blockTime, transactions });
}
function handleHealthz(res) {
  sendJson(res, 200, {
    ok: true, service: "clockchain-anchoring-gateway", proposer: PROPOSER,
    entries: byLedgerId.size, blocks: blocks.size, pending: pendingLedgerIds().length,
    latestBlockHeight, latestBlockTime, sealIntervalMs: SEAL_INTERVAL_MS,
    signingConfigured: SIGNING_KEYS.size > 0,
  });
}
function handleMetrics(res) {
  const lines = [
    `anchor_gateway_entries ${byLedgerId.size}`,
    `anchor_gateway_blocks ${blocks.size}`,
    `anchor_gateway_pending ${pendingLedgerIds().length}`,
    `anchor_gateway_latest_block_height ${latestBlockHeight}`,
    `anchor_gateway_logs_total ${metrics.logs}`,
    `anchor_gateway_idempotent_hits_total ${metrics.idempotentHits}`,
    `anchor_gateway_seals_total ${metrics.seals}`,
    `anchor_gateway_sealed_entries_total ${metrics.sealedEntries}`,
    `anchor_gateway_not_found_total ${metrics.notFound}`,
    `anchor_gateway_bad_requests_total ${metrics.badRequests}`,
    `anchor_gateway_auth_ok_total ${metrics.authOk}`,
    `anchor_gateway_auth_failures_total ${metrics.authFailures}`,
    `anchor_gateway_signing_configured ${SIGNING_KEYS.size > 0 ? 1 : 0}`,
    `anchor_gateway_replay_cache_size ${seenNonces.size}`,
  ].join("\n") + "\n";
  res.writeHead(200, { "content-type": "text/plain; version=0.0.4", "cache-control": "no-store" });
  res.end(lines);
}

// ---- server ------------------------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const p = url.pathname;
    const method = req.method || "GET";
    // Open, unauthenticated monitoring endpoints only — liveness + counters, no trust material, no enumeration.
    if (method === "GET" && (p === "/healthz" || p === "/health")) return handleHealthz(res);
    if (method === "GET" && p === "/metrics") return handleMetrics(res);
    // Everything else is PROTECTED. Read the body (POST) so the signature can bind it, then verify before any
    // work. `req.url` is the exact path+query the signer signed. An async fsync/seal rejection in handleLog is
    // caught below (500), never an unanswered socket.
    const rawBody = method === "POST" ? await readBody(req) : "";
    const auth = verifySignature(req, method, req.url, rawBody);
    if (!auth.ok) {
      metrics.authFailures += 1;
      // Do not leak which check failed (a keyId/stage oracle). All 401s report a single generic reason; the
      // specific `auth.code` stays server-side (metrics/log). 503 keeps its operational "signing_not_configured".
      const message = auth.status === 503 ? auth.code : "unauthenticated";
      return sendJson(res, auth.status, { success: false, error: { message } });
    }
    metrics.authOk += 1;
    if (method === "GET" && p === "/getTime") return handleGetTime(res);
    if (method === "POST" && p === "/log") return await handleLog(res, rawBody);
    if (method === "GET" && p.startsWith("/ledger/")) return handleGetLedger(res, decodeURIComponent(p.slice("/ledger/".length)));
    if (method === "GET" && p === "/searchAsset") return handleSearchAsset(res, url);
    if (method === "GET" && p === "/api/time/block") return handleApiTimeBlock(res, url);
    if (method === "GET" && p === "/searchAssetFromChain") return handleSearchAssetFromChain(res, url);
    sendJson(res, 404, { success: false, error: { message: "not found" } });
  } catch (err) {
    metrics.badRequests += 1;
    sendJson(res, 500, { success: false, error: { message: "internal error" } });
  }
});

openLog();
recover();
const sealTimer = setInterval(sealPending, SEAL_INTERVAL_MS);
sealTimer.unref?.();
server.listen(PORT, HOST, () => {
  console.log(JSON.stringify({ event: "gateway_listening", host: HOST, port: PORT, dataDir: DATA_DIR, proposer: PROPOSER }));
});
function shutdown(sig) {
  console.log(JSON.stringify({ event: "gateway_shutdown", sig }));
  try { sealPending(); } catch {}
  try { if (logFd !== null) fs.fsyncSync(logFd); } catch {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref?.();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export { RFC3339, recordShape }; // for the self-test
