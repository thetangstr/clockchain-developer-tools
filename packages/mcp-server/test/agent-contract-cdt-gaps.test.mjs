// CDT-GAPS: the four evidence gaps left after CDT-SEC
// (state/ledger/notes/cdt-gaps-build.md). Each test fails on
// track-b/cdt-integration-sec (bf5fad1) and passes after its fix.
// Offline: loopback ports 19520-19539 only; every key is generated.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { afterEach, beforeEach } from "node:test";

import { createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { createCloseEmitter } from "../dist/agent-contract/close-emitter.js";
import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import {
  ACCEPT, HOST_ROOTS, POLICY, SIGNER, bindPair, boot, fakeAnchor, mintCertificate, rootKey, keys,
  serverPubKey, sinkCheckReceipt, uuid, waitFor,
} from "./n4b9-harness.mjs";
import { generateKeyPairSync } from "node:crypto";

// --- loopback ports 19520-19539, rotating ---------------------------------------

let nextPort = 0;
async function listen(server) {
  for (let tries = 0; tries < 20; tries += 1) {
    const p = 19520 + (nextPort++ % 20);
    const ok = await new Promise((resolve) => {
      const onError = () => resolve(false);
      server.once("error", onError);
      server.listen(p, "127.0.0.1", () => { server.off("error", onError); resolve(true); });
    });
    if (ok) return `http://127.0.0.1:${p}`;
  }
  throw new Error("no free loopback port in 19520-19539");
}
const closeServer = (srv) => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); });

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tp1:provider:kp1:9453:responder",
].join(",");
const SERVER_SEED = Buffer.alloc(32, 9);

/** Production wiring: loadContractConfig (env) → the HTTP handler, over loopback. */
async function bootConfig(t, env = {}) {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS_RAW,
    CONTRACT_HOST_ROOTS: HOST_ROOTS.map((r) => `${r.kid}:${r.fingerprint}`).join(","),
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED.toString("base64"),
    CONTRACT_SERVER_KEY_ID: "contract-server-gaps",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-gaps-")),
    ...env,
  });
  if (cfg.kind !== "ready") return { cfg };
  t.after(() => cfg.service.close());
  const srv = createServer(createContractHttpHandler({
    authenticate: cfg.authenticate, hostRoots: cfg.hostRoots, signer: cfg.signer, service: cfg.service,
    ...(cfg.telemetryLanes !== undefined ? { telemetryLanes: cfg.telemetryLanes } : {}),
  }));
  const baseUrl = `${await listen(srv)}/contract/mcp`;
  t.after(() => closeServer(srv));
  const sessions = new Map();
  let id = 1;
  const callTool = async (token, name, args = {}) => {
    let sid = sessions.get(token);
    if (!sid) {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "gaps", version: "1" } } }),
      });
      sid = init.headers.get("mcp-session-id");
      sessions.set(token, sid);
      await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
    }
    const res = await fetch(baseUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", id: id++, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    if (body.error !== undefined) return { rpcError: body.error };
    return body.result?.structuredContent ?? {};
  };
  return { cfg, service: cfg.service, callTool };
}

// Node 20's runner abandons a pending test once the event loop empties; the
// emitter's timers are unref'd. A ref'd keep-alive per test keeps it honest.
let keepAlive;
beforeEach(() => { keepAlive = setInterval(() => {}, 60_000); });
afterEach(() => { clearInterval(keepAlive); });

// =============================================================================
// Gap 4 — the close emitter stored up to 200 characters of the sink's
// response body as lastError (close-emitter.ts:237), and contract_status,
// the outbox job and the failed-close receipt carried it. L9 treatment:
// status and refusal code only.
// =============================================================================

const ECHO_MARKER = "ECHOED-REQUEST-CONTENT-7f3a";

test("gap 4: a refused close keeps only the HTTP status and refusal code, never the body", async () => {
  const cases = [
    { status: 409, body: JSON.stringify({ error: "link_conflict", echo: ECHO_MARKER }), want: "http 409 link_conflict" },
    { status: 400, body: JSON.stringify({ code: "receipt_invalid", detail: ECHO_MARKER }), want: "http 400 receipt_invalid" },
    // A non-code error value (spaces, upper case) is dropped, not copied.
    { status: 403, body: JSON.stringify({ error: `Forbidden ${ECHO_MARKER}` }), want: "http 403" },
    { status: 502, body: `<html><body>Bad gateway ${ECHO_MARKER}</body></html>`, want: "http 502" },
  ];
  for (const c of cases) {
    const states = [];
    const outcomes = [];
    const emitter = createCloseEmitter({
      signer: SIGNER,
      closeUrl: "http://127.0.0.1:1",
      backoffMs: [0],
      fetchImpl: async () => ({ status: c.status, text: async () => c.body }),
      setState: (_runId, st) => states.push({ ...st }),
      recordOutcome: (outcome, d) => outcomes.push({ outcome, ...d }),
    });
    emitter.notify({ runId: `run-g4-${c.status}`, terminalState: "settled", ts: "2026-09-01T00:00:00Z" });
    await emitter.flush();
    const final = states.at(-1);
    assert.equal(final.status, "failed");
    assert.equal(final.lastError, c.want, `status ${c.status}`);
    for (const st of states) {
      assert.ok(!JSON.stringify(st).includes(ECHO_MARKER), `state leaked body: ${JSON.stringify(st)}`);
    }
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].outcome, "failed");
    assert.equal(outcomes[0].lastError, c.want);
    assert.ok(!JSON.stringify(outcomes).includes(ECHO_MARKER));
  }
});

test("gap 4: contract_status and the outbox job never carry the sink's response body", async (t) => {
  // A sink that refuses every close and echoes the request back in its body.
  const sink = createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    res.writeHead(409, { "content-type": "application/json" })
      .end(JSON.stringify({ error: "receipt_invalid", echo: body, marker: ECHO_MARKER }));
  });
  const sinkUrl = await listen(sink);
  t.after(() => closeServer(sink));
  const env = await bootConfig(t, { TELEMETRY_CLOSE_URL: sinkUrl, TELEMETRY_CLOSE_BACKOFF_MS: "0" });
  assert.equal(env.cfg.kind, "ready", JSON.stringify(env.cfg));
  const runId = await bindPair(env, uuid(4001), "tb1", "tp1");
  await env.callTool("tb1", "contract_withdraw", {});
  const failed = await waitFor(() => env.service.runFor(runId)?.telemetryClose?.status === "failed");
  assert.ok(failed, "close delivery marked failed");

  const st = await env.callTool("tb1", "contract_status", {});
  assert.equal(st.telemetryClose.status, "failed");
  assert.equal(st.telemetryClose.lastError, "http 409 receipt_invalid");
  assert.ok(!JSON.stringify(st).includes(ECHO_MARKER), "contract_status leaked the sink body");

  const job = env.service.terminalJobFor(runId);
  assert.equal(job.close.lastError, "http 409 receipt_invalid");
  assert.ok(!JSON.stringify(job).includes(ECHO_MARKER), "the outbox job leaked the sink body");
});

// =============================================================================
// Gap 2 — a fully bound run still non-terminal at its 24 h TTL was dropped
// by evictEnded with no terminal state, no terminal/final anchor and no
// close. CONTRACT_EXPIRE_AT_TTL=1 ends it "expired" on the normal terminal
// path; the half-bound bind-deadline path (expired_unbound) is unchanged.
// =============================================================================

/**
 * The harness service plus a real close emitter wired exactly as config.ts
 * wires it (setState → run + outbox job, recordOutcome → run chain), with a
 * fake sink that accepts every close.
 */
async function bootWithClose(serviceOptions) {
  let env;
  const delivered = [];
  const emitter = createCloseEmitter({
    signer: SIGNER,
    closeUrl: "http://127.0.0.1:1",
    backoffMs: [0],
    fetchImpl: async (_url, init) => {
      delivered.push(JSON.parse(init.body));
      return { status: 200, text: async () => JSON.stringify({ closed: true }) };
    },
    setState: (runId, state) => {
      const run = env.service.runFor(runId);
      if (run !== undefined) run.telemetryClose = state;
      env.service.persistTerminalClose(runId, {
        status: state.status, attempts: state.attempts, lastError: state.lastError, deliveredAt: state.deliveredAt,
      });
    },
    recordOutcome: (outcome, d) => env.service.recordTerminalOutcome(d.runId, outcome, d),
  });
  env = await boot({
    ...serviceOptions,
    signer: SIGNER,
    onTerminalRun: (_run, _state, _principal, receipt) => emitter.resume(receipt),
  });
  return { env, emitter, delivered };
}

/** The verifier's subject rule: head of the last receipt before the first anchoring-surface receipt. */
function headBeforeAnchoring(receipts) {
  const i = receipts.findIndex((r) => r.surface === "anchoring");
  assert.ok(i > 0, "an anchoring-surface receipt follows the terminal transition");
  return canonicalDigest(receipts[i - 1]);
}

test("gap 2: a fully bound run reaching its TTL ends 'expired' with terminal anchor, close and final anchor", async () => {
  let clock = Date.now();
  const anchor = fakeAnchor();
  const { env, emitter, delivered } = await bootWithClose({
    now: () => clock, runTtlMs: 60_000, expireAtTtl: true, serverAnchors: true, anchor,
  });
  try {
    const runId = await bindPair(env, uuid(4201), "tb1", "tp1");
    const before = env.service.receiptFeed(runId);
    const headAtTtl = before.head;
    const countAtTtl = before.receipts.length;

    clock += 61_000; // past the TTL, both roles bound, nothing terminal
    const st0 = await env.callTool("tb1", "contract_status", {});
    assert.equal(st0.terminalState, "expired", JSON.stringify(st0));

    // Close delivered and the final anchor recorded on the LIVE run.
    const settled = await waitFor(() => {
      const r = env.service.runFor(runId);
      return r?.telemetryClose?.status === "delivered" && r.anchors?.final?.status === "anchored" ? r : undefined;
    });
    assert.ok(settled, "close delivered and final anchored while the expired run is held");
    await emitter.flush();

    // Terminal anchor: the head at the TTL transition (before any anchoring receipt).
    assert.equal(settled.terminalState, "expired");
    assert.equal(settled.anchors.terminal.digest, headAtTtl);
    assert.equal(settled.anchors.terminal.status, "anchored");
    const feed = env.service.receiptFeed(runId);
    assert.equal(headBeforeAnchoring(feed.receipts), headAtTtl);
    assert.ok(anchor.calls.some((c) => c.kind === "terminal" && c.runId === runId && c.digestHex === headAtTtl));

    // Close: one signed terminal receipt the sink accepts, terminalState "expired".
    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].terminalState, "expired");
    assert.equal(sinkCheckReceipt(delivered[0], runId, serverPubKey), true);
    const job = env.service.terminalJobFor(runId);
    assert.equal(job.terminalState, "expired");
    assert.equal(job.close.status, "delivered");
    assert.equal(job.anchors.terminal.digest, headAtTtl);

    // Final anchor: covers the whole live chain, with its receipt count.
    assert.ok(feed.receipts.length > countAtTtl, "close/anchor evidence chained after the TTL head");
    assert.equal(settled.anchors.final.receiptCount, feed.receipts.length);
    assert.equal(settled.anchors.final.digest, feed.head);
    assert.equal(verifyChain(feed.receipts, { [SIGNER.keyId]: serverPubKey }).ok, true);

    const st = await env.callTool("tp1", "contract_status", {});
    assert.equal(st.terminalState, "expired");
    assert.equal(st.anchors.final.receiptCount, feed.receipts.length);
    assert.equal(st.anchors.terminal.digest, headAtTtl);

    // Past the hold window (default 15 min) the expired run is dropped; its job stays.
    clock += 15 * 60_000;
    assert.equal(env.service.runFor(runId), undefined);
    assert.equal(env.service.terminalJobFor(runId).terminalState, "expired");
  } finally {
    env.close();
  }
});

test("gap 2: default off — without expireAtTtl a run reaching its TTL is dropped as before", async () => {
  let clock = Date.now();
  const anchor = fakeAnchor();
  const { env, delivered } = await bootWithClose({ now: () => clock, runTtlMs: 60_000, serverAnchors: true, anchor });
  try {
    const runId = await bindPair(env, uuid(4202), "tb1", "tp1");
    clock += 61_000;
    assert.equal(env.service.runFor(runId), undefined);
    assert.equal(env.service.terminalJobFor(runId), undefined);
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(delivered.length, 0);
    assert.ok(!anchor.calls.some((c) => c.kind === "terminal" || c.kind === "final"));
  } finally {
    env.close();
  }
});

test("gap 2: config — CONTRACT_EXPIRE_AT_TTL is a 0|1 switch, off by default", async (t) => {
  const bad = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS_RAW,
    CONTRACT_HOST_ROOTS: HOST_ROOTS.map((r) => `${r.kid}:${r.fingerprint}`).join(","),
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED.toString("base64"),
    CONTRACT_SERVER_KEY_ID: "contract-server-gaps",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "cdt-gaps-")),
    CONTRACT_EXPIRE_AT_TTL: "yes",
  });
  assert.equal(bad.kind, "misconfigured");
  assert.match(bad.reason, /CONTRACT_EXPIRE_AT_TTL wants 0 or 1/);
  const on = await bootConfig(t, { CONTRACT_EXPIRE_AT_TTL: "1", CONTRACT_RUN_TTL_MS: "60000" });
  assert.equal(on.cfg.kind, "ready", JSON.stringify(on.cfg));
});

test("gap 2: the half-bound expiry path still ends expired_unbound with the verifier's subject", async () => {
  // Bind deadline = certificate validUntil (+10 min) + grace (10 min).
  for (const expireAtTtl of [false, true]) {
    let clock = Date.now();
    const anchor = fakeAnchor();
    const { env, emitter, delivered } = await bootWithClose({
      now: () => clock, expireAtTtl, serverAnchors: true, anchor,
    });
    try {
      const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(4203) });
      const b = await env.callTool("tb1", "contract_bind", {
        certificate: cert,
        signerKey: { keyId: keys.buyerSigner.keyId, publicKeyHex: keys.buyerSigner.publicKeyHex },
        approvalKey: { keyId: keys.buyerApproval.keyId, publicKeyHex: keys.buyerApproval.publicKeyHex },
      });
      assert.equal(b.bound, true, JSON.stringify(b));
      const headAtDeadline = env.service.receiptFeed(b.runId).head;
      clock += 21 * 60_000; // past validUntil + grace; TTL (24 h) far away
      const st = await env.callTool("tb1", "contract_status", {});
      assert.equal(st.terminalState, "expired_unbound", `expireAtTtl=${expireAtTtl}`);
      const settled = await waitFor(() => {
        const r = env.service.runFor(b.runId);
        return r?.telemetryClose?.status === "delivered" && r.anchors?.final?.status === "anchored" ? r : undefined;
      });
      assert.ok(settled, `expired_unbound settles (expireAtTtl=${expireAtTtl})`);
      await emitter.flush();
      assert.equal(settled.anchors.terminal.digest, headAtDeadline);
      assert.equal(headBeforeAnchoring(env.service.receiptFeed(b.runId).receipts), headAtDeadline);
      assert.equal(delivered.length, 1);
      assert.equal(delivered[0].terminalState, "expired_unbound");
      // Fewer than two roles hold an ok contract_bind.
      const binds = env.service.receiptFeed(b.runId).receipts.filter((r) => r.tool === "contract_bind" && r.outcome === "ok");
      assert.ok(binds.length < 2);
    } finally {
      env.close();
    }
  }
});

test("gap 2: with expireAtTtl a half-bound run reaching its TTL first ends expired_unbound", async () => {
  let clock = Date.now();
  const anchor = fakeAnchor();
  const { env, delivered, emitter } = await bootWithClose({
    now: () => clock, runTtlMs: 60_000, expireAtTtl: true, serverAnchors: true, anchor,
  });
  try {
    const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(4204) });
    const b = await env.callTool("tp1", "contract_bind", {
      certificate: cert,
      signerKey: { keyId: keys.providerSigner.keyId, publicKeyHex: keys.providerSigner.publicKeyHex },
      approvalKey: { keyId: keys.providerApproval.keyId, publicKeyHex: keys.providerApproval.publicKeyHex },
    });
    assert.equal(b.bound, true, JSON.stringify(b));
    clock += 61_000; // TTL passes long before the bind deadline
    const st = await env.callTool("tp1", "contract_status", {});
    assert.equal(st.terminalState, "expired_unbound");
    await waitFor(() => env.service.runFor(b.runId)?.telemetryClose?.status === "delivered");
    await emitter.flush();
    assert.equal(delivered[0].terminalState, "expired_unbound");
  } finally {
    env.close();
  }
});
