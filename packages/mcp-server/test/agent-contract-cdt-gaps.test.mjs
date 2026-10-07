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
import { ACCEPT, HOST_ROOTS, POLICY, SIGNER, bindPair, uuid, waitFor } from "./n4b9-harness.mjs";

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
