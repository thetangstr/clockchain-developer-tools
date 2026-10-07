// CDT integration (track-b/cdt-integration): the three Track B builds —
// O-2 standing listing (cdt-listing), O-3 session routing + server-side
// anchors (cdt-coord), O-1 sealed-log lanes (cdt-sink) — composed on one
// service. Each test pins one interaction point the merge had to resolve.
// Offline: loopback ports 19480-19499 only; every key is generated; the
// telemetry sink is the real one from ../telemetry-sink/dist, in-process.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { createCloseEmitter } from "../dist/agent-contract/close-emitter.js";
import { createTelemetryLanes } from "../dist/agent-contract/telemetry-lanes.js";
import { CONTRACT_TOOL_NAMES } from "../dist/agent-contract/schemas.js";
import { toolsListForRole } from "../dist/agent-contract/tools-list.js";
import {
  ACCEPT, HOST_ROOTS, POLICY, PRINCIPALS, SIGNER, serverPubKey, keys, mintCertificate, rootKey, uuid, fakeAnchor,
} from "./n4b9-harness.mjs";
import {
  createEnrollmentRegistry, createLaneService, createRunLedger, createTelemetrySink,
  createTelemetrySinkServer, createTokenStore, enrollParty,
} from "../../telemetry-sink/dist/index.js";

// --- loopback ports 19480-19499, rotating (never reuse a just-closed port) ---

let nextPort = 0;
async function listen(server) {
  for (let tries = 0; tries < 20; tries += 1) {
    const p = 19480 + (nextPort++ % 20);
    const ok = await new Promise((resolve) => {
      const onError = () => resolve(false);
      server.once("error", onError);
      server.listen(p, "127.0.0.1", () => { server.off("error", onError); resolve(true); });
    });
    if (ok) return `http://127.0.0.1:${p}`;
  }
  throw new Error("no free loopback port in 19480-19499");
}
const closeServer = (srv) => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); });

// --- shared fixtures ------------------------------------------------------------

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tb2:buyer:kb2:9452:initiator",
  "tp1:provider:kp1:9453:responder",
].join(",");
const SERVER_SEED = Buffer.alloc(32, 9);
const CONFIG_KEY_ID = "contract-server-integ";
const configServerPubKey = createPublicKey(createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SERVER_SEED]),
  format: "der",
  type: "pkcs8",
}));
const x25519Pub = () => {
  const jwk = generateKeyPairSync("x25519").privateKey.export({ format: "jwk" });
  return `0x${Buffer.from(jwk.x, "base64url").toString("hex")}`;
};
const SEAL_KEY = `0x${"11".repeat(32)}`;
const seal = (n) => ({
  v: 2,
  epk: `0x${n.toString(16).padStart(2, "0").repeat(32)}`,
  iv: `0x${"cd".repeat(12)}`,
  ct: `0x${n.toString(16).padStart(2, "0").repeat(48)}`,
  tag: `0x${"01".repeat(16)}`,
});
const ROUTE = { origin: "SFO", destination: "FCO" };

async function waitFor(fn, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await new Promise((r) => setTimeout(r, 20));
  }
}

// --- the real telemetry sink, in-process ----------------------------------------

// CDT-SEC L5: the sink's signing keyId is the audience of every signed lane body.
const SINK_AUD = "ac-telemetry-integ";

async function bootSink(t, contractKeys) {
  const dir = mkdtempSync(path.join(tmpdir(), "integ-sink-"));
  const enrollFile = path.join(dir, "enrollments.json");
  await enrollParty({ file: enrollFile, keyId: "kb1", role: "buyer", x25519: x25519Pub() });
  await enrollParty({ file: enrollFile, keyId: "kp1", role: "provider", x25519: x25519Pub() });
  const tokens = createTokenStore({ recordsFile: path.join(dir, "tokens.json") });
  const lanes = createLaneService({
    audience: SINK_AUD, tokens, enrollments: createEnrollmentRegistry({ file: enrollFile }), contractKeys, file: path.join(dir, "lanes.json"),
  });
  const sink = createTelemetrySink({
    signer: { keyId: SINK_AUD, privateKey: generateKeyPairSync("ed25519").privateKey },
    tokens, runLedger: createRunLedger({ file: path.join(dir, "runs.json") }), lanes, contractKeys, flushGraceMs: 0,
  });
  const servers = createTelemetrySinkServer({ sink, tokens, lanes });
  await listen(servers.write);
  await listen(servers.read);
  const closeUrl = await listen(servers.close);
  t.after(() => Promise.all([servers.write, servers.read, servers.close].map(closeServer)));
  return { sink, lanes, closeUrl };
}

// --- MCP client over the real HTTP handler, one MCP session per sessionKey ------

async function serve(t, handlerOptions) {
  const srv = createServer(createContractHttpHandler(handlerOptions));
  const baseUrl = `${await listen(srv)}/contract/mcp`;
  const sessions = new Map();
  const rpc = async (token, sessionKey, method, params) => {
    let sid = sessions.get(sessionKey);
    if (!sid) {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "integ", version: "1" } } }),
      });
      sid = init.headers.get("mcp-session-id");
      sessions.set(sessionKey, sid);
      await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
    }
    const res = await fetch(baseUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    return JSON.parse(data ? data.slice(5) : text);
  };
  // sessionKey defaults to the token: one session per token.
  const callTool = async (token, name, args = {}, sessionKey = token) => {
    const body = await rpc(token, sessionKey, "tools/call", { name, arguments: args });
    if (body.error !== undefined) return { rpcError: body.error };
    return body.result?.structuredContent ?? {};
  };
  const listTools = async (token, sessionKey = token) => (await rpc(token, sessionKey, "tools/list", {})).result;
  t.after(() => closeServer(srv));
  return { callTool, listTools, sessionIdOf: (k) => sessions.get(k) };
}

/** Production wiring: loadContractConfig (env) → the HTTP handler. */
async function bootConfig(t, env = {}) {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS_RAW,
    CONTRACT_HOST_ROOTS: HOST_ROOTS.map((r) => `${r.kid}:${r.fingerprint}`).join(","),
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED.toString("base64"),
    CONTRACT_SERVER_KEY_ID: CONFIG_KEY_ID,
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY.buyer},provider:${POLICY.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "integ-contract-")),
    TELEMETRY_CLOSE_BACKOFF_MS: "0,50",
    ...env,
  });
  assert.equal(cfg.kind, "ready", JSON.stringify(cfg));
  t.after(() => cfg.service.close());
  const client = await serve(t, {
    authenticate: cfg.authenticate, hostRoots: cfg.hostRoots, signer: cfg.signer, service: cfg.service,
    ...(cfg.telemetryLanes !== undefined ? { telemetryLanes: cfg.telemetryLanes } : {}),
  });
  return { cfg, service: cfg.service, lanes: cfg.telemetryLanes, ...client };
}

function bindArgs(certificate, role, extra = {}) {
  const signerKey = role === "buyer" ? keys.buyerSigner : keys.providerSigner;
  const approvalKey = role === "buyer" ? keys.buyerApproval : keys.providerApproval;
  return {
    certificate,
    signerKey: { keyId: signerKey.keyId, publicKeyHex: signerKey.publicKeyHex },
    approvalKey: { keyId: approvalKey.keyId, publicKeyHex: approvalKey.publicKeyHex },
    ...extra,
  };
}

/** Binds one handshake: buyer `token`/`session`, provider `token`/`session`. */
async function bindPair(env, sessionId, buyer, provider, providerExtra = {}) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await env.callTool(buyer.token, "contract_bind", bindArgs(cert, "buyer"), buyer.session);
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await env.callTool(provider.token, "contract_bind", bindArgs(cert, "provider", providerExtra), provider.session);
  return { runId: b.runId, provider: p };
}

// =============================================================================
// 1. O-1 x O-3: two sessions under one keyId (cap 2) each get their own lane
//    AND their own run link, under the run id the session router assigned.
// =============================================================================

test("integration: cap 2 — two sessions of one keyId get their own lane and their own run link", async (t) => {
  const sink = await bootSink(t, { [CONFIG_KEY_ID]: configServerPubKey });
  const env = await bootConfig(t, {
    TELEMETRY_CLOSE_URL: sink.closeUrl, TELEMETRY_SINK_KEY_ID: SINK_AUD, TELEMETRY_LANES: "1", CONTRACT_MAX_RUNS_PER_KEY: "2",
  });
  // One buyer key (kb1) and one provider key (kp1), two MCP sessions each.
  const laneA = await env.callTool("tb1", "telemetry_open", {}, "buyer-A");
  const laneB = await env.callTool("tb1", "telemetry_open", {}, "buyer-B");
  const laneP1 = await env.callTool("tp1", "telemetry_open", {}, "prov-1");
  const laneP2 = await env.callTool("tp1", "telemetry_open", {}, "prov-2");
  for (const l of [laneA, laneB, laneP1, laneP2]) assert.match(l.laneId ?? "", /^lane:[0-9a-f]{32}$/, JSON.stringify(l));
  assert.equal(new Set([laneA, laneB, laneP1, laneP2].map((l) => l.laneId)).size, 4);

  const x = await bindPair(env, uuid(1001), { token: "tb1", session: "buyer-A" }, { token: "tp1", session: "prov-1" });
  assert.equal(x.provider.bound, true, JSON.stringify(x.provider));
  const y = await bindPair(env, uuid(1002), { token: "tb1", session: "buyer-B" }, { token: "tp1", session: "prov-2" });
  assert.equal(y.provider.bound, true, JSON.stringify(y.provider));
  assert.notEqual(x.runId, y.runId);

  // The link is keyed by the run id each session routes to.
  const sid = (k) => env.sessionIdOf(k);
  assert.equal(env.service.runIdForPrincipal("kb1", sid("buyer-A")), x.runId);
  assert.equal(env.service.runIdForPrincipal("kb1", sid("buyer-B")), y.runId);
  assert.equal(env.service.runIdForPrincipal("kp1", sid("prov-1")), x.runId);
  assert.equal(env.service.runIdForPrincipal("kp1", sid("prov-2")), y.runId);

  // Each run links ONLY its own sessions' lanes — run X never captures the
  // lane of session B, which was still unlinked when X bound.
  const linkX = env.lanes.linkFor(env.service.runIdForPrincipal("kb1", sid("buyer-A")));
  const linkY = env.lanes.linkFor(env.service.runIdForPrincipal("kb1", sid("buyer-B")));
  assert.deepEqual(linkX.lanes, { buyer: [laneA.laneId], provider: [laneP1.laneId] });
  assert.deepEqual(linkY.lanes, { buyer: [laneB.laneId], provider: [laneP2.laneId] });
  // The sink accepted both links as sent (write-once, no LANE_REUSED).
  for (const [runId, link] of [[x.runId, linkX], [y.runId, linkY]]) {
    const atSink = await waitFor(() => sink.lanes.linkFor(runId));
    assert.ok(atSink, `sink has the link for ${runId}`);
    assert.deepEqual(atSink.lanes, link.lanes);
    assert.equal((await waitFor(() => env.lanes.linkFor(runId).status === "delivered" && link)).status, "delivered");
  }

  // Ending run X through session A closes with a v2 over X's lanes only;
  // run Y stays live with its own link.
  const w = await env.callTool("tb1", "contract_withdraw", { reason: "integ" }, "buyer-A");
  assert.equal(w.state, "withdrawn", JSON.stringify(w));
  const jobX = await waitFor(() => env.service.terminalJobFor(x.runId)?.close?.status === "delivered"
    && env.service.terminalJobFor(x.runId));
  assert.ok(jobX, "close for X delivered");
  assert.equal(jobX.receipt.schema, "ac-terminal-receipt/v2");
  assert.deepEqual(jobX.receipt.lanes, linkX.lanes);
  assert.equal(env.service.runEnded(env.service.runFor(y.runId)), false);
  assert.equal(await waitFor(() => sink.sink.isClosed(laneA.laneId)), true);
  assert.equal(sink.sink.isClosed(laneB.laneId), false, "session B's lane is not frozen by X's close");
});

// =============================================================================
// 2. O-2 x O-3: a standing listing still receives invitations and binds,
//    with the provider's sessions routed to separate concurrent runs.
// =============================================================================

test("integration: cap 2 — a standing listing receives invitations and binds two concurrent runs under session routing", async (t) => {
  const env = await bootConfig(t, { CONTRACT_DIRECTORY: "roma-travel:kp1", CONTRACT_MAX_RUNS_PER_KEY: "2" });
  const pub = await env.callTool("tp1", "rendezvous_publish_listing", {
    title: "Roma Travel", summary: "Standing agency listing",
    sealedBoxPublicKeyHex: SEAL_KEY, directoryName: "roma-travel", standing: true,
  }, "roma-1");
  assert.equal(pub.standing, true, JSON.stringify(pub));
  const listingId = pub.listingId;

  const runs = [];
  for (const [i, buyerToken, romaSession] of [[1, "tb1", "roma-1"], [2, "tb2", "roma-2"]]) {
    const found = await env.callTool(buyerToken, "rendezvous_search", { ...ROUTE, name: "roma-travel" });
    assert.deepEqual(found.listings.map((l) => l.listingId), [listingId]);
    // Roma's long-poll (from THIS session) wakes on the traveler's delivery.
    const poll = env.callTool("tp1", "rendezvous_inbox", { waitMs: 10_000 }, romaSession);
    await new Promise((r) => setTimeout(r, 100));
    const sent = await env.callTool(buyerToken, "rendezvous_send_invitation", { listingId, sealedInvitation: seal(i) });
    assert.equal(sent.delivered, true, JSON.stringify(sent));
    const box = await poll;
    const mine = box.messages.filter((m) => m.listingId === listingId);
    assert.equal(mine.length, 1, JSON.stringify(box));
    assert.equal(mine[0].sealedPayload.ct, seal(i).ct);
    const ack = await env.callTool("tp1", "rendezvous_ack", { messageIds: [mine[0].messageId] }, romaSession);
    assert.equal(ack.acked, 1, JSON.stringify(ack));

    // Bind through the standing listing; run 1 is still LIVE when run 2 binds.
    const r = await bindPair(env, uuid(1100 + i), { token: buyerToken, session: buyerToken },
      { token: "tp1", session: romaSession }, { listingId });
    assert.equal(r.provider.bound, true, `run ${i} provider bind: ${JSON.stringify(r.provider)}`);
    runs.push(r.runId);
  }
  assert.notEqual(runs[0], runs[1]);
  assert.equal(env.service.runEnded(env.service.runFor(runs[0])), false, "run 1 still live");
  // Each Roma session routes to its own run.
  assert.equal(env.service.runIdForPrincipal("kp1", env.sessionIdOf("roma-1")), runs[0]);
  assert.equal(env.service.runIdForPrincipal("kp1", env.sessionIdOf("roma-2")), runs[1]);
  // The standing listing survived both binds.
  const still = await env.callTool("tb1", "rendezvous_search", { ...ROUTE, name: "roma-travel" });
  assert.deepEqual(still.listings.map((l) => l.listingId), [listingId]);
  // Each session's pre-bind inbox reads are on that session's own pre-bind chain.
  for (const s of ["roma-1", "roma-2"]) {
    const feed = env.service.preBindFeed("kp1", env.sessionIdOf(s));
    const inbox = feed.receipts.filter((r) => r.tool === "rendezvous_inbox");
    assert.ok(inbox.length >= 1, `${s} inbox receipt`);
    assert.ok(inbox.every((r) => r.mcpSessionId === env.sessionIdOf(s)));
  }
  // The cap still holds for the standing provider: kp1 has 2 live runs, so a
  // third Roma session's bind through the listing is refused.
  const third = await bindPair(env, uuid(1103), { token: "tb1", session: "tb1-other" },
    { token: "tp1", session: "roma-3" }, { listingId });
  assert.equal(third.provider.error, "STATE_REFUSED", JSON.stringify(third.provider));
});

// =============================================================================
// 3. Anchoring x O-1: the final anchor's head covers the receipt written for
//    the v2 close (the telemetry_close evidence receipt).
// =============================================================================

test("integration: the final anchor head includes the v2 close receipt", async (t) => {
  const sink = await bootSink(t, { [SIGNER.keyId]: serverPubKey });
  const stateDir = mkdtempSync(path.join(tmpdir(), "integ-wired-"));
  const anchor = fakeAnchor();
  // Same wiring as config.ts (TELEMETRY_LANES=1 + TELEMETRY_CLOSE_URL), with
  // the fake anchor injected — the config path has no anchor test seam.
  let service;
  let lanes;
  const emitter = createCloseEmitter({
    signer: SIGNER, closeUrl: sink.closeUrl, backoffMs: [0, 50],
    setState: (runId, state) => {
      const run = service.runFor(runId);
      if (run !== undefined) run.telemetryClose = state;
      service.persistTerminalClose(runId, {
        status: state.status, attempts: state.attempts, lastError: state.lastError, deliveredAt: state.deliveredAt,
      });
    },
    recordOutcome: (outcome, d) => service.recordTerminalOutcome(d.runId, outcome, d),
  });
  service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, policyDigests: POLICY, principals: PRINCIPALS, stateDir,
    maxRunsPerKey: 2, anchor, serverAnchors: true,
    onTerminalRun: (_run, _state, _p, receipt) => emitter.resume(receipt),
    mintTerminalReceipt: (fields, s) => lanes.terminalReceiptFor(fields, s),
    onRunBound: (run, sessions) => lanes?.onRunBound(run, sessions),
  });
  lanes = createTelemetryLanes({ signer: SIGNER, sinkAudience: SINK_AUD, closeUrl: sink.closeUrl, stateDir, backoffMs: [0, 50] });
  t.after(() => service.close());
  const env = await serve(t, {
    authenticate: tokenAuthenticator(parseContractTokens(TOKENS_RAW)),
    hostRoots: HOST_ROOTS, signer: SIGNER, service, telemetryLanes: lanes,
  });

  const bl = await env.callTool("tb1", "telemetry_open", {}, "buyer-A");
  const pl = await env.callTool("tp1", "telemetry_open", {}, "prov-1");
  const { runId, provider } = await bindPair(env, uuid(1201), { token: "tb1", session: "buyer-A" }, { token: "tp1", session: "prov-1" });
  assert.equal(provider.bound, true, JSON.stringify(provider));
  assert.deepEqual(lanes.linkFor(runId).lanes, { buyer: [bl.laneId], provider: [pl.laneId] });

  const w = await env.callTool("tb1", "contract_withdraw", { reason: "integ" }, "buyer-A");
  assert.equal(w.state, "withdrawn", JSON.stringify(w));
  // The v2 close is delivered (it may be refused until the link lands, then retried).
  const closeReceipt = await waitFor(() => service.receiptFeed(runId).receipts.find((r) => r.tool === "telemetry_close"));
  assert.ok(closeReceipt, "telemetry_close receipt on the run chain");
  assert.equal(closeReceipt.outcome, "telemetry_close_delivered");
  const job = service.terminalJobFor(runId);
  assert.equal(job.receipt.schema, "ac-terminal-receipt/v2");
  assert.equal(closeReceipt.argsDigest,
    canonicalDigest({ runId, terminalState: job.terminalState, receiptDigest: canonicalDigest(job.receipt) }),
    "the close receipt names the v2 receipt");

  const st = await env.callTool("tb1", "contract_status", {}, "buyer-A");
  assert.equal(st.terminalState, job.terminalState, JSON.stringify(st));
  assert.equal(st.anchors.final?.status, "anchored", JSON.stringify(st.anchors));
  const receipts = service.receiptFeed(runId).receipts;
  const n = st.anchors.final.receiptCount;
  const closeAt = receipts.findIndex((r) => r.tool === "telemetry_close");
  assert.ok(n > closeAt, `final covers receipts[0..${n - 1}], the v2 close receipt is #${closeAt}`);
  assert.equal(st.anchors.final.digest, canonicalDigest(receipts[n - 1]), "final = chain head over the first n receipts");
  assert.equal(anchor.calls.filter((c) => c.kind === "final").length, 1);
});

// =============================================================================
// 4. The merged tool surface: telemetry_open is still hidden and {}-only.
// =============================================================================

test("integration: telemetry_open stays hidden from the merged tools/list and accepts only {}", async (t) => {
  assert.ok(!CONTRACT_TOOL_NAMES.includes("telemetry_open"));
  const sink = await bootSink(t, { [CONFIG_KEY_ID]: configServerPubKey });
  // CDT-SEC M5: every gated feature is switched on by its own env here.
  const briefsDir = mkdtempSync(path.join(tmpdir(), "integ-briefs-"));
  const briefText = "# brief\n";
  writeFileSync(path.join(briefsDir, "family-travel.md"), briefText);
  const briefDigest = `0x${createHash("sha256").update(briefText).digest("hex")}`;
  const env = await bootConfig(t, {
    TELEMETRY_CLOSE_URL: sink.closeUrl, TELEMETRY_SINK_KEY_ID: SINK_AUD, TELEMETRY_LANES: "1", CONTRACT_MAX_RUNS_PER_KEY: "2",
    CONTRACT_POLICY_REGISTRATION: "1", CONTRACT_DIRECTORY: "roma-travel:kp1",
    CONTRACT_BRIEFS: `family-travel:${briefDigest}`, CONTRACT_BRIEFS_DIR: briefsDir,
  });
  assert.deepEqual(env.service.features, { directory: true, policyRegistration: true, briefs: true });
  for (const [token, role, count] of [["tb1", "buyer", 23], ["tp1", "provider", 20]]) {
    const list = await env.listTools(token);
    assert.equal(list.tools.length, count, `${role} tools`);
    assert.ok(!list.tools.some((x) => x.name === "telemetry_open"), role);
    assert.equal(canonicalDigest(list), canonicalDigest(toolsListForRole(role, env.service.features)), `${role}: verbatim role payload`);
  }
  for (const args of [{ x25519: SEAL_KEY }, { mcpSessionId: "other" }, { keyId: "kb1" }]) {
    const out = await env.callTool("tb1", "telemetry_open", args, "buyer-A");
    assert.equal(out.rpcError?.code, -32602, JSON.stringify(out));
  }
  const ok = await env.callTool("tb1", "telemetry_open", {}, "buyer-A");
  assert.deepEqual(Object.keys(ok).sort(), ["laneId", "role", "sealedBox", "serverNonce"]);
  // Off by default: the name is NOT_FOUND without TELEMETRY_LANES=1, and
  // without the feature envs the surface is the b04059e 21 + 18.
  const plain = await bootConfig(t, { CONTRACT_MAX_RUNS_PER_KEY: "2" });
  assert.equal((await plain.callTool("tb1", "telemetry_open")).error, "NOT_FOUND");
  for (const [token, role, count] of [["tb1", "buyer", 21], ["tp1", "provider", 18]]) {
    const list = await plain.listTools(token);
    assert.equal(list.tools.length, count, `default ${role} tools`);
    assert.equal(canonicalDigest(list), canonicalDigest(toolsListForRole(role)), `default ${role}: verbatim role payload`);
  }
});
