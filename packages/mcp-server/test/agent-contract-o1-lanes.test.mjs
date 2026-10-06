// O-1 sealed-log lanes, contract side: the adapter's `telemetry_open`, the
// run link written at bind, and the v2 terminal receipt — against the REAL
// telemetry sink (packages/telemetry-sink/dist, in-process). Loopback ports
// 19440-19479 only.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  createPrivateKey, createPublicKey, generateKeyPairSync, createHash, sign as edSign,
} from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { toolsListForRole } from "../dist/agent-contract/tools-list.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { eip191SignDigest32, eip191RecoverPublicKey } from "../dist/agent-contract/eip191.js";
import { linkDigestOf } from "../dist/agent-contract/telemetry-lanes.js";
import {
  createEnrollmentRegistry,
  createLaneService,
  createRunLedger,
  createTelemetrySink,
  createTelemetrySinkServer,
  createTokenStore,
  enrollParty,
  openSealJwk,
} from "../../telemetry-sink/dist/index.js";

const ACCEPT = "application/json, text/event-stream";

let nextPort = 19440;
const port = () => {
  const p = nextPort;
  nextPort = nextPort >= 19479 ? 19440 : nextPort + 1;
  return p;
};
// Other local agents share the 194xx range — skip a port that is taken.
async function listen(server) {
  for (let tries = 0; ; tries += 1) {
    const p = port();
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(p, "127.0.0.1", () => { server.off("error", reject); resolve(); });
      });
      return `http://127.0.0.1:${p}`;
    } catch (err) {
      if (err.code !== "EADDRINUSE" || tries >= 40) throw err;
    }
  }
}

// --- test-only certificate minter (same wire format as the close suite) -----

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64");
}

function mintCertificate({ root, session, sessionId }) {
  const t = Date.now();
  const sessionKeyAddress = `0x${createHash("sha256").update(session.publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 40)}`;
  const certificate = {
    schema: "clockchain.host-session-key/v1",
    rootKid: "root-test",
    sessionId,
    repositorySha: "d".repeat(40),
    sessionPublicKey: rawPublicKeyBase64(session.publicKey),
    validFromMs: String(t - 60_000),
    validUntilMs: String(t + 10 * 60_000),
  };
  const hostSessionKeyCertificate = {
    certificate,
    rootSignature: {
      algorithm: "ed25519",
      keyId: "root-test",
      publicKey: rawPublicKeyBase64(root.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(certificate), "utf8"), root.privateKey).toString("base64"),
    },
  };
  const party = (addr, agentId, n) => ({
    sessionKeyAddress: addr,
    policyDigest: `${n === 0 ? "a" : "b"}${"0".repeat(63)}`,
    erc8004: {
      agentId,
      chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
      registrationTx: `0x${"a".repeat(64)}`,
      registrationBlock: `700${n}`,
    },
  });
  const initiator = party(sessionKeyAddress, "9452", 0);
  const responder = party(`0x${"9".repeat(40)}`, "9453", 1);
  const anchor = (kind, n) => ({ blockHeight: String(7010 + n), blockTimeRaw: `2026-08-09T17:0${n}:00.000Z`, digest: `${n}${"0".repeat(63)}`, kind, ledgerId: `33333333-4444-4555-8666-77777777777${n}` });
  const result = {
    anchors: [anchor("proposal", 0), anchor("acceptance", 1), anchor("acknowledgment", 2)],
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: canonicalDigest(hostSessionKeyCertificate).slice(2),
    identityPolicy: { chainId: "eip155:11155111", erc8004: "required_fresh", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
    issuedAtMs: String(t),
    outcome: "VERIFIED",
    parties: { initiator, responder },
    policyDigests: { initiator: initiator.policyDigest, responder: responder.policyDigest },
    reference: "NS-1847",
    schema: "clockchain.agent-handshake-result/v2",
    sessionDigest: "e".repeat(64),
    sessionId,
    statementDigest: "f".repeat(64),
    subjectRun: "stakeholder",
  };
  return {
    hostSessionKeyCertificate,
    result,
    signer: {
      algorithm: "ed25519",
      keyId: "session-host",
      publicKey: rawPublicKeyBase64(session.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(result), "utf8"), session.privateKey).toString("base64"),
    },
  };
}

const rootKey = generateKeyPairSync("ed25519");
const HOST_ROOTS_ENV = `root-test:${createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex")}`;

const secpPriv = (n) => `0x${n.toString(16).padStart(64, "0")}`;
function pubFromPriv(privHex) {
  const dummy = Buffer.alloc(32, 1);
  const sig = eip191SignDigest32(dummy, privHex);
  return `0x${Buffer.from(eip191RecoverPublicKey(dummy, sig)).toString("hex")}`;
}
const keys = {
  buyerSigner: { keyId: "signer-buyer", priv: secpPriv(0xb1) },
  buyerApproval: { keyId: "approval-buyer", priv: secpPriv(0xb2) },
  providerSigner: { keyId: "signer-provider", priv: secpPriv(0xc1) },
  providerApproval: { keyId: "approval-provider", priv: secpPriv(0xc2) },
};
for (const k of Object.values(keys)) k.publicKeyHex = pubFromPriv(k.priv);

const POLICY_DIGESTS = { buyer: `0x${"7".repeat(64)}`, provider: `0x${"8".repeat(64)}` };
const SERVER_SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";
const configServerPubKey = createPublicKey(createPrivateKey({
  key: Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX, "hex"), Buffer.alloc(32, 7)]),
  format: "der",
  type: "pkcs8",
}));
const CONTRACT_KEY_ID = "contract-server-test";

// kb1/kp1 are enrolled at the sink; kb2 is a valid contract principal the
// sink admin never enrolled.
const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder,tb2:buyer:kb2:9452:initiator";

// Party services keys — generated per test run; only the PUBLIC half is
// ever enrolled (the contract service never sees either half).
const x25519 = () => {
  const kp = generateKeyPairSync("x25519");
  const jwk = kp.privateKey.export({ format: "jwk" });
  return { jwk, pub: `0x${Buffer.from(jwk.x, "base64url").toString("hex")}` };
};
const buyerKey = x25519();
const providerKey = x25519();

const SPAN = (name) => JSON.stringify({ resourceSpans: [{ scopeSpans: [{ spans: [{ name }] }] }] });

// --- the real sink, in-process ------------------------------------------------

async function bootSink(t) {
  const dir = mkdtempSync(path.join(tmpdir(), "o1-sink-"));
  const sinkKeys = generateKeyPairSync("ed25519");
  const tokens = createTokenStore({ recordsFile: path.join(dir, "tokens.json") });
  await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "kb1", role: "buyer", x25519: buyerKey.pub });
  await enrollParty({ file: path.join(dir, "enrollments.json"), keyId: "kp1", role: "provider", x25519: providerKey.pub });
  const contractKeys = { [CONTRACT_KEY_ID]: configServerPubKey };
  const lanes = createLaneService({
    tokens,
    enrollments: createEnrollmentRegistry({ file: path.join(dir, "enrollments.json") }),
    contractKeys,
    file: path.join(dir, "lanes.json"),
  });
  const sink = createTelemetrySink({
    signer: { keyId: "ac-telemetry-test", privateKey: sinkKeys.privateKey },
    tokens,
    runLedger: createRunLedger({ file: path.join(dir, "runs.json") }),
    lanes,
    contractKeys,
    flushGraceMs: 0,
  });
  const servers = createTelemetrySinkServer({ sink, tokens, lanes });
  const writeUrl = await listen(servers.write);
  const readUrl = await listen(servers.read);
  const closeUrl = await listen(servers.close);
  t.after(() => { servers.write.close(); servers.read.close(); servers.close.close(); });
  return { dir, sink, tokens, lanes, writeUrl, readUrl, closeUrl };
}

// --- config-booted contract server -------------------------------------------

async function bootContract(t, extra = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "o1-contract-"));
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_HOST_ROOTS: HOST_ROOTS_ENV,
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED_B64,
    CONTRACT_SERVER_KEY_ID: CONTRACT_KEY_ID,
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY_DIGESTS.buyer},provider:${POLICY_DIGESTS.provider}`,
    CONTRACT_STATE_DIR: dir,
    TELEMETRY_CLOSE_BACKOFF_MS: "0,50",
    ...extra,
  });
  assert.equal(cfg.kind, "ready", JSON.stringify(cfg));
  const handler = createContractHttpHandler({
    authenticate: cfg.authenticate,
    hostRoots: cfg.hostRoots,
    signer: cfg.signer,
    service: cfg.service,
    ...(cfg.telemetryLanes !== undefined ? { telemetryLanes: cfg.telemetryLanes } : {}),
  });
  const srv = createServer(handler);
  const baseUrl = `${await listen(srv)}/contract/mcp`;
  const sessions = new Map();
  const rpc = async (token, session, method, params) => {
    const key = `${token}/${session}`;
    let sid = sessions.get(key);
    if (!sid) {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "adapter", version: "1" } } }),
      });
      sid = init.headers.get("mcp-session-id");
      sessions.set(key, sid);
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
    return { sid, body: JSON.parse(data ? data.slice(5) : text) };
  };
  const callTool = async (token, name, args = {}, session = "s1") => {
    const { sid, body } = await rpc(token, session, "tools/call", { name, arguments: args });
    if (body.error !== undefined) return { rpcError: body.error, sid };
    return { ...(body.result?.structuredContent ?? {}), sid };
  };
  const listTools = async (token, session = "s1") => (await rpc(token, session, "tools/list", {})).body.result;
  t.after(() => { srv.close(); cfg.service.close(); });
  return { cfg, dir, callTool, listTools };
}

function bindArgs(certificate, role) {
  const signerKey = role === "buyer" ? keys.buyerSigner : keys.providerSigner;
  const approvalKey = role === "buyer" ? keys.buyerApproval : keys.providerApproval;
  return {
    certificate,
    signerKey: { keyId: signerKey.keyId, publicKeyHex: signerKey.publicKeyHex },
    approvalKey: { keyId: approvalKey.keyId, publicKeyHex: approvalKey.publicKeyHex },
  };
}

async function bindPair(env, sessionId, sessions = { buyer: "s1", provider: "s1" }) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await env.callTool("tb1", "contract_bind", bindArgs(cert, "buyer"), sessions.buyer);
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await env.callTool("tp1", "contract_bind", bindArgs(cert, "provider"), sessions.provider);
  assert.equal(p.bound, true, `provider bind: ${JSON.stringify(p)}`);
  return b.runId;
}

async function waitFor(fn, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await new Promise((r) => setTimeout(r, 20));
  }
}

const postJson = (url, p, body, token) => fetch(url + p, {
  method: "POST",
  headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: typeof body === "string" ? body : JSON.stringify(body),
});

const lanesEnv = (sink) => ({ TELEMETRY_CLOSE_URL: sink.closeUrl, TELEMETRY_LANES: "1" });

// --- tests --------------------------------------------------------------------

test("telemetry_open: hidden from tools/list (guidanceDigests unchanged); returns ciphertext only, sealed to the ENROLLED key; receipted", async (t) => {
  const sink = await bootSink(t);
  const env = await bootContract(t, lanesEnv(sink));

  // R10: the served list is still the verbatim role payload.
  const list = await env.listTools("tb1");
  assert.equal(canonicalDigest(list), canonicalDigest(toolsListForRole("buyer")));
  assert.ok(!list.tools.some((tool) => tool.name === "telemetry_open"));

  const out = await env.callTool("tb1", "telemetry_open");
  assert.deepEqual(Object.keys(out).sort(), ["laneId", "role", "sealedBox", "serverNonce", "sid"]);
  assert.match(out.laneId, /^lane:[0-9a-f]{32}$/);
  assert.equal(out.role, "buyer");
  // Only the enrolled party key opens it, and only bound to (laneId, role).
  const token = openSealJwk(buyerKey.jwk, out.sealedBox, { runId: out.laneId, role: "buyer" });
  assert.equal(typeof token, "string");
  assert.throws(() => openSealJwk(providerKey.jwk, out.sealedBox, { runId: out.laneId, role: "buyer" }));
  assert.throws(() => openSealJwk(buyerKey.jwk, out.sealedBox, { runId: out.laneId, role: "provider" }));
  // The sink recorded the lane under this MCP session.
  assert.equal(sink.lanes.lane(out.laneId).mcpSessionId, out.sid);
  assert.equal(sink.lanes.lane(out.laneId).keyId, "kb1");

  // Receipted on the principal's pre-bind chain, carrying the session id.
  const feed = env.cfg.service.preBindFeed("kb1");
  const r = feed.receipts.find((x) => x.tool === "telemetry_open");
  assert.ok(r, "telemetry_open receipt on the pre-bind chain");
  assert.equal(r.outcome, "ok");
  assert.equal(r.mcpSessionId, out.sid);
  assert.equal(verifyChain(feed.receipts, { [CONTRACT_KEY_ID]: configServerPubKey }, { firstPrevHash: feed.anchor }).ok, true);

  // The MCP never holds the plaintext token: not in its state dir, not in
  // any receipt.
  for (const f of readdirSync(env.dir)) {
    try { assert.ok(!readFileSync(path.join(env.dir, f), "utf8").includes(token), `token leaked into ${f}`); } catch (e) {
      if (e.code !== "EISDIR") throw e;
    }
  }
  assert.ok(!JSON.stringify(feed).includes(token));
});

test("telemetry_open: two sessions under one keyId get two lanes; a same-session retry returns the same lane", async (t) => {
  const sink = await bootSink(t);
  const env = await bootContract(t, lanesEnv(sink));
  const a = await env.callTool("tb1", "telemetry_open", {}, "A");
  const again = await env.callTool("tb1", "telemetry_open", {}, "A");
  const b = await env.callTool("tb1", "telemetry_open", {}, "B");
  assert.equal(again.laneId, a.laneId, "cached per (keyId, mcpSessionId) — the sink would refuse LANE_REUSED");
  assert.deepEqual(again.sealedBox, a.sealedBox);
  assert.notEqual(b.laneId, a.laneId);
  assert.notEqual(a.sid, b.sid);
  assert.equal(sink.lanes.lane(a.laneId).mcpSessionId, a.sid);
  assert.equal(sink.lanes.lane(b.laneId).mcpSessionId, b.sid);
});

test("telemetry_open: a public key (or any argument) is invalid params — nothing reaches the sink; an unenrolled keyId is NOT_FOUND", async (t) => {
  const sink = await bootSink(t);
  const env = await bootContract(t, lanesEnv(sink));
  const attacker = x25519();
  for (const args of [{ x25519: attacker.pub }, { publicKey: attacker.pub }, { keyId: "kb1" }]) {
    const out = await env.callTool("tb1", "telemetry_open", args);
    assert.equal(out.rpcError?.code, -32602, JSON.stringify(out));
  }
  const lanesFile = path.join(sink.dir, "lanes.json");
  const persisted = (() => { try { return JSON.parse(readFileSync(lanesFile, "utf8")); } catch { return { lanes: {} }; } })();
  assert.equal(Object.keys(persisted.lanes).length, 0, "no lane was opened");
  const invalid = env.cfg.service.preBindFeed("kb1").receipts.filter((x) => x.tool === "telemetry_open");
  assert.equal(invalid.length, 3);
  assert.ok(invalid.every((x) => x.outcome === "INVALID_PARAMS"));

  const refused = await env.callTool("tb2", "telemetry_open");
  assert.equal(refused.error, "NOT_FOUND");
  assert.equal(refused.retryable, false);
  assert.equal(refused.sealedBox, undefined);
  const r = env.cfg.service.preBindFeed("kb2").receipts.find((x) => x.tool === "telemetry_open");
  assert.equal(r.outcome, "NOT_FOUND");
});

test("bind links every role's lanes; spans sent before the handshake are covered; terminal emits v2 and the sink freezes the lanes", async (t) => {
  const sink = await bootSink(t);
  const env = await bootContract(t, lanesEnv(sink));
  // Buyer reconnects once before bind: two sessions, two lanes. Provider: one.
  const b1 = await env.callTool("tb1", "telemetry_open", {}, "b-first");
  const b2 = await env.callTool("tb1", "telemetry_open", {}, "b-second");
  const p1 = await env.callTool("tp1", "telemetry_open", {}, "p-only");
  // The adapter/forwarder (party side) opens its box and ingests pre-bind spans.
  const bTok = openSealJwk(buyerKey.jwk, b1.sealedBox, { runId: b1.laneId, role: "buyer" });
  const pTok = openSealJwk(providerKey.jwk, p1.sealedBox, { runId: p1.laneId, role: "provider" });
  assert.equal((await postJson(sink.writeUrl, "/v1/traces", SPAN("pre-bind-buyer"), bTok)).status, 200);
  assert.equal((await postJson(sink.writeUrl, "/v1/traces", SPAN("pre-bind-provider"), pTok)).status, 200);

  const runId = await bindPair(env, "deadbeef-0001-4444-8888-0000000000a1", { buyer: "b-second", provider: "p-only" });
  const link = env.cfg.telemetryLanes.linkFor(runId);
  assert.deepEqual(link.lanes, { buyer: [b1.laneId, b2.laneId], provider: [p1.laneId] });
  assert.equal(link.linkDigest, linkDigestOf(runId, link.lanes));
  // The sink holds the same link (write-once, contract-signed).
  const linked = await waitFor(() => sink.lanes.linkFor(runId));
  assert.ok(linked, "sink received the run link");
  assert.deepEqual(linked.lanes, link.lanes);
  assert.equal(linked.linkDigest, link.linkDigest);
  assert.equal(env.cfg.telemetryLanes.linkFor(runId).status, "delivered");

  const withdrawn = await env.callTool("tb1", "contract_withdraw", { reason: "plans changed" }, "b-second");
  assert.equal(withdrawn.state, "withdrawn");
  const st = await waitFor(async () => {
    const s = await env.callTool("tb1", "contract_status", {}, "b-second");
    return s.telemetryClose?.status === "delivered" ? s : undefined;
  });
  assert.ok(st, "close delivered");
  const job = env.cfg.service.terminalJobFor(runId);
  assert.equal(job.receipt.schema, "ac-terminal-receipt/v2");
  assert.deepEqual(job.receipt.lanes, link.lanes);
  assert.equal(job.receipt.linkDigest, link.linkDigest);
  assert.equal(st.telemetryClose.receiptDigest, canonicalDigest(job.receipt));

  // The sink kept the receipt body and froze every member lane under it.
  const q = sink.tokens.mintQuery({ runId });
  const rr = await fetch(`${sink.readUrl}/v1/runs/${encodeURIComponent(runId)}/receipt`, { headers: { authorization: `Bearer ${q.token}` } });
  assert.equal(rr.status, 200);
  assert.deepEqual((await rr.json()).receipt ?? null, job.receipt);
  for (const laneId of [b1.laneId, b2.laneId, p1.laneId]) {
    assert.equal(await waitFor(() => sink.sink.isClosed(laneId)), true, `${laneId} frozen`);
  }
  const set = sink.sink.runSet(runId);
  assert.equal(set.receiptDigest, canonicalDigest(job.receipt));
  const buyerLane = set.lanes.buyer.find((l) => l.laneId === b1.laneId);
  assert.equal(buyerLane.state, "final");
  assert.equal(buyerLane.head.receiptDigest, canonicalDigest(job.receipt));
  // Post-close ingest is refused.
  assert.equal((await postJson(sink.writeUrl, "/v1/traces", SPAN("late"), bTok)).status, 409);
});

test("default unchanged: without TELEMETRY_LANES the tool is NOT_FOUND and the close is v1; with lanes but no telemetry_open the close stays v1", async (t) => {
  const sink = await bootSink(t);
  const plain = await bootContract(t, { TELEMETRY_CLOSE_URL: sink.closeUrl });
  assert.equal(plain.cfg.telemetryLanes, undefined);
  const nf = await plain.callTool("tb1", "telemetry_open");
  assert.equal(nf.error, "NOT_FOUND");

  const runId = await bindPair(plain, "deadbeef-0001-4444-8888-0000000000b1");
  await plain.callTool("tb1", "contract_withdraw", { reason: "x" });
  const job = await waitFor(() => plain.cfg.service.terminalJobFor(runId)?.receipt);
  assert.equal(job.schema, "ac-terminal-receipt/v1");

  const lanesOn = await bootContract(t, lanesEnv(sink));
  const runId2 = await bindPair(lanesOn, "deadbeef-0001-4444-8888-0000000000b2");
  assert.equal(lanesOn.cfg.telemetryLanes.linkFor(runId2), undefined, "no lanes → no link");
  await lanesOn.callTool("tb1", "contract_withdraw", { reason: "x" });
  const job2 = await waitFor(() => lanesOn.cfg.service.terminalJobFor(runId2)?.receipt);
  assert.equal(job2.schema, "ac-terminal-receipt/v1");
});

test("a lane is linked to one run only; lanes opened by a principal after a link go to its NEXT run", async (t) => {
  const sink = await bootSink(t);
  const env = await bootContract(t, lanesEnv(sink));
  const first = await env.callTool("tb1", "telemetry_open", {}, "r1");
  const runId = await bindPair(env, "deadbeef-0001-4444-8888-0000000000c1", { buyer: "r1", provider: "r1" });
  assert.deepEqual(env.cfg.telemetryLanes.linkFor(runId).lanes, { buyer: [first.laneId], provider: [] });
  await waitFor(() => env.cfg.telemetryLanes.linkFor(runId).status === "delivered");
  await env.callTool("tb1", "contract_withdraw", { reason: "x" }, "r1");
  await waitFor(() => env.cfg.service.terminalJobFor(runId)?.close?.status === "delivered");

  const second = await env.callTool("tb1", "telemetry_open", {}, "r2");
  const runId2 = await bindPair(env, "deadbeef-0001-4444-8888-0000000000c2", { buyer: "r2", provider: "r2" });
  assert.notEqual(runId2, runId);
  assert.deepEqual(env.cfg.telemetryLanes.linkFor(runId2).lanes, { buyer: [second.laneId], provider: [] });
});

test("config: TELEMETRY_LANES needs TELEMETRY_CLOSE_URL and a 0|1 value; lane state survives a restart", async (t) => {
  const base = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_HOST_ROOTS: HOST_ROOTS_ENV,
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED_B64,
    CONTRACT_SERVER_KEY_ID: CONTRACT_KEY_ID,
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY_DIGESTS.buyer},provider:${POLICY_DIGESTS.provider}`,
  };
  const noUrl = loadContractConfig({ ...base, CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "o1-c-")), TELEMETRY_LANES: "1" });
  assert.equal(noUrl.kind, "misconfigured");
  assert.match(noUrl.reason, /TELEMETRY_LANES=1 requires TELEMETRY_CLOSE_URL/);
  const bad = loadContractConfig({ ...base, CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "o1-c-")), TELEMETRY_LANES: "yes", TELEMETRY_CLOSE_URL: "http://127.0.0.1:19479" });
  assert.equal(bad.kind, "misconfigured");

  const sink = await bootSink(t);
  const dir = mkdtempSync(path.join(tmpdir(), "o1-c-"));
  const first = await bootContract(t, { ...lanesEnv(sink), CONTRACT_STATE_DIR: dir });
  const opened = await first.callTool("tb1", "telemetry_open");
  first.cfg.service.close();
  const persisted = JSON.parse(readFileSync(path.join(dir, "telemetry-lanes.json"), "utf8"));
  assert.equal(persisted.lanes.length, 1);
  assert.equal(persisted.lanes[0].laneId, opened.laneId);
  const second = loadContractConfig({ ...base, ...lanesEnv(sink), CONTRACT_STATE_DIR: dir });
  assert.equal(second.kind, "ready", JSON.stringify(second));
  t.after(() => second.service.close());
});
