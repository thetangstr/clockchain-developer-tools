import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  createPrivateKey, createPublicKey, generateKeyPairSync, createHash,
  sign as edSign, verify as edVerify,
} from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { createCloseEmitter, mintTerminalReceipt } from "../dist/agent-contract/close-emitter.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { eip191SignDigest32, eip191RecoverPublicKey } from "../dist/agent-contract/eip191.js";
import { checkConfig } from "../scripts/agent-contract/check-config.mjs";

// N4b-8 gap 3: the terminal close emitter. When a run ends the server mints
// the signed ac-terminal-receipt/v1 and POSTs it to TELEMETRY_CLOSE_URL
// (the sink's close-only listener), retries with backoff, receipts the
// outcome, and surfaces a permanently failed close in contract_status.

const ACCEPT = "application/json, text/event-stream";

// --- test-only certificate minter (same wire format as the business suite) --

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
  const identityPolicy = {
    chainId: "eip155:11155111",
    erc8004: "required_fresh",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  };
  const anchor = (kind, n) => ({ blockHeight: String(7010 + n), blockTimeRaw: `2026-08-09T17:0${n}:00.000Z`, digest: `${n}${"0".repeat(63)}`, kind, ledgerId: `33333333-4444-4555-8666-77777777777${n}` });
  const result = {
    anchors: [anchor("proposal", 0), anchor("acceptance", 1), anchor("acknowledgment", 2)],
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: canonicalDigest(hostSessionKeyCertificate).slice(2),
    identityPolicy,
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
const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex") },
]);
const HOST_ROOTS_ENV = `root-test:${HOST_ROOTS[0].fingerprint}`;

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
const SERVER_SEED_B64 = Buffer.alloc(32, 7).toString("base64"); // deterministic server key for config boots
// The config boot derives its ed25519 keypair from the seed; compute the
// public key the sink-side verification must check against.
const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";
const configServerKey = createPrivateKey({
  key: Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX, "hex"), Buffer.alloc(32, 7)]),
  format: "der",
  type: "pkcs8",
});
const configServerPubKey = createPublicKey(configServerKey);

const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder";

// --- fake telemetry-sink close listener -------------------------------------
// Faithful replication of packages/telemetry-sink checkReceipt + closeRun
// semantics (the sink package lives on the n4c branch — not importable here):
//  - body must be ac-terminal-receipt/v1 with a signature that verifies under
//    the contract server's ed25519 key over the canonical signed message;
//  - first valid close answers {closed:true, head}; a replayed close for the
//    same run answers the SAME head (idempotent).
// The canonicalJson here is an INDEPENDENT sorted-keys implementation — not
// the emitter's own module — so canonicalization bugs still show.

function sinkCanonicalJson(v) {
  if (v === null) return "null";
  switch (typeof v) {
    case "number": return JSON.stringify(v);
    case "boolean":
    case "string": return JSON.stringify(v);
    case "object": {
      if (Array.isArray(v)) return `[${v.map(sinkCanonicalJson).join(",")}]`;
      return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${sinkCanonicalJson(v[k])}`).join(",")}}`;
    }
    default: throw new Error("unrepresentable");
  }
}

async function fakeSink({ respond = "closed", publicKey = configServerPubKey } = {}) {
  const received = [];
  const heads = new Map();
  const srv = createServer(async (req, res) => {
    const m = /^\/v1\/runs\/([^/]+)\/close$/.exec(new URL(req.url ?? "/", "http://x").pathname);
    if (req.method !== "POST" || m === null) {
      res.writeHead(404, { "content-type": "application/json" }).end('{"error":"not_found"}');
      return;
    }
    const [, runId] = m;
    let body = "";
    for await (const c of req) body += c;
    let receipt;
    try { receipt = JSON.parse(body); } catch {
      res.writeHead(400, { "content-type": "application/json" }).end('{"error":"request_invalid"}');
      return;
    }
    received.push({ runId, receipt });
    if (respond === "fail") {
      res.writeHead(500, { "content-type": "application/json" }).end('{"error":"internal_error"}');
      return;
    }
    // checkReceipt — the sink's exact verification.
    const r = receipt;
    const s = r.signature;
    const ok =
      r.schema === "ac-terminal-receipt/v1" && r.runId === runId &&
      typeof r.terminalState === "string" && typeof r.ts === "string" &&
      s?.alg === "ed25519" && typeof s.keyId === "string" && /^0x[0-9a-f]{128}$/.test(s.sig ?? "") &&
      edVerify(null, Buffer.from(sinkCanonicalJson({
        schema: r.schema, runId: r.runId, terminalState: r.terminalState, ts: r.ts,
        alg: s.alg, keyId: s.keyId,
      }), "utf8"), publicKey, Buffer.from(s.sig.slice(2), "hex"));
    if (!ok) {
      res.writeHead(400, { "content-type": "application/json" }).end('{"error":"receipt_invalid"}');
      return;
    }
    if (!heads.has(runId)) {
      heads.set(runId, { schema: "ac-run-head/v1", runId, seq: 0, final: true, closeCause: "receipt" });
    }
    res.writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ closed: true, head: heads.get(runId) }));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  return { url, received, heads, close: () => new Promise((r) => srv.close(r)) };
}

// --- config-booted contract server -------------------------------------------

async function bootConfig(extra = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "n4b8-close-"));
  const env = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_HOST_ROOTS: HOST_ROOTS_ENV,
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED_B64,
    CONTRACT_SERVER_KEY_ID: "contract-server-test",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY_DIGESTS.buyer},provider:${POLICY_DIGESTS.provider}`,
    CONTRACT_STATE_DIR: dir,
    TELEMETRY_CLOSE_BACKOFF_MS: "0,0",
    ...extra,
  };
  const cfg = loadContractConfig(env);
  assert.equal(cfg.kind, "ready", JSON.stringify(cfg));
  const handler = createContractHttpHandler({
    authenticate: cfg.authenticate,
    hostRoots: cfg.hostRoots,
    signer: cfg.signer,
    service: cfg.service,
  });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const baseUrl = `http://127.0.0.1:${srv.address().port}/contract/mcp`;
  const sessions = new Map();
  const callTool = async (token, name, args = {}) => {
    let sid = sessions.get(token);
    if (!sid) {
      const init = await fetch(baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
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
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    if (body.error !== undefined) return { rpcError: body.error };
    return body.result?.structuredContent ?? {};
  };
  return { cfg, callTool, close: () => { srv.close(); cfg.service.close(); } };
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

async function bindPair(env, sessionId) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await env.callTool("tb1", "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await env.callTool("tp1", "contract_bind", bindArgs(cert, "provider"));
  assert.equal(p.bound, true, `provider bind: ${JSON.stringify(p)}`);
  return b.runId;
}

async function waitFor(fn, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await new Promise((r) => setTimeout(r, 10));
  }
}

// --- tests ------------------------------------------------------------------

test("terminal run POSTs the signed receipt to TELEMETRY_CLOSE_URL and receipts it", async () => {
  const sink = await fakeSink();
  const env = await bootConfig({ TELEMETRY_CLOSE_URL: sink.url });
  try {
    const runId = await bindPair(env, "deadbeef-0001-4444-8888-000000000001");
    const withdrawn = await env.callTool("tb1", "contract_withdraw", { reason: "plans changed" });
    assert.equal(withdrawn.state, "withdrawn");

    // The close POST lands — exactly one, carrying a signature that verifies
    // under the contract server's published key.
    const delivered = await waitFor(() => sink.received.length === 1);
    assert.ok(delivered, "sink received the terminal receipt");
    const { runId: rid, receipt } = sink.received[0];
    assert.equal(rid, runId);
    assert.equal(receipt.schema, "ac-terminal-receipt/v1");
    assert.equal(receipt.terminalState, "no_agreement");
    assert.equal(receipt.signature.keyId, "contract-server-test");

    // contract_status surfaces the delivered close.
    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.terminalState, "no_agreement");
    assert.equal(st.telemetryClose.status, "delivered");
    assert.equal(st.telemetryClose.attempts, 1);

    // The delivery outcome is receipted onto the run chain — and the chain
    // still verifies end to end.
    const feed = env.cfg.service.receiptFeed(runId);
    const closeRcpt = feed.receipts.find((r) => r.tool === "telemetry_close");
    assert.ok(closeRcpt, "telemetry_close receipt on the run chain");
    assert.equal(closeRcpt.outcome, "telemetry_close_delivered");
    const verdict = verifyChain(feed.receipts, { "contract-server-test": configServerPubKey });
    assert.equal(verdict.ok, true);
  } finally {
    env.close();
    await sink.close();
  }
});

test("a permanently failed close is receipted and visible in contract_status", async () => {
  const sink = await fakeSink({ respond: "fail" });
  const env = await bootConfig({ TELEMETRY_CLOSE_URL: sink.url });
  try {
    const runId = await bindPair(env, "deadbeef-0002-4444-8888-000000000002");
    await env.callTool("tb1", "contract_withdraw", {});

    // backoff "0,0" → attempts 1,2,3 (1 + backoff.length) then failed.
    const failed = await waitFor(() => env.cfg.service.runFor(runId)?.telemetryClose?.status === "failed");
    assert.ok(failed, "close delivery eventually marked failed");
    assert.ok(sink.received.length >= 3, `retries happened (got ${sink.received.length})`);

    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.telemetryClose.status, "failed");
    assert.match(st.telemetryClose.lastError, /http 500/);

    const feed = env.cfg.service.receiptFeed(runId);
    const closeRcpt = feed.receipts.find((r) => r.tool === "telemetry_close");
    assert.equal(closeRcpt.outcome, "telemetry_close_failed");
    const verdict = verifyChain(feed.receipts, { "contract-server-test": configServerPubKey });
    assert.equal(verdict.ok, true);
  } finally {
    env.close();
    await sink.close();
  }
});

test("close delivery is idempotent — a replayed notify re-posts the same signed receipt", async () => {
  const sink = await fakeSink();
  try {
    const signer = { keyId: "contract-server-test", privateKey: configServerKey };
    const states = new Map();
    const emitter = createCloseEmitter({
      signer,
      closeUrl: sink.url,
      backoffMs: [0, 0],
      setState: (runId, st) => states.set(runId, st),
    });
    const fields = { runId: "run-9", terminalState: "settled", ts: "2026-09-01T00:00:00.000Z" };
    emitter.notify(fields);
    emitter.notify(fields); // in-flight notify is a no-op
    await emitter.flush();
    assert.equal(sink.received.length, 1);
    assert.equal(states.get("run-9").status, "delivered");
    // A post-completion replay is a fresh POST — the sink answers the same head.
    emitter.notify(fields);
    await emitter.flush();
    assert.equal(sink.received.length, 2);
    assert.deepEqual(sink.received[1].receipt, sink.received[0].receipt);
  } finally {
    await sink.close();
  }
});

test("mintTerminalReceipt matches the sink's ac-terminal-receipt/v1 verification", async () => {
  const sink = await fakeSink();
  try {
    const receipt = mintTerminalReceipt(
      { runId: "run-x", terminalState: "verification_failed", ts: "2026-09-01T00:00:00Z" },
      { keyId: "contract-server-test", privateKey: configServerKey },
    );
    const res = await fetch(`${sink.url}/v1/runs/run-x/close`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(receipt),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.closed, true);
    // Bad signature refused.
    const bad = { ...receipt, signature: { ...receipt.signature, sig: `0x${"0".repeat(128)}` } };
    const res2 = await fetch(`${sink.url}/v1/runs/run-y/close`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bad),
    });
    assert.equal(res2.status, 400);
  } finally {
    await sink.close();
  }
});

test("unset TELEMETRY_CLOSE_URL refuses at S/P, allowed at L; check-config surfaces it", () => {
  const base = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_HOST_ROOTS: HOST_ROOTS_ENV,
    CONTRACT_SERVER_ED25519_SEED: SERVER_SEED_B64,
    CONTRACT_SERVER_KEY_ID: "contract-server-test",
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z",
    CONTRACT_POLICY_DIGESTS: `buyer:${POLICY_DIGESTS.buyer},provider:${POLICY_DIGESTS.provider}`,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n4b8-close-cfg-")),
  };
  // L, unset → ready, no emitter.
  const l = loadContractConfig({ ...base });
  assert.equal(l.kind, "ready");
  assert.equal(l.telemetryCloseUrl, undefined);
  l.service.close();
  // S, unset → misconfigured.
  const s = loadContractConfig({
    ...base,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n4b8-close-cfg-")),
    CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
  });
  assert.equal(s.kind, "misconfigured");
  assert.match(s.reason, /TELEMETRY_CLOSE_URL/);
  // check-config reports the same verdict.
  const chk = checkConfig({
    ...base,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n4b8-close-cfg-")),
    CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
  });
  assert.equal(chk.exitCode, 1);
  assert.equal(chk.report.status, "misconfigured");
  assert.match(chk.report.reason, /TELEMETRY_CLOSE_URL/);
  // P, unset → misconfigured too.
  const p = loadContractConfig({
    ...base,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n4b8-close-cfg-")),
    CONTRACT_LEVEL: "P", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
  });
  assert.equal(p.kind, "misconfigured");
  // Malformed URL refuses at any level.
  const bad = loadContractConfig({
    ...base,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n4b8-close-cfg-")),
    TELEMETRY_CLOSE_URL: "ftp://nope",
  });
  assert.equal(bad.kind, "misconfigured");
  // S with the URL set and published (production) roots → check-config green,
  // and the report carries the close URL.
  const sOk = checkConfig({
    ...base,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n4b8-close-cfg-")),
    CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
    CONTRACT_HOST_ROOTS: "root-2026-08:da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8",
    TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083",
  });
  assert.equal(sOk.exitCode, 0, JSON.stringify(sOk.report));
  assert.equal(sOk.report.telemetryCloseUrl, "http://telemetry-sink:8083");
});
