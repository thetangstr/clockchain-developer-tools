import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign, createPublicKey } from "node:crypto";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { toolsListForRole, CONTRACT_SERVER_INSTRUCTIONS, guidanceDigests } from "../dist/agent-contract/tools-list.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { verifyCertificateEnvelope } from "../dist/agent-contract/certificate.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const ACCEPT = "application/json, text/event-stream";

// --- test-only certificate minter ------------------------------------------
// Reproduces the agent-handshake-v2 certificate envelope wire format
// (clockchain.host-session-key/v1 + agent-handshake-result/v2 + session-key
// signature) with freshly generated ed25519 keys — no real keys anywhere.
// Validity defaults to "now" so the freshness check accepts; pass explicit
// validUntilMs to exercise expiry.

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64"); // strip 12-byte SPKI prefix
}

function mintCertificate({ root, session, sessionId, outcome = "VERIFIED", issuedAtMs, validFromMs, validUntilMs }) {
  const t = Date.now();
  issuedAtMs ??= String(t);
  validFromMs ??= String(t - 60_000);
  validUntilMs ??= String(t + 10 * 60_000);
  const sessionKeyAddress = `0x${createHash("sha256").update(session.publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 40)}`;
  const counterKeyAddress = `0x${"9".repeat(40)}`;
  const certificate = {
    schema: "clockchain.host-session-key/v1",
    rootKid: "root-test",
    sessionId,
    repositorySha: "d".repeat(40),
    sessionPublicKey: rawPublicKeyBase64(session.publicKey),
    validFromMs,
    validUntilMs,
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
  const party = (sessionAddress, agentId, policyDigest, regBlock) => ({
    sessionKeyAddress: sessionAddress,
    policyDigest,
    erc8004: {
      agentId,
      chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
      registrationTx: `0x${"a".repeat(64)}`,
      registrationBlock: regBlock,
    },
  });
  const initiator = party(sessionKeyAddress, "9452", "a".repeat(64), "7000");
  const responder = party(counterKeyAddress, "9453", "b".repeat(64), "7001");
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
    issuedAtMs,
    outcome,
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

const rootA = generateKeyPairSync("ed25519");
const rootB = generateKeyPairSync("ed25519");
const sessionA = generateKeyPairSync("ed25519");
const sessionB = generateKeyPairSync("ed25519");
const sessionC = generateKeyPairSync("ed25519");
const SESSION_A = "aaaaaaaa-1111-4444-8888-aaaaaaaaaaaa";
const SESSION_B = "bbbbbbbb-2222-4444-8888-bbbbbbbbbbbb";
const SESSION_C = "cccccccc-3333-4444-8888-cccccccccccc";

const certA = mintCertificate({ root: rootA, session: sessionA, sessionId: SESSION_A });
const certB = mintCertificate({ root: rootA, session: sessionB, sessionId: SESSION_B });
const certC = mintCertificate({ root: rootA, session: sessionC, sessionId: SESSION_C });

const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootA.publicKey), "base64")).digest("hex") },
]);

// --- HTTP harness ------------------------------------------------------------
// token:role:keyId:agentId:side — agentId must match the certificate party on
// the claimed side (C2). Sessions mint agentId 9452 initiator / 9453 responder.
const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tb2:buyer:kb2:9452:initiator",
  "tb3:buyer:kb3:9452:initiator",
  "tb4:buyer:kb4:9452:initiator",
  "tp1:provider:kp1:9453:responder",
  "tp2:provider:kp2:9453:responder",
  "tp3:provider:kp3:9453:responder",
  "tpwrong:provider:kpw:9453:initiator", // right agentId, wrong side
  "tpsame:provider:kps:9452:initiator",  // provider claiming the initiator side
  "tev:buyer:kev:7777:initiator",       // not a party to any minted session
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const serverPublicB64 = rawPublicKeyBase64(serverKeys.publicKey);
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };

const stateDir = mkdtempSync(path.join(tmpdir(), "contract-bind-"));
let http;
let baseUrl;
let service;

const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

test.before(async () => {
  service = createContractService({
    hostRoots: HOST_ROOTS,
    signer: SIGNER,
    stateDir,
  });
  const handler = createContractHttpHandler({
    authenticate,
    hostRoots: HOST_ROOTS,
    signer: SIGNER,
    service,
  });
  http = createServer(handler);
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${http.address().port}/contract/mcp`;
});

test.after(() => new Promise((resolve) => http.close(resolve)));

async function rpc(method, params = {}, token = "tb1", url = baseUrl, extraHeaders = {}) {
  const headers = { "content-type": "application/json", accept: ACCEPT, ...extraHeaders };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await response.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  const body = JSON.parse(data ? data.slice(5) : text);
  return { status: response.status, body };
}

function bindArgs(certificate, suffix = "") {
  return {
    certificate,
    signerKey: { keyId: `signer-${suffix || "x"}`, publicKeyHex: `0x${"11".repeat(32)}` },
    approvalKey: { keyId: `approval-${suffix || "x"}`, publicKeyHex: `0x${"22".repeat(32)}` },
  };
}

// --- auth + surface shape ----------------------------------------------------

test("parseContractTokens maps 5-field entries to role+agentId+side principals", () => {
  const entries = parseContractTokens(TOKENS_RAW);
  const p = authenticate({ authorization: "Bearer tb1" });
  assert.deepEqual(p, { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" });
  assert.equal(authenticate({ authorization: "Bearer tp1" }).side, "responder");
  assert.equal(authenticate({ authorization: "Bearer nope" }), null);
});

test("the route requires a role-scoped bearer token", async () => {
  for (const token of [null, "nope", "constructor", "__proto__", "toString", "hasOwnProperty"]) {
    const list = await rpc("tools/list", {}, token);
    assert.equal(list.status, 401, String(token));
    const init = await rpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } }, token);
    assert.equal(init.status, 401, String(token));
    const call = await rpc("tools/call", { name: "contract_status", arguments: {} }, token);
    assert.equal(call.status, 401, String(token));
  }
});

test("tools/list serves the verbatim N4a role payload, matching guidanceDigests", async () => {
  const buyer = await rpc("tools/list");
  assert.equal(buyer.status, 200);
  assert.deepEqual(buyer.body.result, toolsListForRole("buyer"));
  assert.equal(canonicalDigest(buyer.body.result), guidanceDigests("buyer").toolsListDigest);
  const provider = await rpc("tools/list", {}, "tp1");
  assert.deepEqual(provider.body.result, toolsListForRole("provider"));
  assert.equal(canonicalDigest(provider.body.result), guidanceDigests("provider").toolsListDigest);
  assert.ok(toolsListForRole("provider").tools.some((t) => t.name === "catalog_quote"));
  assert.ok(!toolsListForRole("buyer").tools.some((t) => t.name === "catalog_quote"));
});

test("initialize returns the published server instructions", async () => {
  const res = await rpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } });
  assert.equal(res.body.result.instructions, CONTRACT_SERVER_INSTRUCTIONS);
});

// --- contract_bind -------------------------------------------------------------

test("both roles bind the same verified certificate; status advances to bound", async () => {
  const b = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certA, "b1") });
  assert.equal(b.status, 200);
  const sc = b.body.result.structuredContent;
  assert.equal(sc.bound, true);
  assert.equal(sc.runId, SESSION_A);
  assert.equal(sc.bindAssurance, "agentId-pinned-token");
  assert.equal(sc.side, "initiator");
  const p = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certA, "p1") }, "tp1");
  assert.equal(p.body.result.structuredContent.bound, true);
  const s = await rpc("tools/call", { name: "contract_status", arguments: {} });
  assert.equal(s.body.result.structuredContent.stage, "bound");
  // The run records {buyer: side/agentId, provider: side/agentId}.
  assert.deepEqual(service.runFor(SESSION_A).bound.buyer, {
    principalKeyId: "kb1", agentId: "9452", side: "initiator",
    signerKey: bindArgs(certA, "b1").signerKey, approvalKey: bindArgs(certA, "b1").approvalKey,
    boundAt: service.runFor(SESSION_A).bound.buyer.boundAt,
  });
});

test("a certificate from a session the principal is not a party to is refused", async () => {
  const res = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certB) }, "tev");
  assert.equal(res.body.result.structuredContent.error, "CERTIFICATE_INVALID");
});

test("the wrong side is refused", async () => {
  const res = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certB) }, "tpwrong");
  assert.equal(res.body.result.structuredContent.error, "CERTIFICATE_INVALID");
});

test("two roles on the same side are refused", async () => {
  const b = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certB, "b2") }, "tb2");
  assert.equal(b.body.result.structuredContent.bound, true);
  const p = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certB) }, "tpsame");
  assert.equal(p.body.result.structuredContent.error, "ROLE_REFUSED");
  const tp = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certB, "p2") }, "tp2");
  assert.equal(tp.body.result.structuredContent.bound, true);
});

test("a second principal replaying a taken seat is SEAT_TAKEN", async () => {
  // tb1 holds the buyer seat on SESSION_A; tb3 replays with a fresh cert-pair.
  const res = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certA, "squat") }, "tb3");
  assert.equal(res.body.result.structuredContent.error, "SEAT_TAKEN");
});

test("idempotent rebind requires identical {certDigest, signerKey}", async () => {
  const same = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certA, "b1") });
  assert.equal(same.body.result.structuredContent.bound, true);
  const drifted = await rpc("tools/call", {
    name: "contract_bind",
    arguments: { ...bindArgs(certA, "b1"), signerKey: { keyId: "signer-b1", publicKeyHex: `0x${"33".repeat(32)}` } },
  });
  assert.equal(drifted.body.result.structuredContent.error, "STATE_REFUSED");
});

test("contract_bind refuses certificates that fail verification", async () => {
  for (const cert of [
    { garbage: true },
    mintCertificate({ root: rootB, session: generateKeyPairSync("ed25519"), sessionId: "44444444-5555-4444-8888-444444444444" }),
    mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: "55555555-6666-4444-8888-555555555555", outcome: "FAILED" }),
  ]) {
    const res = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(cert) }, "tb4");
    assert.equal(res.body.result.structuredContent.error, "CERTIFICATE_INVALID");
  }
});

test("an expired certificate is refused", async () => {
  const expired = mintCertificate({
    root: rootA,
    session: generateKeyPairSync("ed25519"),
    sessionId: "66666666-7777-4444-8888-666666666666",
    issuedAtMs: String(Date.now() - 3600_000),
    validFromMs: String(Date.now() - 3600_000),
    validUntilMs: String(Date.now() - 60 * 60_000), // 1h ago, well past the 10min grace
  });
  const res = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(expired) }, "tb4");
  assert.equal(res.body.result.structuredContent.error, "CERTIFICATE_INVALID");
});

test("a malleated envelope maps to the same run identity; genuine parties still bind", async () => {
  const mal = JSON.parse(JSON.stringify(certC));
  mal.signer.keyId = "attacker"; // unsigned cosmetic field — must not change identity
  const b = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(mal, "b3") }, "tb3");
  assert.equal(b.body.result.structuredContent.bound, true);
  assert.equal(b.body.result.structuredContent.runId, SESSION_C);
  const p = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(certC, "p3") }, "tp3");
  assert.equal(p.body.result.structuredContent.bound, true);
  // Identity is sessionId + canonicalDigest(result) — one run, digest of SIGNED content.
  assert.equal(service.runFor(SESSION_C).resultDigest, canonicalDigest(certC.result));
});

test("a non-canonical base64 signature is refused even when it decodes identically", async () => {
  const mal = JSON.parse(JSON.stringify(certC));
  const sig = mal.signer.signature; // 86-char b64, '==' padding → last char has 4 free bits
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const i = alphabet.indexOf(sig[85]);
  mal.signer.signature = sig.slice(0, 85) + alphabet[(i & ~15) | ((i + 1) & 15)] + "==";
  assert.notEqual(mal.signer.signature, certC.signer.signature);
  const res = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(mal) }, "tb4");
  assert.equal(res.body.result.structuredContent.error, "CERTIFICATE_INVALID");
});

test("a refused bind leaves no run", async () => {
  const ghost = mintCertificate({ root: rootB, session: sessionB, sessionId: "77777777-8888-4444-8888-777777777777" });
  const res = await rpc("tools/call", { name: "contract_bind", arguments: bindArgs(ghost) }, "tb4");
  assert.equal(res.body.result.structuredContent.error, "CERTIFICATE_INVALID");
  assert.equal(service.runFor("77777777-8888-4444-8888-777777777777"), undefined);
});

test("used sessionIds are durable: a restart cannot start a second genesis", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "contract-restart-"));
  const certR = mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: "88888888-9999-4444-8888-888888888888" });
  const args = bindArgs(certR, "r");
  const s1 = createContractService({ hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: dir });
  const first = s1.bind(
    { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" },
    args,
    { argsDigest: canonicalDigest(args), serverNonce: `0x${"ab".repeat(16)}`, tool: "contract_bind" },
  );
  assert.equal(first.ok, true);
  // Simulated restart: fresh service, same stateDir. Same sessionId must never
  // mint a second genesis — refuse (no live run to be idempotent against).
  const s2 = createContractService({ hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: dir });
  const replay = s2.bind(
    { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" },
    args,
    { argsDigest: canonicalDigest(args), serverNonce: `0x${"cd".repeat(16)}`, tool: "contract_bind" },
  );
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "STATE_REFUSED");
  assert.equal(s2.runFor("88888888-9999-4444-8888-888888888888"), undefined);
});

test("an 80-char XFF cannot leave a bound run with zero receipts", async () => {
  const svc = createContractService({ hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: mkdtempSync(path.join(tmpdir(), "c-")) });
  const handler = createContractHttpHandler({ authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: svc, trustProxy: true });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const url = `http://127.0.0.1:${srv.address().port}/contract/mcp`;
    const certX = mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: "99999999-aaaa-4444-8888-999999999999" });
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tb4", "x-forwarded-for": "1".repeat(80) },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "contract_bind", arguments: bindArgs(certX, "xff") } }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    const run = svc.runFor("99999999-aaaa-4444-8888-999999999999");
    if (body.result?.structuredContent?.bound) {
      assert.ok(run.receipts.length >= 1, "committed bind must carry its receipt");
      assert.ok(run.receipts.at(-1).sourceIp.length <= 64);
      assert.equal(run.receipts.at(-1).sourceIp, "1".repeat(64));
    } else {
      assert.equal(run, undefined, "no receipt, no commit");
    }
  } finally {
    await new Promise((r) => srv.close(r));
  }
});

test("client XFF is not trusted by default; only the last hop with trust on", async () => {
  const mkSvc = () => createContractService({ hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: mkdtempSync(path.join(tmpdir(), "c-")) });
  for (const [trust, sid, want] of [
    [false, "aaaaaaaa-1111-4444-9999-aaaaaaaaaaa1", "127.0.0.1"],
    [true, "aaaaaaaa-1111-4444-9999-aaaaaaaaaaa2", "203.0.113.9"],
  ]) {
    const svc = mkSvc();
    const handler = createContractHttpHandler({ authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: svc, trustProxy: trust });
    const srv = createServer(handler);
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${srv.address().port}/contract/mcp`;
      const certX = mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: sid });
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tb4", "x-forwarded-for": "10.0.0.1, 203.0.113.9" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "contract_bind", arguments: bindArgs(certX, "xff2") } }),
      });
      const text = await res.text();
      const data = text.split("\n").find((l) => l.startsWith("data:"));
      const body = JSON.parse(data ? data.slice(5) : text);
      assert.equal(body.result.structuredContent.bound, true);
      assert.equal(svc.runFor(sid).receipts.at(-1).sourceIp, want);
    } finally {
      await new Promise((r) => srv.close(r));
    }
  }
});

// --- scoping + receipts --------------------------------------------------------

test("role scoping on tools/call; unimplemented tools refuse cleanly", async () => {
  const res = await rpc("tools/call", { name: "catalog_quote", arguments: { query: {} } });
  assert.equal(res.body.result.structuredContent.error, "ROLE_REFUSED");
  const missing = await rpc("tools/call", { name: "not_a_tool", arguments: {} });
  assert.equal(missing.body.result.structuredContent.error, "NOT_FOUND");
  const unimpl = await rpc("tools/call", { name: "mandate_prepare", arguments: { mandate: {} } });
  assert.equal(unimpl.body.result.structuredContent.error, "CONTRACT_UNAVAILABLE");
});

test("malformed call arguments fail as JSON-RPC invalid params, not a refusal", async () => {
  const res = await rpc("tools/call", { name: "contract_bind", arguments: { certificate: "junk" } });
  assert.equal(res.body.error.code, -32602);
});

test("an unbound caller reports the rendezvous stage", async () => {
  const res = await rpc("tools/call", { name: "contract_status", arguments: {} }, "tev");
  assert.equal(res.body.result.structuredContent.stage, "rendezvous");
});

test("every bound call appends a verifiable receipt to the run chain", async () => {
  const run = service.runFor(SESSION_A);
  assert.ok(run.receipts.length >= 3, `expected receipts, got ${run.receipts.length}`);
  const verdict = verifyChain(run.receipts, { [SIGNER.keyId]: serverKeys.publicKey });
  assert.equal(verdict.ok, true, JSON.stringify(verdict));
  const bindReceipt = run.receipts.find((r) => r.tool === "contract_bind");
  assert.equal(bindReceipt.bindAssurance, "agentId-pinned-token");
  assert.equal(run.receipts[0].prevHash, `0x${"0".repeat(64)}`);
  const s = await rpc("tools/call", { name: "contract_status", arguments: {} });
  const nonce = s.body.result.structuredContent.serverNonce;
  const last = run.receipts.at(-1);
  assert.equal(last.serverNonce, nonce);
  assert.equal(last.tool, "contract_status");
});

test("run and receipt caps reject when full", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "c-"));
  const svc = createContractService({ hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: dir, maxRuns: 1 });
  const args = bindArgs(certB, "cap");
  const ok = svc.bind(
    { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" },
    args,
    { argsDigest: canonicalDigest(args), serverNonce: `0x${"ab".repeat(16)}`, tool: "contract_bind" },
  );
  assert.equal(ok.ok, true);
  const certD = mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: "bbbbbbbb-1111-4444-8888-bbbbbbbbbbb1" });
  const args2 = bindArgs(certD);
  const full = svc.bind(
    { keyId: "kb9", role: "buyer", agentId: "9452", side: "initiator" },
    args2,
    { argsDigest: canonicalDigest(args2), serverNonce: `0x${"cd".repeat(16)}`, tool: "contract_bind" },
  );
  assert.equal(full.ok, false);
  assert.equal(full.code, "RATE_LIMITED");
});

test("a principal can bind a new run once the previous run has ended (TTL)", async () => {
  let t = Date.now();
  const now = () => t;
  const dir = mkdtempSync(path.join(tmpdir(), "c-"));
  const svc = createContractService({ hostRoots: HOST_ROOTS, signer: SIGNER, stateDir: dir, now });
  const me = { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" };
  const cert1 = mintCertificate({ root: rootA, session: generateKeyPairSync("ed25519"), sessionId: "cccccccc-1111-4444-8888-ccccccccccc1" });
  const a1 = bindArgs(cert1, "e1");
  assert.equal(svc.bind(me, a1, { argsDigest: canonicalDigest(a1), serverNonce: `0x${"ab".repeat(16)}`, tool: "contract_bind" }).ok, true);
  t += 25 * 3600_000; // past the 24h run TTL
  const cert2 = mintCertificate({
    root: rootA,
    session: generateKeyPairSync("ed25519"),
    sessionId: "cccccccc-1111-4444-8888-ccccccccccc2",
    issuedAtMs: String(t - 60_000),
    validFromMs: String(t - 120_000),
    validUntilMs: String(t + 10 * 60_000), // fresh under the mocked clock
  });
  const a2 = bindArgs(cert2, "e2");
  const reb = svc.bind(me, a2, { argsDigest: canonicalDigest(a2), serverNonce: `0x${"ef".repeat(16)}`, tool: "contract_bind" });
  assert.equal(reb.ok, true);
  assert.equal(reb.runId, "cccccccc-1111-4444-8888-ccccccccccc2");
});

test("verifyCertificateEnvelope accepts the canonical fixture with its root pinned", () => {
  const fixture = JSON.parse(readFileSync(path.join(FIXTURES, "agent-handshake-v2-canonical.json"), "utf8"));
  const envelope = fixture.objects.certificateEnvelope;
  const rootPub = envelope.hostSessionKeyCertificate.rootSignature.publicKey;
  const fp = createHash("sha256").update(Buffer.from(rootPub, "base64")).digest("hex");
  const verdict = verifyCertificateEnvelope(envelope, {
    hostRoots: [{ kid: "root-2026-08", fingerprint: fp }],
    now: () => 1786337300000, // inside the fixture's validity window
  });
  assert.equal(verdict.ok, true, JSON.stringify(verdict));
  assert.equal(verdict.sessionId, "22222222-3333-4444-8555-666666666666");
  assert.equal(verdict.resultDigest, canonicalDigest(envelope.result));
});
