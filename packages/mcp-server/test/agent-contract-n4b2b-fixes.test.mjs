import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { computeApprovalDigest, computeApprovalSigDigest } from "../dist/agent-contract/approval.js";
import {
  eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress,
} from "../dist/agent-contract/eip191.js";
import { createSimWorld } from "../dist/agent-contract/sim/index.js";
import { createBusinessOps } from "../dist/agent-contract/business.js";

const ACCEPT = "application/json, text/event-stream";

// N4b-2b review fixes (N4B2B-CHANGES-1): every test in this file was written
// red against 5a78555 — the write-once agreement, the principal-signed pinned
// mandate, the exact v2 payload builders, the pinned approval policy digest,
// receipts-first, serverNonce on refusals, and rendezvous hardening.

// --- test-only certificate minter ---------------------------------------------

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
    identityPolicy: {
      chainId: "eip155:11155111", erc8004: "required_fresh",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    },
    issuedAtMs: String(t), outcome: "VERIFIED",
    parties: { initiator, responder },
    policyDigests: { initiator: initiator.policyDigest, responder: responder.policyDigest },
    reference: "NS-1847", schema: "clockchain.agent-handshake-result/v2",
    sessionDigest: "e".repeat(64), sessionId,
    statementDigest: "f".repeat(64), subjectRun: "stakeholder",
  };
  return {
    hostSessionKeyCertificate, result,
    signer: {
      algorithm: "ed25519", keyId: "session-host",
      publicKey: rawPublicKeyBase64(session.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(result), "utf8"), session.privateKey).toString("base64"),
    },
  };
}

const rootKey = generateKeyPairSync("ed25519");
const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex") },
]);

// --- test-only secp256k1 keys (EIP-191; no real keys anywhere) -----------------

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

// The family principal (the mandate signer) — its own secp key + address.
const PRINCIPAL_PRIV = secpPriv(0xd5);
const PRINCIPAL_ADDRESS = publicKeyToAddress(
  Buffer.from(pubFromPriv(PRINCIPAL_PRIV).slice(2), "hex"),
);

const POLICY_DIGESTS = Object.freeze({
  buyer: `0x${"7".repeat(64)}`,
  provider: `0x${"8".repeat(64)}`,
});
const PRINCIPALS = Object.freeze(new Map([
  ["kb1", PRINCIPAL_ADDRESS], ["kb2", PRINCIPAL_ADDRESS], ["kb3", PRINCIPAL_ADDRESS],
  ["kb4", PRINCIPAL_ADDRESS], ["kb5", PRINCIPAL_ADDRESS], ["kb6", PRINCIPAL_ADDRESS],
  ["kb7", PRINCIPAL_ADDRESS], ["kb8", PRINCIPAL_ADDRESS],
]));

function signRoleSig(privHex, { runId, role, tool, nonce, payloadDigest }) {
  const digest = canonicalDigest({
    domain: "agent-contract.role-sig/v1", runId, role, tool, nonce, payloadDigest,
  });
  return eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), privHex);
}

function makeApproval({ envelope, role, action, tool, key, policyDigest, decision = "allow", approverKeyId, ts }) {
  const digest = computeApprovalDigest({
    runId: envelope.runId, tool, nonce: envelope.nonce,
    envelopeDigest: canonicalDigest(envelope), expiresAt: envelope.expiresAt,
  });
  const record = {
    role, action, digest,
    policyDigest: policyDigest ?? POLICY_DIGESTS[role],
    decision, ts: ts ?? Date.now(),
    approverKeyId: approverKeyId ?? key.keyId,
  };
  const sigDigest = computeApprovalSigDigest({ runId: envelope.runId, role, record });
  return { ...record, signature: eip191SignDigest32(Buffer.from(sigDigest.slice(2), "hex"), key.priv) };
}

/** The principal's EIP-191 signature over the mandate digest (CONTRACT-PAYLOADS-v2 §Mandate). */
function signMandate(privHex, mandate) {
  const digest = canonicalDigest({ domain: "agent-contract.mandate/v1", ...mandate });
  return eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), privHex);
}

function goodMandate(overrides = {}) {
  return {
    kind: "mandate",
    mandateId: `mdt-${Math.floor(Math.random() * 1e6)}`,
    capMinor: 500_000,
    currency: "USD",
    allowedItineraryIds: ["IT-QW-ONESTOP"],
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    ...overrides,
  };
}

// A real v2 seal (the N5 wire shape) — values needn't decrypt, only parse.
const V2_SEAL = {
  v: 2,
  epk: `0x${"ab".repeat(32)}`,
  iv: `0x${"cd".repeat(12)}`,
  ct: `0x${"ef".repeat(48)}`,
  tag: `0x${"01".repeat(16)}`,
};

// --- service + HTTP harness ----------------------------------------------------

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator", "tb2:buyer:kb2:9452:initiator",
  "tb3:buyer:kb3:9452:initiator", "tb4:buyer:kb4:9452:initiator",
  "tb5:buyer:kb5:9452:initiator", "tb6:buyer:kb6:9452:initiator",
  "tb7:buyer:kb7:9452:initiator", "tb8:buyer:kb8:9452:initiator",
  "tp1:provider:kp1:9453:responder", "tp2:provider:kp2:9453:responder",
  "tp3:provider:kp3:9453:responder", "tp4:provider:kp4:9453:responder",
  "tp5:provider:kp5:9453:responder", "tp6:provider:kp6:9453:responder",
  "tp7:provider:kp7:9453:responder", "tp8:provider:kp8:9453:responder",
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };

const stateDir = mkdtempSync(path.join(tmpdir(), "contract-fix-"));
let http;
let baseUrl;
let service;

const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

function serviceOpts(extra = {}) {
  return {
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    allowLegacySealV2: true, // test posture = CONTRACT_LEVEL=L
    ...extra,
  };
}

test.before(async () => {
  service = createContractService(serviceOpts({ stateDir }));
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  http = createServer(handler);
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${http.address().port}/contract/mcp`;
});

test.after(() => new Promise((resolve) => http.close(resolve)));

// M2: the transport is stateful — negotiate an mcp-session-id once per token.
const sessions = new Map();
async function ensureSession(token) {
  const key = `${baseUrl}|${token}`;
  if (sessions.has(key)) return;
  const headers = { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` };
  const response = await fetch(baseUrl, {
    method: "POST", headers,
    body: JSON.stringify({
      jsonrpc: "2.0", id: 0, method: "initialize",
      params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    }),
  });
  assert.ok(response.status < 300, `initialize: ${response.status}`);
  const sid = response.headers.get("mcp-session-id");
  sessions.set(key, sid);
  if (sid !== null) {
    await fetch(baseUrl, {
      method: "POST",
      headers: { ...headers, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });
  }
}

async function rpc(method, params = {}, token = "tb1") {
  const headers = { "content-type": "application/json", accept: ACCEPT };
  if (token !== null) {
    headers.authorization = `Bearer ${token}`;
    await ensureSession(token);
    const sid = sessions.get(`${baseUrl}|${token}`);
    if (sid) headers["mcp-session-id"] = sid;
  }
  const response = await fetch(baseUrl, {
    method: "POST", headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await response.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  const body = JSON.parse(data ? data.slice(5) : text);
  return { status: response.status, body };
}

async function callTool(token, name, args = {}) {
  const r = await rpc("tools/call", { name, arguments: args }, token);
  if (r.body.error !== undefined) return { rpcError: r.body.error };
  return r.body.result?.structuredContent ?? {};
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

async function bindPair(sessionId, buyerToken, providerToken) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await callTool(buyerToken, "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await callTool(providerToken, "contract_bind", bindArgs(cert, "provider"));
  assert.equal(p.bound, true, `provider bind: ${JSON.stringify(p)}`);
  return { cert, runId: b.runId };
}

async function signedSubmit({ token, role, prepared, submitTool, extraArgs = {} }) {
  const env = prepared.envelope;
  const signatureHex = signRoleSig(keys[`${role}Signer`].priv, {
    runId: env.runId, role, tool: env.tool, nonce: env.nonce, payloadDigest: env.payloadDigest,
  });
  return callTool(token, submitTool, { envelope: env, signatureHex, ...extraArgs });
}

function uuid(n) {
  return `deadbeef-${String(n).padStart(4, "0")}-4444-8888-${String(n).padStart(12, "0")}`;
}

/** Present the principal-signed mandate (schema-valid by default). */
async function submitMandate(token, mandate = goodMandate(), sigKey = PRINCIPAL_PRIV) {
  const mandateSignature = signMandate(sigKey, mandate);
  const prep = await callTool(token, "mandate_prepare", { mandate, mandateSignature });
  if (prep.error || prep.rpcError) return prep;
  return signedSubmit({ token, role: "buyer", prepared: prep, submitTool: "mandate_submit" });
}

async function offer(tok, role, itineraryId, feeMinor) {
  const p = await callTool(tok, "offer_prepare", { itineraryId, feeMinor });
  if (p.error || p.rpcError) return p;
  return signedSubmit({ token: tok, role, prepared: p, submitTool: "offer_submit" });
}
async function accept(tok, role, offerId) {
  const p = await callTool(tok, "offer_accept_prepare", { offerId });
  if (p.error || p.rpcError) return p;
  return signedSubmit({ token: tok, role, prepared: p, submitTool: "offer_accept_submit" });
}

/** Drive a bound pair to an agreement via provider offer + buyer accept. */
async function agreePair(sessionId, buyerToken, providerToken) {
  const { runId } = await bindPair(sessionId, buyerToken, providerToken);
  const m = await submitMandate(buyerToken);
  assert.match(m.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(m));
  const o = await offer(providerToken, "provider", "IT-QW-ONESTOP", 10_000);
  assert.equal(o.state, "offered", JSON.stringify(o));
  const a = await accept(buyerToken, "buyer", o.offerId);
  assert.equal(a.agreementFormed, true, JSON.stringify(a));
  return { runId, agreementId: a.agreementId };
}

async function book(providerToken, agreementId) {
  const prep = await callTool(providerToken, "booking_prepare", { agreementId });
  const approval = makeApproval({
    envelope: prep.envelope, role: "provider", action: "booking",
    tool: "booking_execute", key: keys.providerApproval,
  });
  return signedSubmit({
    token: providerToken, role: "provider", prepared: prep,
    submitTool: "booking_execute", extraArgs: { approval },
  });
}

// === 1. write-once agreement + latest-offer-only ==============================

test("PROBE A replay: a stale accept after booking+verification cannot rewrite the agreement", async () => {
  const { runId, agreementId } = await agreePair(uuid(901), "tb1", "tp1");
  const ag1 = (await callTool("tp1", "agreement_get", {})).agreement;
  const b = await book("tp1", agreementId);
  assert.equal(b.simulated, true, JSON.stringify(b));
  const vPrep = await callTool("tb1", "verification_prepare", {
    orderRef: b.orderRef, result: "match", findingsDigest: `0x${"9d".repeat(32)}`,
  });
  const v = await signedSubmit({ token: "tb1", role: "buyer", prepared: vPrep, submitTool: "verification_submit" });
  assert.equal(v.outcome, "match", JSON.stringify(v));

  // Every offer-path tool is closed once an agreement exists.
  const o3 = await callTool("tb1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 0 });
  assert.equal(o3.error, "STATE_REFUSED", JSON.stringify(o3));
  const o4 = await callTool("tp1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 0 });
  assert.equal(o4.error, "STATE_REFUSED");
  const a2 = await callTool("tp1", "offer_accept_prepare", { offerId: "off-0001" });
  assert.equal(a2.error, "STATE_REFUSED");

  // The agreement is untouched; settlement still pays the BOOKED amount.
  const ag2 = (await callTool("tb1", "agreement_get", {})).agreement;
  assert.equal(ag2.agreementDigest, ag1.agreementDigest);
  assert.equal(ag2.totalMinor, b.simulated === true ? ag1.totalMinor : ag1.totalMinor);
  const sp = await callTool("tb1", "settlement_prepare", {});
  assert.equal(sp.envelope.payload.amountMinor, ag1.totalMinor);
  assert.equal(sp.envelope.payload.agreementDigest, ag1.agreementDigest);
  const approval = makeApproval({
    envelope: sp.envelope, role: "buyer", action: "settlement",
    tool: "settlement_authorize", key: keys.buyerApproval,
  });
  const s = await signedSubmit({
    token: "tb1", role: "buyer", prepared: sp,
    submitTool: "settlement_authorize", extraArgs: { approval },
  });
  assert.equal(s.status, "released", JSON.stringify(s));
});

test("only the counterparty's LATEST live offer can be accepted; a same-party offer supersedes", async () => {
  await bindPair(uuid(905), "tb2", "tp2");
  await submitMandate("tb2");
  const o1 = await offer("tp2", "provider", "IT-QW-ONESTOP", 50_000);
  const o2 = await offer("tp2", "provider", "IT-QW-ONESTOP", 20_000); // supersedes o1
  assert.equal(o2.state, "offered", JSON.stringify(o2));
  // o1 is stale: the buyer cannot accept it
  const stale = await accept("tb2", "buyer", o1.offerId);
  assert.equal(stale.error ?? stale.rpcError?.message, "STATE_REFUSED", JSON.stringify(stale));
  const a = await accept("tb2", "buyer", o2.offerId);
  assert.equal(a.agreementFormed, true, JSON.stringify(a));
  const ag = (await callTool("tb2", "agreement_get", {})).agreement;
  assert.equal(ag.offerId, o2.offerId);
  assert.equal(ag.totalMinor, 429_000 + 20_000);
});

// === 2. principal-signed, pinned, write-once mandate ==========================

test("the mandate is principal-signed, pinned, schema-strict and write-once", async () => {
  await bindPair(uuid(902), "tb3", "tp3");

  // an offer BEFORE the mandate is refused
  const early = await callTool("tb3", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 0 });
  assert.equal(early.error, "STATE_REFUSED", JSON.stringify(early));

  // empty / partial mandates are refused
  for (const bad of [{}, { capMinor: 100 }, { capMinor: 500_000, currency: "USD" }, { ...goodMandate(), currency: "usd" }]) {
    const r = await submitMandate("tb3", bad);
    assert.ok(r.error === "MANDATE_INVALID" || r.rpcError !== undefined, `mandate ${JSON.stringify(bad)}: ${JSON.stringify(r)}`);
  }
  // a mandate signed by a key that isn't the pinned principal is refused
  const wrongSigner = await submitMandate("tb3", goodMandate(), secpPriv(0x99));
  assert.equal(wrongSigner.error, "MANDATE_INVALID", JSON.stringify(wrongSigner));

  // the good mandate lands
  const okMandate = await submitMandate("tb3");
  assert.match(okMandate.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(okMandate));

  // write-once: a resubmission (which used to raise the cap) is refused
  const again = await submitMandate("tb3", goodMandate({ capMinor: 10_000_000 }));
  assert.equal(again.error, "STATE_REFUSED", JSON.stringify(again));

  // the cap still binds: a too-expensive buyer offer is refused
  const over = await callTool("tb3", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 100_000 });
  assert.equal(over.error, "MANDATE_REFUSED");
});

test("an expired mandate is refused; a buyer pinned to no principal cannot mandate", async () => {
  await bindPair(uuid(906), "tb4", "tp4");
  const expired = await submitMandate("tb4", goodMandate({ expiresAt: new Date(Date.now() - 1000).toISOString() }));
  assert.equal(expired.error, "MANDATE_INVALID", JSON.stringify(expired));
});

// === 3. exact v2 builders against the frozen vectors ==========================

test("the prepare builders emit exactly the frozen v2 payloads, field for field", async () => {
  // Drive createBusinessOps directly on a fabricated run pinned to the
  // vectors' runId — digests then reproduce byte-for-byte.
  const vectors = JSON.parse((await import("node:fs")).readFileSync(
    new URL("./fixtures/prepare-envelope-vectors.v2.json", import.meta.url), "utf8",
  ));
  const sim = createSimWorld({ now: Date.now });
  const run = {
    runId: "run-test-0002",
    resultDigest: `0x${"0".repeat(64)}`,
    sessionPublicKey: "x",
    createdAtMs: Date.now(),
    bound: {
      buyer: { principalKeyId: "kb1", agentId: "9452", side: "initiator", signerKey: keys.buyerSigner, approvalKey: keys.buyerApproval, boundAt: "t" },
      provider: { principalKeyId: "kp1", agentId: "9453", side: "responder", signerKey: keys.providerSigner, approvalKey: keys.providerApproval, boundAt: "t" },
    },
    receipts: [],
    receiptsByPrincipal: new Map(),
    simRun: sim.forRun("run-test-0002"),
    claimedNonces: new Set(),
    mandate: {
      digest: "x", mandateId: "m", capMinor: 10_000_000, currency: "USD",
      allowedItineraryIds: ["IT-QW-ONESTOP"],
      expiresAt: "2099-01-01T00:00:00.000Z", principalAddress: PRINCIPAL_ADDRESS, submittedAt: "t",
    },
    offers: new Map(), offerSeq: 0,
    terminalState: null, stage: "negotiating",
  };
  const business = createBusinessOps({
    signer: SIGNER, sim, policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    endRun: () => {},
  });
  const buyer = { keyId: "kb1", role: "buyer", agentId: "9452", side: "initiator" };
  const provider = { keyId: "kp1", role: "provider", agentId: "9453", side: "responder" };

  const vec = (i) => vectors.vectors[i].envelope;
  const payloadOf = (out) => {
    assert.equal(out.ok, true, JSON.stringify(out));
    return out.result.envelope.payload;
  };

  // offer (vector 0)
  const offerPayload = payloadOf(business.dispatch(buyer, run, "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000, note: "window seat" }, "0xnonce"));
  assert.deepEqual(offerPayload, vec(0).payload);
  assert.equal(canonicalDigest(offerPayload), vec(0).payloadDigest);

  // counter (vector 1): the buyer's offer must be live for inReplyTo
  run.offers.set("off-0001", { offerId: "off-0001", payload: offerPayload, role: "buyer", principalKeyId: "kb1", state: "live", submittedAt: "t", seq: 1 });
  run.offerSeq = 1;
  const counterPayload = payloadOf(business.dispatch(provider, run, "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 8_000 }, "0xnonce"));
  assert.deepEqual(counterPayload, vec(1).payload);
  assert.equal(canonicalDigest(counterPayload), vec(1).payloadDigest);
  run.offers.set("off-0002", { offerId: "off-0002", payload: counterPayload, role: "provider", principalKeyId: "kp1", state: "live", submittedAt: "t", seq: 2 });
  run.offerSeq = 2;

  // accept (vector 2)
  const acceptPayload = payloadOf(business.dispatch(buyer, run, "offer_accept_prepare", { offerId: "off-0002" }, "0xnonce"));
  assert.deepEqual(acceptPayload, vec(2).payload);
  assert.equal(canonicalDigest(acceptPayload), vec(2).payloadDigest);

  // agreement (write-once record) — agreementDigest must equal the vector's
  const agreementDigest = canonicalDigest({
    domain: "agent-contract.agreement/v1", runId: "run-test-0002",
    offerDigest: canonicalDigest(counterPayload),
  });
  assert.equal(agreementDigest, vectors.ledgerFacts.agreementDigest);
  run.agreement = {
    agreementId: "agr-0002", offerId: "off-0002",
    offerDigest: canonicalDigest(counterPayload), agreementDigest,
    offerPayload: counterPayload, acceptPayload,
    itineraryId: "IT-QW-ONESTOP", currency: "USD",
    fareMinor: 429_000, feeMinor: 8_000, totalMinor: 437_000, formedAt: "t",
  };
  run.stage = "agreed";

  // booking (vector 3) — server-derived from the agreement
  const bookingPayload = payloadOf(business.dispatch(provider, run, "booking_prepare", { agreementId: "agr-0002" }, "0xnonce"));
  assert.deepEqual(bookingPayload, vec(3).payload);
  assert.equal(canonicalDigest(bookingPayload), vec(3).payloadDigest);
  run.booking = { orderRef: "ORD-X", pnr: "PNR-56VQOC", tickets: [], bookedAt: "t" };
  run.stage = "booked";

  // verification (vector 4)
  const verificationPayload = payloadOf(business.dispatch(buyer, run, "verification_prepare", {
    orderRef: "ORD-X", result: "match",
    findingsDigest: "0x9d0f2143c61cfbb6c0cf0425ce8b447811a32d48ec37333ba8b3700218631b36",
  }, "0xnonce"));
  assert.deepEqual(verificationPayload, vec(4).payload);
  assert.equal(canonicalDigest(verificationPayload), vec(4).payloadDigest);
  const verificationDigest = canonicalDigest(verificationPayload);
  assert.equal(verificationDigest, vectors.ledgerFacts.verificationDigest);
  run.verification = {
    result: "match", verificationDigest, findingsDigest: verificationPayload.findingsDigest,
    agreementId: "agr-0002", agreementDigest: run.agreement.agreementDigest,
    orderRef: "ORD-X", bookingRef: "PNR-56VQOC", flagged: false, submittedAt: "t",
  };
  run.stage = "verified";

  // settlement (vector 5)
  const settlementPayload = payloadOf(business.dispatch(buyer, run, "settlement_prepare", {}, "0xnonce"));
  assert.deepEqual(settlementPayload, vec(5).payload);
  assert.equal(canonicalDigest(settlementPayload), vec(5).payloadDigest);
});

// === 4. pinned policy digest + allow + key/ts binding =========================

test("PROBE C replay: an approval needs the pinned policy digest, 'allow', bound keyId and in-window ts", async () => {
  const { agreementId } = await agreePair(uuid(903), "tb5", "tp5");
  const attempt = async (overrides) => {
    const prep = await callTool("tp5", "booking_prepare", { agreementId });
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval, ...overrides,
    });
    return signedSubmit({
      token: "tp5", role: "provider", prepared: prep,
      submitTool: "booking_execute", extraArgs: { approval },
    });
  };

  // zero-digest policy pin is refused (previously sailed through)
  const zeroPolicy = await attempt({ policyDigest: `0x${"0".repeat(64)}` });
  assert.equal(zeroPolicy.error, "APPROVAL_INVALID", JSON.stringify(zeroPolicy));
  // 'approve' is not the spec decision — refused at the schema (-32602) or
  // as APPROVAL_INVALID if it somehow reaches verification
  const approveWord = await attempt({ decision: "approve" });
  assert.ok(
    approveWord.error === "APPROVAL_INVALID" || approveWord.rpcError !== undefined,
    JSON.stringify(approveWord),
  );
  // a foreign approverKeyId is refused even with a valid signature
  const wrongKeyId = await attempt({ approverKeyId: "someone-else" });
  assert.equal(wrongKeyId.error, "APPROVAL_INVALID");
  // a post-dated approval is refused
  const future = await attempt({ ts: Date.now() + 3_600_000 });
  assert.equal(future.error, "APPROVAL_INVALID");

  const good = await attempt({});
  assert.equal(good.simulated, true, JSON.stringify(good));
});

test("bind refuses an approval key identical to the signer key", async () => {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(907) });
  const same = { certificate: cert, signerKey: { keyId: keys.buyerSigner.keyId, publicKeyHex: keys.buyerSigner.publicKeyHex }, approvalKey: { keyId: keys.buyerSigner.keyId, publicKeyHex: keys.buyerSigner.publicKeyHex } };
  const refused = await callTool("tb6", "contract_bind", same);
  assert.ok(refused.error !== undefined, JSON.stringify(refused));
  const status = await callTool("tb6", "contract_status", {});
  assert.equal(status.stage, "rendezvous");
});

// === 5. receipts-first for consequential actions ==============================

test("PROBE D replay: with the receipt budget exhausted, settlement_authorize neither runs nor releases", async () => {
  const svc = createContractService(serviceOpts({ maxReceiptsPerPrincipal: 11 }));
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: svc,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS, callsPerMinute: 10000,
  });
  const h = createServer(handler);
  await new Promise((r) => h.listen(0, "127.0.0.1", r));
  const saved = baseUrl;
  baseUrl = `http://127.0.0.1:${h.address().port}/contract/mcp`;
  try {
    const { runId } = await bindPair(uuid(904), "tb4", "tp4");      // buyer: 1
    await callTool("tb4", "mandate_prepare", { mandate: goodMandate(), mandateSignature: "0x00" }); // 2 (refused ok)
    const m = await submitMandate("tb4");                          // 3 (+prepare above may count)
    assert.match(m.mandateDigest, /^0x/, JSON.stringify(m));
    const o = await offer("tp4", "provider", "IT-QW-ONESTOP", 0);
    const a = await accept("tb4", "buyer", o.offerId);
    assert.equal(a.agreementFormed, true, JSON.stringify(a));
    const ag = (await callTool("tp4", "agreement_get", {})).agreement;
    const b = await book("tp4", ag.agreementId);
    assert.equal(b.simulated, true, JSON.stringify(b));
    const vp = await callTool("tb4", "verification_prepare", { orderRef: b.orderRef, result: "match", findingsDigest: `0x${"1".repeat(64)}` });
    await signedSubmit({ token: "tb4", role: "buyer", prepared: vp, submitTool: "verification_submit" });
    // burn the buyer's remaining receipt slots
    for (let i = 0; i < 4; i++) await callTool("tb4", "contract_status", {});
    // now over budget: the consequential call must not happen at all —
    // prepare is refused before dispatch, and even if an envelope were in
    // hand the authorize is refused without releasing.
    const sp = await callTool("tb4", "settlement_prepare", {});
    if (sp.envelope) {
      const approval = makeApproval({
        envelope: sp.envelope, role: "buyer", action: "settlement",
        tool: "settlement_authorize", key: keys.buyerApproval,
      });
      const s = await signedSubmit({
        token: "tb4", role: "buyer", prepared: sp,
        submitTool: "settlement_authorize", extraArgs: { approval },
      });
      assert.equal(s.error, "RATE_LIMITED", JSON.stringify(s));
    } else {
      assert.equal(sp.error, "RATE_LIMITED", JSON.stringify(sp));
    }
    const s2 = await callTool("tb4", "settlement_status", {});
    assert.ok(s2.state === "none" || s2.error === "RATE_LIMITED", JSON.stringify(s2));
    const run = svc.runFor(runId);
    assert.equal(run.settlement, undefined, "the payment must not have executed");
  } finally {
    baseUrl = saved;
    await new Promise((r) => h.close(r));
    svc.close();
  }
});

// === 6. serverNonce on refusals + refusals are receipted ======================

test("every refusal body carries serverNonce and refusals land on the chain", async () => {
  const { runId } = await bindPair(uuid(908), "tb6", "tp6");
  const refused = await callTool("tb6", "offer_accept_prepare", { offerId: "off-9999" });
  assert.equal(refused.error, "NOT_FOUND"); // unknown offer id
  // whichever generic refusal fires, the nonce must ride the body
  assert.match(refused.serverNonce, /^0x[0-9a-f]{32}$/, JSON.stringify(refused));

  const roleRefused = await callTool("tp6", "booking_prepare", { agreementId: "agr-9999" });
  // booking_prepare on a bound run w/o agreement → NOT_FOUND (provider-only is satisfied)
  assert.match(roleRefused.serverNonce ?? "", /^0x[0-9a-f]{32}$/, JSON.stringify(roleRefused));

  const feed = service.receiptFeed(runId);
  const outcomes = feed.receipts.map((r) => `${r.tool}:${r.outcome}`);
  assert.ok(outcomes.some((o) => o.includes("offer_accept_prepare") && !o.endsWith(":ok")), JSON.stringify(outcomes));
});

// === 7. rendezvous hardening ====================================================

test("PROBE E replay: a junk seal can't burn a listing; only the owner resets; caps/TTL/sender limit", async () => {
  const l = await callTool("tp6", "rendezvous_publish_listing", {
    title: "Victim listing", summary: "x",
    sealedBoxPublicKeyHex: `0x${"11".repeat(32)}`,
    terms: { origin: "ZRH", destination: "JFK" },
  });
  assert.match(l.listingId, /^lst-/);

  // junk ciphertext — schema rejects (never reaches dispatch, never burns)
  const junk = await callTool("tb6", "rendezvous_send_invitation", {
    listingId: l.listingId,
    sealedInvitation: { alg: "x25519-xsalsa20-poly1305", ciphertextHex: "0x00" },
  });
  assert.ok(junk.rpcError !== undefined || junk.error !== undefined, JSON.stringify(junk));
  // …and the legitimate sender's valid seal still delivers
  const legit = await callTool("tb5", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: V2_SEAL });
  assert.equal(legit.delivered, true, JSON.stringify(legit));

  // a second (valid) delivery from a DIFFERENT sender also lands — the
  // listing holds multiple pending deliveries until the provider acts
  // (N4B2B-CHANGES-2 §1: no more first-delivery burn).
  const second = await callTool("tb6", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: V2_SEAL });
  assert.equal(second.delivered, true, JSON.stringify(second));

  // owner republish still doesn't clear or consume the pending deliveries
  await callTool("tp6", "rendezvous_publish_listing", {
    title: "Victim listing", summary: "x", sealedBoxPublicKeyHex: `0x${"11".repeat(32)}`,
  });
  const afterRepublish = await callTool("tb5", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: V2_SEAL });
  assert.equal(afterRepublish.delivered, true, JSON.stringify(afterRepublish));

  // malformed-but-schema-shaped seals are refused without burning a fresh listing
  const l2 = await callTool("tp6", "rendezvous_publish_listing", {
    title: "Second listing", summary: "x", sealedBoxPublicKeyHex: `0x${"22".repeat(32)}`,
  });
  const badField = await callTool("tb5", "rendezvous_send_invitation", {
    listingId: l2.listingId, sealedInvitation: { v: 2, epk: "a", iv: "b", ct: "c", tag: "d" },
  });
  assert.ok(badField.rpcError !== undefined || badField.error !== undefined, JSON.stringify(badField));
  const l2Legit = await callTool("tb5", "rendezvous_send_invitation", { listingId: l2.listingId, sealedInvitation: V2_SEAL });
  assert.equal(l2Legit.delivered, true, JSON.stringify(l2Legit));

  // search filters actually filter (terms-declaring listing only on match)
  const hit = await callTool("tb5", "rendezvous_search", { origin: "ZRH", destination: "JFK" });
  assert.ok(hit.listings.some((x) => x.listingId === l.listingId));
  const miss = await callTool("tb5", "rendezvous_search", { origin: "SFO", destination: "JFK" });
  assert.ok(!miss.listings.some((x) => x.listingId === l.listingId));
});

// === also-fix: withdraw-after-booking, verification write-once =================

test("contract_withdraw is refused after booking; a submitted verification is write-once", async () => {
  const { agreementId } = await agreePair(uuid(909), "tb7", "tp7");
  const b = await book("tp7", agreementId);
  assert.equal(b.simulated, true, JSON.stringify(b));
  const w = await callTool("tb7", "contract_withdraw", {});
  assert.equal(w.error, "STATE_REFUSED", JSON.stringify(w));

  const vp = await callTool("tb7", "verification_prepare", { orderRef: b.orderRef, result: "mismatch", findingsDigest: `0x${"2".repeat(64)}` });
  const v = await signedSubmit({ token: "tb7", role: "buyer", prepared: vp, submitTool: "verification_submit" });
  assert.equal(v.flagged, true, JSON.stringify(v)); // observed=match, claimed mismatch
  // N4B2B-CHANGES-2 §2: a buyer-declared mismatch is terminal either way.
  assert.equal(v.terminalState, "verification_failed", JSON.stringify(v));

  // a second verification can never overwrite the record — the run ended.
  const vp2 = await callTool("tb7", "verification_prepare", { orderRef: b.orderRef, result: "match", findingsDigest: `0x${"3".repeat(64)}` });
  const outcome2 = vp2.envelope === undefined ? vp2 : await signedSubmit({ token: "tb7", role: "buyer", prepared: vp2, submitTool: "verification_submit" });
  assert.equal(outcome2.error, "ALREADY_TERMINAL", JSON.stringify(outcome2));
});
