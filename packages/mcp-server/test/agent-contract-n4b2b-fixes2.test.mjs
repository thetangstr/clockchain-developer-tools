import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { computeApprovalDigest, computeApprovalSigDigest } from "../dist/agent-contract/approval.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { createBusinessOps } from "../dist/agent-contract/business.js";
import { createSimWorld } from "../dist/agent-contract/sim/index.js";
import {
  eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress,
} from "../dist/agent-contract/eip191.js";

const ACCEPT = "application/json, text/event-stream";

// N4b-2b review fixes 2 (N4B2B-CHANGES-2): a listing holds MULTIPLE pending
// sealed deliveries and is consumed only when the provider acts; a claimed
// mismatch is terminal verification_failed; mandateIds are single-use per
// principal, durably; listing caps are per-provider; commercialTransfer:false
// rides the settlement_authorize result.

// --- test-only certificate minter (same wire format as the bind suite) -------

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64");
}

const rootKey = generateKeyPairSync("ed25519");
const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex") },
]);

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

// --- test-only secp256k1 keys -------------------------------------------------

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

const PRINCIPAL_PRIV = secpPriv(0xd5);
const PRINCIPAL_ADDRESS = publicKeyToAddress(
  Buffer.from(pubFromPriv(PRINCIPAL_PRIV).slice(2), "hex"),
);

const POLICY_DIGESTS = Object.freeze({
  buyer: `0x${"7".repeat(64)}`,
  provider: `0x${"8".repeat(64)}`,
});
const PRINCIPALS = Object.freeze(new Map(
  Array.from({ length: 12 }, (_, i) => [`kb${i + 1}`, PRINCIPAL_ADDRESS]),
));

function signRoleSig(privHex, { runId, role, tool, nonce, payloadDigest }) {
  const digest = canonicalDigest({
    domain: "agent-contract.role-sig/v1", runId, role, tool, nonce, payloadDigest,
  });
  return eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), privHex);
}

function makeApproval({ envelope, role, action, tool, key, policyDigest }) {
  const digest = computeApprovalDigest({
    runId: envelope.runId, tool, nonce: envelope.nonce,
    envelopeDigest: canonicalDigest(envelope), expiresAt: envelope.expiresAt,
  });
  const record = {
    role, action, digest, policyDigest: policyDigest ?? POLICY_DIGESTS[role],
    decision: "allow", ts: Date.now(), approverKeyId: key.keyId,
  };
  const sigDigest = computeApprovalSigDigest({ runId: envelope.runId, role, record });
  return { ...record, signature: eip191SignDigest32(Buffer.from(sigDigest.slice(2), "hex"), key.priv) };
}

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
    partySize: 2,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    ...overrides,
  };
}

// Distinct well-formed v2 seals per sender — the content needn't decrypt.
const seal = (n) => ({
  v: 2,
  epk: `0x${n.toString(16).padStart(2, "0").repeat(32)}`,
  iv: `0x${"cd".repeat(12)}`,
  ct: `0x${n.toString(16).padStart(2, "0").repeat(48)}`,
  tag: `0x${"01".repeat(16)}`,
});

// --- service + HTTP harness ----------------------------------------------------

const TOKENS_RAW = [
  ...Array.from({ length: 12 }, (_, i) => `tb${i + 1}:buyer:kb${i + 1}:9452:initiator`),
  ...Array.from({ length: 12 }, (_, i) => `tp${i + 1}:provider:kp${i + 1}:9453:responder`),
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };

const stateDir = mkdtempSync(path.join(tmpdir(), "contract-fix2-"));
let http;
let baseUrl;
let service;

const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

test.before(async () => {
  service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    stateDir,
    allowLegacySealV2: true, // test posture = CONTRACT_LEVEL=L
  });
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
  if (sessions.has(token)) return;
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
  sessions.set(token, sid);
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
    const sid = sessions.get(token);
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

async function bindPair(sessionId, buyerToken, providerToken, listingId) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await callTool(buyerToken, "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await callTool(providerToken, "contract_bind", bindArgs(cert, "provider", { listingId }));
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

// === 1. listing burn: multiple pending deliveries; consumed only when the
//        provider acts (E, N4B2B-CHANGES-2 §1) ==================================

test("a listing holds multiple pending deliveries; consumed only when the provider acts", async () => {
  const l = await callTool("tp1", "rendezvous_publish_listing", {
    title: "Multi delivery listing", summary: "x",
    sealedBoxPublicKeyHex: `0x${"11".repeat(32)}`,
  });

  // Buyer X's well-formed junk and buyer Y's genuine delivery BOTH land —
  // a bad delivery can no longer burn the listing for everyone.
  const junk = await callTool("tb1", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: seal(0x11) });
  assert.equal(junk.delivered, true, JSON.stringify(junk));
  const legit = await callTool("tb2", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: seal(0x22) });
  assert.equal(legit.delivered, true, JSON.stringify(legit));

  // The provider's inbox lists EVERY pending delivery.
  const inbox1 = await callTool("tp1", "rendezvous_inbox", {});
  const forListing = inbox1.messages.filter((m) => m.listingId === l.listingId);
  assert.equal(forListing.length, 2, JSON.stringify(forListing));
  const cts = forListing.map((m) => m.sealedPayload?.ct).sort();
  assert.deepEqual(cts, [seal(0x11).ct, seal(0x22).ct].sort());

  // One pending per sender: X's second delivery REPLACES its first.
  const replace = await callTool("tb1", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: seal(0x33) });
  assert.equal(replace.delivered, true);
  const inbox2 = await callTool("tp1", "rendezvous_inbox", {});
  const forListing2 = inbox2.messages.filter((m) => m.listingId === l.listingId);
  assert.equal(forListing2.length, 2, JSON.stringify(forListing2));
  const cts2 = forListing2.map((m) => m.sealedPayload?.ct).sort();
  assert.deepEqual(cts2, [seal(0x22).ct, seal(0x33).ct].sort());

  // The provider ACTS on THIS listing: it binds a handshake naming the
  // listingId the delivery came through (N4b-3 LOW). The listing is now
  // consumed — every other pending delivery is cleared, new ones refused.
  await bindPair(uuid(201), "tb3", "tp1", l.listingId);
  const late = await callTool("tb4", "rendezvous_send_invitation", { listingId: l.listingId, sealedInvitation: seal(0x44) });
  assert.equal(late.error, "LISTING_UNAVAILABLE", JSON.stringify(late));
  const inbox3 = await callTool("tp1", "rendezvous_inbox", {});
  assert.equal(
    inbox3.messages.filter((m) => m.listingId === l.listingId).length, 0,
    "pending deliveries cleared once the provider acted",
  );
});

// === caps: pending per listing + per-provider listing cap =====================

test("a listing holds at most 16 pending deliveries; one live listing per provider", () => {
  const ops = createBusinessOps({
    signer: SIGNER, sim: createSimWorld({ now: Date.now }),
    policyDigests: POLICY_DIGESTS, endRun() {},
    allowLegacySealV2: true,
  });
  const providerA = { keyId: "kpA", role: "provider", agentId: "9453", side: "responder" };
  const providerB = { keyId: "kpB", role: "provider", agentId: "9453", side: "responder" };
  const sender = (i) => ({ keyId: `kx${i}`, role: "buyer", agentId: "9452", side: "initiator" });
  const nonce = () => `0x${"0".repeat(32)}`;

  const pub = (p, title) => ops.dispatch(p, undefined, "rendezvous_publish_listing", {
    title, summary: "x", sealedBoxPublicKeyHex: `0x${"11".repeat(32)}`,
  }, nonce());
  const send = (s, listingId, n) => ops.dispatch(s, undefined, "rendezvous_send_invitation", {
    listingId, sealedInvitation: seal(n),
  }, nonce());
  const read = (p) => ops.dispatch(p, undefined, "rendezvous_inbox", {}, nonce());

  const l = pub(providerA, "pending cap listing");
  assert.equal(l.ok, true);
  const listingId = l.result.listingId;

  // 16 distinct senders fill the pending slots; the 17th is refused.
  for (let i = 0; i < 16; i++) {
    assert.equal(send(sender(i), listingId, i + 1).ok, true, `sender ${i}`);
  }
  const overflow = send(sender(16), listingId, 0xee);
  assert.equal(overflow.ok, false);
  assert.equal(overflow.code, "LISTING_UNAVAILABLE");
  // …but the listing is NOT consumed: a replacing resend still lands.
  assert.equal(send(sender(0), listingId, 0xaa).ok, true);
  const box = read(providerA).result.messages.filter((m) => m.listingId === listingId);
  assert.equal(box.length, 16);
  assert.ok(box.some((m) => m.sealedPayload.ct === seal(0xaa).ct));

  // One live listing per provider (live run p6-l-2026-10-01-8): a NEW
  // listing from provider A supersedes its previous one, so republishing
  // never runs into a per-provider cap and A always holds exactly one
  // listing — and provider B can still publish.
  let lastA;
  for (let i = 0; i < 40; i++) {
    const r = pub(providerA, `provider A listing ${i}`);
    assert.equal(r.ok, true, `listing ${i}: ${JSON.stringify(r)}`);
    lastA = r.result.listingId;
  }
  const searchA = ops.dispatch(sender(99), undefined, "rendezvous_search", { origin: "ZRH", destination: "JFK" }, nonce());
  assert.deepEqual(searchA.result.listings.map((x) => x.listingId), [lastA]);
  // The superseded first listing (with its 16 pendings) is closed and its
  // pendings are gone from A's inbox.
  assert.equal(send(sender(1), listingId, 0xbb).code, "LISTING_UNAVAILABLE");
  assert.equal(read(providerA).result.messages.filter((m) => m.listingId === listingId).length, 0);
  const other = pub(providerB, "provider B listing");
  assert.equal(other.ok, true, "one provider can't lock out another");
});

// === 2. a claimed mismatch is terminal =========================================

test("a false mismatch is terminal: the run ends verification_failed, no settlement", async () => {
  const { agreementId } = await agreePair(uuid(202), "tb5", "tp5");
  const b = await book("tp5", agreementId);
  assert.equal(b.simulated, true, JSON.stringify(b));

  // Buyer claims mismatch; the server's own observation says match. The claim
  // is recorded as flagged — but a buyer-declared mismatch is TERMINAL.
  const vp = await callTool("tb5", "verification_prepare", {
    orderRef: b.orderRef, result: "mismatch", findingsDigest: `0x${"cc".repeat(32)}`,
  });
  const v = await signedSubmit({ token: "tb5", role: "buyer", prepared: vp, submitTool: "verification_submit" });
  assert.equal(v.outcome, "mismatch", JSON.stringify(v));
  assert.equal(v.flagged, true);
  assert.equal(v.terminalState, "verification_failed", JSON.stringify(v));

  const status = await callTool("tb5", "contract_status", {});
  assert.equal(status.terminalState, "verification_failed", JSON.stringify(status));
  assert.equal(status.stage, "terminal");

  // No settlement is possible — the run is over.
  const sp = await callTool("tb5", "settlement_prepare", {});
  assert.equal(sp.error, "ALREADY_TERMINAL", JSON.stringify(sp));
});

// === 3. single-use mandateId per principal, durable =============================

test("a mandateId is single-use per principal — durably across a restart", async () => {
  // Dedicated service + stateDir so this test can restart cleanly.
  const dir = mkdtempSync(path.join(tmpdir(), "contract-mandate-"));
  const svc1 = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS, stateDir: dir,
  });
  const h1 = createServer(createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: svc1,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  }));
  await new Promise((r) => h1.listen(0, "127.0.0.1", r));
  const saved = baseUrl;
  baseUrl = `http://127.0.0.1:${h1.address().port}/contract/mcp`;
  const mandate = goodMandate({ mandateId: "mdt-single-use-1" });
  try {
    await bindPair(uuid(203), "tb6", "tp6");
    const m = await submitMandate("tb6", mandate);
    assert.match(m.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(m));
  } finally {
    baseUrl = saved;
    await new Promise((r) => h1.close(r));
    svc1.close();
  }

  // RESTART: a fresh service over the same state dir must still refuse the id.
  const svc2 = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS, stateDir: dir,
  });
  const h2 = createServer(createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service: svc2,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  }));
  await new Promise((r) => h2.listen(0, "127.0.0.1", r));
  baseUrl = `http://127.0.0.1:${h2.address().port}/contract/mcp`;
  try {
    // A different buyer bound to the SAME family principal reuses the id.
    await bindPair(uuid(204), "tb7", "tp7");
    const reuse = await submitMandate("tb7", mandate);
    assert.equal(reuse.error, "MANDATE_INVALID", JSON.stringify(reuse));

    // And a fresh mandateId by the same principal still works.
    const fresh = await submitMandate("tb7", goodMandate({ mandateId: "mdt-single-use-2" }));
    assert.match(fresh.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(fresh));
  } finally {
    baseUrl = saved;
    await new Promise((r) => h2.close(r));
    svc2.close();
  }
});

// === 4. commercialTransfer:false on the settlement result =======================

test("settlement_authorize result carries commercialTransfer:false", async () => {
  const { agreementId } = await agreePair(uuid(205), "tb8", "tp8");
  const b = await book("tp8", agreementId);
  const vp = await callTool("tb8", "verification_prepare", {
    orderRef: b.orderRef, result: "match", findingsDigest: `0x${"9d".repeat(32)}`,
  });
  const v = await signedSubmit({ token: "tb8", role: "buyer", prepared: vp, submitTool: "verification_submit" });
  assert.equal(v.outcome, "match", JSON.stringify(v));

  const sp = await callTool("tb8", "settlement_prepare", {});
  const approval = makeApproval({
    envelope: sp.envelope, role: "buyer", action: "settlement",
    tool: "settlement_authorize", key: keys.buyerApproval,
  });
  const s = await signedSubmit({
    token: "tb8", role: "buyer", prepared: sp,
    submitTool: "settlement_authorize", extraArgs: { approval },
  });
  assert.equal(s.status, "released", JSON.stringify(s));
  assert.equal(s.simulated, true);
  assert.equal(s.commercialTransfer, false, JSON.stringify(s));
});
