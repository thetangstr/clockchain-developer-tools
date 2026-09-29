import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { computeApprovalDigest, computeApprovalSigDigest } from "../dist/agent-contract/approval.js";
import { eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";

const ACCEPT = "application/json, text/event-stream";

// --- test-only certificate minter (same wire format as the bind suite) ------

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

// --- test-only secp256k1 role keys (EIP-191; no real keys anywhere) ----------

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
  // The family principal that signs mandates (CONTRACT_PRINCIPALS pin).
  principal: { keyId: "principal", priv: secpPriv(0xd1) },
};
for (const k of Object.values(keys)) k.publicKeyHex = pubFromPriv(k.priv);
const PRINCIPAL_ADDRESS = publicKeyToAddress(Buffer.from(keys.principal.publicKeyHex.slice(2), "hex"));

const POLICY_DIGEST = `0x${"7".repeat(64)}`;
const POLICY = { buyer: POLICY_DIGEST, provider: POLICY_DIGEST };
// Every test buyer keyId pins the same test principal address.
const PRINCIPALS = new Map(
  ["kb1", "kb2", "kb3", "kb4", "kb5", "kb6"].map((k) => [k, PRINCIPAL_ADDRESS]),
);

function signRoleSig(privHex, { runId, role, tool, nonce, payloadDigest }) {
  const digest = canonicalDigest({
    domain: "agent-contract.role-sig/v1", runId, role, tool, nonce, payloadDigest,
  });
  return eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), privHex);
}

/** The family principal's signed mandate (rev 6.5) — all v2 fields required. */
function signMandate(overrides = {}) {
  const mandate = {
    kind: "mandate",
    mandateId: `mnd-${Math.floor(Math.random() * 1e9)}`,
    capMinor: 500_000,
    currency: "USD",
    allowedItineraryIds: ["IT-QW-ONESTOP"],
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    ...overrides,
  };
  const digest = canonicalDigest({ domain: "agent-contract.mandate/v1", ...mandate });
  return {
    mandate,
    mandateSignature: eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), keys.principal.priv),
  };
}

function makeApproval({ envelope, role, action, tool, key, policyDigest = POLICY_DIGEST }) {
  const digest = computeApprovalDigest({
    runId: envelope.runId,
    tool,
    nonce: envelope.nonce,
    envelopeDigest: canonicalDigest(envelope),
    expiresAt: envelope.expiresAt,
  });
  const record = {
    role, action, digest, policyDigest,
    decision: "allow", ts: Date.now(), approverKeyId: key.keyId,
  };
  const sigDigest = computeApprovalSigDigest({ runId: envelope.runId, role, record });
  return { ...record, signature: eip191SignDigest32(Buffer.from(sigDigest.slice(2), "hex"), key.priv) };
}

// --- service + HTTP harness --------------------------------------------------

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tb2:buyer:kb2:9452:initiator",
  "tb3:buyer:kb3:9452:initiator",
  "tb4:buyer:kb4:9452:initiator",
  "tb5:buyer:kb5:9452:initiator",
  "tb6:buyer:kb6:9452:initiator",
  "tp1:provider:kp1:9453:responder",
  "tp2:provider:kp2:9453:responder",
  "tp3:provider:kp3:9453:responder",
  "tp4:provider:kp4:9453:responder",
  "tp5:provider:kp5:9453:responder",
  "tp6:provider:kp6:9453:responder",
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };

const stateDir = mkdtempSync(path.join(tmpdir(), "contract-biz-"));
let http;
let baseUrl;
let service;

const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

test.before(async () => {
  service = createContractService({ hostRoots: HOST_ROOTS, signer: SIGNER, stateDir, policyDigests: POLICY, principals: PRINCIPALS, allowLegacySealV2: true });
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
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await response.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  const body = JSON.parse(data ? data.slice(5) : text);
  return { status: response.status, body };
}

/** tools/call → structuredContent (result payload or {error, retryable}). */
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
  const cert = mintCertificate({
    root: rootKey, session: generateKeyPairSync("ed25519"), sessionId,
  });
  const b = await callTool(buyerToken, "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await callTool(providerToken, "contract_bind", bindArgs(cert, "provider"));
  assert.equal(p.bound, true, `provider bind: ${JSON.stringify(p)}`);
  return { cert, runId: b.runId };
}

/** prepare → EIP-191 role-sign → submit round trip. */
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

/** Drive a bound pair through mandate → offer → accept → agreement. */
async function agreePair(sessionId, buyerToken, providerToken, signed = signMandate()) {
  const { runId } = await bindPair(sessionId, buyerToken, providerToken);
  const prepM = await callTool(buyerToken, "mandate_prepare", signed);
  const m = await signedSubmit({
    token: buyerToken, role: "buyer", prepared: prepM, submitTool: "mandate_submit",
  });
  assert.match(m.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(m));
  const prepO = await callTool(buyerToken, "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
  const offered = await signedSubmit({
    token: buyerToken, role: "buyer", prepared: prepO, submitTool: "offer_submit",
  });
  assert.equal(offered.state, "offered", JSON.stringify(offered));
  const prepA = await callTool(providerToken, "offer_accept_prepare", { offerId: offered.offerId });
  const accepted = await signedSubmit({
    token: providerToken, role: "provider", prepared: prepA, submitTool: "offer_accept_submit",
  });
  assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));
  return { runId, agreementId: accepted.agreementId };
}

// --- the full pairing lifecycle ----------------------------------------------

test("N4b-2: rendezvous → bind → mandate → negotiate → agree → book → verify → settle", async () => {
  const { runId } = await bindPair(uuid(101), "tb1", "tp1");

  // rendezvous: provider publishes, buyer searches, invites, provider reads inbox
  const listing = await callTool("tp1", "rendezvous_publish_listing", {
    title: "ZRH-JFK managed travel",
    summary: "Institutional desk",
    sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`,
  });
  assert.match(listing.listingId, /^lst-/);
  const search = await callTool("tb1", "rendezvous_search", { origin: "ZRH", destination: "JFK" });
  assert.ok(search.listings.some((l) => l.listingId === listing.listingId));
  const invited = await callTool("tb1", "rendezvous_send_invitation", {
    listingId: listing.listingId,
    sealedInvitation: {
      v: 2,
      epk: `0x${"ab".repeat(32)}`,
      iv: `0x${"cd".repeat(12)}`,
      ct: `0x${"ef".repeat(32)}`,
      tag: `0x${"01".repeat(16)}`,
    },
  });
  assert.equal(invited.delivered, true);
  const inbox = await callTool("tp1", "rendezvous_inbox", {});
  assert.ok(inbox.messages.some((m) => m.kind === "handshake_invitation" && m.listingId === listing.listingId));

  // mandate (buyer) — the family principal's signed statement
  const prepM = await callTool("tb1", "mandate_prepare", signMandate());
  // CONTRACT-PAYLOADS-v2 §Mandate: the signed payload IS the flat mandate —
  // the digest recomputes from the payload verbatim.
  assert.equal(prepM.envelope.payload.kind, "mandate");
  assert.equal(
    canonicalDigest({ domain: "agent-contract.mandate/v1", ...prepM.envelope.payload }),
    prepM.mandateDigest,
  );
  const mandated = await signedSubmit({ token: "tb1", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
  assert.match(mandated.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(mandated));

  // catalog quote (provider, sim)
  const quote = await callTool("tp1", "catalog_quote", { origin: "ZRH", destination: "JFK" });
  assert.equal(quote.simulated, true);
  const itin = quote.itineraries.find((i) => i.itineraryId === "IT-QW-ONESTOP");
  assert.equal(itin.fareMinor, 429_000);

  // buyer offer
  const prepO = await callTool("tb1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000, note: "first" });
  assert.deepEqual(prepO.quote, { fareMinor: 429_000, feeMinor: 10_000, totalMinor: 439_000, currency: "USD" });
  assert.equal(prepO.envelope.payload.kind, "offer");
  const offered = await signedSubmit({ token: "tb1", role: "buyer", prepared: prepO, submitTool: "offer_submit" });
  assert.equal(offered.state, "offered", JSON.stringify(offered));
  assert.equal(offered.offerId, "off-0001");

  // provider counter — kind/inReplyTo are server-set, not agent-set
  const prepC = await callTool("tp1", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 9_000 });
  assert.equal(prepC.envelope.payload.kind, "counter");
  assert.equal(prepC.envelope.payload.inReplyTo, "off-0001");
  const counter = await signedSubmit({ token: "tp1", role: "provider", prepared: prepC, submitTool: "offer_submit" });
  assert.equal(counter.offerId, "off-0002", JSON.stringify(counter));

  // buyer accepts the counter → agreement formed
  const prepA = await callTool("tb1", "offer_accept_prepare", { offerId: "off-0002" });
  const accepted = await signedSubmit({ token: "tb1", role: "buyer", prepared: prepA, submitTool: "offer_accept_submit" });
  assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));
  const agreementId = accepted.agreementId;
  const got = await callTool("tp1", "agreement_get", {});
  assert.equal(got.agreement.agreementId, agreementId);
  assert.match(got.anchor.agreementDigest, /^0x[0-9a-f]{64}$/);

  // booking (provider, sim + §13 approval)
  const prepBook = await callTool("tp1", "booking_prepare", { agreementId });
  const bookingApproval = makeApproval({
    envelope: prepBook.envelope, role: "provider", action: "booking",
    tool: "booking_execute", key: keys.providerApproval,
  });
  const booked = await signedSubmit({
    token: "tp1", role: "provider", prepared: prepBook,
    submitTool: "booking_execute", extraArgs: { approval: bookingApproval },
  });
  assert.equal(booked.simulated, true, JSON.stringify(booked));
  assert.match(booked.orderRef, /^ORD-/);
  assert.ok(booked.tickets.length >= 1);

  // buyer looks up the order on the sim
  const observed = await callTool("tb1", "booking_lookup", { orderRef: booked.orderRef });
  assert.equal(observed.observation.status, "ISSUED");
  assert.equal(observed.observation.simulated, true);

  // settlement before verification is refused
  const premature = await callTool("tb1", "settlement_prepare", {});
  assert.equal(premature.error, "STATE_REFUSED");

  // buyer verification — the server's own sim observation is ground truth
  const prepV = await callTool("tb1", "verification_prepare", {
    orderRef: booked.orderRef, result: "match", findingsDigest: `0x${"aa".repeat(32)}`,
  });
  const verified = await signedSubmit({ token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
  assert.equal(verified.outcome, "match", JSON.stringify(verified));
  assert.equal(verified.flagged, false);

  // settlement (buyer, payment rail + approval)
  const prepS = await callTool("tb1", "settlement_prepare", {});
  const settleApproval = makeApproval({
    envelope: prepS.envelope, role: "buyer", action: "settlement",
    tool: "settlement_authorize", key: keys.buyerApproval,
  });
  const settled = await signedSubmit({
    token: "tb1", role: "buyer", prepared: prepS,
    submitTool: "settlement_authorize", extraArgs: { approval: settleApproval },
  });
  assert.equal(settled.simulated, true, JSON.stringify(settled));
  assert.match(settled.transferId, /^sandbox-transfer:/);
  assert.equal(settled.status, "released");

  const status = await callTool("tb1", "settlement_status", {});
  assert.equal(status.state, "released");
  const stage = await callTool("tb1", "contract_status", {});
  assert.equal(stage.stage, "settled");
  assert.equal(stage.terminalState, "settled");

  // every bound call was receipted onto a verifiable hash-chained chain
  const feed = service.receiptFeed(runId);
  assert.ok(feed.receipts.length >= 10);
  const verdict = verifyChain(feed.receipts, { [SIGNER.keyId]: serverKeys.publicKey });
  assert.equal(verdict.ok, true, JSON.stringify(verdict));
});

// --- adverse cases -------------------------------------------------------------

test("a mandate cap refusal is the identical generic body", async () => {
  await bindPair(uuid(102), "tb2", "tp2");
  const prepM = await callTool("tb2", "mandate_prepare", signMandate({ capMinor: 400_000 }));
  const mandated = await signedSubmit({ token: "tb2", role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
  assert.match(mandated.mandateDigest, /^0x/);

  const offered = await callTool("tb2", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
  // The refusal must never leak WHICH cap failed (refusals.ts). The
  // serverNonce is correlation-only — no cap value rides the body.
  assert.equal(offered.error, "MANDATE_REFUSED");
  assert.equal(offered.retryable, false);
  assert.equal(Object.keys(offered).sort().join(","), "error,retryable,serverNonce");

  // A wrong-currency offer is refused identically.
  const prepO2 = await callTool("tp2", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
  assert.equal(prepO2.error, undefined); // provider offers are not cap-checked
});

test("a tampered role signature and a nonce replay are refused", async () => {
  await bindPair(uuid(103), "tb3", "tp3");
  const prepared = await callTool("tb3", "mandate_prepare", signMandate());
  const env = prepared.envelope;

  // a sig made by the provider's key over the buyer tuple
  const badSig = signRoleSig(keys.providerSigner.priv, {
    runId: env.runId, role: "buyer", tool: env.tool, nonce: env.nonce, payloadDigest: env.payloadDigest,
  });
  const bad = await callTool("tb3", "mandate_submit", { envelope: env, signatureHex: badSig });
  assert.equal(bad.error, "SIGNATURE_INVALID");

  // correct signature — accepted
  const goodSig = signRoleSig(keys.buyerSigner.priv, {
    runId: env.runId, role: "buyer", tool: env.tool, nonce: env.nonce, payloadDigest: env.payloadDigest,
  });
  const okSubmit = await callTool("tb3", "mandate_submit", { envelope: env, signatureHex: goodSig });
  assert.match(okSubmit.mandateDigest, /^0x/);

  // replaying the consumed envelope is refused
  const replay = await callTool("tb3", "mandate_submit", { envelope: env, signatureHex: goodSig });
  assert.equal(replay.error, "NONCE_REUSED");
});

test("booking_execute needs a §13 approval on the bound approval key", async () => {
  const { agreementId } = await agreePair(uuid(104), "tb4", "tp4");

  // Each attempt needs a fresh envelope — a consumed nonce is single-use even
  // when the downstream check refuses.
  const attempt = async (approvalKey, decision = "allow") => {
    const prep = await callTool("tp4", "booking_prepare", { agreementId });
    const env = prep.envelope;
    const sig = signRoleSig(keys.providerSigner.priv, {
      runId: env.runId, role: "provider", tool: env.tool, nonce: env.nonce, payloadDigest: env.payloadDigest,
    });
    const approval = makeApproval({
      envelope: env, role: "provider", action: "booking",
      tool: "booking_execute", key: approvalKey,
    });
    return callTool("tp4", "booking_execute", {
      envelope: env, signatureHex: sig, approval: { ...approval, decision },
    });
  };

  // approval signed by the SIGNER key, not the bound approval key
  const refused = await attempt(keys.providerSigner);
  assert.equal(refused.error, "APPROVAL_INVALID", JSON.stringify(refused));

  // a "deny" decision is not an approval (digest binds the wrong decision)
  const denied = await attempt(keys.providerApproval, "deny");
  assert.equal(denied.error, "APPROVAL_INVALID");

  // the buyer cannot drive the provider-only tool at all
  const roleRefused = await callTool("tb4", "booking_prepare", { agreementId });
  assert.equal(roleRefused.error, "ROLE_REFUSED");

  // and a good approval books
  const okBook = await attempt(keys.providerApproval);
  assert.equal(okBook.simulated, true, JSON.stringify(okBook));
});

test("a claimed-mismatch verification flags and blocks settlement", async () => {
  const { runId, agreementId } = await agreePair(uuid(105), "tb5", "tp5");

  const prepBook = await callTool("tp5", "booking_prepare", { agreementId });
  const approval = makeApproval({
    envelope: prepBook.envelope, role: "provider", action: "booking",
    tool: "booking_execute", key: keys.providerApproval,
  });
  const booked = await signedSubmit({
    token: "tp5", role: "provider", prepared: prepBook,
    submitTool: "booking_execute", extraArgs: { approval },
  });
  assert.equal(booked.simulated, true, JSON.stringify(booked));

  // buyer claims mismatch while the sim observation says match → flagged
  // AND terminal (N4B2B-CHANGES-2 §2): a claimed mismatch ends the run
  // verification_failed whether or not the observation agrees.
  const prepV = await callTool("tb5", "verification_prepare", {
    orderRef: booked.orderRef, result: "mismatch", findingsDigest: `0x${"bb".repeat(32)}`,
  });
  const verified = await signedSubmit({ token: "tb5", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
  assert.equal(verified.outcome, "mismatch");
  assert.equal(verified.flagged, true);

  const settle = await callTool("tb5", "settlement_prepare", {});
  assert.equal(settle.error, "ALREADY_TERMINAL");
  const stage = await callTool("tb5", "contract_status", {});
  assert.equal(stage.stage, "terminal");
  assert.equal(stage.terminalState, "verification_failed");
});

test("withdraw ends the run and the receipt chain carries the terminal call", async () => {
  const { runId } = await agreePair(uuid(106), "tb6", "tp6");
  const withdrawn = await callTool("tb6", "contract_withdraw", { reason: "changed plans" });
  assert.equal(withdrawn.state, "withdrawn");
  const stage = await callTool("tb6", "contract_status", {});
  assert.equal(stage.stage, "terminal");
  assert.equal(stage.terminalState, "no_agreement");
  const late = await callTool("tb6", "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
  assert.equal(late.error, "ALREADY_TERMINAL");
  const feed = service.receiptFeed(runId);
  const verdict = verifyChain(feed.receipts, { [SIGNER.keyId]: serverKeys.publicKey });
  assert.equal(verdict.ok, true);
});
