import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { createContractHttpHandler, parseContractTokens, tokenAuthenticator } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { computeApprovalDigest, computeApprovalSigDigest } from "../dist/agent-contract/approval.js";
import { eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";

// N6g-2 review remediation (from N6g-2 request): the retained approval
// record's `boundDigest` must equal the responseDigest of the receipted
// *_prepare response that carried THAT envelope — booking_execute binds to
// booking_prepare, booking_cancel_submit to booking_cancel_prepare,
// settlement_authorize to settlement_prepare. Also pins the H1 simLabels
// and R10c guidance feed fields.

const ACCEPT = "application/json, text/event-stream";

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
  principal: { keyId: "principal", priv: secpPriv(0xd1) },
};
for (const k of Object.values(keys)) k.publicKeyHex = pubFromPriv(k.priv);
const PRINCIPAL_ADDRESS = publicKeyToAddress(Buffer.from(keys.principal.publicKeyHex.slice(2), "hex"));

const POLICY_DIGEST = `0x${"7".repeat(64)}`;
const POLICY = { buyer: POLICY_DIGEST, provider: POLICY_DIGEST };
const PRINCIPALS = new Map(
  ["kb1", "kb2", "kp1", "kp2"].map((k) => [k, PRINCIPAL_ADDRESS]),
);

function signRoleSig(privHex, { runId, role, tool, nonce, payloadDigest }) {
  const digest = canonicalDigest({
    domain: "agent-contract.role-sig/v1", runId, role, tool, nonce, payloadDigest,
  });
  return eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), privHex);
}

function signMandate(overrides = {}) {
  const mandate = {
    kind: "mandate",
    mandateId: `mnd-${Math.floor(Math.random() * 1e9)}`,
    capMinor: 500_000,
    currency: "USD",
    allowedItineraryIds: ["IT-QW-ONESTOP"],
    partySize: 2,
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    ...overrides,
  };
  const digest = canonicalDigest({ domain: "agent-contract.mandate/v1", ...mandate });
  return {
    mandate,
    mandateSignature: eip191SignDigest32(Buffer.from(digest.slice(2), "hex"), keys.principal.priv),
  };
}

function makeApproval({ envelope, role, action, tool, key, policyDigest = POLICY_DIGEST, decision = "allow" }) {
  const digest = computeApprovalDigest({
    runId: envelope.runId,
    tool,
    nonce: envelope.nonce,
    envelopeDigest: canonicalDigest(envelope),
    expiresAt: envelope.expiresAt,
  });
  const record = {
    role, action, digest, policyDigest,
    decision, ts: Date.now(), approverKeyId: key.keyId,
  };
  const sigDigest = computeApprovalSigDigest({ runId: envelope.runId, role, record });
  return { ...record, signature: eip191SignDigest32(Buffer.from(sigDigest.slice(2), "hex"), key.priv) };
}

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tb2:buyer:kb2:9452:initiator",
  "tp1:provider:kp1:9453:responder",
  "tp2:provider:kp2:9453:responder",
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };
const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

async function boot(serviceOptions = {}) {
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, policyDigests: POLICY, principals: PRINCIPALS,
    stateDir: mkdtempSync(path.join(tmpdir(), "n6g2-r12-")),
    ...serviceOptions,
  });
  const handler = createContractHttpHandler({ authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service });
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
  return { service, callTool, close: () => { srv.close(); service.close(); } };
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

async function bindPair(env, sessionId, buyerToken, providerToken) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId });
  const b = await env.callTool(buyerToken, "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await env.callTool(providerToken, "contract_bind", bindArgs(cert, "provider"));
  assert.equal(p.bound, true, `provider bind: ${JSON.stringify(p)}`);
  return b.runId;
}

async function signedSubmit(env, { token, role, prepared, submitTool, extraArgs = {} }) {
  const e = prepared.envelope;
  const signatureHex = signRoleSig(keys[`${role}Signer`].priv, {
    runId: e.runId, role, tool: e.tool, nonce: e.nonce, payloadDigest: e.payloadDigest,
  });
  return env.callTool(token, submitTool, { envelope: e, signatureHex, ...extraArgs });
}

function uuid(n) {
  return `deadbeef-${String(n).padStart(4, "0")}-4444-8888-${String(n).padStart(12, "0")}`;
}

async function agreePair(env, sessionId, buyerToken, providerToken) {
  const runId = await bindPair(env, sessionId, buyerToken, providerToken);
  const prepM = await env.callTool(buyerToken, "mandate_prepare", signMandate());
  const m = await signedSubmit(env, { token: buyerToken, role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
  assert.match(m.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(m));
  const prepO = await env.callTool(buyerToken, "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
  const offered = await signedSubmit(env, { token: buyerToken, role: "buyer", prepared: prepO, submitTool: "offer_submit" });
  assert.equal(offered.state, "offered", JSON.stringify(offered));
  const prepA = await env.callTool(providerToken, "offer_accept_prepare", { offerId: offered.offerId });
  const accepted = await signedSubmit(env, { token: providerToken, role: "provider", prepared: prepA, submitTool: "offer_accept_submit" });
  assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));
  return { runId, agreementId: accepted.agreementId };
}

// -----------------------------------------------------------------------------

test("R12: booking_execute approval binds to the booking_prepare receipt's responseDigest", async () => {
  const env = await boot();
  try {
    const { runId, agreementId } = await agreePair(env, uuid(301), "tb1", "tp1");
    const prep = await env.callTool("tp1", "booking_prepare", { agreementId });
    assert.ok(prep.envelope, JSON.stringify(prep));
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval, decision: "allow",
    });
    const out = await signedSubmit(env, {
      token: "tp1", role: "provider", prepared: prep,
      submitTool: "booking_execute", extraArgs: { approval },
    });
    assert.ok(out.orderRef, JSON.stringify(out));

    const feed = env.service.receiptFeed(runId);
    const prepReceipt = feed.receipts.find((r) => r.tool === "booking_prepare" && r.outcome === "ok");
    assert.ok(prepReceipt, "a receipted booking_prepare response exists");

    const rec = feed.approvalRecords?.find((a) => a.action === "booking" && a.role === "provider");
    assert.ok(rec, "the verified approval is retained");
    // digest = the bound receipt's responseDigest (boundDigest ?? record.digest).
    assert.equal(rec.digest, prepReceipt.responseDigest, "approval binds to the prepare receipt's responseDigest");
    assert.equal(rec.decision, "allow");
    assert.equal(rec.approverKeyId, keys.providerApproval.keyId);
    assert.equal(rec.policyDigest, POLICY_DIGEST);
    assert.match(rec.ts, /^\d{4}-\d{2}-\d{2}T/);

    // H1: simLabels present and label the sim-backed receipts.
    assert.ok(Array.isArray(feed.simLabels));
    const bookingReceipt = feed.receipts.find((r) => r.tool === "booking_execute");
    assert.ok(feed.simLabels.some((l) => l.receiptId === bookingReceipt.receiptId && l.simulated === true));
    const prepSim = feed.simLabels.find((l) => l.receiptId === prepReceipt.receiptId);
    assert.equal(prepSim?.simulated, true, "booking_prepare envelope is SIMULATED-labelled");

    // R10c: published guidance digests per role ride the feed.
    assert.ok(feed.guidance?.buyer?.digest?.match(/^0x[0-9a-f]{64}$/) ?? feed.guidance?.buyer !== undefined);
    assert.ok(feed.guidance?.provider !== undefined);
  } finally { env.close(); }
});

test("R12: a booking_cancel_submit approval binds to the booking_cancel_prepare receipt — not booking_prepare", async () => {
  const env = await boot();
  try {
    const { runId, agreementId } = await agreePair(env, uuid(302), "tb2", "tp2");
    const prep = await env.callTool("tp2", "booking_prepare", { agreementId });
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval, decision: "allow",
    });
    const out = await signedSubmit(env, {
      token: "tp2", role: "provider", prepared: prep,
      submitTool: "booking_execute", extraArgs: { approval },
    });
    assert.ok(out.orderRef, JSON.stringify(out));

    // Now cancel — the approval must bind to booking_cancel_prepare's
    // receipted responseDigest (the foreign hunk searched booking_prepare,
    // leaving boundDigest undefined / mis-bound).
    const cancelPrep = await env.callTool("tp2", "booking_cancel_prepare", { reason: "mutual_withdrawal" });
    assert.ok(cancelPrep.envelope, JSON.stringify(cancelPrep));
    const cancelApproval = makeApproval({
      envelope: cancelPrep.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval, decision: "allow",
    });
    const cancelled = await signedSubmit(env, {
      token: "tp2", role: "provider", prepared: cancelPrep,
      submitTool: "booking_cancel_submit", extraArgs: { approval: cancelApproval },
    });
    assert.equal(cancelled.status, "CANCELLED", JSON.stringify(cancelled));

    const feed = env.service.receiptFeed(runId);
    const cancelPrepReceipt = feed.receipts.find((r) => r.tool === "booking_cancel_prepare" && r.outcome === "ok");
    const bookingPrepReceipt = feed.receipts.find((r) => r.tool === "booking_prepare" && r.outcome === "ok");
    assert.ok(cancelPrepReceipt && bookingPrepReceipt);

    const cancelRec = feed.approvalRecords?.at(-1);
    assert.ok(cancelRec, "cancel approval retained");
    assert.equal(cancelRec.digest, cancelPrepReceipt.responseDigest,
      "cancel approval binds to the booking_cancel_prepare receipt");
    assert.notEqual(cancelRec.digest, bookingPrepReceipt.responseDigest,
      "and never to a different tool's receipt");
  } finally { env.close(); }
});
