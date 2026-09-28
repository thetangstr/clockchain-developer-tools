import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { parseContractTokens, tokenAuthenticator, createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";
import { computeApprovalDigest, computeApprovalSigDigest } from "../dist/agent-contract/approval.js";

const ACCEPT = "application/json, text/event-stream";

// N4b-4 (docs/agent-contract/N4B4-BRIEF.md):
//  1. booking_cancel — provider, v2 envelope kind "cancel"
//     {agreementId, agreementDigest, bookingRef, reason} + booking-class
//     approval; idempotent; refused after settlement; sim shows CANCELLED;
//     the run's terminalState records "cancelled".
//  2. The poll limiter is per PRINCIPAL — a fresh session must not reset it.
//  3. The server refuses to sign once the published key's validUntil has
//     passed, and refuses to start when it already has.

// --- test-only certificate minter (same wire format as the other suites) ----

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
const PRINCIPAL_ADDRESS = publicKeyToAddress(Buffer.from(pubFromPriv(PRINCIPAL_PRIV).slice(2), "hex"));

const POLICY_DIGESTS = Object.freeze({ buyer: `0x${"7".repeat(64)}`, provider: `0x${"8".repeat(64)}` });
const PRINCIPALS = Object.freeze(new Map(
  Array.from({ length: 12 }, (_, i) => [`kb${i + 1}`, PRINCIPAL_ADDRESS]),
));

const TOKENS_RAW = [
  ...Array.from({ length: 12 }, (_, i) => `tb${i + 1}:buyer:kb${i + 1}:9452:initiator`),
  ...Array.from({ length: 12 }, (_, i) => `tp${i + 1}:provider:kp${i + 1}:9453:responder`),
].join(",");
const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };

function uuid(n) {
  return `deadbeef-${String(n).padStart(4, "0")}-4444-8888-${String(n).padStart(12, "0")}`;
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

// --- HTTP harness (one server per test that needs isolation) ------------------

const CLIENT_INFO = { name: "n4b4-test-client", version: "1.0.0" };

async function boot(handlerOptions = {}) {
  const service = handlerOptions.service ?? createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    ...handlerOptions.serviceOptions,
  });
  const handler = createContractHttpHandler({
    authenticate, hostRoots: HOST_ROOTS, signer: SIGNER, service,
    ...handlerOptions.handler,
  });
  const srv = createServer(handler);
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  const sessions = new Map();
  const rpc = async (token, name, args = {}) => {
    let sid = sessions.get(token);
    if (!sid) {
      const init = await fetch(`${url}/contract/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
          params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
      });
      sid = init.headers.get("mcp-session-id");
      sessions.set(token, sid);
      await fetch(`${url}/contract/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
    }
    const res = await fetch(`${url}/contract/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}`, "mcp-session-id": sid },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await res.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    return body.result?.structuredContent ?? {};
  };
  const freshSession = async (token) => {
    sessions.delete(token);
    const init = await fetch(`${url}/contract/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
    });
    const sid = init.headers.get("mcp-session-id");
    sessions.set(token, sid);
    return sid;
  };
  return {
    url, service, rpc, freshSession,
    async close() { await new Promise((r) => srv.close(r)); service.close(); },
  };
}

async function signedSubmit(rpc, { token, role, prepared, submitTool, extraArgs = {} }) {
  const env = prepared.envelope;
  const signatureHex = signRoleSig(keys[`${role}Signer`].priv, {
    runId: env.runId, role, tool: env.tool, nonce: env.nonce, payloadDigest: env.payloadDigest,
  });
  return rpc(token, submitTool, { envelope: env, signatureHex, ...extraArgs });
}

/** bind → mandate → offer → accept → book. Returns {runId, agreementId, orderRef, pnr}. */
async function bookedPair(rpc, sessionN, buyerToken, providerToken) {
  const cert = mintCertificate({ root: rootKey, session: generateKeyPairSync("ed25519"), sessionId: uuid(sessionN) });
  const b = await rpc(buyerToken, "contract_bind", bindArgs(cert, "buyer"));
  assert.equal(b.bound, true, `buyer bind: ${JSON.stringify(b)}`);
  const p = await rpc(providerToken, "contract_bind", bindArgs(cert, "provider"));
  assert.equal(p.bound, true, `provider bind: ${JSON.stringify(p)}`);

  const mandate = goodMandate();
  const prepM = await rpc(buyerToken, "mandate_prepare", {
    mandate, mandateSignature: signMandate(PRINCIPAL_PRIV, mandate),
  });
  const mandated = await signedSubmit(rpc, { token: buyerToken, role: "buyer", prepared: prepM, submitTool: "mandate_submit" });
  assert.match(mandated.mandateDigest, /^0x[0-9a-f]{64}$/, JSON.stringify(mandated));

  const prepO = await rpc(buyerToken, "offer_prepare", { itineraryId: "IT-QW-ONESTOP", feeMinor: 10_000 });
  const offered = await signedSubmit(rpc, { token: buyerToken, role: "buyer", prepared: prepO, submitTool: "offer_submit" });
  assert.equal(offered.state, "offered", JSON.stringify(offered));
  const prepA = await rpc(providerToken, "offer_accept_prepare", { offerId: offered.offerId });
  const accepted = await signedSubmit(rpc, { token: providerToken, role: "provider", prepared: prepA, submitTool: "offer_accept_submit" });
  assert.equal(accepted.agreementFormed, true, JSON.stringify(accepted));

  const prepBook = await rpc(providerToken, "booking_prepare", { agreementId: accepted.agreementId });
  const bookingApproval = makeApproval({
    envelope: prepBook.envelope, role: "provider", action: "booking",
    tool: "booking_execute", key: keys.providerApproval,
  });
  const booked = await signedSubmit(rpc, {
    token: providerToken, role: "provider", prepared: prepBook,
    submitTool: "booking_execute", extraArgs: { approval: bookingApproval },
  });
  assert.equal(booked.simulated, true, JSON.stringify(booked));
  return { runId: b.runId, agreementId: accepted.agreementId, orderRef: booked.orderRef, pnr: booked.pnr };
}

// === 1. booking_cancel ========================================================

test("booking_cancel: a provider cancels a booked run — CANCELLED on the sim, run terminal 'cancelled'", async () => {
  const app = await boot();
  try {
    const { runId, agreementId, orderRef, pnr } = await bookedPair(app.rpc, 301, "tb1", "tp1");

    const prep = await app.rpc("tp1", "booking_cancel_prepare", { reason: "schedule change" });
    assert.ok(prep.envelope, JSON.stringify(prep));
    // The v2 cancel payload — {kind, agreementId, agreementDigest, bookingRef, reason}.
    assert.deepEqual(prep.envelope.payload, {
      kind: "cancel",
      agreementId,
      agreementDigest: prep.envelope.payload.agreementDigest,
      bookingRef: pnr,
      reason: "schedule change",
    });
    assert.match(prep.envelope.payload.agreementDigest, /^0x[0-9a-f]{64}$/);

    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval,
    });
    const cancelled = await signedSubmit(app.rpc, {
      token: "tp1", role: "provider", prepared: prep,
      submitTool: "booking_cancel_submit", extraArgs: { approval },
    });
    assert.equal(cancelled.status, "CANCELLED", JSON.stringify(cancelled));
    assert.equal(cancelled.orderRef, orderRef);
    assert.equal(cancelled.simulated, true);
    assert.equal(cancelled.terminalState, "cancelled");

    // The sim's order shows CANCELLED; the run's status records the terminal state.
    const looked = await app.rpc("tb1", "booking_lookup", { orderRef });
    assert.equal(looked.observation.status, "CANCELLED");
    const status = await app.rpc("tb1", "contract_status", {});
    assert.equal(status.stage, "terminal");
    assert.equal(status.terminalState, "cancelled");
    void runId;
  } finally { await app.close(); }
});

test("booking_cancel runs after a claimed mismatch (terminal verification_failed)", async () => {
  const app = await boot();
  try {
    const { orderRef } = await bookedPair(app.rpc, 302, "tb2", "tp2");
    const prepV = await app.rpc("tb2", "verification_prepare", {
      orderRef, result: "mismatch", findingsDigest: `0x${"bb".repeat(32)}`,
    });
    const verified = await signedSubmit(app.rpc, {
      token: "tb2", role: "buyer", prepared: prepV, submitTool: "verification_submit",
    });
    assert.equal(verified.terminalState, "verification_failed", JSON.stringify(verified));

    // The run is terminal — cancel is the one provider action still allowed.
    const prep = await app.rpc("tp2", "booking_cancel_prepare", { reason: "buyer disputed the order" });
    assert.ok(prep.envelope, JSON.stringify(prep));
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval,
    });
    const cancelled = await signedSubmit(app.rpc, {
      token: "tp2", role: "provider", prepared: prep,
      submitTool: "booking_cancel_submit", extraArgs: { approval },
    });
    assert.equal(cancelled.status, "CANCELLED", JSON.stringify(cancelled));
    assert.equal(cancelled.terminalState, "cancelled");
    const status = await app.rpc("tb2", "contract_status", {});
    assert.equal(status.terminalState, "cancelled");
  } finally { await app.close(); }
});

test("booking_cancel is refused after settlement; a replayed submit is idempotent", async () => {
  const app = await boot();
  try {
    // Settled run → cancel refused.
    const settled = await bookedPair(app.rpc, 303, "tb3", "tp3");
    const prepV = await app.rpc("tb3", "verification_prepare", {
      orderRef: settled.orderRef, result: "match", findingsDigest: `0x${"cc".repeat(32)}`,
    });
    await signedSubmit(app.rpc, { token: "tb3", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
    const prepS = await app.rpc("tb3", "settlement_prepare", {});
    const settleApproval = makeApproval({
      envelope: prepS.envelope, role: "buyer", action: "settlement",
      tool: "settlement_authorize", key: keys.buyerApproval,
    });
    const settledRes = await signedSubmit(app.rpc, {
      token: "tb3", role: "buyer", prepared: prepS,
      submitTool: "settlement_authorize", extraArgs: { approval: settleApproval },
    });
    assert.equal(settledRes.status, "released", JSON.stringify(settledRes));
    const late = await app.rpc("tp3", "booking_cancel_prepare", { reason: "too late" });
    assert.equal(late.error, "ALREADY_TERMINAL", JSON.stringify(late));

    // Idempotent replay on a fresh run: cancel once, then resubmit the SAME
    // envelope — the recorded cancel is returned, not a nonce error.
    const again = await bookedPair(app.rpc, 304, "tb4", "tp4");
    const prep = await app.rpc("tp4", "booking_cancel_prepare", { reason: "ops" });
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_cancel_submit", key: keys.providerApproval,
    });
    const first = await signedSubmit(app.rpc, {
      token: "tp4", role: "provider", prepared: prep,
      submitTool: "booking_cancel_submit", extraArgs: { approval },
    });
    assert.equal(first.status, "CANCELLED", JSON.stringify(first));
    const replay = await app.rpc("tp4", "booking_cancel_submit", {
      envelope: prep.envelope,
      signatureHex: signRoleSig(keys.providerSigner.priv, {
        runId: prep.envelope.runId, role: "provider", tool: prep.envelope.tool,
        nonce: prep.envelope.nonce, payloadDigest: prep.envelope.payloadDigest,
      }),
      approval,
    });
    assert.equal(replay.status, "CANCELLED", JSON.stringify(replay));
    assert.equal(replay.orderRef, again.orderRef);
    assert.equal(replay.terminalState, "cancelled");
  } finally { await app.close(); }
});

test("booking_cancel is provider-only and needs a booking-class approval", async () => {
  const app = await boot();
  try {
    const { orderRef } = await bookedPair(app.rpc, 305, "tb5", "tp5");

    // Wrong role: the buyer can't see or call either cancel tool.
    const buyerPrep = await app.rpc("tb5", "booking_cancel_prepare", { reason: "buyer attempt" });
    assert.equal(buyerPrep.error, "ROLE_REFUSED", JSON.stringify(buyerPrep));

    // Right role, no approval → APPROVAL_INVALID.
    const prep = await app.rpc("tp5", "booking_cancel_prepare", { reason: "ops" });
    assert.ok(prep.envelope);
    const noApproval = await signedSubmit(app.rpc, {
      token: "tp5", role: "provider", prepared: prep, submitTool: "booking_cancel_submit",
      extraArgs: { approval: makeApproval({
        envelope: prep.envelope, role: "provider", action: "settlement", // wrong class
        tool: "booking_cancel_submit", key: keys.providerApproval,
      }) },
    });
    assert.equal(noApproval.error, "APPROVAL_INVALID", JSON.stringify(noApproval));
    // And nothing was cancelled.
    const looked = await app.rpc("tb5", "booking_lookup", { orderRef });
    assert.equal(looked.observation.status, "ISSUED");
  } finally { await app.close(); }
});

// === 2. poll limiter is per PRINCIPAL =========================================

test("the poll limiter is per principal — a fresh session does NOT reset it", async () => {
  const app = await boot({ handler: { pollsPerMinute: 3 } });
  try {
    for (let i = 0; i < 3; i++) {
      const out = await app.rpc("tp6", "rendezvous_inbox");
      assert.equal(out.error, undefined, `poll ${i}: ${JSON.stringify(out)}`);
    }
    const limited = await app.rpc("tp6", "rendezvous_inbox");
    assert.equal(limited.error, "RATE_LIMITED", JSON.stringify(limited));

    // A fresh session for the SAME principal must still be limited.
    await app.freshSession("tp6");
    const reset = await app.rpc("tp6", "rendezvous_inbox");
    assert.equal(reset.error, "RATE_LIMITED",
      "a new session must not reset the per-principal poll budget");
    // A different principal is unaffected.
    const other = await app.rpc("tp7", "rendezvous_inbox");
    assert.equal(other.error, undefined, JSON.stringify(other));
  } finally { await app.close(); }
});

// === 3. key validity at the source ============================================

test("an already-expired published key refuses to start", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "contract-n4b4-key-"));
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
    CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(32, 7).toString("base64"),
    CONTRACT_POLICY_DIGESTS: `buyer:0x${"7".repeat(64)},provider:0x${"8".repeat(64)}`,
    CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00.000Z",
    CONTRACT_SERVER_KEY_VALID_UNTIL: "2020-06-01T00:00:00.000Z", // long past
    CONTRACT_STATE_DIR: dir,
  });
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /valid|expir/i);
});

test("a service past its key's validUntil refuses to sign — every call is refused before dispatch", async () => {
  // The key expired 1s ago: receipts and envelopes cannot be signed, so
  // NOTHING may execute — even read-only polls would land unevidenced.
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
    signerValidUntilMs: Date.now() - 1_000,
  });
  const app = await boot({ service });
  try {
    const status = await app.rpc("tb8", "contract_status", {});
    assert.equal(status.error, "CONTRACT_UNAVAILABLE", JSON.stringify(status));
    const search = await app.rpc("tb8", "rendezvous_search", { origin: "LON", destination: "PAR" });
    assert.equal(search.error, "CONTRACT_UNAVAILABLE", JSON.stringify(search));
    // Nothing was receipted either — the chain stays empty.
    assert.equal(service.preBindFeed("kb8"), undefined);
  } finally { await app.close(); }
});
