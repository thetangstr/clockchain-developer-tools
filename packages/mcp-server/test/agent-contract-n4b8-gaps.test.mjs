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
import { eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";

// N4b-8 gaps 4/5/6: tsa-backed anchoring (agreement digest + terminal chain
// head), reachable blocked_by_policy via a signed deny, and idempotent
// booking_execute replay. The anchor under test is an injected fake — no
// network (the production tsa_issue client is config-gated).

const ACCEPT = "application/json, text/event-stream";

// --- certificate minter + role keys (same wire format as the business suite) -

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
  ["kb1", "kb2", "kb3", "kb4"].map((k) => [k, PRINCIPAL_ADDRESS]),
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

// --- fake anchor --------------------------------------------------------------

function fakeAnchor({ fail = false } = {}) {
  const calls = [];
  return {
    calls,
    async anchor({ kind, runId, digestHex }) {
      calls.push({ kind, runId, digestHex });
      if (fail) throw new Error("anchor substrate unreachable (fake)");
      return {
        anchorId: `tsa:fake-${kind}-${digestHex.slice(2, 10)}`,
        eventHash: `0x${createHash("sha256").update(`${kind}|${digestHex}`).digest("hex")}`,
        anchor: { ledgerId: "ledger-fake", blockHeight: "42", time: "2026-09-01T00:00:00Z", status: "anchored" },
      };
    },
  };
}

// --- service + HTTP harness ---------------------------------------------------

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tb2:buyer:kb2:9452:initiator",
  "tb3:buyer:kb3:9452:initiator",
  "tb4:buyer:kb4:9452:initiator",
  "tp1:provider:kp1:9453:responder",
  "tp2:provider:kp2:9453:responder",
  "tp3:provider:kp3:9453:responder",
  "tp4:provider:kp4:9453:responder",
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };
const authenticate = tokenAuthenticator(parseContractTokens(TOKENS_RAW));

async function boot(serviceOptions = {}) {
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER, policyDigests: POLICY, principals: PRINCIPALS,
    stateDir: mkdtempSync(path.join(tmpdir(), "n4b8-gaps-")),
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

async function waitFor(fn, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await new Promise((r) => setTimeout(r, 10));
  }
}

// --- A3: anchoring ------------------------------------------------------------

test("agreement digest and terminal chain head are anchored; ids land on receipts and agreement_get", async () => {
  const anchor = fakeAnchor();
  const env = await boot({ anchor });
  try {
    const { runId } = await agreePair(env, uuid(201), "tb1", "tp1");

    // Agreement anchor resolved asynchronously — status + id in agreement_get.
    await waitFor(() => env.service.runFor(runId)?.anchors?.agreement?.status === "anchored");
    const got = await env.callTool("tp1", "agreement_get", {});
    assert.equal(got.anchor.status, "anchored");
    assert.match(got.anchor.anchorId, /^tsa:fake-agreement-[0-9a-f]{8}$/);
    assert.equal(got.anchor.ledger.status, "anchored");

    // Terminal anchor fires at the terminal transition over the chain head.
    await env.callTool("tb1", "contract_withdraw", {});
    await waitFor(() => env.service.runFor(runId)?.anchors?.terminal?.status === "anchored");
    const run = env.service.runFor(runId);
    const terminalDigest = run.anchors.terminal.digest;

    // The anchored digest is the chain head AT the terminal transition —
    // the withdraw call's own receipt is appended right after endRun fires,
    // so its prevHash IS the anchored head.
    const feed = env.service.receiptFeed(runId);
    const withdrawReceipt = feed.receipts.find((r) => r.tool === "contract_withdraw");
    assert.equal(withdrawReceipt.prevHash, terminalDigest);

    // Both outcomes are receipted; the full chain (incl. evidence receipts)
    // still verifies.
    const anchorReceipts = feed.receipts.filter((r) => r.tool === "anchor");
    assert.equal(anchorReceipts.length, 2);
    assert.ok(anchorReceipts.every((r) => r.outcome === "anchor_anchored"));
    const full = verifyChain(feed.receipts, { [SIGNER.keyId]: serverKeys.publicKey });
    assert.equal(full.ok, true);

    const st = await env.callTool("tb1", "contract_status", {});
    assert.equal(st.anchor, "ok");
    assert.equal(st.anchors.terminal.status, "anchored");
  } finally { env.close(); }
});

test("an anchoring failure is recorded and surfaced as anchor:failed — never silent", async () => {
  const anchor = fakeAnchor({ fail: true });
  const env = await boot({ anchor });
  try {
    const { runId } = await agreePair(env, uuid(202), "tb2", "tp2");
    await waitFor(() => env.service.runFor(runId)?.anchors?.agreement?.status === "failed");

    const got = await env.callTool("tp2", "agreement_get", {});
    assert.equal(got.anchor.status, "failed");
    assert.match(got.anchor.error, /unreachable/);

    const st = await env.callTool("tb2", "contract_status", {});
    assert.equal(st.anchor, "failed");
    assert.equal(st.anchors.agreement.status, "failed");

    const feed = env.service.receiptFeed(runId);
    const failed = feed.receipts.filter((r) => r.outcome === "anchor_failed");
    assert.equal(failed.length, 1);
    const verdict = verifyChain(feed.receipts, { [SIGNER.keyId]: serverKeys.publicKey });
    assert.equal(verdict.ok, true);
  } finally { env.close(); }
});

test("no anchor configured → anchor:disabled, agreement_get says disabled", async () => {
  const env = await boot();
  try {
    const { runId } = await agreePair(env, uuid(203), "tb3", "tp3");
    const got = await env.callTool("tp3", "agreement_get", {});
    assert.equal(got.anchor.status, "disabled");
    const st = await env.callTool("tb3", "contract_status", {});
    assert.equal(st.anchor, "disabled");
    assert.equal(st.anchors, null);
    const feed = env.service.receiptFeed(runId);
    assert.equal(feed.receipts.filter((r) => r.tool === "anchor").length, 0);
  } finally { env.close(); }
});

// --- A4: reachable blocked_by_policy -------------------------------------------

test("a signed deny approval on booking_execute ends the run blocked_by_policy", async () => {
  const terminalCalls = [];
  const env = await boot({
    onTerminalRun: (run, terminalState) => terminalCalls.push({ runId: run.runId, terminalState }),
  });
  try {
    const { runId, agreementId } = await agreePair(env, uuid(204), "tb4", "tp4");
    const prep = await env.callTool("tp4", "booking_prepare", { agreementId });
    const deny = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval, decision: "deny",
    });
    const out = await signedSubmit(env, {
      token: "tp4", role: "provider", prepared: prep,
      submitTool: "booking_execute", extraArgs: { approval: deny },
    });
    assert.equal(out.error, "POLICY_DENIED", JSON.stringify(out));

    // Terminal, receipted, and the terminal hook (close emitter) fired.
    const st = await env.callTool("tb4", "contract_status", {});
    assert.equal(st.stage, "terminal");
    assert.equal(st.terminalState, "blocked_by_policy");
    assert.deepEqual(terminalCalls, [{ runId, terminalState: "blocked_by_policy" }]);

    // No booking exists; consequential tools are done.
    const late = await env.callTool("tb4", "booking_lookup", { orderRef: "ORD-x" });
    assert.ok(late.observation !== undefined || late.error !== undefined);
    const prep2 = await env.callTool("tp4", "booking_prepare", { agreementId });
    assert.equal(prep2.error, "ALREADY_TERMINAL");

    const feed = env.service.receiptFeed(runId);
    const verdict = verifyChain(feed.receipts, { [SIGNER.keyId]: serverKeys.publicKey });
    assert.equal(verdict.ok, true);
    const denied = feed.receipts.find((r) => r.tool === "booking_execute");
    assert.match(denied.outcome, /POLICY_DENIED/);

    // A forged "deny" (decision field flipped post-signature) stays invalid.
    const env2 = await boot({});
    try {
      const { agreementId: aid2 } = await agreePair(env2, uuid(205), "tb3", "tp3");
      const prep3 = await env2.callTool("tp3", "booking_prepare", { agreementId: aid2 });
      const allow = makeApproval({
        envelope: prep3.envelope, role: "provider", action: "booking",
        tool: "booking_execute", key: keys.providerApproval, decision: "allow",
      });
      const forged = { ...allow, decision: "deny" }; // signature still covers "allow"
      const out2 = await signedSubmit(env2, {
        token: "tp3", role: "provider", prepared: prep3,
        submitTool: "booking_execute", extraArgs: { approval: forged },
      });
      assert.equal(out2.error, "APPROVAL_INVALID");
      const st2 = await env2.callTool("tb3", "contract_status", {});
      assert.equal(st2.terminalState, null);
    } finally { env2.close(); }
  } finally { env.close(); }
});

// --- A5: idempotent booking_execute replay -------------------------------------

test("a replayed booking_execute returns the original result; different approval/args refused", async () => {
  const env = await boot();
  try {
    const { agreementId } = await agreePair(env, uuid(206), "tb1", "tp1");
    const prep = await env.callTool("tp1", "booking_prepare", { agreementId });
    const approval = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval,
    });
    const signatureHex = signRoleSig(keys.providerSigner.priv, {
      runId: prep.envelope.runId, role: "provider", tool: prep.envelope.tool,
      nonce: prep.envelope.nonce, payloadDigest: prep.envelope.payloadDigest,
    });
    const args = { envelope: prep.envelope, signatureHex, approval };

    const first = await env.callTool("tp1", "booking_execute", args);
    assert.equal(first.simulated, true, JSON.stringify(first));
    assert.match(first.orderRef, /^ORD-/);

    // Byte-identical replay → the recorded result (fresh serverNonce aside).
    const replay = await env.callTool("tp1", "booking_execute", args);
    assert.equal(replay.orderRef, first.orderRef);
    assert.equal(replay.pnr, first.pnr);
    assert.deepEqual(replay.tickets, first.tickets);
    assert.equal(replay.simulated, true);

    // Different approval → refused; no double-booking.
    const approval2 = makeApproval({
      envelope: prep.envelope, role: "provider", action: "booking",
      tool: "booking_execute", key: keys.providerApproval,
    });
    approval2.ts += 1; // different record, re-signed? no — mutate then re-sign honestly
    approval2.signature = eip191SignDigest32(
      Buffer.from(computeApprovalSigDigest({
        runId: prep.envelope.runId, role: "provider",
        record: { role: "provider", action: "booking", digest: approval2.digest, policyDigest: approval2.policyDigest, decision: "allow", ts: approval2.ts, approverKeyId: approval2.approverKeyId },
      }).slice(2), "hex"),
      keys.providerApproval.priv,
    );
    const diffApproval = await env.callTool("tp1", "booking_execute", { ...args, approval: approval2 });
    assert.equal(diffApproval.error, "STATE_REFUSED");

    // Different args (mutated signatureHex → different request digest) → refused.
    const diffEnv = await env.callTool("tp1", "booking_execute", {
      envelope: prep.envelope, signatureHex: `0x${"ff".repeat(65)}`, approval,
    });
    assert.equal(diffEnv.error, "STATE_REFUSED");

    // Still one booking on the run — the order ref never advanced.
    const again = await env.callTool("tp1", "booking_execute", args);
    assert.equal(again.orderRef, first.orderRef);
    const run = env.service.runFor(prep.envelope.runId);
    assert.equal(run.booking.orderRef, first.orderRef);
  } finally { env.close(); }
});
