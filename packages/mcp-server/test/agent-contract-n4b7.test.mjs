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

const ACCEPT = "application/json, text/event-stream";

// N4b-7 (docs/agent-contract/N4B7-BRIEF equivalent — briefs/n4b7-late-bind.md):
//  1. Late agentId: `token:role:keyId:*:side` — the agentId is taken from the
//     certificate's party on the token's side at contract_bind and recorded
//     write-once in durable state {keyId → agentId, runId}. A second bind of
//     the same token to a different agentId or run → STATE_REFUSED. Static
//     tokens are unchanged.
//  2. The bind-statement hook (the P-GAP), gated by
//     CONTRACT_REQUIRE_BIND_STATEMENT=1 (mandatory at CONTRACT_LEVEL S|P):
//     contract_bind_challenge issues a single-use short-TTL nonce;
//     contract_bind accepts an optional DRAFT bindStatement whose EIP-191
//     signature must recover to the certificate party's sessionKeyAddress —
//     NOT the hostSessionKeyCertificate.
//  3. Bind receipts record bindMode: static|late + bindStatement:
//     verified|absent.

// --- test-only certificate minter (parameterized parties) -------------------

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64");
}

const rootKey = generateKeyPairSync("ed25519");
const HOST_ROOTS = Object.freeze([
  { kid: "root-test", fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex") },
]);

function mintCertificate({ session, sessionId, parties, t = Date.now() }) {
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
      publicKey: rawPublicKeyBase64(rootKey.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(certificate), "utf8"), rootKey.privateKey).toString("base64"),
    },
  };
  const party = ({ sessionKeyAddress, agentId }, n) => ({
    sessionKeyAddress,
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
  const initiator = party(parties.initiator, 0);
  const responder = party(parties.responder, 1);
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

// --- secp256k1 session keys (the handshake parties' sessionKeyAddress) -------

const secpPriv = (n) => `0x${n.toString(16).padStart(64, "0")}`;
function pubFromPriv(privHex) {
  const dummy = Buffer.alloc(32, 1);
  const sig = eip191SignDigest32(dummy, privHex);
  return `0x${Buffer.from(eip191RecoverPublicKey(dummy, sig)).toString("hex")}`;
}
const sessionEvm = {
  initiator: { priv: secpPriv(0xe1) },
  responder: { priv: secpPriv(0xe2) },
  stranger: { priv: secpPriv(0xe3) },
};
for (const k of Object.values(sessionEvm)) {
  k.address = publicKeyToAddress(Buffer.from(pubFromPriv(k.priv).slice(2), "hex"));
}

const keys = {
  buyerSigner: { keyId: "signer-buyer", priv: secpPriv(0xb1) },
  buyerApproval: { keyId: "approval-buyer", priv: secpPriv(0xb2) },
  providerSigner: { keyId: "signer-provider", priv: secpPriv(0xc1) },
  providerApproval: { keyId: "approval-provider", priv: secpPriv(0xc2) },
};
for (const k of Object.values(keys)) k.publicKeyHex = pubFromPriv(k.priv);

const TOKENS_RAW = [
  "tb1:buyer:kb1:9452:initiator",
  "tp1:provider:kp1:9453:responder",
  "tlb1:buyer:klb1:*:initiator",
  "tlp1:provider:klp1:*:responder",
  "tlb2:buyer:klb2:*:initiator",
  "tlp2:provider:klp2:*:responder",
  "tlb3:buyer:klb3:*:initiator",
].join(",");

const serverKeys = generateKeyPairSync("ed25519");
const SIGNER = { keyId: "contract-server-test", privateKey: serverKeys.privateKey };

const POLICY_DIGESTS = Object.freeze({ buyer: `0x${"7".repeat(64)}`, provider: `0x${"8".repeat(64)}` });

function uuid(n) {
  return `deadbeef-${String(n).padStart(4, "0")}-4444-8888-${String(n).padStart(12, "0")}`;
}

const sessionKeys = new Map();
function cert(sessionN, overrides = {}) {
  if (!sessionKeys.has(sessionN)) sessionKeys.set(sessionN, generateKeyPairSync("ed25519"));
  return mintCertificate({
    session: sessionKeys.get(sessionN),
    sessionId: uuid(sessionN),
    ...(overrides.t !== undefined ? { t: overrides.t } : {}),
    parties: {
      initiator: { sessionKeyAddress: sessionEvm.initiator.address, agentId: "9501", ...overrides.initiator },
      responder: { sessionKeyAddress: sessionEvm.responder.address, agentId: "9502", ...overrides.responder },
    },
  });
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

/** DRAFT schema (n4b7): the audit agent owns the final bind-statement shape. */
function makeStatement({ runId, side, tokenKeyId, challenge, serverKeyId = SIGNER.keyId, issuedAt, domain }) {
  return {
    domain: domain ?? "agent-contract.bind/v1",
    runId, side, tokenKeyId, serverKeyId, challenge,
    issuedAt: issuedAt ?? new Date().toISOString(),
  };
}

function signStatement(priv, statement) {
  return eip191SignDigest32(Buffer.from(canonicalDigest(statement).slice(2), "hex"), priv);
}

// --- HTTP harness -----------------------------------------------------------

const CLIENT_INFO = { name: "n4b7-test-client", version: "1.0.0" };

async function boot({ serviceOptions = {}, stateDir, tokens } = {}) {
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS,
    allowLegacySealV2: true, // test posture = CONTRACT_LEVEL=L
    ...(stateDir !== undefined ? { stateDir } : {}),
    ...serviceOptions,
  });
  const handler = createContractHttpHandler({
    authenticate: tokens ?? tokenAuthenticator(parseContractTokens(TOKENS_RAW)),
    hostRoots: HOST_ROOTS, signer: SIGNER, service,
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
    return { ...(body.result?.structuredContent ?? {}), ...(body.error ? { rpcError: body.error.code } : {}) };
  };
  return {
    url, service, rpc,
    async close() { await new Promise((r) => srv.close(r)); service.close(); },
  };
}

function bindReceipt(service, runId) {
  return service.receiptFeed(runId).receipts.find((r) => r.tool === "contract_bind");
}

/**
 * A late (`*`) bind always needs a verified statement — take a fresh
 * challenge, build the statement for this exact bind, sign with the
 * certificate side's session key (or an override for adversarial tests).
 */
async function bindLate(rpc, token, { keyId, role, side, certificate, runId, priv, issuedAt }) {
  const { challenge } = await rpc(token, "contract_bind_challenge", {});
  const st = makeStatement({ runId, side, tokenKeyId: keyId, challenge, issuedAt });
  return rpc(token, "contract_bind", bindArgs(certificate, role, {
    bindStatement: st,
    bindStatementSignature: signStatement(priv ?? sessionEvm[side].priv, st),
  }));
}

// --- piece 1: late agentId ---------------------------------------------------

test("late token binds the certificate's agentId on the token's own side", async () => {
  const env = await boot();
  try {
    const c = cert(1);
    // N4b-7 HIGH-1: a late bind ALWAYS carries a verified statement.
    const buyer = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: c, runId: uuid(1),
    });
    assert.equal(buyer.bound, true);
    assert.equal(buyer.runId, uuid(1));
    // The agentId came from the cert's INITIATOR party, not the token.
    const run = env.service.runFor(buyer.runId);
    assert.equal(run.bound.buyer.agentId, "9501");
    // ... and the responder seat picks the responder's agentId.
    const provider = await bindLate(env.rpc, "tlp1", {
      keyId: "klp1", role: "provider", side: "responder", certificate: c, runId: uuid(1),
    });
    assert.equal(provider.bound, true);
    assert.equal(env.service.runFor(buyer.runId).bound.provider.agentId, "9502");
    // Receipts disclose the mode + the verified statement.
    const receipt = bindReceipt(env.service, buyer.runId);
    assert.equal(receipt.bindMode, "late");
    assert.equal(receipt.bindStatement, "verified");
    assert.equal(receipt.bindAssurance, "late-certificate-party");
    // ... and the tool result carries the same disclosure.
    assert.equal(buyer.bindMode, "late");
    assert.equal(buyer.bindStatement, "verified");
  } finally { await env.close(); }
});

test("static tokens keep the pinned-agentId check and bindMode: static", async () => {
  const env = await boot();
  try {
    // Static pin still enforced: tb1 pins agentId 9452; the cert says 9501.
    const refused = await env.rpc("tb1", "contract_bind", bindArgs(cert(2), "buyer"));
    assert.equal(refused.error, "CERTIFICATE_INVALID");
    // A cert whose initiator carries the pinned agentId binds fine.
    const c = cert(3, { initiator: { agentId: "9452" } });
    const ok = await env.rpc("tb1", "contract_bind", bindArgs(c, "buyer"));
    assert.equal(ok.bound, true);
    assert.equal(env.service.runFor(ok.runId).bound.buyer.agentId, "9452");
    const receipt = bindReceipt(env.service, ok.runId);
    assert.equal(receipt.bindMode, "static");
    assert.equal(receipt.bindStatement, "absent");
    assert.equal(receipt.bindAssurance, "agentId-pinned-token");
    assert.equal(ok.bindMode, "static");
    assert.equal(ok.bindStatement, "absent");
  } finally { await env.close(); }
});

test("a static token with a verified statement reports session-key-possession", async () => {
  const env = await boot();
  try {
    const c = cert(30, { initiator: { agentId: "9452" } });
    const { challenge } = await env.rpc("tb1", "contract_bind_challenge", {});
    const st = makeStatement({ runId: uuid(30), side: "initiator", tokenKeyId: "kb1", challenge });
    const bound = await env.rpc("tb1", "contract_bind",
      bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st) }));
    assert.equal(bound.bound, true);
    const receipt = bindReceipt(env.service, bound.runId);
    assert.equal(receipt.bindMode, "static");
    assert.equal(receipt.bindStatement, "verified");
    assert.equal(receipt.bindAssurance, "session-key-possession");
    assert.equal(bound.bindAssurance, "session-key-possession");
  } finally { await env.close(); }
});

test("late binding holds for the live run — a different agentId or run refuses while it is live", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b7-"));
  const env = await boot({ stateDir });
  try {
    const bound = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(4), runId: uuid(4),
    });
    assert.equal(bound.bound, true);
    // Same token, a DIFFERENT handshake certificate (different run) while run
    // 1 is still live: a valid statement reaches the binding gate → refused.
    const other = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(5, { initiator: { agentId: "9601" } }), runId: uuid(5),
    });
    assert.equal(other.error, "STATE_REFUSED");
    // ... and the same agentId on a different live-run certificate refuses too.
    const sameAgent = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(8), runId: uuid(8),
    });
    assert.equal(sameAgent.error, "STATE_REFUSED");
    // The live run is untouched.
    assert.equal(env.service.runFor(bound.runId).bound.buyer.agentId, "9501");
  } finally { await env.close(); }
});

// Late-bind release (P7/P8 fix): a `*` keyId's binding is RUN-scoped. When the
// bound run reaches a terminal state, or its TTL lapses, the keyId may bind a
// NEW run with a new certificate + a freshly verified bind statement. One live
// run per keyId still holds; a released binding never re-opens the old run.
for (const terminalState of ["settled", "cancelled", "no_agreement", "verification_failed", "blocked_by_policy", "withdrawn"]) {
  test(`late binding is released when the run ends (${terminalState}) — run 2 binds a new certificate`, async () => {
    const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b7-rel-"));
    const env = await boot({ stateDir });
    const base = 200 + ["settled", "cancelled", "no_agreement", "verification_failed", "blocked_by_policy", "withdrawn"].indexOf(terminalState) * 3;
    try {
      const run1 = await bindLate(env.rpc, "tlb1", {
        keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(base), runId: uuid(base),
      });
      assert.equal(run1.bound, true);
      env.service.endRun(env.service.runFor(run1.runId), terminalState);
      // Run 2: a different certificate (and a different, freshly registered
      // agentId) — binds OK with its own verified statement.
      const run2 = await bindLate(env.rpc, "tlb1", {
        keyId: "klb1", role: "buyer", side: "initiator",
        certificate: cert(base + 1, { initiator: { agentId: "9611" } }), runId: uuid(base + 1),
      });
      assert.equal(run2.bound, true, JSON.stringify(run2));
      assert.equal(run2.runId, uuid(base + 1));
      assert.equal(env.service.runFor(run2.runId).bound.buyer.agentId, "9611");
      assert.equal(bindReceipt(env.service, run2.runId).bindMode, "late");
      // The old run stays terminal — the release never re-opens it.
      assert.equal(env.service.runFor(run1.runId).terminalState, terminalState);
      // Run 3 while run 2 is live is still refused.
      const run3 = await bindLate(env.rpc, "tlb1", {
        keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(base + 2), runId: uuid(base + 2),
      });
      assert.equal(run3.error, "STATE_REFUSED");
    } finally { await env.close(); }
  });
}

test("released late binding: still needs the statement, and a stranger's key cannot claim the agentId", async () => {
  const env = await boot();
  try {
    const run1 = await bindLate(env.rpc, "tlb2", {
      keyId: "klb2", role: "buyer", side: "initiator", certificate: cert(230), runId: uuid(230),
    });
    assert.equal(run1.bound, true);
    env.service.endRun(env.service.runFor(run1.runId), "settled");
    const c = cert(231, { initiator: { agentId: "9999" } });
    const statementless = await env.rpc("tlb2", "contract_bind", bindArgs(c, "buyer"));
    assert.equal(statementless.error, "BIND_STATEMENT_INVALID");
    const forged = await bindLate(env.rpc, "tlb2", {
      keyId: "klb2", role: "buyer", side: "initiator", certificate: c, runId: uuid(231),
      priv: sessionEvm.stranger.priv,
    });
    assert.equal(forged.error, "BIND_STATEMENT_INVALID");
  } finally { await env.close(); }
});

test("a late-bound run that never reached terminal is released at TTL", async () => {
  let now = Date.now();
  const env = await boot({ serviceOptions: { runTtlMs: 60_000, now: () => now } });
  try {
    const run1 = await bindLate(env.rpc, "tlb3", {
      keyId: "klb3", role: "buyer", side: "initiator", certificate: cert(240), runId: uuid(240),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(run1.bound, true);
    // Before TTL: refused.
    const early = await bindLate(env.rpc, "tlb3", {
      keyId: "klb3", role: "buyer", side: "initiator", certificate: cert(241), runId: uuid(241),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(early.error, "STATE_REFUSED");
    now += 61_000; // past the run TTL — the cert window (10 min) still holds
    const run2 = await bindLate(env.rpc, "tlb3", {
      keyId: "klb3", role: "buyer", side: "initiator",
      certificate: cert(242, { initiator: { agentId: "9622" } }), runId: uuid(242),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(run2.bound, true, JSON.stringify(run2));
    assert.equal(env.service.runFor(run2.runId).bound.buyer.agentId, "9622");
  } finally { await env.close(); }
});

test("late binding across a restart: the dropped run releases; its session can never re-open", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b7-rs-"));
  const env = await boot({ stateDir });
  try {
    const run1 = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(250), runId: uuid(250),
    });
    assert.equal(run1.bound, true);
  } finally { await env.close(); }
  const env2 = await boot({ stateDir });
  try {
    // The in-flight run did not survive the restart — re-binding its
    // certificate is refused (used-session guard)...
    const replay = await bindLate(env2.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(250), runId: uuid(250),
    });
    assert.equal(replay.error, "STATE_REFUSED");
    // ... but a NEW run binds — the keyId is not stranded forever.
    const run2 = await bindLate(env2.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(251, { initiator: { agentId: "9651" } }), runId: uuid(251),
    });
    assert.equal(run2.bound, true, JSON.stringify(run2));
  } finally { await env2.close(); }
});

// Half-bound run release (live: scripted-2026-10-03-9/-10). The buyer bound
// late, the provider's bind refused, and the buyer's token stayed seated on a
// run that could never finish: no business tool (incl. contract_withdraw)
// works until BOTH sides bind, so only the 24 h run TTL freed it. A run that
// is still missing a party once its certificate window (validUntil + grace)
// has passed can never complete — no bind can verify that certificate any
// more — so it ends `expired_unbound` and releases its seats. The bound party
// may also withdraw its own half-bound run before then.
const CERT_WINDOW_MS = 10 * 60_000; // mintCertificate: validUntil = t + 10 min
const GRACE_MS = 600_000;           // default (and maximum) certificate grace

test("half-bound run: the bound buyer's token is released once the bind deadline passes (expired_unbound)", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b7-hb-"));
  let now = Date.now();
  const t0 = now;
  const env = await boot({ stateDir, serviceOptions: { now: () => now } });
  try {
    const certA = cert(260, { t: t0 });
    const runA = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: certA, runId: uuid(260),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(runA.bound, true, JSON.stringify(runA));
    const status0 = await env.rpc("tlb1", "contract_status", {});
    assert.equal(status0.stage, "handshake");
    assert.equal(status0.terminalState, null);

    // Inside the bind window the provider could still bind: the seat holds.
    now = t0 + CERT_WINDOW_MS + GRACE_MS - 1_000;
    const early = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(261, { t: now }), runId: uuid(261),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(early.error, "STATE_REFUSED");
    assert.equal(env.service.runFor(runA.runId).terminalState, null);

    // Past validUntil + grace no bind can ever verify run A's certificate.
    now = t0 + CERT_WINDOW_MS + GRACE_MS + 1_000;
    const status1 = await env.rpc("tlb1", "contract_status", {});
    assert.equal(status1.stage, "terminal", JSON.stringify(status1));
    assert.equal(status1.terminalState, "expired_unbound");
    // The provider can never join the dead run.
    const lateProvider = await bindLate(env.rpc, "tlp1", {
      keyId: "klp1", role: "provider", side: "responder", certificate: certA, runId: uuid(260),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(lateProvider.error, "CERTIFICATE_INVALID");
    assert.equal(env.service.runFor(runA.runId).bound.provider, undefined);
    // The buyer token binds a NEW run with no client action.
    const runB = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(262, { t: now, initiator: { agentId: "9662" } }), runId: uuid(262),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(runB.bound, true, JSON.stringify(runB));
    assert.equal(env.service.runFor(runB.runId).bound.buyer.agentId, "9662");
    // Receipts stay intact: run A keeps its bind receipt and is terminal.
    const runAState = env.service.runFor(runA.runId);
    assert.equal(runAState.terminalState, "expired_unbound");
    assert.equal(bindReceipt(env.service, runA.runId).principal.keyId, "klb1");
    assert.equal(env.service.terminalJobFor(runA.runId).terminalState, "expired_unbound");
  } finally { await env.close(); }
});

test("a fully bound run is NOT expired by the bind deadline", async () => {
  let now = Date.now();
  const t0 = now;
  const env = await boot({ serviceOptions: { now: () => now } });
  try {
    const c = cert(270, { t: t0 });
    const b = await bindLate(env.rpc, "tlb2", {
      keyId: "klb2", role: "buyer", side: "initiator", certificate: c, runId: uuid(270),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(b.bound, true, JSON.stringify(b));
    const p = await bindLate(env.rpc, "tlp2", {
      keyId: "klp2", role: "provider", side: "responder", certificate: c, runId: uuid(270),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(p.bound, true, JSON.stringify(p));
    now = t0 + CERT_WINDOW_MS + GRACE_MS + 60_000;
    const status = await env.rpc("tlb2", "contract_status", {});
    assert.equal(status.stage, "bound", JSON.stringify(status));
    assert.equal(status.terminalState, null);
    assert.equal(env.service.runFor(uuid(270)).terminalState, null);
  } finally { await env.close(); }
});

test("half-bound run: the bound party may withdraw its own run; the counterparty can no longer join it", async () => {
  const env = await boot();
  try {
    const certA = cert(280);
    const runA = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: certA, runId: uuid(280),
    });
    assert.equal(runA.bound, true, JSON.stringify(runA));
    // A different principal has no run — it cannot withdraw someone else's seat.
    const stranger = await env.rpc("tlb2", "contract_withdraw", {});
    assert.equal(stranger.error, "STATE_REFUSED");
    assert.equal(env.service.runFor(runA.runId).terminalState, null);

    const withdrawn = await env.rpc("tlb1", "contract_withdraw", {});
    assert.equal(withdrawn.state, "withdrawn", JSON.stringify(withdrawn));
    assert.equal(env.service.runFor(runA.runId).terminalState, "no_agreement");
    // The provider's certificate is still inside its window, but the run
    // ended: joining a terminal run is refused (no post-terminal seat).
    const provider = await bindLate(env.rpc, "tlp1", {
      keyId: "klp1", role: "provider", side: "responder", certificate: certA, runId: uuid(280),
    });
    assert.equal(provider.error, "STATE_REFUSED");
    assert.equal(env.service.runFor(runA.runId).bound.provider, undefined);
    // The buyer token is free for a new run right away.
    const runB = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(281, { initiator: { agentId: "9681" } }), runId: uuid(281),
    });
    assert.equal(runB.bound, true, JSON.stringify(runB));
    // The withdraw receipt is on run A's chain.
    assert.ok(env.service.receiptFeed(runA.runId).receipts.some((r) => r.tool === "contract_withdraw" && r.outcome === "ok"));
  } finally { await env.close(); }
});

test("a late token cannot bind a certificate for someone else's agentId (HIGH-1)", async () => {
  const env = await boot(); // no requireBindStatement — the late bind must still demand it
  try {
    // The cert names agentId 9999 on the initiator side — NOT this token
    // holder's claim. Without a statement the bind is an identity takeover.
    const c = cert(40, { initiator: { agentId: "9999" } });
    const statementless = await env.rpc("tlb1", "contract_bind", bindArgs(c, "buyer"));
    assert.equal(statementless.error, "BIND_STATEMENT_INVALID");
    // A statement signed by the ATTACKER's key (not the cert party's session
    // key) refuses too — possession of the certificate is not possession of
    // the identity.
    const { challenge } = await env.rpc("tlb1", "contract_bind_challenge", {});
    const st = makeStatement({ runId: uuid(40), side: "initiator", tokenKeyId: "klb1", challenge });
    const forged = await env.rpc("tlb1", "contract_bind",
      bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.stranger.priv, st) }));
    assert.equal(forged.error, "BIND_STATEMENT_INVALID");
    // The real cert party's session key binds — legitimately, even though the
    // token was provisioned without an agentId.
    const honest = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: c, runId: uuid(40),
    });
    assert.equal(honest.bound, true);
    assert.equal(env.service.runFor(uuid(40)).bound.buyer.agentId, "9999");
  } finally { await env.close(); }
});

// --- piece 2: bind statement (the P-GAP, DRAFT schema) ----------------------

test("contract_bind_challenge issues a single-use nonce; the statement proves session-key possession", async () => {
  const env = await boot({ serviceOptions: { requireBindStatement: true } });
  try {
    const challenge = await env.rpc("tlb1", "contract_bind_challenge", {});
    assert.match(challenge.challenge, /^[0-9a-f]{64}$/);
    assert.ok(typeof challenge.expiresAt === "string");
    const c = cert(10);
    const st = makeStatement({ runId: uuid(10), side: "initiator", tokenKeyId: "klb1", challenge: challenge.challenge });
    const bound = await env.rpc("tlb1", "contract_bind",
      bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st) }));
    assert.equal(bound.bound, true);
    const receipt = bindReceipt(env.service, bound.runId);
    assert.equal(receipt.bindMode, "late");
    assert.equal(receipt.bindStatement, "verified");
    // Single-use: a second bind naming the SAME challenge refuses.
    const c2 = cert(11);
    const st2 = makeStatement({ runId: uuid(11), side: "initiator", tokenKeyId: "klb2", challenge: challenge.challenge });
    const replay = await env.rpc("tlb2", "contract_bind",
      bindArgs(c2, "buyer", { bindStatement: st2, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st2) }));
    assert.equal(replay.error, "BIND_STATEMENT_INVALID");
  } finally { await env.close(); }
});

test("the challenge expires — a stale nonce refuses", async () => {
  let now = Date.now();
  const env = await boot({ serviceOptions: { requireBindStatement: true, bindChallengeTtlMs: 5_000, now: () => now } });
  try {
    const { challenge } = await env.rpc("tlb1", "contract_bind_challenge", {});
    now += 10_000; // past the TTL — the cert window (10 min) still holds
    const st = makeStatement({ runId: uuid(12), side: "initiator", tokenKeyId: "klb1", challenge });
    const refused = await env.rpc("tlb1", "contract_bind",
      bindArgs(cert(12), "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st) }));
    assert.equal(refused.error, "BIND_STATEMENT_INVALID");
  } finally { await env.close(); }
});

test("a statement signed by the wrong key refuses — other side's or a stranger's", async () => {
  const env = await boot({ serviceOptions: { requireBindStatement: true } });
  try {
    const { challenge } = await env.rpc("tlb1", "contract_bind_challenge", {});
    const st = makeStatement({ runId: uuid(13), side: "initiator", tokenKeyId: "klb1", challenge });
    // The OTHER side's session key.
    const wrongSide = await env.rpc("tlb1", "contract_bind",
      bindArgs(cert(13), "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.responder.priv, st) }));
    assert.equal(wrongSide.error, "BIND_STATEMENT_INVALID");
    // An unrelated key entirely.
    const stranger = await env.rpc("tlb1", "contract_bind",
      bindArgs(cert(13), "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.stranger.priv, st) }));
    assert.equal(stranger.error, "BIND_STATEMENT_INVALID");
  } finally { await env.close(); }
});

test("domain, runId, side, tokenKeyId or serverKeyId mismatch refuses", async () => {
  const env = await boot({ serviceOptions: { requireBindStatement: true } });
  try {
    const { challenge } = await env.rpc("tlb1", "contract_bind_challenge", {});
    const c = cert(14);
    // Domain is pinned by the DRAFT schema — wrong domain dies at the schema.
    const badDomain = makeStatement({ runId: uuid(14), side: "initiator", tokenKeyId: "klb1", challenge, domain: "agent-contract.bind/v0" });
    const dom = await env.rpc("tlb1", "contract_bind",
      bindArgs(c, "buyer", { bindStatement: badDomain, bindStatementSignature: signStatement(sessionEvm.initiator.priv, badDomain) }));
    assert.equal(dom.rpcError, -32602);
    for (const patch of [
      { runId: uuid(99) },                 // a different handshake session
      { side: "responder" },               // wrong side for a buyer token
      { tokenKeyId: "kpx" },               // not this principal's keyId
      { serverKeyId: "contract-server-2" },// not this server's keyId
    ]) {
      const st = makeStatement({ runId: uuid(14), side: "initiator", tokenKeyId: "klb1", challenge, ...patch });
      const out = await env.rpc("tlb1", "contract_bind",
        bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st) }));
      assert.equal(out.error, "BIND_STATEMENT_INVALID", JSON.stringify(patch));
    }
  } finally { await env.close(); }
});

test("CONTRACT_REQUIRE_BIND_STATEMENT: absent refuses when required; optional at L", async () => {
  const required = await boot({ serviceOptions: { requireBindStatement: true } });
  try {
    const noStatement = await required.rpc("tlb1", "contract_bind", bindArgs(cert(15), "buyer"));
    assert.equal(noStatement.error, "BIND_STATEMENT_INVALID");
  } finally { await required.close(); }
  // At L (flag off) a presented statement is still verified.
  const optional = await boot();
  try {
    const { challenge } = await optional.rpc("tlb1", "contract_bind_challenge", {});
    const st = makeStatement({ runId: uuid(16), side: "initiator", tokenKeyId: "klb1", challenge });
    const bound = await optional.rpc("tlb1", "contract_bind",
      bindArgs(cert(16), "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st) }));
    assert.equal(bound.bound, true);
    assert.equal(bindReceipt(optional.service, bound.runId).bindStatement, "verified");
    // Absence stays legal at L — but only for STATIC tokens (the token's own
    // pin is the assurance). A late `*` token must always prove possession.
    const plain = await optional.rpc("tb1", "contract_bind",
      bindArgs(cert(17, { initiator: { agentId: "9452" } }), "buyer"));
    assert.equal(plain.bound, true);
    assert.equal(bindReceipt(optional.service, plain.runId).bindStatement, "absent");
    const lateAbsent = await optional.rpc("tlb3", "contract_bind", bindArgs(cert(18), "buyer"));
    assert.equal(lateAbsent.error, "BIND_STATEMENT_INVALID");
  } finally { await optional.close(); }
});

test("a challenge issued to one principal cannot be consumed by another", async () => {
  const env = await boot({ serviceOptions: { requireBindStatement: true } });
  try {
    const { challenge } = await env.rpc("tlb1", "contract_bind_challenge", {});
    // klb2 presents klb1's challenge under its own tokenKeyId.
    const st = makeStatement({ runId: uuid(18), side: "initiator", tokenKeyId: "klb2", challenge });
    const out = await env.rpc("tlb2", "contract_bind",
      bindArgs(cert(18), "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st) }));
    assert.equal(out.error, "BIND_STATEMENT_INVALID");
  } finally { await env.close(); }
});

// --- config gate -------------------------------------------------------------

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const READY_ENV = Object.freeze({
  CONTRACT_MCP_ENABLED: "1",
  CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
  CONTRACT_SERVER_ED25519_SEED: SEED_B64,
  CONTRACT_POLICY_DIGESTS: `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`,
  CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
});

test("CONTRACT_LEVEL S|P refuse to start without CONTRACT_REQUIRE_BIND_STATEMENT=1", () => {
  const dir = () => mkdtempSync(path.join(tmpdir(), "contract-n4b7-cfg-"));
  for (const level of ["S", "P"]) {
    const missing = loadContractConfig({ ...READY_ENV, CONTRACT_LEVEL: level, CONTRACT_STATE_DIR: dir() });
    assert.equal(missing.kind, "misconfigured", `level ${level} without the flag`);
    // N4b-8 gap 3: S|P also require TELEMETRY_CLOSE_URL (terminal close sink).
    const set = loadContractConfig({
      ...READY_ENV, CONTRACT_LEVEL: level, CONTRACT_REQUIRE_BIND_STATEMENT: "1",
      TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083", CONTRACT_STATE_DIR: dir(),
    });
    assert.equal(set.kind, "ready", `level ${level} with the flag`);
    set.service.close();
  }
  // L: the flag is optional both ways.
  const lPlain = loadContractConfig({ ...READY_ENV, CONTRACT_LEVEL: "L", CONTRACT_STATE_DIR: dir() });
  assert.equal(lPlain.kind, "ready");
  lPlain.service.close();
  const lFlag = loadContractConfig({ ...READY_ENV, CONTRACT_LEVEL: "L", CONTRACT_REQUIRE_BIND_STATEMENT: "1", CONTRACT_STATE_DIR: dir() });
  assert.equal(lFlag.kind, "ready");
  lFlag.service.close();
  // Unset behaves as L; garbage refuses.
  const unset = loadContractConfig({ ...READY_ENV, CONTRACT_STATE_DIR: dir() });
  assert.equal(unset.kind, "ready");
  unset.service.close();
  const bad = loadContractConfig({ ...READY_ENV, CONTRACT_LEVEL: "X", CONTRACT_STATE_DIR: dir() });
  assert.equal(bad.kind, "misconfigured");
});

test("startup refuses a `*` token without CONTRACT_REQUIRE_BIND_STATEMENT=1 (HIGH-1)", () => {
  const dir = () => mkdtempSync(path.join(tmpdir(), "contract-n4b7-cfg-"));
  const LATE_TOKENS = "tlb1:buyer:klb1:*:initiator,tp1:provider:kp1:9453:responder";
  // Even at L — a late-binding token with no statement gate is a takeover.
  const refused = loadContractConfig({ ...READY_ENV, CONTRACT_AUTH_TOKENS: LATE_TOKENS, CONTRACT_STATE_DIR: dir() });
  assert.equal(refused.kind, "misconfigured");
  assert.match(refused.reason, /BIND_STATEMENT/i);
  const allowed = loadContractConfig({
    ...READY_ENV, CONTRACT_AUTH_TOKENS: LATE_TOKENS,
    CONTRACT_REQUIRE_BIND_STATEMENT: "1", CONTRACT_STATE_DIR: dir(),
  });
  assert.equal(allowed.kind, "ready");
  allowed.service.close();
});

// --- review fixes (LOW-4 / LOW-5 / MEDIUM-3) ---------------------------------

test("LOW-4: statement issuedAt is bounded to the challenge TTL", async () => {
  let now = Date.now();
  const env = await boot({ serviceOptions: { requireBindStatement: true, bindChallengeTtlMs: 5_000, now: () => now } });
  try {
    const { challenge } = await env.rpc("tlb1", "contract_bind_challenge", {});
    const c = cert(20);
    for (const [label, issuedAt] of [
      ["predates the challenge", new Date(now - 1_000)],
      ["past the challenge TTL", new Date(now + 6_000)],
    ]) {
      const st = makeStatement({
        runId: uuid(20), side: "initiator", tokenKeyId: "klb1", challenge,
        issuedAt: issuedAt.toISOString(),
      });
      const out = await env.rpc("tlb1", "contract_bind",
        bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: signStatement(sessionEvm.initiator.priv, st) }));
      assert.equal(out.error, "BIND_STATEMENT_INVALID", label);
    }
  } finally { await env.close(); }
});

test("LOW-5: the statement signature requires low-s and v in {27,28}", async () => {
  const SECP_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  const env = await boot({ serviceOptions: { requireBindStatement: true } });
  try {
    const { challenge } = await env.rpc("tlb1", "contract_bind_challenge", {});
    const c = cert(21);
    const st = makeStatement({ runId: uuid(21), side: "initiator", tokenKeyId: "klb1", challenge });
    const good = signStatement(sessionEvm.initiator.priv, st); // 0x + r(64) + s(64) + v(2)
    const bytes = Buffer.from(good.slice(2), "hex");
    const s = BigInt(`0x${bytes.subarray(32, 64).toString("hex")}`);
    const v = bytes[64];
    // High-s malleation (EIP-2) — same recovered address, must refuse.
    const hiS = Buffer.concat([bytes.subarray(0, 32),
      Buffer.from((SECP_N - s).toString(16).padStart(64, "0"), "hex"),
      Buffer.from([v === 27 ? 28 : 27])]);
    const malleated = `0x${hiS.toString("hex")}`;
    const hi = await env.rpc("tlb1", "contract_bind",
      bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: malleated }));
    assert.equal(hi.error, "BIND_STATEMENT_INVALID");
    // Raw recovery-id v (0|1) — recovers under the lenient path, must refuse.
    const rawV = `0x${Buffer.concat([bytes.subarray(0, 64), Buffer.from([v - 27])]).toString("hex")}`;
    const rv = await env.rpc("tlb1", "contract_bind",
      bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: rawV }));
    assert.equal(rv.error, "BIND_STATEMENT_INVALID");
    // The strict, canonical signature still binds.
    const ok = await env.rpc("tlb1", "contract_bind",
      bindArgs(c, "buyer", { bindStatement: st, bindStatementSignature: good }));
    assert.equal(ok.bound, true);
  } finally { await env.close(); }
});

test("D8: an unbound `*` principal CAN invite pre-bind — disclosed as unproven", async () => {
  const env = await boot();
  try {
    const listing = await env.rpc("tp1", "rendezvous_publish_listing", {
      title: "SFO-FCO managed travel", summary: "desk", sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`,
    });
    const seal = {
      v: 2, epk: `0x${"ab".repeat(32)}`, iv: `0x${"cd".repeat(12)}`,
      ct: `0x${"ef".repeat(32)}`, tag: `0x${"01".repeat(16)}`,
    };
    // The rendezvous precedes the handshake — an unbound `*` buyer MUST be
    // able to deliver, but nothing claims an identity it hasn't proven.
    const unbound = await env.rpc("tlb1", "rendezvous_send_invitation", {
      listingId: listing.listingId, sealedInvitation: seal,
    });
    assert.equal(unbound.delivered, true);
    assert.equal(unbound.senderAgentId, null);
    assert.equal(unbound.senderProof, "unproven-pre-bind");
    let inbox = await env.rpc("tp1", "rendezvous_inbox", {});
    let msg = inbox.messages.find((m) => m.listingId === listing.listingId && m.senderKeyId === "klb1");
    assert.equal(msg.senderAgentId, null);
    assert.equal(msg.senderProof, "unproven-pre-bind");
    // The pre-bind receipt carries the same disclosure.
    const preBindReceipt = env.service.preBindFeed("klb1").receipts.at(-1);
    assert.equal(preBindReceipt.tool, "rendezvous_send_invitation");
    assert.equal(preBindReceipt.senderProof, "unproven-pre-bind");
    // After binding, the invitation stamps the CERTIFICATE-resolved agentId.
    const c = cert(22);
    await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: c, runId: uuid(22),
    });
    const delivered = await env.rpc("tlb1", "rendezvous_send_invitation", {
      listingId: listing.listingId, sealedInvitation: seal,
    });
    assert.equal(delivered.delivered, true);
    assert.equal(delivered.senderAgentId, "9501");
    assert.equal(delivered.senderProof, "certificate-bound");
    inbox = await env.rpc("tp1", "rendezvous_inbox", {});
    msg = inbox.messages.find((m) => m.listingId === listing.listingId && m.senderKeyId === "klb1");
    assert.equal(msg.senderAgentId, "9501");
    assert.equal(msg.senderProof, "certificate-bound");
    // A static token stamps its pinned agentId — senderProof "token-pinned".
    const listing2 = await env.rpc("tp1", "rendezvous_publish_listing", {
      title: "SFO-FCO again", summary: "desk", sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`,
    });
    const staticDelivered = await env.rpc("tb1", "rendezvous_send_invitation", {
      listingId: listing2.listingId, sealedInvitation: seal,
    });
    assert.equal(staticDelivered.senderAgentId, "9452");
    assert.equal(staticDelivered.senderProof, "token-pinned");
    inbox = await env.rpc("tp1", "rendezvous_inbox", {});
    msg = inbox.messages.find((m) => m.listingId === listing2.listingId && m.senderKeyId === "kb1");
    assert.equal(msg.senderAgentId, "9452");
    assert.equal(msg.senderProof, "token-pinned");
  } finally { await env.close(); }
});

// --- pre-bind routing after terminal (live: p6-l-2026-10-03-1) ---------------
// Once a keyId had bound a run, runIdForPrincipal kept resolving that run for
// its full 24 h TTL — terminal or not — and every PRE-BIND call of the keyId
// (rendezvous_*, contract_bind_challenge, contract_status, a refused bind) was
// receipted on the OLD run's chain. The next run's pre-bind evidence was then
// unmatchable (R8): the AI run's receipts landed on scripted run a5f8a36a.
// Expected: an ended run (terminal, or released per #176/#179) no longer
// captures the keyId's pre-bind calls; they go to its pre-bind chain, whose
// head the next run's bind receipt links. The ended run's chain is untouched.

const PRE_BIND_TOOLS = new Set(["rendezvous_inbox", "contract_bind_challenge", "contract_status", "contract_bind"]);

function chainSnapshot(service, runId) {
  const receipts = service.receiptFeed(runId).receipts;
  return { length: receipts.length, digests: receipts.map((r) => canonicalDigest(r)) };
}

/** Make the pre-bind calls an agent makes before its next bind. */
async function preBindCalls(rpc, token) {
  const nonces = [];
  const inbox = await rpc(token, "rendezvous_inbox", {});
  assert.ok(Array.isArray(inbox.messages), JSON.stringify(inbox));
  nonces.push(inbox.serverNonce);
  const ch = await rpc(token, "contract_bind_challenge", {});
  assert.equal(typeof ch.challenge, "string", JSON.stringify(ch));
  nonces.push(ch.serverNonce);
  const status = await rpc(token, "contract_status", {});
  nonces.push(status.serverNonce);
  return { nonces, status };
}

async function bindBoth(env, n) {
  const c = cert(n);
  const b = await bindLate(env.rpc, "tlb1", { keyId: "klb1", role: "buyer", side: "initiator", certificate: c, runId: uuid(n) });
  assert.equal(b.bound, true, JSON.stringify(b));
  const p = await bindLate(env.rpc, "tlp1", { keyId: "klp1", role: "provider", side: "responder", certificate: c, runId: uuid(n) });
  assert.equal(p.bound, true, JSON.stringify(p));
  return b.runId;
}

test("pre-bind routing: a TERMINAL run no longer captures the keyId's pre-bind calls; the next bind links them", async () => {
  const env = await boot();
  try {
    const runA = await bindBoth(env, 300);
    const withdrawn = await env.rpc("tlb1", "contract_withdraw", {});
    assert.equal(withdrawn.state, "withdrawn", JSON.stringify(withdrawn));
    assert.equal(env.service.runFor(runA).terminalState, "no_agreement");
    const before = chainSnapshot(env.service, runA);
    const preBefore = env.service.preBindFeed("klb1")?.receipts.length ?? 0;

    const { nonces, status } = await preBindCalls(env.rpc, "tlb1");
    // Observability is kept: the caller still reads run A's terminal state ...
    assert.equal(status.terminalState, "no_agreement", JSON.stringify(status));
    // ... but run A's chain is immutable after terminal: nothing appended,
    // nothing rewritten.
    assert.deepEqual(chainSnapshot(env.service, runA), before);
    for (const r of env.service.receiptFeed(runA).receipts) {
      assert.ok(!nonces.includes(r.serverNonce), `pre-bind ${r.tool} landed on terminal run A`);
    }
    // Every pre-bind call is on klb1's pre-bind chain — each exactly once.
    const pre = env.service.preBindFeed("klb1");
    assert.equal(pre.receipts.length, preBefore + nonces.length);
    for (const nonce of nonces) {
      assert.equal(pre.receipts.filter((r) => r.serverNonce === nonce).length, 1, `nonce ${nonce} not on pre-bind chain once`);
    }
    // The next run's bind links the pre-bind head — R8 can match the evidence.
    const runB = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(301, { initiator: { agentId: "9701" } }), runId: uuid(301),
    });
    assert.equal(runB.bound, true, JSON.stringify(runB));
    const preAtBind = env.service.preBindFeed("klb1");
    assert.equal(bindReceipt(env.service, runB.runId).preBindHead, preAtBind.head);
    assert.ok(preAtBind.receipts.some((r) => r.tool === "contract_bind_challenge" && nonces.includes(r.serverNonce)));
    // Run A is still intact after run B bound.
    assert.deepEqual(chainSnapshot(env.service, runA), before);
    assert.equal(env.service.terminalJobFor(runA).terminalState, "no_agreement");
  } finally { await env.close(); }
});

test("pre-bind routing: a refused bind after terminal lands on the pre-bind chain, not the terminal run", async () => {
  const env = await boot();
  try {
    const runA = await bindBoth(env, 310);
    await env.rpc("tlb1", "contract_withdraw", {});
    const before = chainSnapshot(env.service, runA);
    // A statementless late bind is refused BIND_STATEMENT_INVALID.
    const refused = await env.rpc("tlb1", "contract_bind", bindArgs(cert(311), "buyer"));
    assert.ok(refused.error, JSON.stringify(refused));
    assert.deepEqual(chainSnapshot(env.service, runA), before);
    const last = env.service.preBindFeed("klb1").receipts.at(-1);
    assert.equal(last.tool, "contract_bind");
    assert.equal(last.outcome, refused.error);
  } finally { await env.close(); }
});

test("pre-bind routing: a LIVE bound run still captures the keyId's calls on its own chain", async () => {
  const env = await boot();
  try {
    const runA = await bindBoth(env, 320);
    const before = chainSnapshot(env.service, runA);
    const preBefore = env.service.preBindFeed("klb1")?.receipts.length ?? 0;
    const { nonces, status } = await preBindCalls(env.rpc, "tlb1");
    assert.equal(status.stage, "bound", JSON.stringify(status));
    const after = env.service.receiptFeed(runA).receipts;
    assert.equal(after.length, before.length + nonces.length);
    for (const nonce of nonces) {
      assert.equal(after.filter((r) => r.serverNonce === nonce).length, 1, `nonce ${nonce} not on live run once`);
    }
    // The prefix is untouched (append-only).
    assert.deepEqual(after.slice(0, before.length).map((r) => canonicalDigest(r)), before.digests);
    assert.equal(env.service.preBindFeed("klb1")?.receipts.length ?? 0, preBefore);
  } finally { await env.close(); }
});

test("pre-bind routing: post-terminal business replays/reads still use the terminal run (not pre-bind tools)", async () => {
  const env = await boot();
  try {
    const runA = await bindBoth(env, 330);
    await env.rpc("tlb1", "contract_withdraw", {});
    const before = chainSnapshot(env.service, runA);
    // A business call after terminal is refused on run A's own chain, as before.
    const again = await env.rpc("tlb1", "contract_withdraw", {});
    assert.equal(again.error, "ALREADY_TERMINAL", JSON.stringify(again));
    const after = env.service.receiptFeed(runA).receipts;
    assert.equal(after.length, before.length + 1);
    assert.equal(after.at(-1).tool, "contract_withdraw");
    assert.ok(!PRE_BIND_TOOLS.has(after.at(-1).tool));
  } finally { await env.close(); }
});

test("pre-bind routing + #179: a half-bound run captures calls until its bind deadline, then releases them to pre-bind", async () => {
  let now = Date.now();
  const t0 = now;
  const env = await boot({ serviceOptions: { now: () => now } });
  try {
    const runA = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(340, { t: t0 }), runId: uuid(340),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(runA.bound, true, JSON.stringify(runA));
    // Before the deadline the half-bound run is live: it captures the calls.
    const live = chainSnapshot(env.service, runA.runId);
    await env.rpc("tlb1", "rendezvous_inbox", {});
    assert.equal(chainSnapshot(env.service, runA.runId).length, live.length + 1);

    // Past validUntil + grace: run A ends expired_unbound (#179).
    now = t0 + CERT_WINDOW_MS + GRACE_MS + 1_000;
    const status = await env.rpc("tlb1", "contract_status", {});
    assert.equal(status.terminalState, "expired_unbound", JSON.stringify(status));
    const before = chainSnapshot(env.service, runA.runId);
    const { nonces } = await preBindCalls(env.rpc, "tlb1");
    assert.deepEqual(chainSnapshot(env.service, runA.runId), before);
    const pre = env.service.preBindFeed("klb1");
    for (const nonce of [status.serverNonce, ...nonces]) {
      assert.equal(pre.receipts.filter((r) => r.serverNonce === nonce).length, 1);
    }
    // #176: the late token binds a new run; its bind links the pre-bind head.
    const runB = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(341, { t: now, initiator: { agentId: "9741" } }), runId: uuid(341),
      issuedAt: new Date(now).toISOString(),
    });
    assert.equal(runB.bound, true, JSON.stringify(runB));
    assert.equal(bindReceipt(env.service, runB.runId).preBindHead, env.service.preBindFeed("klb1").head);
    assert.deepEqual(chainSnapshot(env.service, runA.runId), before);
    assert.equal(env.service.terminalJobFor(runA.runId).terminalState, "expired_unbound");
  } finally { await env.close(); }
});

test("pre-bind routing + #179: a withdrawn half-bound run releases the bound party's pre-bind calls", async () => {
  const env = await boot();
  try {
    const runA = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(350), runId: uuid(350),
    });
    assert.equal(runA.bound, true, JSON.stringify(runA));
    const w = await env.rpc("tlb1", "contract_withdraw", {});
    assert.equal(w.state, "withdrawn", JSON.stringify(w));
    const before = chainSnapshot(env.service, runA.runId);
    const { nonces } = await preBindCalls(env.rpc, "tlb1");
    assert.deepEqual(chainSnapshot(env.service, runA.runId), before);
    const pre = env.service.preBindFeed("klb1");
    for (const nonce of nonces) assert.equal(pre.receipts.filter((r) => r.serverNonce === nonce).length, 1);
    // The withdraw receipt itself stays on run A.
    assert.ok(env.service.receiptFeed(runA.runId).receipts.some((r) => r.tool === "contract_withdraw" && r.outcome === "ok"));
  } finally { await env.close(); }
});
