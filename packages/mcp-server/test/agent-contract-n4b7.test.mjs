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

function mintCertificate({ session, sessionId, parties }) {
  const t = Date.now();
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
async function bindLate(rpc, token, { keyId, role, side, certificate, runId, priv }) {
  const { challenge } = await rpc(token, "contract_bind_challenge", {});
  const st = makeStatement({ runId, side, tokenKeyId: keyId, challenge });
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

test("late binding is write-once — a different agentId or run refuses, durably", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b7-"));
  const env = await boot({ stateDir });
  try {
    const bound = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: cert(4), runId: uuid(4),
    });
    assert.equal(bound.bound, true);
    // Same token, a DIFFERENT handshake certificate (different run): a valid
    // statement reaches the write-once gate → STATE_REFUSED.
    const other = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(5, { initiator: { agentId: "9601" } }), runId: uuid(5),
    });
    assert.equal(other.error, "STATE_REFUSED");
    // End the first run — the seat frees but the write-once record holds.
    env.service.endRun(env.service.runFor(bound.runId), "cancelled");
    const afterEnd = await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(6, { initiator: { agentId: "9601" } }), runId: uuid(6),
    });
    assert.equal(afterEnd.error, "STATE_REFUSED");
  } finally { await env.close(); }
  // Across a restart the record survives — same stateDir, fresh service.
  const env2 = await boot({ stateDir });
  try {
    const replayed = await bindLate(env2.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator",
      certificate: cert(7, { initiator: { agentId: "9701" } }), runId: uuid(7),
    });
    assert.equal(replayed.error, "STATE_REFUSED");
  } finally { await env2.close(); }
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
    const set = loadContractConfig({ ...READY_ENV, CONTRACT_LEVEL: level, CONTRACT_REQUIRE_BIND_STATEMENT: "1", CONTRACT_STATE_DIR: dir() });
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

test("MEDIUM-3: an unbound `*` principal cannot send rendezvous invitations", async () => {
  const env = await boot();
  try {
    const listing = await env.rpc("tp1", "rendezvous_publish_listing", {
      title: "SFO-FCO managed travel", summary: "desk", sealedBoxPublicKeyHex: `0x${"ab".repeat(32)}`,
    });
    const seal = {
      v: 2, epk: `0x${"ab".repeat(32)}`, iv: `0x${"cd".repeat(12)}`,
      ct: `0x${"ef".repeat(32)}`, tag: `0x${"01".repeat(16)}`,
    };
    // Unbound: the token has no proven agentId — nothing honest to disclose.
    const refused = await env.rpc("tlb1", "rendezvous_send_invitation", {
      listingId: listing.listingId, sealedInvitation: seal,
    });
    assert.equal(refused.error, "STATE_REFUSED");
    // After binding, the invitation carries the CERTIFICATE-resolved agentId.
    const c = cert(22);
    await bindLate(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", certificate: c, runId: uuid(22),
    });
    const delivered = await env.rpc("tlb1", "rendezvous_send_invitation", {
      listingId: listing.listingId, sealedInvitation: seal,
    });
    assert.equal(delivered.delivered, true);
    const inbox = await env.rpc("tp1", "rendezvous_inbox", {});
    assert.ok(inbox.messages.some((m) => m.senderAgentId === "9501" && m.listingId === listing.listingId));
  } finally { await env.close(); }
});
