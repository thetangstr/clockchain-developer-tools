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

// --- piece 1: late agentId ---------------------------------------------------

test("late token binds the certificate's agentId on the token's own side", async () => {
  const env = await boot();
  try {
    const c = cert(1);
    const buyer = await env.rpc("tlb1", "contract_bind", bindArgs(c, "buyer"));
    assert.equal(buyer.bound, true);
    assert.equal(buyer.runId, uuid(1));
    // The agentId came from the cert's INITIATOR party, not the token.
    const run = env.service.runFor(buyer.runId);
    assert.equal(run.bound.buyer.agentId, "9501");
    // ... and the responder seat picks the responder's agentId.
    const provider = await env.rpc("tlp1", "contract_bind", bindArgs(c, "provider"));
    assert.equal(provider.bound, true);
    assert.equal(env.service.runFor(buyer.runId).bound.provider.agentId, "9502");
    // Receipts disclose the mode.
    const receipt = bindReceipt(env.service, buyer.runId);
    assert.equal(receipt.bindMode, "late");
    assert.equal(receipt.bindStatement, "absent");
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
  } finally { await env.close(); }
});

test("late binding is write-once — a different agentId or run refuses, durably", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "contract-n4b7-"));
  const env = await boot({ stateDir });
  try {
    const bound = await env.rpc("tlb1", "contract_bind", bindArgs(cert(4), "buyer"));
    assert.equal(bound.bound, true);
    // Same token, a DIFFERENT handshake certificate (different run): refused.
    const other = await env.rpc("tlb1", "contract_bind", bindArgs(cert(5, { initiator: { agentId: "9601" } }), "buyer"));
    assert.equal(other.error, "STATE_REFUSED");
    // End the first run — the seat frees but the write-once record holds.
    env.service.endRun(env.service.runFor(bound.runId), "cancelled");
    const afterEnd = await env.rpc("tlb1", "contract_bind", bindArgs(cert(6, { initiator: { agentId: "9601" } }), "buyer"));
    assert.equal(afterEnd.error, "STATE_REFUSED");
  } finally { await env.close(); }
  // Across a restart the record survives — same stateDir, fresh service.
  const env2 = await boot({ stateDir });
  try {
    const replayed = await env2.rpc("tlb1", "contract_bind", bindArgs(cert(7, { initiator: { agentId: "9701" } }), "buyer"));
    assert.equal(replayed.error, "STATE_REFUSED");
  } finally { await env2.close(); }
});

