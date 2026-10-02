import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { parseContractTokens, tokenAuthenticator, createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { createRelayCertificateResolver } from "../dist/agent-contract/certificate-resolver.js";
import { toolsListForRole } from "../dist/agent-contract/tools-list.js";
import { eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";

const ACCEPT = "application/json, text/event-stream";

// contract_bind BY REFERENCE (p6-l-2026-10-01-13): the agent presents the
// handshake sessionId and the server resolves the closing certificate itself
// (from the handshake relay, the coordinator's own source of truth) — a
// model never carries the signed certificate object. Verification is
// unchanged (host-root signature, parties, ERC-8004 pins), the bind
// statement requirement is unchanged, and a certificate presented alongside
// must equal the resolved one canonically.

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

async function boot({ serviceOptions = {}, stateDir, tokens, resolveCertificate } = {}) {
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
    ...(resolveCertificate !== undefined ? { resolveCertificate } : {}),
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


/** In-memory resolver: sessionId → envelope | "pending" | absent (unknown). */
function fakeResolver(table) {
  const calls = [];
  const fn = async (sessionId) => {
    calls.push(sessionId);
    const hit = table.get(sessionId);
    if (hit === "pending") return { ok: false, code: "CERTIFICATE_NOT_READY", retryable: true, retryAfterMs: 5000 };
    if (hit === "down") return { ok: false, code: "CONTRACT_UNAVAILABLE", retryable: true, retryAfterMs: 5000 };
    if (hit === undefined) return { ok: false, code: "HANDSHAKE_SESSION_UNKNOWN", retryable: false };
    return { ok: true, certificate: hit };
  };
  fn.calls = calls;
  return fn;
}

function sessionBindArgs(role, extra = {}) {
  const signerKey = role === "buyer" ? keys.buyerSigner : keys.providerSigner;
  const approvalKey = role === "buyer" ? keys.buyerApproval : keys.providerApproval;
  return {
    signerKey: { keyId: signerKey.keyId, publicKeyHex: signerKey.publicKeyHex },
    approvalKey: { keyId: approvalKey.keyId, publicKeyHex: approvalKey.publicKeyHex },
    ...extra,
  };
}

async function bindBySession(rpc, token, { keyId, role, side, sessionId, priv, extra = {} }) {
  const { challenge } = await rpc(token, "contract_bind_challenge", {});
  const st = makeStatement({ runId: sessionId, side, tokenKeyId: keyId, challenge });
  return rpc(token, "contract_bind", sessionBindArgs(role, {
    handshakeSessionId: sessionId,
    bindStatement: st,
    bindStatementSignature: signStatement(priv ?? sessionEvm[side].priv, st),
    ...extra,
  }));
}

test("both companies bind by handshakeSessionId alone — the server resolves the certificate", async () => {
  const c = cert(101);
  const resolver = fakeResolver(new Map([[uuid(101), c]]));
  const env = await boot({ resolveCertificate: resolver });
  try {
    const buyer = await bindBySession(env.rpc, "tlb1", { keyId: "klb1", role: "buyer", side: "initiator", sessionId: uuid(101) });
    assert.equal(buyer.bound, true, JSON.stringify(buyer));
    assert.equal(buyer.runId, uuid(101));
    assert.equal(buyer.bindStatement, "verified");
    const provider = await bindBySession(env.rpc, "tlp1", { keyId: "klp1", role: "provider", side: "responder", sessionId: uuid(101) });
    assert.equal(provider.bound, true, JSON.stringify(provider));
    assert.equal(provider.runId, uuid(101));
    const run = env.service.runFor(uuid(101));
    assert.equal(run.bound.buyer.agentId, "9501");
    assert.equal(run.bound.provider.agentId, "9502");
    assert.deepEqual(resolver.calls, [uuid(101), uuid(101)]);
  } finally { await env.close(); }
});

test("static token binds by session id too (no statement needed at level L)", async () => {
  const c = cert(102, { initiator: { agentId: "9452" } });
  const env = await boot({ resolveCertificate: fakeResolver(new Map([[uuid(102), c]])) });
  try {
    const ok = await env.rpc("tb1", "contract_bind", sessionBindArgs("buyer", { handshakeSessionId: uuid(102) }));
    assert.equal(ok.bound, true, JSON.stringify(ok));
    assert.equal(ok.runId, uuid(102));
  } finally { await env.close(); }
});

test("a certificate presented with the session id must equal the resolved one canonically", async () => {
  const c = cert(103);
  const env = await boot({ resolveCertificate: fakeResolver(new Map([[uuid(103), c]])) });
  try {
    // Key order differs, canonical bytes equal → accepted.
    const reordered = { signer: c.signer, result: c.result, hostSessionKeyCertificate: c.hostSessionKeyCertificate };
    const ok = await bindBySession(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", sessionId: uuid(103), extra: { certificate: reordered },
    });
    assert.equal(ok.bound, true, JSON.stringify(ok));
    // A different (independently valid) certificate for the same session → refused.
    sessionKeys.delete(103);
    const other = cert(103);
    const refused = await bindBySession(env.rpc, "tlp1", {
      keyId: "klp1", role: "provider", side: "responder", sessionId: uuid(103), extra: { certificate: other },
    });
    assert.equal(refused.error, "CERTIFICATE_INVALID");
    // A hand-reconstructed copy missing a field → refused, never "repaired".
    const { externalBusinessActionPerformed, ...thinResult } = c.result;
    const thin = { ...c, result: thinResult };
    const refused2 = await bindBySession(env.rpc, "tlp1", {
      keyId: "klp1", role: "provider", side: "responder", sessionId: uuid(103), extra: { certificate: thin },
    });
    assert.equal(refused2.error, "CERTIFICATE_INVALID");
  } finally { await env.close(); }
});

test("an open (not yet closed) session refuses CERTIFICATE_NOT_READY, retryable, with no run created", async () => {
  const env = await boot({ resolveCertificate: fakeResolver(new Map([[uuid(104), "pending"]])) });
  try {
    const r = await bindBySession(env.rpc, "tlb1", { keyId: "klb1", role: "buyer", side: "initiator", sessionId: uuid(104) });
    assert.equal(r.error, "CERTIFICATE_NOT_READY");
    assert.equal(r.retryable, true);
    assert.equal(r.retryAfterMs, 5000);
    assert.equal(env.service.runFor(uuid(104)), undefined);
  } finally { await env.close(); }
});

test("an unknown session refuses HANDSHAKE_SESSION_UNKNOWN; a relay outage refuses CONTRACT_UNAVAILABLE retryable", async () => {
  const env = await boot({ resolveCertificate: fakeResolver(new Map([[uuid(106), "down"]])) });
  try {
    const r = await bindBySession(env.rpc, "tlb1", { keyId: "klb1", role: "buyer", side: "initiator", sessionId: uuid(105) });
    assert.equal(r.error, "HANDSHAKE_SESSION_UNKNOWN");
    assert.equal(r.retryable, false);
    const d = await bindBySession(env.rpc, "tlb1", { keyId: "klb1", role: "buyer", side: "initiator", sessionId: uuid(106) });
    assert.equal(d.error, "CONTRACT_UNAVAILABLE");
    assert.equal(d.retryable, true);
  } finally { await env.close(); }
});

test("a resolver that returns another session's certificate is refused", async () => {
  const env = await boot({ resolveCertificate: fakeResolver(new Map([[uuid(107), cert(108)]])) });
  try {
    const r = await bindBySession(env.rpc, "tlb1", { keyId: "klb1", role: "buyer", side: "initiator", sessionId: uuid(107) });
    assert.equal(r.error, "CERTIFICATE_INVALID");
    assert.equal(env.service.runFor(uuid(108)), undefined);
  } finally { await env.close(); }
});

test("the bind statement requirement is unchanged when binding by session id", async () => {
  const env = await boot({ resolveCertificate: fakeResolver(new Map([[uuid(109), cert(109)]])) });
  try {
    // Late token, no statement → refused exactly as with a certificate.
    const none = await env.rpc("tlb1", "contract_bind", sessionBindArgs("buyer", { handshakeSessionId: uuid(109) }));
    assert.equal(none.error, "BIND_STATEMENT_INVALID");
    // Statement signed by the wrong key → refused.
    const wrong = await bindBySession(env.rpc, "tlb1", {
      keyId: "klb1", role: "buyer", side: "initiator", sessionId: uuid(109), priv: sessionEvm.stranger.priv,
    });
    assert.equal(wrong.error, "BIND_STATEMENT_INVALID");
  } finally { await env.close(); }
});

test("neither certificate nor session id refuses PAYLOAD_INVALID; no resolver configured refuses CONTRACT_UNAVAILABLE", async () => {
  const env = await boot();
  try {
    const neither = await env.rpc("tb1", "contract_bind", sessionBindArgs("buyer"));
    assert.equal(neither.error, "PAYLOAD_INVALID");
    const unwired = await env.rpc("tb1", "contract_bind", sessionBindArgs("buyer", { handshakeSessionId: uuid(110) }));
    assert.equal(unwired.error, "CONTRACT_UNAVAILABLE");
    assert.equal(unwired.retryable, false);
    // Backward compatible: certificate-only bind still works without a resolver.
    const ok = await env.rpc("tb1", "contract_bind", bindArgs(cert(111, { initiator: { agentId: "9452" } }), "buyer"));
    assert.equal(ok.bound, true, JSON.stringify(ok));
  } finally { await env.close(); }
});

test("tools/list: contract_bind takes handshakeSessionId and no longer requires certificate", () => {
  for (const role of ["buyer", "provider"]) {
    const bind = toolsListForRole(role).tools.find((t) => t.name === "contract_bind");
    assert.ok(bind.inputSchema.properties.handshakeSessionId, "handshakeSessionId property");
    assert.equal(bind.inputSchema.properties.handshakeSessionId.type, "string");
    assert.ok(!bind.inputSchema.required.includes("certificate"));
    assert.ok(!bind.inputSchema.required.includes("handshakeSessionId"));
    assert.match(bind.description, /session id/i);
  }
});

// --- relay resolver (production wiring) --------------------------------------

function fakeFetch(handler) {
  return async (url) => {
    const { status, body, throws } = handler(String(url));
    if (throws) throw new TypeError("fetch failed");
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  };
}

test("relay resolver: 200 → certificate; RESULT_NOT_SET → NOT_READY; other 404 → UNKNOWN; network → UNAVAILABLE", async () => {
  const c = cert(120);
  const resolve = createRelayCertificateResolver({
    relayUrl: "http://relay.test:8080",
    fetch: fakeFetch((url) => {
      if (url.endsWith(`/v1/sessions/${uuid(120)}/result`)) return { status: 200, body: c };
      if (url.endsWith(`/v1/sessions/${uuid(121)}/result`)) return { status: 404, body: { error: "RESULT_NOT_SET" } };
      if (url.endsWith(`/v1/sessions/${uuid(122)}/result`)) return { status: 404, body: { error: "SESSION_NOT_FOUND" } };
      return { throws: true };
    }),
  });
  assert.deepEqual(await resolve(uuid(120)), { ok: true, certificate: c });
  const pending = await resolve(uuid(121));
  assert.equal(pending.code, "CERTIFICATE_NOT_READY");
  assert.equal(pending.retryable, true);
  const unknown = await resolve(uuid(122));
  assert.equal(unknown.code, "HANDSHAKE_SESSION_UNKNOWN");
  assert.equal(unknown.retryable, false);
  const down = await resolve(uuid(123));
  assert.equal(down.code, "CONTRACT_UNAVAILABLE");
  assert.equal(down.retryable, true);
  const bad = await resolve("not-a-uuid");
  assert.equal(bad.code, "HANDSHAKE_SESSION_UNKNOWN");
});
