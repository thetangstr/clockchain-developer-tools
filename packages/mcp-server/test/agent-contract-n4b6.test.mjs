import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { parseContractTokens, tokenAuthenticator, createContractHttpHandler } from "../dist/agent-contract/http-handler.js";
import { createContractService } from "../dist/agent-contract/service.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { buildServerCard, buildServerKeysDoc } from "../dist/agent-contract/server-card.js";
import { eip191SignDigest32, eip191RecoverPublicKey, publicKeyToAddress } from "../dist/agent-contract/eip191.js";
import { computeApprovalDigest, computeApprovalSigDigest } from "../dist/agent-contract/approval.js";
import { createSimWorld } from "../dist/agent-contract/sim/index.js";
import { runHttp } from "../dist/http.js";

/**
 * N4b-6 (docs/agent-contract/N4B6-BRIEF.md):
 *  1. Fault-injected runs are visible in evidence — CONTRACT_SIM_FAULTS is
 *     refused unless CONTRACT_ALLOW_SIM_FAULTS=1; the card and /contract/keys
 *     publish simFaultsEnabled; a faulted run's receipts carry simFault.
 *  2. The evidence routes (GET /contract/receipts, /contract/keys,
 *     /contract/run-salt) are exported so http.ts and the l-stack share ONE
 *     code path, with a listenHost option for a loopback-only mount.
 */

const ACCEPT = "application/json, text/event-stream";

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
    mandateId: `mdt-${Math.floor(Math.random() * 1e9)}`,
    capMinor: 500_000,
    currency: "USD",
    allowedItineraryIds: ["IT-QW-ONESTOP"],
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    ...overrides,
  };
}

// --- HTTP harness -------------------------------------------------------------

const CLIENT_INFO = { name: "n4b6-test-client", version: "1.0.0" };

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
    return { ...(body.result?.structuredContent ?? {}), ...(body.error ? { rpcError: body.error.code } : {}) };
  };
  return {
    url, service, rpc,
    async close() { await new Promise((r) => srv.close(r)); service.close(); },
  };
}

// runHttp harness — env-driven, for the config-gate and card/keys flag tests.
const ENV_KEYS = [
  "PORT", "MCP_PORT", "CONTRACT_MCP_ENABLED", "CONTRACT_AUTH_TOKENS",
  "CONTRACT_SERVER_ED25519_SEED", "CONTRACT_ALLOW_EPHEMERAL_KEY",
  "CONTRACT_SERVER_KEY_ID", "CONTRACT_TRUST_PROXY", "CONTRACT_STATE_DIR",
  "CONTRACT_HOST_ROOTS", "CONTRACT_CALLS_PER_MINUTE", "CONTRACT_OBSERVER_TOKEN",
  "CONTRACT_POLICY_DIGESTS", "CONTRACT_PRINCIPALS", "CONTRACT_OBSERVER_PER_MINUTE",
  "CONTRACT_SERVER_KEY_VALID_FROM", "CONTRACT_SERVER_KEY_VALID_UNTIL",
  "CONTRACT_SESSION_TTL_MS", "CONTRACT_VERIFIER_TOKEN", "CONTRACT_SIM_FAULTS",
  "CONTRACT_ALLOW_SIM_FAULTS",
];
const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const POLICIES_ENV = `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`;
const READY_ENV = {
  CONTRACT_MCP_ENABLED: "1",
  CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
  CONTRACT_SERVER_ED25519_SEED: SEED_B64,
  CONTRACT_POLICY_DIGESTS: POLICIES_ENV,
  CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
  CONTRACT_OBSERVER_TOKEN: "obs-token",
  CONTRACT_VERIFIER_TOKEN: "ver-token",
};

async function bootHttp(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0", CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-n4b6-")) }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    server,
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
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

// === 1. fault-injected runs are visible in evidence ===========================

test("CONTRACT_SIM_FAULTS without CONTRACT_ALLOW_SIM_FAULTS=1 → misconfigured (closed)", async () => {
  const faults = JSON.stringify({ [uuid(901)]: { issueMismatch: "fare" } });
  const cfg = loadContractConfig({
    ...READY_ENV,
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-n4b6-cfg-")),
    CONTRACT_SIM_FAULTS: faults,
  });
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /CONTRACT_ALLOW_SIM_FAULTS/);

  // The served surface refuses closed rather than half-serving.
  const app = await bootHttp({ ...READY_ENV, CONTRACT_SIM_FAULTS: faults });
  try {
    const res = await fetch(`${app.url}/contract/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, authorization: "Bearer tb1" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: CLIENT_INFO } }),
    });
    assert.equal(res.status, 503);
    assert.deepEqual(await res.json(), { error: "contract_unavailable" });
  } finally {
    await app.close();
  }
});

test("CONTRACT_ALLOW_SIM_FAULTS=1 publishes simFaultsEnabled on the card and /contract/keys", async () => {
  const faults = JSON.stringify({ [uuid(902)]: { issueMismatch: "travellers" } });
  const app = await bootHttp({ ...READY_ENV, CONTRACT_ALLOW_SIM_FAULTS: "1", CONTRACT_SIM_FAULTS: faults });
  try {
    const card = await (await fetch(`${app.url}/.well-known/mcp/server-card.json`)).json();
    assert.equal(card.simFaultsEnabled, true);
    // The flag is inside the digest's coverage — a card that claims the
    // capability and one that doesn't digest differently.
    const cleanCard = buildServerCard([]);
    assert.notEqual(card.cardDigest, cleanCard.cardDigest);
    const keysDoc = await (await fetch(`${app.url}/contract/keys`)).json();
    assert.equal(keysDoc.simFaultsEnabled, true);
  } finally {
    await app.close();
  }

  // Without the gate there is no flag — and the field is absent entirely.
  const clean = await bootHttp({ ...READY_ENV });
  try {
    const card = await (await fetch(`${clean.url}/.well-known/mcp/server-card.json`)).json();
    assert.ok(!("simFaultsEnabled" in card));
    const keysDoc = await (await fetch(`${clean.url}/contract/keys`)).json();
    assert.ok(!("simFaultsEnabled" in keysDoc));
    assert.deepEqual(buildServerKeysDoc([]), { schema: "agent-contract.server-keys/v1", keys: [] });
  } finally {
    await clean.close();
  }
});

test("a faulted run carries simFault on its receipts; the feed exposes it; verification catches A2", async () => {
  const sim = createSimWorld({ faults: { [uuid(903)]: { issueMismatch: "fare" } } });
  const app = await boot({ serviceOptions: { sim } });
  try {
    const { runId, orderRef } = await bookedPair(app.rpc, 903, "tb1", "tp1");
    assert.equal(runId, uuid(903));

    const feed = app.service.receiptFeed(runId);
    assert.ok(feed, "run feed exists");
    // The A2 fault is disclosed on the feed…
    assert.deepEqual(feed.simFault, { issueMismatch: "fare" });
    // …and on the booking_execute receipt…
    const execReceipt = feed.receipts.find((r) => r.tool === "booking_execute");
    assert.ok(execReceipt, "booking_execute receipt");
    assert.deepEqual(execReceipt.simFault, { issueMismatch: "fare" });
    // …and on EVERY run receipt (status calls included).
    assert.ok(feed.receipts.every((r) => "simFault" in r), "every run receipt carries simFault");

    // A buyer claiming "match" still fails verification: the server's own
    // observation sees the drifted fare — the terminal receipt carries it too.
    const prepV = await app.rpc("tb1", "verification_prepare", {
      orderRef, result: "match", findingsDigest: `0x${"aa".repeat(32)}`,
    });
    const verified = await signedSubmit(app.rpc, { token: "tb1", role: "buyer", prepared: prepV, submitTool: "verification_submit" });
    assert.equal(verified.terminalState, "verification_failed", JSON.stringify(verified));
    const feed2 = app.service.receiptFeed(runId);
    const termReceipt = feed2.receipts.at(-1);
    assert.equal(termReceipt.tool, "verification_submit");
    assert.deepEqual(termReceipt.simFault, { issueMismatch: "fare" });
  } finally {
    await app.close();
  }
});

test("an honest run carries no simFault field anywhere", async () => {
  const app = await boot();
  try {
    const { runId } = await bookedPair(app.rpc, 904, "tb1", "tp1");
    const feed = app.service.receiptFeed(runId);
    assert.ok(feed);
    assert.ok(!("simFault" in feed));
    for (const r of feed.receipts) assert.ok(!("simFault" in r), `${r.tool} leaked a simFault`);
    const status = await app.rpc("tb1", "contract_status", {});
    assert.ok(status, "status call");
    const feed2 = app.service.receiptFeed(runId);
    assert.ok(feed2.receipts.every((r) => !("simFault" in r)));
  } finally {
    await app.close();
  }
});

// === 2. the evidence routes are one exported code path =======================

const KEYS_DOC = buildServerKeysDoc([
  { keyId: "contract-server-test", alg: "Ed25519",
    publicKeyHex: `0x${"aa".repeat(32)}`, validFrom: "2026-01-01T00:00:00.000Z", validUntil: null },
]);

async function probe(url, { method = "GET", token = null } = {}) {
  const headers = {};
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const res = await fetch(url, { method, headers });
  return { status: res.status, body: await res.text() };
}

test("the exported evidence routes serve receipts, keys and run-salt over a shared service", async () => {
  const { startContractEvidenceServer } = await import("../dist/agent-contract/evidence-routes.js");
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const app = await boot({ service });
  const evidence = await startContractEvidenceServer({
    service, observerToken: "obs", verifierToken: "ver", keysDoc: KEYS_DOC,
    allowFeed: () => true,
  });
  try {
    const { runId } = await bookedPair(app.rpc, 905, "tb1", "tp1");

    // /contract/receipts — observer-token auth, run feed.
    assert.equal((await probe(`${evidence.url}/contract/receipts?runId=${runId}`)).status, 401);
    const feedRes = await fetch(`${evidence.url}/contract/receipts?runId=${runId}`, {
      headers: { authorization: "Bearer obs" },
    });
    assert.equal(feedRes.status, 200);
    const feed = await feedRes.json();
    assert.equal(feed.runId, runId);
    assert.ok(feed.receipts.length > 0);
    assert.equal(feed.head.length > 0, true);
    // The verifier token does NOT open the observer feed — separate credentials.
    assert.equal(
      (await probe(`${evidence.url}/contract/receipts?runId=${runId}`, { token: "ver" })).status, 401,
    );

    // /contract/run-salt — verifier-token auth, salt disclosure.
    assert.equal((await probe(`${evidence.url}/contract/run-salt?runId=${runId}`)).status, 401);
    assert.equal(
      (await probe(`${evidence.url}/contract/run-salt?runId=${runId}`, { token: "obs" })).status, 401,
    );
    const saltRes = await fetch(`${evidence.url}/contract/run-salt?runId=${runId}`, {
      headers: { authorization: "Bearer ver" },
    });
    assert.equal(saltRes.status, 200);
    const salt = await saltRes.json();
    assert.deepEqual({ scope: salt.scope, id: salt.id }, { scope: "run", id: runId });
    assert.match(salt.salt, /^[0-9a-f]{64}$/);

    // /contract/keys — public, byte-identical to the document passed in.
    const keysRes = await fetch(`${evidence.url}/contract/keys`);
    assert.equal(keysRes.status, 200);
    assert.equal(await keysRes.text(), JSON.stringify(KEYS_DOC));

    // Everything else is closed on the evidence mount.
    assert.equal((await probe(`${evidence.url}/contract/mcp`)).status, 404);
    assert.equal((await probe(`${evidence.url}/contract/keys`, { method: "POST" })).status, 404);
  } finally {
    await evidence.close();
    await app.close();
  }
});

test("http.ts and the exported handler give identical responses on shared inputs", async () => {
  const { startContractEvidenceServer } = await import("../dist/agent-contract/evidence-routes.js");
  const app = await bootHttp(READY_ENV); // obs-token / ver-token wired via env
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const evidence = await startContractEvidenceServer({
    service, observerToken: "obs-token", verifierToken: "ver-token",
    keysDoc: { schema: "agent-contract.server-keys/v1", keys: [] },
    allowFeed: () => true,
  });
  try {
    // Same statuses and byte-identical bodies for every shared input.
    for (const [path, opts] of [
      ["/contract/receipts?runId=nope", {}],
      ["/contract/receipts?runId=nope", { token: "wrong" }],
      ["/contract/receipts?runId=nope", { token: "obs-token" }],
      ["/contract/receipts", { method: "POST", token: "obs-token" }],
      ["/contract/run-salt?runId=nope", {}],
      ["/contract/run-salt?runId=nope", { token: "ver-token" }],
      ["/contract/run-salt", { method: "POST", token: "ver-token" }],
      ["/contract/keys", { method: "POST" }],
    ]) {
      const a = await probe(`${app.url}${path}`, opts);
      const b = await probe(`${evidence.url}${path}`, opts);
      assert.equal(b.status, a.status, `${opts.method ?? "GET"} ${path}`);
      assert.equal(b.body, a.body, `${opts.method ?? "GET"} ${path}`);
    }
    // Tokens unset → both routes are closed (404), identically.
    const closed = await startContractEvidenceServer({
      service, keysDoc: { schema: "agent-contract.server-keys/v1", keys: [] },
      allowFeed: () => true,
    });
    try {
      assert.equal((await probe(`${closed.url}/contract/receipts?runId=x`, { token: "obs-token" })).status, 404);
      assert.equal((await probe(`${closed.url}/contract/run-salt?runId=x`, { token: "ver-token" })).status, 404);
    } finally {
      await closed.close();
    }
  } finally {
    await evidence.close();
    await app.close();
    service.close();
  }
});

test("the evidence server is loopback-only by default and honors listenHost", async () => {
  const { startContractEvidenceServer } = await import("../dist/agent-contract/evidence-routes.js");
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  const evidence = await startContractEvidenceServer({
    service, keysDoc: KEYS_DOC,
  });
  try {
    assert.equal(evidence.server.address().address, "127.0.0.1");
    assert.match(evidence.url, /^http:\/\/127\.0\.0\.1:\d+/);
    assert.equal((await fetch(`${evidence.url}/contract/keys`)).status, 200);
  } finally {
    await evidence.close();
    service.close();
  }
});

test("the exported routes rate-limit feed access like http.ts does", async () => {
  const { createContractEvidenceRoutes } = await import("../dist/agent-contract/evidence-routes.js");
  const service = createContractService({
    hostRoots: HOST_ROOTS, signer: SIGNER,
    policyDigests: POLICY_DIGESTS, principals: PRINCIPALS,
  });
  // No allowFeed injected → the built-in low-rate default applies.
  const routes = createContractEvidenceRoutes({
    service, observerToken: "obs", keysDoc: KEYS_DOC,
  });
  const srv = createServer((req, res) => {
    if (!routes(req, res)) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
    }
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  try {
    let last = 0;
    for (let i = 0; i < 30; i += 1) {
      last = (await probe(`${url}/contract/receipts?runId=nope`, { token: "obs" })).status;
    }
    assert.equal(last, 404); // 30 within the window, all fine (unknown run)
    const limited = await probe(`${url}/contract/receipts?runId=nope`, { token: "obs" });
    assert.equal(limited.status, 429);
    assert.deepEqual(JSON.parse(limited.body), { error: "rate_limited" });
  } finally {
    await new Promise((r) => srv.close(r));
    service.close();
  }
});
