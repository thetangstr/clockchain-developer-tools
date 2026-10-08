import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, createHmac, createPublicKey, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";
import { verifyChain } from "../dist/agent-contract/receipts.js";

// H3/C1: these tests boot the REAL runHttp wiring — env → loadContractConfig →
// dispatch — so the enable gate, fail-closed config and prototype-key probes
// exercise exactly what production runs.

const ENV_KEYS = [
  "PORT", "MCP_PORT", "CONTRACT_MCP_ENABLED", "CONTRACT_AUTH_TOKENS",
  "CONTRACT_SERVER_ED25519_SEED", "CONTRACT_ALLOW_EPHEMERAL_KEY",
  "CONTRACT_SERVER_KEY_ID", "CONTRACT_TRUST_PROXY", "CONTRACT_STATE_DIR",
  "CONTRACT_HOST_ROOTS", "CONTRACT_CALLS_PER_MINUTE", "CONTRACT_OBSERVER_TOKEN",
  "CONTRACT_POLICY_DIGESTS", "CONTRACT_PRINCIPALS", "CONTRACT_OBSERVER_PER_MINUTE", "CONTRACT_OBSERVER_PER_KEY_PER_MINUTE",
  "CONTRACT_SERVER_KEY_VALID_FROM", "CONTRACT_SERVER_KEY_VALID_UNTIL",
  "CONTRACT_SESSION_TTL_MS", "CONTRACT_VERIFIER_TOKEN", "CONTRACT_SIM_FAULTS",
  "CONTRACT_ALLOW_SIM_FAULTS",
  "CONTRACT_LEVEL", "CONTRACT_REQUIRE_BIND_STATEMENT",
];

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
// Required §13 policy pins — a "ready" config is impossible without them.
const POLICIES = `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`;
// N4b-3 LOW: the published key's validity window is pinned config — never
// boot time — so every ready-expecting env carries it.
const KEY_VALID_FROM = "2026-09-01T00:00:00.000Z";
const ACCEPT = "application/json, text/event-stream";

async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0", CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-wiring-")) }, env);
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

// M2: the transport is stateful — negotiate an mcp-session-id once per
// (server, token) before any other call.
const sessions = new Map();
async function ensureSession(url, token) {
  const key = `${url}|${token}`;
  if (sessions.has(key)) return;
  const headers = { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` };
  const res = await fetch(`${url}/contract/mcp`, {
    method: "POST", headers,
    body: JSON.stringify({
      jsonrpc: "2.0", id: 0, method: "initialize",
      params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    }),
  });
  // Tolerant: tests probing disabled/misconfigured routes expect the probe
  // call's own status (404/503), so a refused initialize must not throw.
  sessions.set(key, res.status < 300 ? res.headers.get("mcp-session-id") : null);
}

async function post(url, method, params = {}, token = null) {
  const headers = { "content-type": "application/json", accept: ACCEPT };
  if (token !== null) {
    headers.authorization = `Bearer ${token}`;
    await ensureSession(url, token);
    const sid = sessions.get(`${url}|${token}`);
    if (sid) headers["mcp-session-id"] = sid;
  }
  const res = await fetch(`${url}/contract/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await res.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  let body;
  try { body = JSON.parse(data ? data.slice(5) : text); } catch { body = text; }
  return { status: res.status, body };
}

test("H3: /contract/mcp answers 404 unless CONTRACT_MCP_ENABLED=1", async () => {
  const app = await boot({ MCP_TOKEN_SIGNING_SECRET: "", MCP_AUTH_TOKENS: "" });
  try {
    const res = await post(app.url, "tools/list", {}, "whatever");
    assert.equal(res.status, 404);
  } finally { await app.close(); }
});

test("H3: enabled without a seed (and no ephemeral opt-in) refuses the route", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
    CONTRACT_POLICY_DIGESTS: POLICIES,
  });
  try {
    const res = await post(app.url, "tools/list", {}, "tb1");
    assert.equal(res.status, 503);
    assert.deepEqual(res.body, { error: "contract_unavailable" });
  } finally { await app.close(); }
});

test("H3: ephemeral key requires explicit opt-in and is forced to ephemeral-dev-*", async () => {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
    CONTRACT_ALLOW_EPHEMERAL_KEY: "1",
    CONTRACT_SERVER_KEY_ID: "attacker-supplied", // must NOT be honored
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
  });
  assert.equal(cfg.kind, "ready");
  assert.equal(cfg.signerEphemeral, true);
  assert.match(cfg.signer.keyId, /^ephemeral-dev-/);
  assert.notEqual(cfg.signer.keyId, "attacker-supplied");
  const noOptIn = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
    CONTRACT_POLICY_DIGESTS: POLICIES,
  });
  assert.equal(noOptIn.kind, "misconfigured");
});

test("C1: no tokens configured — prototype keys and constructor get 401 on every method", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
    // CONTRACT_AUTH_TOKENS intentionally unset
  });
  try {
    for (const tok of ["constructor", "__proto__", "toString", "hasOwnProperty", "x"]) {
      for (const [method, params] of [
        ["initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } }],
        ["tools/list", {}],
        ["tools/call", { name: "contract_status", arguments: {} }],
      ]) {
        const res = await post(app.url, method, params, tok);
        assert.equal(res.status, 401, `${method} as "${tok}"`);
      }
    }
  } finally { await app.close(); }
});

test("C1: duplicate tokens and tokens containing ':' are a startup parse error", () => {
  const dup = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_AUTH_TOKENS: "t1:buyer:k1:9452:initiator,t1:provider:k2:9453:responder",
  });
  assert.equal(dup.kind, "misconfigured");
  const colonTok = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_AUTH_TOKENS: "to:k:buyer:k1:9452:initiator",
  });
  assert.equal(colonTok.kind, "misconfigured");
});

test("H3: enabled + seeded + tokens → route serves; disabled env → not mounted", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
  });
  try {
    const noTok = await post(app.url, "tools/list");
    assert.equal(noTok.status, 401);
    const ok = await post(app.url, "tools/list", {}, "tb1");
    assert.equal(ok.status, 200);
    assert.ok(ok.body.result.tools.length > 0);
  } finally { await app.close(); }
});

test("N1: a corrupt used-sessions record closes the route (503, no binds)", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "contract-wiring-corrupt-"));
  writeFileSync(path.join(dir, "used-sessions.json"), "{corrupt");
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
    CONTRACT_STATE_DIR: dir,
  });
  try {
    const res = await post(app.url, "tools/call", { name: "contract_bind", arguments: {} }, "tb1");
    assert.equal(res.status, 503);
    assert.deepEqual(res.body, { error: "contract_unavailable" });
  } finally { await app.close(); }
});

test("N2: a second process on the same state dir is refused (exclusive lock)", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "contract-wiring-lock-"));
  const env = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
    CONTRACT_STATE_DIR: dir,
  };
  const app = await boot(env);
  try {
    // The live route holds the lock; a second config on the same dir refuses.
    const second = loadContractConfig(env);
    assert.equal(second.kind, "misconfigured");
    assert.match(second.reason, /lock/i);
    // …but the live route keeps serving.
    const ok = await post(app.url, "tools/list", {}, "tb1");
    assert.equal(ok.status, 200);
  } finally { await app.close(); }
});

// --- observer receipt feed (N4b-2b) -------------------------------------------

function rawPublicKeyBase64(publicKey) {
  return Buffer.from(publicKey.export({ format: "der", type: "spki" }).subarray(12)).toString("base64");
}

function mintCertificate({ root, session, sessionId }) {
  const t = Date.now();
  const sessionKeyAddress = `0x${createHash("sha256").update(session.publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 40)}`;
  const certificate = {
    schema: "clockchain.host-session-key/v1",
    rootKid: "root-test", sessionId, repositorySha: "d".repeat(40),
    sessionPublicKey: rawPublicKeyBase64(session.publicKey),
    validFromMs: String(t - 60_000), validUntilMs: String(t + 10 * 60_000),
  };
  const hostSessionKeyCertificate = {
    certificate,
    rootSignature: {
      algorithm: "ed25519", keyId: "root-test",
      publicKey: rawPublicKeyBase64(root.publicKey),
      signature: edSign(null, Buffer.from(canonicalJson(certificate), "utf8"), root.privateKey).toString("base64"),
    },
  };
  const party = (addr, agentId, n) => ({
    sessionKeyAddress: addr, policyDigest: `${"ab".repeat(31)}${String(n)}0`,
    erc8004: {
      agentId, chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
      registrationTx: `0x${"a".repeat(64)}`, registrationBlock: `700${n}`,
    },
  });
  const initiator = party(sessionKeyAddress, "9452", 0);
  const responder = party(`0x${"9".repeat(40)}`, "9453", 1);
  const anchor = (kind, n) => ({
    blockHeight: String(7010 + n), blockTimeRaw: `2026-08-09T17:0${n}:00.000Z`,
    digest: `${n}${"0".repeat(63)}`, kind,
    ledgerId: `33333333-4444-4555-8666-77777777777${n}`,
  });
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

test("observer feed: /contract/receipts is token-gated and serves a bound run's chain", async () => {
  const root = generateKeyPairSync("ed25519");
  const fingerprint = createHash("sha256")
    .update(Buffer.from(rawPublicKeyBase64(root.publicKey), "base64")).digest("hex");
  const env = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_HOST_ROOTS: `root-test:${fingerprint}`,
    CONTRACT_OBSERVER_TOKEN: "observer-secret",
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
  };

  // Off without the observer token even when the route is ready.
  const { CONTRACT_OBSERVER_TOKEN: _drop, ...noTokenEnv } = env;
  const unconfigured = await boot(noTokenEnv);
  try {
    const res = await fetch(`${unconfigured.url}/contract/receipts?runId=x`);
    assert.equal(res.status, 404);
  } finally { await unconfigured.close(); }

  const app = await boot(env);
  try {
    // non-GET → 403; missing/wrong token → 401; unknown run → 404
    const nonGet = await fetch(`${app.url}/contract/receipts?runId=x`, {
      method: "POST", headers: { authorization: "Bearer observer-secret" },
    });
    assert.equal(nonGet.status, 403);
    for (const auth of [undefined, "Bearer wrong"]) {
      const res = await fetch(`${app.url}/contract/receipts?runId=x`, {
        headers: auth === undefined ? {} : { authorization: auth },
      });
      assert.equal(res.status, 401, String(auth));
    }
    const noRun = await fetch(`${app.url}/contract/receipts?runId=unknown`, {
      headers: { authorization: "Bearer observer-secret" },
    });
    assert.equal(noRun.status, 404);

    // bind both parties through the real route, then read the feed
    const cert = mintCertificate({
      root, session: generateKeyPairSync("ed25519"),
      sessionId: "feedfeed-0001-4444-8888-000000000001",
    });
    const bindArgs = {
      certificate: cert,
      signerKey: { keyId: "k", publicKeyHex: `0x${"11".repeat(32)}` },
      approvalKey: { keyId: "a", publicKeyHex: `0x${"22".repeat(32)}` },
    };
    const bindB = await post(app.url, "tools/call", { name: "contract_bind", arguments: bindArgs }, "tb1");
    assert.equal(bindB.body.result.structuredContent.bound, true, JSON.stringify(bindB.body));
    const runId = bindB.body.result.structuredContent.runId;
    const bindP = await post(app.url, "tools/call", { name: "contract_bind", arguments: bindArgs }, "tp1");
    assert.equal(bindP.body.result.structuredContent.bound, true, JSON.stringify(bindP.body));

    const feed = await fetch(`${app.url}/contract/receipts?runId=${runId}`, {
      headers: { authorization: "Bearer observer-secret" },
    });
    assert.equal(feed.status, 200);
    const body = await feed.json();
    assert.equal(body.runId, runId);
    assert.ok(Array.isArray(body.receipts) && body.receipts.length >= 2);
    assert.match(body.head, /^0x[0-9a-f]{64}$/);
  } finally { await app.close(); }
});

// === M3: published server signing key =========================================

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const pubFromHex = (hex) => createPublicKey({
  key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex.slice(2), "hex")]),
  format: "der", type: "spki",
});

test("M3: the server card and /contract/keys publish the signing key + rotation metadata", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_SERVER_KEY_ID: "contract-server-test",
    CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z",
    CONTRACT_SERVER_KEY_VALID_UNTIL: "2027-03-01T00:00:00.000Z",
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_OBSERVER_TOKEN: "observer-secret",
  });
  try {
    // The server card is public discovery — no bearer token.
    const cardRes = await fetch(`${app.url}/.well-known/mcp/server-card.json`);
    assert.equal(cardRes.status, 200);
    const card = await cardRes.json();
    assert.equal(card.schema, "agent-contract.server-card/v1");
    assert.ok(Array.isArray(card.keys) && card.keys.length === 1);
    const pub = card.keys[0];
    assert.equal(pub.keyId, "contract-server-test");
    assert.equal(pub.alg, "Ed25519");
    assert.match(pub.publicKeyHex, /^0x[0-9a-f]{64}$/);
    assert.equal(pub.validFrom, "2026-09-01T00:00:00.000Z");
    assert.equal(pub.validUntil, "2027-03-01T00:00:00.000Z");
    assert.equal(pub.ephemeral, undefined);

    // The key endpoint serves the same key list.
    const keysRes = await fetch(`${app.url}/contract/keys`);
    assert.equal(keysRes.status, 200);
    const keysDoc = await keysRes.json();
    assert.equal(keysDoc.schema, "agent-contract.server-keys/v1");
    assert.deepEqual(keysDoc.keys, card.keys);

    // The published key actually verifies live receipts: a pre-bind call
    // lands a signed receipt; the observer feed hands it back.
    await post(app.url, "tools/call", { name: "contract_status", arguments: {} }, "tb1");
    const feed = await fetch(`${app.url}/contract/receipts?keyId=kb1`, {
      headers: { authorization: "Bearer observer-secret" },
    });
    assert.equal(feed.status, 200);
    const body = await feed.json();
    const verdict = verifyChain(body.receipts, { [pub.keyId]: pubFromHex(pub.publicKeyHex) });
    assert.equal(verdict.ok, true, JSON.stringify(verdict));
  } finally { await app.close(); }
});

test("M3: an ephemeral dev key is published flagged ephemeral:true", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
    CONTRACT_ALLOW_EPHEMERAL_KEY: "1",
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
  });
  try {
    const keysRes = await fetch(`${app.url}/contract/keys`);
    assert.equal(keysRes.status, 200);
    const keysDoc = await keysRes.json();
    assert.equal(keysDoc.keys.length, 1);
    assert.equal(keysDoc.keys[0].ephemeral, true);
    assert.match(keysDoc.keys[0].keyId, /^ephemeral-dev-/);
    const card = await (await fetch(`${app.url}/.well-known/mcp/server-card.json`)).json();
    assert.equal(card.keys[0].ephemeral, true);
  } finally { await app.close(); }
});

test("M3: the key endpoints stay closed when the contract surface is off", async () => {
  const app = await boot({ MCP_TOKEN_SIGNING_SECRET: "", MCP_AUTH_TOKENS: "" });
  try {
    assert.equal((await fetch(`${app.url}/contract/keys`)).status, 404);
    assert.equal((await fetch(`${app.url}/.well-known/mcp/server-card.json`)).status, 404);
  } finally { await app.close(); }
});

// === M4: salted argsDigest for cap-bearing calls ==============================

test("M4: mandate argsDigest is HMAC-salted; the salt is disclosed only to the verifier", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_OBSERVER_TOKEN: "observer-secret",
    CONTRACT_VERIFIER_TOKEN: "verifier-secret",
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
  });
  try {
    // A cap-bearing call — mandate_prepare carries mandate.capMinor.
    const mandateArgs = {
      mandate: {
        kind: "agent-contract.mandate/v1", mandateId: "m-salt-1",
        capMinor: 500_000, currency: "USD",
        allowedItineraryIds: ["IT-QW-ONESTOP"], expiresAt: "2030-01-01T00:00:00.000Z",
      },
      mandateSignature: `0x${"0".repeat(130)}`,
    };
    const call = await post(app.url, "tools/call", { name: "mandate_prepare", arguments: mandateArgs }, "tb1");
    assert.ok(call.status === 200, JSON.stringify(call.body));

    // Observer feed: the receipt's argsDigest is NOT the plain canonicalDigest.
    const feed = await (await fetch(`${app.url}/contract/receipts?keyId=kb1`, {
      headers: { authorization: "Bearer observer-secret" },
    })).json();
    const receipt = feed.receipts.find((r) => r.tool === "mandate_prepare");
    assert.ok(receipt, "mandate_prepare receipt on the pre-bind chain");
    const plain = canonicalDigest(mandateArgs);
    assert.notEqual(receipt.argsDigest, plain, "cap-bearing argsDigest must be salted");
    assert.equal(receipt.argsDigestScheme, "hmac-sha256");
    // A NON-cap call keeps the plain digest.
    await post(app.url, "tools/call", { name: "contract_status", arguments: {} }, "tb1");
    const feed2 = await (await fetch(`${app.url}/contract/receipts?keyId=kb1`, {
      headers: { authorization: "Bearer observer-secret" },
    })).json();
    const statusReceipt = feed2.receipts.find((r) => r.tool === "contract_status");
    assert.equal(statusReceipt.argsDigest, canonicalDigest({}), "non-cap call keeps canonicalDigest");
    assert.equal(statusReceipt.argsDigestScheme ?? "canonical", "canonical");

    // Brute force without the salt fails: candidate caps digest to `plain`,
    // never to the salted value (structural — the salt is 32 bytes).
    for (const cap of [0, 479_000, 500_000, 1_000_000]) {
      const candidate = { ...mandateArgs, mandate: { ...mandateArgs.mandate, capMinor: cap } };
      assert.notEqual(canonicalDigest(candidate), receipt.argsDigest);
    }

    // The observer token CANNOT read the salt — wrong scope.
    const obsAttempt = await fetch(`${app.url}/contract/run-salt?keyId=kb1`, {
      headers: { authorization: "Bearer observer-secret" },
    });
    assert.equal(obsAttempt.status, 401);

    // The verifier token discloses the principal's salt; the digest verifies.
    const saltRes = await fetch(`${app.url}/contract/run-salt?keyId=kb1`, {
      headers: { authorization: "Bearer verifier-secret" },
    });
    const saltDoc = await saltRes.json();
    assert.equal(saltRes.status, 200, JSON.stringify(saltDoc));
    const { salt } = saltDoc;
    assert.match(salt, /^[0-9a-f]{64}$/);
    const hmac = createHmac("sha256", Buffer.from(salt, "hex"))
      .update(canonicalJson(mandateArgs)).digest("hex");
    assert.equal(receipt.argsDigest, `0x${hmac}`, "salted digest reconstructs with the disclosed salt");
  } finally { await app.close(); }
});

test("M4: no verifier token configured → the run-salt endpoint is closed", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_OBSERVER_TOKEN: "observer-secret",
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
    // CONTRACT_VERIFIER_TOKEN intentionally unset
  });
  try {
    const res = await fetch(`${app.url}/contract/run-salt?keyId=kb1`, {
      headers: { authorization: "Bearer verifier-secret" },
    });
    assert.equal(res.status, 404);
  } finally { await app.close(); }
});
