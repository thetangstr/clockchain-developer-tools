import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";
import { canonicalJson, canonicalDigest } from "../dist/agent-contract/canonical.js";

// H3/C1: these tests boot the REAL runHttp wiring — env → loadContractConfig →
// dispatch — so the enable gate, fail-closed config and prototype-key probes
// exercise exactly what production runs.

const ENV_KEYS = [
  "PORT", "MCP_PORT", "CONTRACT_MCP_ENABLED", "CONTRACT_AUTH_TOKENS",
  "CONTRACT_SERVER_ED25519_SEED", "CONTRACT_ALLOW_EPHEMERAL_KEY",
  "CONTRACT_SERVER_KEY_ID", "CONTRACT_TRUST_PROXY", "CONTRACT_STATE_DIR",
  "CONTRACT_HOST_ROOTS", "CONTRACT_CALLS_PER_MINUTE", "CONTRACT_OBSERVER_TOKEN",
  "CONTRACT_POLICY_DIGESTS", "CONTRACT_PRINCIPALS", "CONTRACT_OBSERVER_PER_MINUTE",
];

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
// Required §13 policy pins — a "ready" config is impossible without them.
const POLICIES = `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`;
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

async function post(url, method, params = {}, token = null) {
  const headers = { "content-type": "application/json", accept: ACCEPT };
  if (token !== null) headers.authorization = `Bearer ${token}`;
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
