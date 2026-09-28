import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { loadContractConfig } from "../dist/agent-contract/config.js";

// H3/C1: these tests boot the REAL runHttp wiring — env → loadContractConfig →
// dispatch — so the enable gate, fail-closed config and prototype-key probes
// exercise exactly what production runs.

const ENV_KEYS = [
  "PORT", "MCP_PORT", "CONTRACT_MCP_ENABLED", "CONTRACT_AUTH_TOKENS",
  "CONTRACT_SERVER_ED25519_SEED", "CONTRACT_ALLOW_EPHEMERAL_KEY",
  "CONTRACT_SERVER_KEY_ID", "CONTRACT_TRUST_PROXY", "CONTRACT_STATE_DIR",
  "CONTRACT_HOST_ROOTS", "CONTRACT_CALLS_PER_MINUTE",
];

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
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
  });
  assert.equal(cfg.kind, "ready");
  assert.equal(cfg.signerEphemeral, true);
  assert.match(cfg.signer.keyId, /^ephemeral-dev-/);
  assert.notEqual(cfg.signer.keyId, "attacker-supplied");
  const noOptIn = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator",
  });
  assert.equal(noOptIn.kind, "misconfigured");
});

test("C1: no tokens configured — prototype keys and constructor get 401 on every method", async () => {
  const app = await boot({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
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
