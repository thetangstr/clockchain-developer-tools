import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { probeSurface } from "../scripts/agent-contract/probe-staging.mjs";

// N7b piece 3: read-only staging conformance probe, run against the real
// in-process runHttp — no external network.

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const POLICIES = `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`;
const KEY_VALID_FROM = "2026-09-01T00:00:00.000Z";
const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:3301:responder";

function readyEnv(extra = {}) {
  return {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_SERVER_KEY_ID: "contract-server-v1",
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_PRINCIPALS: "kb1:0x5C518D5cf2BEa6e0BcDb0D86B10f279f7b14a8Bb",
    CONTRACT_OBSERVER_TOKEN: "obs-token",
    CONTRACT_VERIFIER_TOKEN: "ver-token",
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n7b-probe-")),
    ...extra,
  };
}

// ---- probe ----

const ENV_KEYS = [
  "PORT", "MCP_PORT", "CONTRACT_MCP_ENABLED", "CONTRACT_AUTH_TOKENS",
  "CONTRACT_SERVER_ED25519_SEED", "CONTRACT_SERVER_KEY_ID",
  "CONTRACT_SERVER_KEY_VALID_FROM", "CONTRACT_POLICY_DIGESTS",
  "CONTRACT_STATE_DIR", "CONTRACT_OBSERVER_TOKEN", "CONTRACT_VERIFIER_TOKEN",
];

async function bootServer(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

test("probe-staging: all checks pass against a conforming in-process server", async () => {
  const app = await bootServer(readyEnv({ MCP_PORT: "0" }));
  try {
    const out = await probeSurface(app.url, { buyer: "tb1", provider: "tp1" });
    assert.equal(out.ok, true);
    const steps = Object.fromEntries(out.checks.map((c) => [c.name, c.ok]));
    assert.equal(steps["server-card"], true);
    assert.equal(steps["card-digest"], true);
    assert.equal(steps["keys"], true);
    assert.equal(steps["initialize:buyer"], true);
    assert.equal(steps["tools-list:buyer"], true);
    assert.equal(steps["tools-list:provider"], true);
    assert.equal(steps["contract-status-no-run"], true);
    // The probe records the digest it compared, never the token.
    assert.equal(JSON.stringify(out).includes("tb1"), false);
  } finally { await app.close(); }
});

test("probe-staging: a token that is not provisioned fails auth cleanly", async () => {
  const app = await bootServer(readyEnv({ MCP_PORT: "0" }));
  try {
    const out = await probeSurface(app.url, { buyer: "wrong-token", provider: "tp1" });
    assert.equal(out.ok, false);
    assert.equal(out.checks.find((c) => c.name === "initialize:buyer").ok, false);
  } finally { await app.close(); }
});

test("probe-staging: disabled surface fails every step read-only", async () => {
  const app = await bootServer({ MCP_PORT: "0" });
  try {
    const out = await probeSurface(app.url, { buyer: "tb1" });
    assert.equal(out.ok, false);
  } finally { await app.close(); }
});
