import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { checkConfig } from "../scripts/agent-contract/check-config.mjs";

// N7b piece 1: check-config CLI — loads config as the server does, prints a
// redacted readiness report, exits non-zero on any misconfiguration.

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const POLICIES = `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`;
const KEY_VALID_FROM = "2026-09-01T00:00:00.000Z";
const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:3301:responder";
const PROD_ROOT = "root-2026-08:da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8";

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
    CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "n7b-cfg-")),
    ...extra,
  };
}

test("check-config reports a redacted ready verdict", async () => {
  const out = await checkConfig(readyEnv({ CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1", TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083" }));
  assert.equal(out.exitCode, 0);
  assert.equal(out.report.status, "ready");
  assert.equal(out.report.level, "S");
  assert.equal(out.report.requireBindStatement, true);
  assert.equal(out.report.signer.keyId, "contract-server-v1");
  assert.equal(out.report.keyWindow.validFrom, KEY_VALID_FROM);
  assert.deepEqual(out.report.principals, [
    { keyId: "kb1", address: "0x5c518d5cf2bea6e0bcdb0d86b10f279f7b14a8bb" },
  ]);
  assert.deepEqual(out.report.tokens, [
    { role: "buyer", keyId: "kb1", agentId: "9452", side: "initiator" },
    { role: "provider", keyId: "kp1", agentId: "3301", side: "responder" },
  ]);
  assert.equal(out.report.policyDigests.buyer, `0x${"77".repeat(32)}`);
  assert.equal(out.report.observerToken, "configured");
  assert.equal(out.report.verifierToken, "configured");
  assert.equal(out.report.hostRoots[0].kid, "root-2026-08");
  assert.equal(out.report.hostRoots[0].production, true);
  // No secrets anywhere in the serialized report.
  const text = JSON.stringify(out.report);
  assert.equal(text.includes("tb1"), false);
  assert.equal(text.includes("tp1"), false);
  assert.equal(text.includes(SEED_B64), false);
  assert.equal(text.includes("obs-token"), false);
  assert.equal(text.includes("ver-token"), false);
});

test("check-config exits non-zero on misconfiguration", async () => {
  // missing seed
  const noSeed = await checkConfig(readyEnv({ CONTRACT_SERVER_ED25519_SEED: "" }));
  assert.equal(noSeed.exitCode, 1);
  assert.equal(noSeed.report.status, "misconfigured");
  // S without the bind-statement flag
  const sNoFlag = await checkConfig(readyEnv({ CONTRACT_LEVEL: "S" }));
  assert.equal(sNoFlag.exitCode, 1);
  assert.match(sNoFlag.report.reason, /REQUIRE_BIND_STATEMENT/);
  // * token without the flag (HIGH-1 startup gate)
  const star = await checkConfig(readyEnv({
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:*:initiator",
    CONTRACT_LEVEL: "L",
  }));
  assert.equal(star.exitCode, 1);
  // bad level
  const badLevel = await checkConfig(readyEnv({ CONTRACT_LEVEL: "X" }));
  assert.equal(badLevel.exitCode, 1);
});

test("check-config reports disabled distinctly (exit 2)", async () => {
  const out = await checkConfig({});
  assert.equal(out.exitCode, 2);
  assert.equal(out.report.status, "disabled");
});

test("check-config refuses a test root at S/P but allows it at L", async () => {
  const testRoot = `root-test:${"ab".repeat(32)}`;
  const atP = await checkConfig(readyEnv({
    CONTRACT_LEVEL: "P", CONTRACT_REQUIRE_BIND_STATEMENT: "1", TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083",
    CONTRACT_HOST_ROOTS: testRoot,
  }));
  assert.equal(atP.exitCode, 1);
  assert.match(atP.report.refusals.join(" "), /non-production host root/i);
  const atL = await checkConfig(readyEnv({ CONTRACT_LEVEL: "L", CONTRACT_HOST_ROOTS: testRoot }));
  assert.equal(atL.exitCode, 0);
  assert.equal(atL.report.hostRoots[0].production, false);
  // Production root at P is fine.
  const prodAtP = await checkConfig(readyEnv({
    CONTRACT_LEVEL: "P", CONTRACT_REQUIRE_BIND_STATEMENT: "1", TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083",
    CONTRACT_HOST_ROOTS: PROD_ROOT,
  }));
  assert.equal(prodAtP.exitCode, 0);
});

test("check-config refuses an ephemeral signer at S/P", async () => {
  const out = await checkConfig(readyEnv({
    CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1", TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083",
    CONTRACT_SERVER_ED25519_SEED: "", CONTRACT_ALLOW_EPHEMERAL_KEY: "1",
  }));
  assert.equal(out.exitCode, 1);
  assert.match(out.report.refusals.join(" "), /ephemeral/i);
});

// N4b-10 (D13): CONTRACT_SETTLEMENT_RAIL parse + check-config key-status
// reporting. The resolver seam stands in for Secrets Manager — no AWS.
test("check-config parses CONTRACT_SETTLEMENT_RAIL and reports key status redacted", async () => {
  // Default: simulated rail, no key probe.
  const sim = await checkConfig(readyEnv({}));
  assert.equal(sim.exitCode, 0);
  assert.equal(sim.report.settlementRail, "simulated");
  assert.equal(sim.report.stripeTestKey, null);

  // Unknown value → misconfigured.
  const bad = await checkConfig(readyEnv({ CONTRACT_SETTLEMENT_RAIL: "stripe_live" }));
  assert.equal(bad.exitCode, 1);
  assert.match(bad.report.reason, /CONTRACT_SETTLEMENT_RAIL/);

  // stripe_test_mode with a test key resolvable → status "configured",
  // and the serialized report never carries the key bytes.
  const cfg = await checkConfig(
    readyEnv({ CONTRACT_SETTLEMENT_RAIL: "stripe_test_mode" }),
    { resolveStripeTestSecret: async () => "sk_test_CheckConfigOnly" },
  );
  assert.equal(cfg.exitCode, 0);
  assert.equal(cfg.report.settlementRail, "stripe_test_mode");
  assert.equal(cfg.report.stripeTestKey, "configured");
  assert.equal(JSON.stringify(cfg.report).includes("sk_test_CheckConfigOnly"), false,
    "the key never appears in the report");

  // Absent → honest "absent", still ready (awaiting stop is runtime's).
  const absent = await checkConfig(
    readyEnv({ CONTRACT_SETTLEMENT_RAIL: "stripe_test_mode" }),
    { resolveStripeTestSecret: async () => undefined },
  );
  assert.equal(absent.exitCode, 0);
  assert.equal(absent.report.stripeTestKey, "absent");

  // A non-test key resolves → "refused" at L (reported); at S it's a gate.
  const live = await checkConfig(
    readyEnv({ CONTRACT_SETTLEMENT_RAIL: "stripe_test_mode" }),
    { resolveStripeTestSecret: async () => "sk_live_ShouldNeverBeUsed" },
  );
  assert.equal(live.report.stripeTestKey, "refused");
  assert.equal(JSON.stringify(live.report).includes("sk_live_ShouldNeverBeUsed"), false);
  const liveAtS = await checkConfig(
    readyEnv({
      CONTRACT_SETTLEMENT_RAIL: "stripe_test_mode",
      CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
      TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083",
    }),
    { resolveStripeTestSecret: async () => "sk_live_ShouldNeverBeUsed" },
  );
  assert.equal(liveAtS.exitCode, 1);
  assert.match(liveAtS.report.refusals.join(" "), /non-TEST key/i);
});

