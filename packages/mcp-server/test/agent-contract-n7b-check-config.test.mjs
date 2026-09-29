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

test("check-config reports a redacted ready verdict", () => {
  const out = checkConfig(readyEnv({ CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1" }));
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

test("check-config exits non-zero on misconfiguration", () => {
  // missing seed
  const noSeed = checkConfig(readyEnv({ CONTRACT_SERVER_ED25519_SEED: "" }));
  assert.equal(noSeed.exitCode, 1);
  assert.equal(noSeed.report.status, "misconfigured");
  // S without the bind-statement flag
  const sNoFlag = checkConfig(readyEnv({ CONTRACT_LEVEL: "S" }));
  assert.equal(sNoFlag.exitCode, 1);
  assert.match(sNoFlag.report.reason, /REQUIRE_BIND_STATEMENT/);
  // * token without the flag (HIGH-1 startup gate)
  const star = checkConfig(readyEnv({
    CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:*:initiator",
    CONTRACT_LEVEL: "L",
  }));
  assert.equal(star.exitCode, 1);
  // bad level
  const badLevel = checkConfig(readyEnv({ CONTRACT_LEVEL: "X" }));
  assert.equal(badLevel.exitCode, 1);
});

test("check-config reports disabled distinctly (exit 2)", () => {
  const out = checkConfig({});
  assert.equal(out.exitCode, 2);
  assert.equal(out.report.status, "disabled");
});

test("check-config refuses a test root at S/P but allows it at L", () => {
  const testRoot = `root-test:${"ab".repeat(32)}`;
  const atP = checkConfig(readyEnv({
    CONTRACT_LEVEL: "P", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
    CONTRACT_HOST_ROOTS: testRoot,
  }));
  assert.equal(atP.exitCode, 1);
  assert.match(atP.report.refusals.join(" "), /non-production host root/i);
  const atL = checkConfig(readyEnv({ CONTRACT_LEVEL: "L", CONTRACT_HOST_ROOTS: testRoot }));
  assert.equal(atL.exitCode, 0);
  assert.equal(atL.report.hostRoots[0].production, false);
  // Production root at P is fine.
  const prodAtP = checkConfig(readyEnv({
    CONTRACT_LEVEL: "P", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
    CONTRACT_HOST_ROOTS: PROD_ROOT,
  }));
  assert.equal(prodAtP.exitCode, 0);
});

test("check-config refuses an ephemeral signer at S/P", () => {
  const out = checkConfig(readyEnv({
    CONTRACT_LEVEL: "S", CONTRACT_REQUIRE_BIND_STATEMENT: "1",
    CONTRACT_SERVER_ED25519_SEED: "", CONTRACT_ALLOW_EPHEMERAL_KEY: "1",
  }));
  assert.equal(out.exitCode, 1);
  assert.match(out.report.refusals.join(" "), /ephemeral/i);
});

