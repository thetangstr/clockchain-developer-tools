import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ENV_PARAMETERS,
  checkConfigFromSsm,
  loadEnvFromSsm,
  parseArgs,
} from "../scripts/agent-contract/check-config-from-ssm.mjs";

// N7c item 3: check-config-from-ssm CLI — pulls the /clockchain/mcp/<NAME>
// SSM parameters for the whole contract env surface into process.env ONLY,
// then runs the SAME check as check-config.mjs. The AWS fetch is injectable;
// these tests never touch AWS (the SDK is lazily imported).

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const POLICIES = `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`;
const KEY_VALID_FROM = "2026-09-01T00:00:00.000Z";
const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:3301:responder";
const OBS_TOKEN = "obs-token-n7c";
const VER_TOKEN = "ver-token-n7c";
const PROD_ROOT = "root-2026-08:da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8";
const PREFIX = "/clockchain/mcp";

/** A fully-populated level-L SSM map (parameter name → value). */
function ssmFixture(stateDir, overrides = {}) {
  const values = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_HOST_ROOTS: PROD_ROOT,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_SERVER_KEY_ID: "contract-server-v1",
    CONTRACT_ALLOW_EPHEMERAL_KEY: "0",
    CONTRACT_SERVER_KEY_VALID_FROM: KEY_VALID_FROM,
    CONTRACT_SERVER_KEY_VALID_UNTIL: "2030-01-01T00:00:00.000Z",
    CONTRACT_POLICY_DIGESTS: POLICIES,
    CONTRACT_PRINCIPALS: "kb1:0x5C518D5cf2BEa6e0BcDb0D86B10f279f7b14a8Bb",
    CONTRACT_OBSERVER_TOKEN: OBS_TOKEN,
    CONTRACT_VERIFIER_TOKEN: VER_TOKEN,
    CONTRACT_ALLOW_SIM_FAULTS: "0",
    CONTRACT_SIM_FAULTS: "",
    CONTRACT_LEVEL: "L",
    CONTRACT_REQUIRE_BIND_STATEMENT: "0",
    TELEMETRY_CLOSE_URL: "http://telemetry-sink:8083",
    TELEMETRY_CLOSE_BACKOFF_MS: "50,100",
    TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS: "5000",
    TELEMETRY_CLOSE_DEADLINE_MS: "60000",
    CONTRACT_CALLS_PER_MINUTE: "60",
    CONTRACT_MAX_RUNS: "128",
    CONTRACT_MAX_RECEIPTS_PER_RUN: "256",
    CONTRACT_MAX_RECEIPTS_PER_PRINCIPAL: "64",
    CONTRACT_RUN_TTL_MS: "3600000",
    CONTRACT_CERT_GRACE_MS: "300000",
    CONTRACT_SESSION_TTL_MS: "900000",
    CONTRACT_STATE_DIR: stateDir,
    CONTRACT_ERC8004_CHAIN_ID: "8453",
    CONTRACT_ERC8004_REGISTRY_ADDRESS: `0x${"4d".repeat(20)}`,
    CONTRACT_ANCHOR_ENABLED: "0",
    CONTRACT_SETTLEMENT_RAIL: "simulated",
    CONTRACT_TRUST_PROXY: "0",
    ...overrides,
  };
  return new Map(
    Object.entries(values).map(([k, v]) => [`${PREFIX}/${k}`, v]),
  );
}

/** fetchParameters stub: records every call, answers from `found`. */
function recordingFetch(found, calls = []) {
  return async ({ region, names }) => {
    calls.push({ region, names: [...names] });
    const out = new Map();
    for (const n of names) if (found.has(n)) out.set(n, found.get(n));
    return out;
  };
}

test("check-config-from-ssm loads SSM values into env and reports ready (exit 0)", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n7c-ssm-"));
  const found = ssmFixture(stateDir);
  const calls = [];
  const env = {};
  const out = await checkConfigFromSsm({
    region: "us-west-2",
    prefix: PREFIX,
    env,
    fetchParameters: recordingFetch(found, calls),
  });
  assert.equal(out.exitCode, 0);
  assert.equal(out.report.status, "ready");
  // Present parameters landed in the env map the check ran against.
  assert.equal(env.CONTRACT_MCP_ENABLED, "1");
  assert.equal(env.CONTRACT_AUTH_TOKENS, TOKENS);
  assert.equal(env.CONTRACT_SERVER_ED25519_SEED, SEED_B64);
  assert.equal(env.CONTRACT_STATE_DIR, stateDir);
  // Every fixture name reports present; nothing was fetched outside the
  // declared env surface.
  for (const name of ENV_PARAMETERS) {
    assert.equal(out.report.parameters[name], "present", name);
  }
  const fetched = calls.flatMap((c) => c.names);
  assert.deepEqual(fetched.sort(), ENV_PARAMETERS.map((n) => `${PREFIX}/${n}`).sort());
});

test("absent parameters leave env untouched and report absent", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n7c-ssm-"));
  const found = ssmFixture(stateDir);
  found.delete(`${PREFIX}/CONTRACT_OBSERVER_TOKEN`);
  found.delete(`${PREFIX}/CONTRACT_VERIFIER_TOKEN`);
  found.delete(`${PREFIX}/CONTRACT_HOST_ROOTS`);
  const env = {
    CONTRACT_OBSERVER_TOKEN: "pre-existing-obs",
    CONTRACT_VERIFIER_TOKEN: "pre-existing-ver",
  };
  const out = await checkConfigFromSsm({
    env,
    fetchParameters: recordingFetch(found),
  });
  assert.equal(out.exitCode, 0);
  // Untouched: the pre-existing values survived; the unset one stays unset.
  assert.equal(env.CONTRACT_OBSERVER_TOKEN, "pre-existing-obs");
  assert.equal(env.CONTRACT_VERIFIER_TOKEN, "pre-existing-ver");
  assert.equal(env.CONTRACT_HOST_ROOTS, undefined);
  assert.equal(out.report.parameters.CONTRACT_OBSERVER_TOKEN, "absent");
  assert.equal(out.report.parameters.CONTRACT_VERIFIER_TOKEN, "absent");
  assert.equal(out.report.parameters.CONTRACT_HOST_ROOTS, "absent");
  assert.equal(out.report.parameters.CONTRACT_MCP_ENABLED, "present");
});

test("the printed report carries no secret bytes", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "n7c-ssm-"));
  const found = ssmFixture(stateDir);
  const out = await checkConfigFromSsm({
    env: {},
    fetchParameters: recordingFetch(found),
  });
  const text = JSON.stringify(out.report);
  for (const secret of [SEED_B64, "tb1", "tp1", OBS_TOKEN, VER_TOKEN]) {
    assert.equal(text.includes(secret), false, `leaked: ${secret}`);
  }
  // The parameters section is names → status strings only.
  for (const v of Object.values(out.report.parameters)) {
    assert.ok(v === "present" || v === "absent");
  }
});

test("--region/--prefix reach the fetcher; parseArgs honors flags and defaults", async () => {
  const calls = [];
  const env = {};
  const out = await checkConfigFromSsm({
    region: "eu-west-1",
    prefix: "/custom/pfx",
    env,
    fetchParameters: recordingFetch(new Map(), calls),
  });
  assert.equal(out.exitCode, 2); // disabled — nothing was loaded
  assert.ok(calls.length > 0);
  for (const c of calls) {
    assert.equal(c.region, "eu-west-1");
    for (const n of c.names) assert.ok(n.startsWith("/custom/pfx/"), n);
  }

  const parsed = parseArgs(["--region", "ap-south-1", "--prefix", "/p2"]);
  assert.equal(parsed.region, "ap-south-1");
  assert.equal(parsed.prefix, "/p2");
  const eq = parseArgs(["--region=eu-central-1", "--prefix=/p3"]);
  assert.equal(eq.region, "eu-central-1");
  assert.equal(eq.prefix, "/p3");

  // Defaults: $AWS_REGION when set, else us-west-2; prefix /clockchain/mcp.
  const saved = process.env.AWS_REGION;
  try {
    delete process.env.AWS_REGION;
    const d = parseArgs([]);
    assert.equal(d.region, "us-west-2");
    assert.equal(d.prefix, "/clockchain/mcp");
    process.env.AWS_REGION = "af-south-1";
    assert.equal(parseArgs([]).region, "af-south-1");
  } finally {
    if (saved === undefined) delete process.env.AWS_REGION;
    else process.env.AWS_REGION = saved;
  }
  assert.equal(parseArgs(["--help"]).help, true);
});

test("the SSM fetch is chunked at 10 parameters per call", async () => {
  assert.ok(ENV_PARAMETERS.length > 10, "surface must exceed one batch");
  const calls = [];
  await loadEnvFromSsm({
    env: {},
    fetchParameters: recordingFetch(new Map(), calls),
  });
  assert.equal(calls.length, Math.ceil(ENV_PARAMETERS.length / 10));
  for (const c of calls) assert.ok(c.names.length <= 10);
  assert.deepEqual(
    calls.flatMap((c) => c.names),
    ENV_PARAMETERS.map((n) => `${PREFIX}/${n}`),
  );
});

test("a ParameterNotFound-style batch is absent, not fatal", async () => {
  const env = {};
  const parameters = await loadEnvFromSsm({
    env,
    fetchParameters: async () => {
      const err = new Error("not here");
      err.name = "ParameterNotFound";
      throw err;
    },
  });
  for (const name of ENV_PARAMETERS) {
    assert.equal(parameters[name], "absent");
    assert.equal(env[name], undefined);
  }
});

test("a fetcher failure is a clean misconfigured verdict — never a secret dump", async () => {
  const failing = async () => {
    throw new Error(`SSM exploded while reading seed=${SEED_B64}`);
  };
  const out = await checkConfigFromSsm({ env: {}, fetchParameters: failing });
  assert.equal(out.exitCode, 1);
  assert.equal(out.report.status, "misconfigured");
  assert.match(out.report.reason, /ssm/i);
  const text = JSON.stringify(out.report);
  assert.equal(text.includes(SEED_B64), false);
  assert.equal(text.includes("SSM exploded"), false, "error message must not be echoed");
});
