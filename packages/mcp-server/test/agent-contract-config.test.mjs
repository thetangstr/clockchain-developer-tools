import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { loadContractConfig } from "../dist/agent-contract/config.js";
import { PUBLISHED_HOST_ROOTS } from "../dist/agent-contract/certificate.js";

// loadContractConfig: the contract surface's eager, fail-closed config verdict.
// It never throws — bad env is a deterministic "misconfigured" the route layer
// turns into a closed endpoint (503), and "disabled" means the route isn't
// mounted at all (404). A "ready" verdict holds an exclusive lock on its
// state dir, so tests give each one a fresh CONTRACT_STATE_DIR.

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder";
const POLICIES = `buyer:0x${"77".repeat(32)},provider:0x${"88".repeat(32)}`;

function stateDirEnv() {
  return { CONTRACT_STATE_DIR: mkdtempSync(path.join(tmpdir(), "contract-cfg-")) };
}

// N4b-3 LOW: a ready config requires the pinned key-validity window.
const KEY_WINDOW = { CONTRACT_SERVER_KEY_VALID_FROM: "2026-09-01T00:00:00.000Z" };

test("unset CONTRACT_MCP_ENABLED → disabled", () => {
  assert.equal(loadContractConfig({}).kind, "disabled");
  assert.equal(loadContractConfig({ CONTRACT_AUTH_TOKENS: TOKENS, CONTRACT_SERVER_ED25519_SEED: SEED_B64 }).kind, "disabled");
});

test("enabled + valid tokens + seed → ready with published host roots", () => {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    ...KEY_WINDOW,
    ...stateDirEnv(),
  });
  assert.equal(cfg.kind, "ready");
  assert.equal(cfg.hostRoots, PUBLISHED_HOST_ROOTS);
  assert.equal(cfg.signer.keyId, "contract-server");
  assert.equal(cfg.signerEphemeral, false);
  cfg.service.close();
});

test("malformed tokens → misconfigured (no throw)", () => {
  for (const raw of [
    "tok-a:wizard:k1:9452:initiator",     // bad role
    "tok-a:buyer:k1:9452:chair",          // bad side
    "tok-a:buyer:k1:not-an-agent:initiator",
    "tok-a:buyer::9452:initiator",        // empty keyId
    "tok-a:buyer:k1:9452",                // missing field
    "tok-a:provider:k1:9453:initiator",   // provider MUST be responder (N4)
    "tok-a:buyer:k1:9452:responder",      // buyer MUST be initiator (N4)
  ]) {
    assert.equal(
      loadContractConfig({ CONTRACT_MCP_ENABLED: "1", CONTRACT_AUTH_TOKENS: raw, CONTRACT_SERVER_ED25519_SEED: SEED_B64 }).kind,
      "misconfigured", raw,
    );
  }
});

test("tokens set + no seed + no ephemeral opt-in → misconfigured", () => {
  const cfg = loadContractConfig({ CONTRACT_MCP_ENABLED: "1", CONTRACT_AUTH_TOKENS: TOKENS });
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /seed|ephemeral/i);
});

test("a bad seed (wrong length) is misconfigured", () => {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(8, 1).toString("base64"),
  });
  assert.equal(cfg.kind, "misconfigured");
});

test("missing or malformed CONTRACT_POLICY_DIGESTS is misconfigured (fail closed)", () => {
  const base = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    ...KEY_WINDOW,
  };
  for (const raw of [
    undefined,                                    // absent entirely
    "",                                           // empty
    `buyer:0x${"77".repeat(32)}`,                 // provider pin missing
    `provider:0x${"88".repeat(32)}`,              // buyer pin missing
    `buyer:0x${"00".repeat(32)},provider:0x${"88".repeat(32)}`, // zero digest is not a pin
    "buyer:notadigest,provider:0x" + "88".repeat(32),
    "wizard:0x" + "77".repeat(32) + ",provider:0x" + "88".repeat(32),
  ]) {
    const cfg = loadContractConfig({ ...base, CONTRACT_POLICY_DIGESTS: raw });
    assert.equal(cfg.kind, "misconfigured", String(raw));
    assert.match(cfg.reason, /policy/i);
  }
});

test("malformed CONTRACT_HOST_ROOTS is misconfigured", () => {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_HOST_ROOTS: "root-2026-08:notahexdigest",
  });
  assert.equal(cfg.kind, "misconfigured");
});

test("a corrupt used-sessions record makes the route misconfigured (fail closed)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "contract-cfg-corrupt-"));
  writeFileSync(path.join(dir, "used-sessions.json"), "{not json");
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    ...KEY_WINDOW,
    CONTRACT_STATE_DIR: dir,
  });
  assert.equal(cfg.kind, "misconfigured");
  assert.match(cfg.reason, /corrupt|state/i);
});

test("a state dir locked by a live service is misconfigured for a second", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "contract-cfg-lock-"));
  const env = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    ...KEY_WINDOW,
    CONTRACT_STATE_DIR: dir,
  };
  const first = loadContractConfig(env);
  assert.equal(first.kind, "ready");
  const second = loadContractConfig(env);
  assert.equal(second.kind, "misconfigured");
  assert.match(second.reason, /lock/i);
  first.service.close();
  // Once released, the dir is usable again.
  const third = loadContractConfig(env);
  assert.equal(third.kind, "ready");
  third.service.close();
});

test("N4b-5: CONTRACT_SIM_FAULTS is config-only JSON keyed by runId", () => {
  const base = {
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_POLICY_DIGESTS: POLICIES,
    ...KEY_WINDOW,
    ...stateDirEnv(),
  };
  // Malformed shapes → misconfigured, never a throw.
  for (const raw of [
    "not-json",
    '["fare"]',
    '{"run-x": {"issueMismatch": "seats"}}',
    '{"run-x": {"issueMismatch": "fare", "extra": true}}',
    '{"run-x": "fare"}',
  ]) {
    const cfg = loadContractConfig({ ...base, CONTRACT_SIM_FAULTS: raw });
    assert.equal(cfg.kind, "misconfigured", raw);
    assert.match(cfg.reason, /CONTRACT_SIM_FAULTS/);
  }
  // A valid seed boots ready.
  const ok = loadContractConfig({
    ...base,
    ...stateDirEnv(),
    CONTRACT_SIM_FAULTS: '{"run-a2": {"issueMismatch": "fare"}}',
  });
  assert.equal(ok.kind, "ready");
  ok.service.close();
});
