import assert from "node:assert/strict";
import test from "node:test";

import { loadContractConfig } from "../dist/agent-contract/config.js";
import { PUBLISHED_HOST_ROOTS } from "../dist/agent-contract/certificate.js";

// loadContractConfig: the contract surface's eager, fail-closed config verdict.
// It never throws — bad env is a deterministic "misconfigured" the route layer
// turns into a closed endpoint (503), and "disabled" means the route isn't
// mounted at all (404).

const SEED_B64 = Buffer.alloc(32, 7).toString("base64");
const TOKENS = "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder";

test("unset CONTRACT_MCP_ENABLED → disabled", () => {
  assert.equal(loadContractConfig({}).kind, "disabled");
  assert.equal(loadContractConfig({ CONTRACT_AUTH_TOKENS: TOKENS, CONTRACT_SERVER_ED25519_SEED: SEED_B64 }).kind, "disabled");
});

test("enabled + valid tokens + seed → ready with published host roots", () => {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
  });
  assert.equal(cfg.kind, "ready");
  assert.equal(cfg.hostRoots, PUBLISHED_HOST_ROOTS);
  assert.equal(cfg.signer.keyId, "contract-server");
  assert.equal(cfg.signerEphemeral, false);
});

test("malformed tokens → misconfigured (no throw)", () => {
  for (const raw of [
    "tok-a:wizard:k1:9452:initiator",     // bad role
    "tok-a:buyer:k1:9452:chair",          // bad side
    "tok-a:buyer:k1:not-an-agent:initiator",
    "tok-a:buyer::9452:initiator",        // empty keyId
    "tok-a:buyer:k1:9452",                // missing field
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

test("malformed CONTRACT_HOST_ROOTS is misconfigured", () => {
  const cfg = loadContractConfig({
    CONTRACT_MCP_ENABLED: "1",
    CONTRACT_AUTH_TOKENS: TOKENS,
    CONTRACT_SERVER_ED25519_SEED: SEED_B64,
    CONTRACT_HOST_ROOTS: "root-2026-08:notahexdigest",
  });
  assert.equal(cfg.kind, "misconfigured");
});
