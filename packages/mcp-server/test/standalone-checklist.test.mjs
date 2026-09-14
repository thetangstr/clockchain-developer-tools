import { test } from "node:test";
import assert from "node:assert/strict";

import { evaluateStandaloneReadiness } from "../dist/standalone-handshake/checklist.js";
import { normalizeStandaloneTerms, normalizeStandaloneReadiness, standaloneCanonicalRecord } from "../dist/standalone-handshake/protocol.js";
import { validTerms, validReadiness } from "./helpers/standalone-fixtures.mjs";

const SESSION = "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01";

const OK_RESOLVE = async (_identity, _sessionKeyAddress) => true;
const SIG_INITIATOR = "0x" + "11".repeat(64) + "1b";
const SIG_RESPONDER = "0x" + "22".repeat(64) + "1c";
const ADDR_INITIATOR = "0x" + "11".repeat(20);
const ADDR_RESPONDER = "0x" + "22".repeat(20);

function recovering() {
  return async ({ signatureHex }) => {
    if (signatureHex === SIG_INITIATOR) return ADDR_INITIATOR;
    if (signatureHex === SIG_RESPONDER) return ADDR_RESPONDER;
    return "0x" + "99".repeat(20);
  };
}

async function run(overrides = {}) {
  const terms = normalizeStandaloneTerms(validTerms(overrides.terms));
  const termsDigest = standaloneCanonicalRecord(terms).digest;
  const initiator = normalizeStandaloneReadiness(
    validReadiness({ sessionKeyAddress: ADDR_INITIATOR, authoritySignatureHex: SIG_INITIATOR, ...(overrides.initiator ?? {}) }),
    terms.identityPolicy.erc8004,
  );
  const responder = normalizeStandaloneReadiness(
    validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER, ...(overrides.responder ?? {}) }),
    terms.identityPolicy.erc8004,
  );
  return evaluateStandaloneReadiness({
    sessionId: SESSION,
    terms,
    termsDigest,
    initiator,
    responder,
    resolveIdentity: overrides.resolveIdentity ?? OK_RESOLVE,
    recoverAddress: overrides.recoverAddress ?? recovering(),
  });
}

test("a fully consistent pair passes with a stable checklist digest", async () => {
  const result = await run();
  assert.equal(result.passed, true);
  assert.deepEqual(result.checks.map((c) => c.check), ["identity", "authority", "manifest"]);
  assert.equal(/^[0-9a-f]{64}$/.test(result.checklistDigest), true);
  const again = await run();
  assert.equal(again.checklistDigest, result.checklistDigest);
});

test("identity failure carries IDENTITY_UNVERIFIED and fails the checklist", async () => {
  const result = await run({
    terms: { identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } },
    initiator: { identity: { agentId: "1", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } },
    responder: { identity: { agentId: "2", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } },
    resolveIdentity: async (_identity, _sessionKeyAddress) => false,
  });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["IDENTITY_UNVERIFIED"]);
});

test("a wrong authority signer fails with AUTHORITY_INVALID", async () => {
  const result = await run({ responder: { authoritySignatureHex: "0x" + "33".repeat(64) + "1d" } });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["AUTHORITY_INVALID"]);
});

test("mismatched data-handling class fails with MANIFEST_MISMATCH", async () => {
  const result = await run({ responder: { capabilityManifest: { dataHandlingClass: "public", purpose: "Discuss delivery options for Q3 orders" } } });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["MANIFEST_MISMATCH"]);
});

test("a party whose manifest purpose differs from the terms fails with PURPOSE_MISMATCH", async () => {
  const result = await run({ initiator: { capabilityManifest: { dataHandlingClass: "confidential", purpose: "Sell advertising inventory" } } });
  assert.equal(result.passed, false);
  assert.deepEqual(result.checks.filter((c) => !c.passed).map((c) => c.reason), ["PURPOSE_MISMATCH"]);
});

test("identity is structurally satisfied when the policy is not_required", async () => {
  const result = await run({ resolveIdentity: async (_identity, _sessionKeyAddress) => { throw new Error("must not be called"); } });
  assert.equal(result.passed, true);
});
