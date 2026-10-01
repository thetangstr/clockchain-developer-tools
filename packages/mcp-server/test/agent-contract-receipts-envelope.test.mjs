import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { canonicalDigest, canonicalJson } from "../dist/agent-contract/canonical.js";
import { contractRefusalSchema } from "../dist/agent-contract/refusals.js";
import {
  signEnvelope,
  verifyEnvelope,
  PREPARE_ENVELOPE_SCHEMA_ID,
} from "../dist/agent-contract/envelope.js";
import {
  chainHead,
  makeReceipt,
  newServerNonce,
  verifyChain,
  RECEIPT_CHAIN_GENESIS,
} from "../dist/agent-contract/receipts.js";

const serverKey = generateKeyPairSync("ed25519");
const wrongKey = generateKeyPairSync("ed25519");
const signer = { keyId: "contract-server-test", privateKey: serverKey.privateKey };
const publicKeys = { "contract-server-test": serverKey.publicKey };

const envelopeFixture = JSON.parse(readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "agent-contract-prepare-envelope-vectors.json"),
  "utf8",
));

/** Raw 32-byte ed25519 public key → SPKI KeyObject. */
function ed25519PublicKeyFromHex(hex) {
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(hex.replace(/^0x/, ""), "hex"),
  ]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

const testServerKeys = {
  [envelopeFixture.testOnlyServerKey.keyId]: ed25519PublicKeyFromHex(
    envelopeFixture.testOnlyServerKey.publicKeyHex,
  ),
};

test("frozen prepare-envelope vectors verify with the test-only key", () => {
  assert.equal(envelopeFixture.schema, "agent-contract.prepare-envelope-vectors/v1");
  assert.equal(envelopeFixture.vectors.length, 3);
  for (const vector of envelopeFixture.vectors) {
    const { envelope, signedMessage, payloadCanonical } = vector;
    assert.equal(canonicalJson(envelope.payload), payloadCanonical);
    assert.equal(canonicalDigest(envelope.payload), envelope.payloadDigest);
    const { serverSig: _sig, ...message } = envelope;
    assert.equal(canonicalJson(message), signedMessage);
    const verdict = verifyEnvelope(envelope, testServerKeys, {
      nowMs: Date.parse("2029-01-01T00:00:00.000Z"),
    });
    assert.deepEqual(verdict, { ok: true, envelope });
  }
});

test("newServerNonce is 128-bit hex and unique", () => {
  const a = newServerNonce();
  const b = newServerNonce();
  assert.match(a, /^0x[0-9a-f]{32}$/);
  assert.notEqual(a, b);
});

test("receipt chain verifies; head is the last receipt's digest", () => {
  const base = {
    runId: "run-test-1",
    tool: "offer_submit",
    argsDigest: "0x" + "a".repeat(64),
    principal: { role: "buyer", keyId: "buyer-signer-1" },
    outcome: "ok",
    responseDigest: "0x" + "b".repeat(64),
  };
  const r1 = makeReceipt(null, base, signer);
  const r2 = makeReceipt(r1, { ...base, tool: "booking_execute" }, signer);
  const r3 = makeReceipt(r2, { ...base, tool: "settlement_authorize" }, signer);
  assert.equal(r1.prevHash, RECEIPT_CHAIN_GENESIS);
  const verdict = verifyChain([r1, r2, r3], publicKeys);
  assert.deepEqual(verdict, { ok: true, head: chainHead([r1, r2, r3]) });
  assert.equal(chainHead([]), null);
});

test("chain fails on tamper, drop, reorder, wrong key", () => {
  const base = {
    runId: "run-test-1",
    tool: "offer_submit",
    argsDigest: "0x" + "a".repeat(64),
    principal: { role: "buyer", keyId: "buyer-signer-1" },
    outcome: "ok",
    responseDigest: "0x" + "b".repeat(64),
  };
  const r1 = makeReceipt(null, base, signer);
  const r2 = makeReceipt(r1, { ...base, tool: "booking_execute" }, signer);
  const r3 = makeReceipt(r2, { ...base, tool: "settlement_authorize" }, signer);

  const tampered = { ...r2, outcome: "refused" };
  assert.equal(verifyChain([r1, tampered, r3], publicKeys).ok, false);
  assert.equal(verifyChain([r1, r3], publicKeys).code, "CHAIN_LINK");
  assert.equal(verifyChain([r1, r3, r2], publicKeys).ok, false);
  assert.equal(verifyChain([r1, r2, r3], { "contract-server-test": wrongKey.publicKey }).code, "RECEIPT_SIGNATURE");
  assert.equal(verifyChain([r1], {}).code, "KEY_UNKNOWN");
  const forgedId = { ...r1, receiptId: "0x" + "f".repeat(64) };
  assert.equal(verifyChain([forgedId], publicKeys).code, "RECEIPT_ID");
});

test("a receipt chain cannot span runIds", () => {
  const base = {
    tool: "offer_submit",
    argsDigest: "0x" + "a".repeat(64),
    principal: { role: "buyer", keyId: "buyer-signer-1" },
    outcome: "ok",
    responseDigest: "0x" + "b".repeat(64),
  };
  const r1 = makeReceipt(null, { ...base, runId: "run-test-1" }, signer);
  // makeReceipt refuses a foreign-run prev outright.
  assert.throws(
    () => makeReceipt(r1, { ...base, runId: "run-test-2" }, signer),
    /runId/,
  );
  // And a chain whose second receipt carries a different runId is rejected,
  // even though its own signature and genesis link are internally consistent.
  const foreign = makeReceipt(null, { ...base, runId: "run-test-2" }, signer);
  const mixed = verifyChain([r1, foreign], publicKeys);
  assert.equal(mixed.ok, false);
  assert.equal(mixed.code, "RUN_MISMATCH");
});

test("signed envelope roundtrips; expiry, nonce reuse, bad signature refuse", () => {
  const now = Date.parse("2029-06-01T00:00:00.000Z");
  const env = signEnvelope(
    {
      payload: { kind: "offer", itineraryId: "IT-ZX118-ECON", fareMinor: 481800, feeMinor: 10000, currency: "USD" },
      runId: "run-test-1",
      tool: "offer_prepare",
      role: "buyer",
      nowMs: now,
    },
    signer,
  );
  assert.equal(env.schema, PREPARE_ENVELOPE_SCHEMA_ID);
  assert.equal(env.role, "buyer");
  assert.equal(env.serverKeyId, "contract-server-test");
  assert.equal(env.payloadDigest, canonicalDigest(env.payload));
  assert.match(env.nonce, /^0x[0-9a-f]{32}$/);

  assert.equal(verifyEnvelope(env, publicKeys, { nowMs: now + 1_000 }).ok, true);
  assert.equal(verifyEnvelope(env, publicKeys, { nowMs: Date.parse(env.expiresAt) }).code, "ENVELOPE_EXPIRED");
  assert.equal(
    verifyEnvelope(env, publicKeys, { nowMs: now + 1_000, nonceSeen: () => true }).code,
    "NONCE_REUSED",
  );
  const tampered = { ...env, tool: "booking_execute" };
  assert.equal(verifyEnvelope(tampered, publicKeys, { nowMs: now + 1_000 }).code, "ENVELOPE_INVALID");
  const badDigest = { ...env, payloadDigest: "0x" + "0".repeat(64) };
  assert.equal(verifyEnvelope(badDigest, publicKeys, { nowMs: now + 1_000 }).code, "ENVELOPE_INVALID");
  const unknownKey = { ...env, serverSig: { ...env.serverSig, keyId: "nobody" } };
  assert.equal(verifyEnvelope(unknownKey, { ...publicKeys, nobody: wrongKey.publicKey }, { nowMs: now + 1_000 }).code, "ENVELOPE_INVALID");
  // serverKeyId === serverSig.keyId but the key is not pinned → KEY_UNKNOWN.
  const stranger = signEnvelope(
    { payload: { kind: "x" }, runId: "run-test-1", tool: "offer_prepare", role: "buyer", nowMs: now },
    { keyId: "nobody", privateKey: wrongKey.privateKey },
  );
  assert.equal(verifyEnvelope(stranger, publicKeys, { nowMs: now + 1_000 }).code, "KEY_UNKNOWN");
  assert.equal(verifyEnvelope({ not: "an envelope" }, publicKeys).code, "ENVELOPE_INVALID");
});

test("every code verifyEnvelope can return parses under contractRefusalSchema", () => {
  const now = Date.parse("2029-06-01T00:00:00.000Z");
  const env = signEnvelope(
    { payload: { kind: "x" }, runId: "run-test-1", tool: "offer_prepare", role: "buyer", nowMs: now },
    signer,
  );
  const stranger = signEnvelope(
    { payload: { kind: "x" }, runId: "run-test-1", tool: "offer_prepare", role: "buyer", nowMs: now },
    { keyId: "nobody", privateKey: wrongKey.privateKey },
  );
  const codes = [
    verifyEnvelope({ nope: 1 }, publicKeys),
    verifyEnvelope({ ...env, payloadDigest: "0x" + "0".repeat(64) }, publicKeys, { nowMs: now }),
    verifyEnvelope(env, publicKeys, { nowMs: Date.parse(env.expiresAt) + 1 }),
    verifyEnvelope(env, publicKeys, { nowMs: now, nonceSeen: () => true }),
    verifyEnvelope(stranger, publicKeys, { nowMs: now }),
    verifyEnvelope({ ...env, serverSig: { ...env.serverSig, sig: `0x${"0".repeat(128)}` } }, publicKeys, { nowMs: now }),
    verifyEnvelope({ ...env, serverKeyId: "other-key" }, publicKeys, { nowMs: now }),
  ];
  const seen = new Set();
  for (const verdict of codes) {
    assert.equal(verdict.ok, false);
    seen.add(verdict.code);
    assert.equal(
      contractRefusalSchema.safeParse({ error: verdict.code, retryable: false }).success,
      true,
      `code ${verdict.code} is not a legal refusal`,
    );
  }
  assert.deepEqual([...seen].sort(), [
    "ENVELOPE_EXPIRED",
    "ENVELOPE_INVALID",
    "KEY_UNKNOWN",
    "NONCE_REUSED",
  ].sort());
});
