import { test } from "node:test";
import assert from "node:assert/strict";

import {
  STANDALONE_HANDSHAKE_PROTOCOL,
  MESSAGE_KINDS,
  DATA_HANDLING_CLASSES,
  StandaloneHandshakeValidationError,
  normalizeStandaloneTerms,
  normalizeStandaloneReadiness,
  standaloneAuthorityRecord,
  buildStandaloneConsentRecord,
  standaloneCanonicalRecord,
  normalizeStandaloneClosure,
} from "../dist/standalone-handshake/protocol.js";

import { validTerms, validReadiness } from "./helpers/standalone-fixtures.mjs";

test("accepts a valid terms record and freezes derived values", () => {
  const terms = normalizeStandaloneTerms(validTerms());
  assert.equal(terms.reference, "delivery-options-q3");
  assert.equal(terms.channelLimits.durationSeconds, "3600");
  assert.deepEqual([...terms.channelLimits.messageKinds], ["question", "proposal", "evidence"]);
  assert.equal(Object.isFrozen(terms), true);
});

test("terms rejects an extra key, a bad kind, an out-of-range duration, and a bad size", () => {
  assert.throws(() => normalizeStandaloneTerms({ ...validTerms(), extra: 1 }), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "60", messageKinds: ["bargain"], maxMessageBytes: "16384" } })), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "59", messageKinds: ["question"], maxMessageBytes: "16384" } })), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "86401", messageKinds: ["question"], maxMessageBytes: "16384" } })), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneTerms(validTerms({ channelLimits: { durationSeconds: "3600", messageKinds: ["question"], maxMessageBytes: "16385" } })), StandaloneHandshakeValidationError);
});

test("readiness validates address, signature shape, class, and identity-vs-policy", () => {
  const readiness = normalizeStandaloneReadiness(validReadiness(), "not_required");
  assert.equal(readiness.capabilityManifest.dataHandlingClass, "confidential");
  assert.throws(() => normalizeStandaloneReadiness(validReadiness({ sessionKeyAddress: "0x1234" }), "not_required"), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneReadiness(validReadiness({ authoritySignatureHex: "0x1234" }), "not_required"), StandaloneHandshakeValidationError);
  assert.throws(() => normalizeStandaloneReadiness(validReadiness({ capabilityManifest: { dataHandlingClass: "topsecret", purpose: "x" } }), "not_required"), StandaloneHandshakeValidationError);
  // identity must be null only when the policy is not_required
  assert.throws(() => normalizeStandaloneReadiness(validReadiness(), "required_fresh"), StandaloneHandshakeValidationError);
});

test("authority record and consent record have stable canonical digests", () => {
  const readiness = normalizeStandaloneReadiness(validReadiness(), "not_required");
  const authority = standaloneAuthorityRecord(readiness);
  assert.equal(authority.schema, "clockchain.standalone-handshake-authority/v1");
  const consentA = standaloneCanonicalRecord(buildStandaloneConsentRecord({ sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", role: "initiator", termsDigest: "a".repeat(64), checklistDigest: "b".repeat(64) }));
  const consentB = standaloneCanonicalRecord(buildStandaloneConsentRecord({ role: "initiator", termsDigest: "a".repeat(64), checklistDigest: "b".repeat(64), sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01" }));
  assert.equal(consentA.digest, consentB.digest); // key order irrelevant
  assert.equal(consentA.digest, /^[0-9a-f]{64}$/.test(consentA.digest) ? consentA.digest : "bad");
});

test("closure validates outcome, byRole, and the no-external-action invariant", () => {
  const closure = normalizeStandaloneClosure({ schema: "clockchain.standalone-handshake-closure/v1", protocol: STANDALONE_HANDSHAKE_PROTOCOL, sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", outcome: "revoked", byRole: "initiator", closedAtMs: "1750000000000", externalBusinessActionPerformed: false });
  assert.equal(closure.outcome, "revoked");
  assert.throws(() => normalizeStandaloneClosure({ schema: "clockchain.standalone-handshake-closure/v1", protocol: STANDALONE_HANDSHAKE_PROTOCOL, sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", outcome: "expired", byRole: "initiator", closedAtMs: "1750000000000", externalBusinessActionPerformed: false }), StandaloneHandshakeValidationError); // expired is never closed by a role
  assert.throws(() => normalizeStandaloneClosure({ schema: "clockchain.standalone-handshake-closure/v1", protocol: STANDALONE_HANDSHAKE_PROTOCOL, sessionId: "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01", outcome: "closed", byRole: "initiator", closedAtMs: "1750000000000", externalBusinessActionPerformed: true }), StandaloneHandshakeValidationError);
});

test("module constants are exact", () => {
  assert.equal(STANDALONE_HANDSHAKE_PROTOCOL, "clockchain.standalone-handshake/v1");
  assert.deepEqual([...MESSAGE_KINDS], ["question", "proposal", "evidence", "note"]);
  assert.deepEqual([...DATA_HANDLING_CLASSES], ["public", "confidential", "restricted"]);
});
