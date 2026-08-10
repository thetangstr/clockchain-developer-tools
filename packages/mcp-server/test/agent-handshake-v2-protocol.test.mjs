import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  normalizeV2Acceptance,
  normalizeV2Descriptor,
  normalizeV2EvidenceResult,
  normalizeV2IdentityClaim,
  normalizeV2Party,
  normalizeV2Policy,
  normalizeV2Proposal,
  normalizeV2Result,
  normalizeV2Terms,
  v2CanonicalRecord,
} from "../dist/agent-handshake/v2/protocol.js";

const fixture = JSON.parse(await readFile(new URL("fixtures/agent-handshake-v2-canonical.json", import.meta.url), "utf8"));

const cases = [
  ["terms", fixture.objects.terms, normalizeV2Terms, fixture.canonical.terms],
  ["initiator policy", fixture.objects.policies.initiator, normalizeV2Policy, fixture.canonical.policies.initiator],
  ["responder policy", fixture.objects.policies.responder, normalizeV2Policy, fixture.canonical.policies.responder],
  ["initiator party", fixture.objects.parties.initiator, (value) => normalizeV2Party(value, fixture.objects.terms.identityPolicy), fixture.canonical.parties.initiator],
  ["responder party", fixture.objects.parties.responder, (value) => normalizeV2Party(value, fixture.objects.terms.identityPolicy), fixture.canonical.parties.responder],
  ["initiator identity", fixture.objects.identityClaims.initiator, normalizeV2IdentityClaim, fixture.canonical.identityClaims.initiator],
  ["responder identity", fixture.objects.identityClaims.responder, normalizeV2IdentityClaim, fixture.canonical.identityClaims.responder],
  ["proposal", fixture.objects.proposalEnvelope.payload, normalizeV2Proposal, fixture.canonical.proposal],
  ["acceptance", fixture.objects.acceptanceEnvelope.payload, normalizeV2Acceptance, fixture.canonical.acceptance],
  ["initiator evidence", fixture.objects.evidence.initiator.result, (value) => normalizeV2EvidenceResult(value, fixture.objects.terms.identityPolicy), fixture.canonical.evidence.initiator],
  ["responder evidence", fixture.objects.evidence.responder.result, (value) => normalizeV2EvidenceResult(value, fixture.objects.terms.identityPolicy), fixture.canonical.evidence.responder],
  ["descriptor", fixture.objects.descriptorEnvelope.descriptor, normalizeV2Descriptor, fixture.canonical.descriptor],
  ["certificate", fixture.objects.certificateEnvelope.result, normalizeV2Result, fixture.canonical.certificate],
];

test("TypeScript validators reproduce every reviewed Handshake v2 byte and digest", () => {
  assert.equal(fixture.handshakeSourceCommit, "c02da109081840262928f1a7e6d636d07e972f42");
  for (const [name, value, normalize, expected] of cases) {
    const normalized = normalize(value);
    assert.deepEqual(normalized, value, name);
    assert.deepEqual(v2CanonicalRecord(normalized), expected, name);
  }
});

test("every v2 validator rejects unknown keys and representative binding mutations", () => {
  for (const [name, value, normalize] of cases) {
    assert.throws(() => normalize({ ...value, extra: true }), undefined, name);
  }
  assert.throws(() => normalizeV2Terms({ ...fixture.objects.terms, validForSeconds: "91" }));
  assert.throws(() => normalizeV2Policy({ ...fixture.objects.policies.initiator, externalBusinessActionsAllowed: true }));
  assert.throws(() => normalizeV2IdentityClaim({ ...fixture.objects.identityClaims.initiator, externalBusinessActionPerformed: true }));
  assert.throws(() => normalizeV2Proposal({ ...fixture.objects.proposalEnvelope.payload, repositorySha: "not-a-sha" }));
  assert.throws(() => normalizeV2Acceptance({ ...fixture.objects.acceptanceEnvelope.payload, decision: "DECLINED" }));
});
