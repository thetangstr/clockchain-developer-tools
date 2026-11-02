// One pending signature per operation agent_handshake_submit completes —
// identity claim, proposal, acceptance, evidence — on the fixture harness,
// with posts through the production relay client. Each setup returns the
// harness, the instant the item's signing window ends, the role and relay
// kind it publishes, the stage a completed submission reports, and submit().
import assert from "node:assert/strict";

import {
  ACCEPT_AT_MS,
  DEADLINE_MS,
  F,
  PROPOSAL_EXPIRES_MS,
  clone,
  createFixtureHarness,
  proposalCheckpointFor,
  sig,
  signedBytesOf,
  signingRequestOf,
} from "./agent-handshake-v2-fixture-harness.mjs";

const HARNESS_OPTIONS = { productionRelayClient: true };

async function pendingIdentityClaim() {
  const harness = await createFixtureHarness(HARNESS_OPTIONS);
  await harness.join("initiator");
  return {
    harness, windowEndMs: DEADLINE_MS, role: "initiator", kind: "agent_v2_identity_claim", stage: "identity_claimed",
    submit: () => harness.submitIdentity("initiator"),
  };
}

async function pendingProposal() {
  const harness = await createFixtureHarness(HARNESS_OPTIONS);
  await harness.ready();
  const response = await harness.coordinator.next({ access: harness.accesses.initiator });
  assert.equal(response.stage, "sign_proposal");
  const payload = JSON.parse(signedBytesOf(signingRequestOf(response)).toString("utf8"));
  const envelope = {
    payload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: F.parties.initiator.sessionKeyAddress, algorithm: "eip191", value: sig(2, "initiator") },
  };
  await harness.coordinator.submitCheckpoint({ access: harness.accesses.initiator, artifactSignatureHex: sig(2, "initiator"), checkpoint: proposalCheckpointFor(envelope) });
  return {
    harness, windowEndMs: Number(payload.expiresAtMs), role: "initiator", kind: "agent_v2_proposal", stage: "proposal_submitted",
    submit: () => harness.coordinator.submit({ access: harness.accesses.initiator, policyDigest: F.parties.initiator.policyDigest, signatureHex: sig(2, "initiator") }),
  };
}

async function acceptanceHarness() {
  const harness = await createFixtureHarness(HARNESS_OPTIONS);
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.setClock(ACCEPT_AT_MS);
  const response = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(response.stage, "sign_acceptance");
  await harness.checkpointAcceptance(signingRequestOf(response));
  return harness;
}

async function pendingAcceptance() {
  const harness = await acceptanceHarness();
  return {
    harness, windowEndMs: PROPOSAL_EXPIRES_MS, role: "responder", kind: "agent_v2_acceptance", stage: "acceptance_submitted",
    submit: () => harness.submitAcceptanceSignature(),
  };
}

async function pendingEvidence() {
  const harness = await acceptanceHarness();
  await harness.submitAcceptanceSignature();
  harness.publishDescriptor();
  const response = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(response.stage, "sign_evidence");
  return {
    harness, windowEndMs: DEADLINE_MS, role: "responder", kind: "agent_v2_evidence", stage: "evidence_submitted",
    submit: () => harness.coordinator.submit({ access: harness.accesses.responder, policyDigest: F.parties.responder.policyDigest, signatureHex: sig(4, "responder") }),
  };
}

// [operation, label, setup]
export const PENDING_SUBMISSIONS = Object.freeze([
  ["identity_claim", "identity claim", pendingIdentityClaim],
  ["proposal", "proposal", pendingProposal],
  ["acceptance", "acceptance", pendingAcceptance],
  ["evidence", "evidence", pendingEvidence],
]);
