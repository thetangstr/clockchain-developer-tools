// H-REQ-07: agent_handshake_submit accepts a signature only while the
// artifact's signing window is open — the proposal or acceptance payload's
// expiry, or the session deadline for identity claims and evidence — read
// against the coordinator's clock before and after the awaited signer
// recovery. A refused submission publishes nothing and keeps the pending item.
import assert from "node:assert/strict";
import test from "node:test";

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
} from "./helpers/agent-handshake-v2-fixture-harness.mjs";

const isWindowExpired = (error) => error?.name === "V2SigningWindowExpiredError";

// The role access itself expires at the session deadline; for a joined role
// still waiting on host funding that expiry is reported as a funding timeout.
const isRoleAccessExpired = (error) => error?.name === "V2RoleAccessError";
const isFundingTimeout = (error) => error?.name === "V2FundingTimeoutError";

function crossAt(harness, instant) {
  harness.hooks.onRecover = () => { harness.setClock(instant); };
}

// ---- proposal: payload expiry ---------------------------------------------

async function pendingProposal() {
  const harness = await createFixtureHarness();
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
  const submit = () => harness.coordinator.submit({ access: harness.accesses.initiator, policyDigest: F.parties.initiator.policyDigest, signatureHex: sig(2, "initiator") });
  return { harness, expiresAtMs: Number(payload.expiresAtMs), submit };
}

async function assertNothingPublished(harness, role, kind, operation) {
  assert.equal(harness.posted(kind, role).length, 0, `${kind} must not be published`);
  const record = await harness.record(role);
  assert.equal(record.data.pending?.operation, operation, "the pending item is kept");
}

test("H-REQ-07: a proposal signature submitted at the payload's expiry is refused", async () => {
  const { harness, expiresAtMs, submit } = await pendingProposal();
  harness.setClock(expiresAtMs);
  await assert.rejects(submit, isWindowExpired);
  await assertNothingPublished(harness, "initiator", "agent_v2_proposal", "proposal");
});

test("H-REQ-07: a proposal signature submitted 1 ms before the payload's expiry is accepted", async () => {
  const { harness, expiresAtMs, submit } = await pendingProposal();
  harness.setClock(expiresAtMs - 1);
  assert.equal((await submit()).stage, "proposal_submitted");
  assert.equal(harness.posted("agent_v2_proposal", "initiator").length, 1);
});

test("H-REQ-07: a proposal submission whose signer recovery completes at the payload's expiry is refused", async () => {
  const { harness, expiresAtMs, submit } = await pendingProposal();
  harness.setClock(expiresAtMs - 1);
  crossAt(harness, expiresAtMs);
  await assert.rejects(submit, isWindowExpired);
  await assertNothingPublished(harness, "initiator", "agent_v2_proposal", "proposal");
});

// ---- acceptance: payload expiry (bound to the proposal's) ------------------

async function pendingAcceptance() {
  const harness = await createFixtureHarness();
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.setClock(ACCEPT_AT_MS);
  const response = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(response.stage, "sign_acceptance");
  const request = signingRequestOf(response);
  assert.equal(JSON.parse(signedBytesOf(request).toString("utf8")).expiresAtMs, String(PROPOSAL_EXPIRES_MS));
  await harness.checkpointAcceptance(request);
  return harness;
}

test("H-REQ-07: an acceptance signature submitted at the payload's expiry is refused", async () => {
  const harness = await pendingAcceptance();
  harness.setClock(PROPOSAL_EXPIRES_MS);
  await assert.rejects(() => harness.submitAcceptanceSignature(), isWindowExpired);
  await assertNothingPublished(harness, "responder", "agent_v2_acceptance", "acceptance");
});

test("H-REQ-07: an acceptance signature submitted 1 ms before the payload's expiry is accepted", async () => {
  const harness = await pendingAcceptance();
  harness.setClock(PROPOSAL_EXPIRES_MS - 1);
  assert.equal((await harness.submitAcceptanceSignature()).stage, "acceptance_submitted");
  assert.equal(harness.posted("agent_v2_acceptance", "responder").length, 1);
});

test("H-REQ-07: an acceptance submission whose signer recovery completes at the payload's expiry is refused", async () => {
  const harness = await pendingAcceptance();
  harness.setClock(PROPOSAL_EXPIRES_MS - 1);
  crossAt(harness, PROPOSAL_EXPIRES_MS);
  await assert.rejects(() => harness.submitAcceptanceSignature(), isWindowExpired);
  await assertNothingPublished(harness, "responder", "agent_v2_acceptance", "acceptance");
});

// ---- evidence: session deadline -------------------------------------------

async function pendingEvidence() {
  const harness = await pendingAcceptance();
  await harness.submitAcceptanceSignature();
  harness.publishDescriptor();
  const response = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(response.stage, "sign_evidence");
  const submit = () => harness.coordinator.submit({ access: harness.accesses.responder, policyDigest: F.parties.responder.policyDigest, signatureHex: sig(4, "responder") });
  return { harness, submit };
}

test("H-REQ-07: an evidence signature submitted at the session deadline is refused", async () => {
  const { harness, submit } = await pendingEvidence();
  harness.setClock(DEADLINE_MS);
  await assert.rejects(submit, isRoleAccessExpired);
  await assertNothingPublished(harness, "responder", "agent_v2_evidence", "evidence");
});

test("H-REQ-07: an evidence signature submitted 1 ms before the session deadline is accepted", async () => {
  const { harness, submit } = await pendingEvidence();
  harness.setClock(DEADLINE_MS - 1);
  assert.equal((await submit()).stage, "evidence_submitted");
  assert.equal(harness.posted("agent_v2_evidence", "responder").length, 1);
});

test("H-REQ-07: an evidence submission whose signer recovery completes at the session deadline is refused", async () => {
  const { harness, submit } = await pendingEvidence();
  harness.setClock(DEADLINE_MS - 1);
  crossAt(harness, DEADLINE_MS);
  await assert.rejects(submit, isWindowExpired);
  await assertNothingPublished(harness, "responder", "agent_v2_evidence", "evidence");
});

// ---- identity claim: session deadline -------------------------------------

async function pendingIdentityClaim() {
  const harness = await createFixtureHarness();
  await harness.join("initiator");
  return harness;
}

test("H-REQ-07: an identity-claim signature submitted at the session deadline is refused", async () => {
  const harness = await pendingIdentityClaim();
  harness.setClock(DEADLINE_MS);
  await assert.rejects(() => harness.submitIdentity("initiator"), isFundingTimeout);
  await assertNothingPublished(harness, "initiator", "agent_v2_identity_claim", "identity_claim");
});

test("H-REQ-07: an identity-claim signature submitted 1 ms before the session deadline is accepted", async () => {
  const harness = await pendingIdentityClaim();
  harness.setClock(DEADLINE_MS - 1);
  assert.equal((await harness.submitIdentity("initiator")).stage, "identity_claimed");
  assert.equal(harness.posted("agent_v2_identity_claim", "initiator").length, 1);
});

test("H-REQ-07: an identity-claim submission whose signer recovery completes at the session deadline is refused", async () => {
  const harness = await pendingIdentityClaim();
  harness.setClock(DEADLINE_MS - 1);
  crossAt(harness, DEADLINE_MS);
  await assert.rejects(() => harness.submitIdentity("initiator"), isWindowExpired);
  await assertNothingPublished(harness, "initiator", "agent_v2_identity_claim", "identity_claim");
});
