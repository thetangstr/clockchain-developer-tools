// H-REQ-07: agent_handshake_submit_checkpoint publishes a session-key-signed
// commitment checkpoint for the pending proposal or acceptance only while that
// item's signing window is open (the payload's expiry, never later than the
// session deadline) and before the checkpoint's own expiry. It reads one
// non-decreasing clock from authorization on: the checkpoint checks, after
// each awaited signer recovery, inside post() and before every post attempt,
// and inside the state write that records the checkpoint. A closed window is
// refused with signing_window_expired, a lapsed checkpoint with
// coordination_failed (checkpoint.expiresAtMs), and a clock read earlier than
// the one before it, or not an integer, with coordination_failed; nothing
// further is sent and the pending item is kept.
import assert from "node:assert/strict";
import test from "node:test";

import { v2CanonicalRecord } from "../dist/agent-handshake/v2/protocol.js";
import {
  ACCEPT_AT_MS,
  ADDRESSES,
  F,
  PROPOSAL_EXPIRES_MS,
  SESSION_ID,
  clone,
  createFixtureHarness,
  proposalCheckpointFor,
  sig,
  signedBytesOf,
  signingRequestOf,
} from "./helpers/agent-handshake-v2-fixture-harness.mjs";

const KIND = "agent_v2_commitment_checkpoint";
const isWindowExpired = (error) => error?.name === "V2SigningWindowExpiredError";
const refusedWith = (detail) => (error) => error?.name === "V2CoordinatorError" && error.detail === detail;
const isRefused = (error) => error?.name === "V2CoordinatorError" || error?.name === "V2SigningWindowExpiredError";
const HARNESS_OPTIONS = { productionRelayClient: true };

// `checkpointExpiresAtMs(windowEndMs)` (optional) sets the checkpoint's own expiry.
async function pendingProposalCheckpoint(checkpointExpiresAtMs) {
  const harness = await createFixtureHarness(HARNESS_OPTIONS);
  await harness.ready();
  const response = await harness.coordinator.next({ access: harness.accesses.initiator });
  assert.equal(response.stage, "sign_proposal");
  const payload = JSON.parse(signedBytesOf(signingRequestOf(response)).toString("utf8"));
  const envelope = {
    payload,
    schema: "clockchain.agent-handshake-proposal-envelope/v2",
    signature: { address: ADDRESSES.initiator, algorithm: "eip191", value: sig(2, "initiator") },
  };
  const windowEndMs = Number(payload.expiresAtMs);
  const checkpoint = proposalCheckpointFor(envelope);
  if (checkpointExpiresAtMs) checkpoint.expiresAtMs = String(checkpointExpiresAtMs(windowEndMs));
  return {
    harness, windowEndMs, checkpoint, role: "initiator", operation: "proposal", field: "proposalCheckpoint",
    submitCheckpoint: () => harness.coordinator.submitCheckpoint({ access: harness.accesses.initiator, artifactSignatureHex: sig(2, "initiator"), checkpoint }),
  };
}

async function pendingAcceptanceCheckpoint(checkpointExpiresAtMs) {
  const harness = await createFixtureHarness(HARNESS_OPTIONS);
  await harness.ready();
  harness.publishProposal(clone(F.proposalEnvelope));
  harness.setClock(ACCEPT_AT_MS);
  const response = await harness.coordinator.next({ access: harness.accesses.responder });
  assert.equal(response.stage, "sign_acceptance");
  const request = signingRequestOf(response);
  const payload = JSON.parse(signedBytesOf(request).toString("utf8"));
  assert.equal(payload.expiresAtMs, String(PROPOSAL_EXPIRES_MS));
  const envelope = {
    payload,
    schema: "clockchain.agent-handshake-acceptance-envelope/v2",
    signature: { address: ADDRESSES.responder, algorithm: "eip191", value: sig(3, "responder") },
  };
  const windowEndMs = PROPOSAL_EXPIRES_MS;
  const checkpoint = {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1", version: "1",
    protocol: "clockchain.agent-handshake/v2", sessionId: SESSION_ID, role: "responder", artifactType: "acceptance",
    artifactDigest: v2CanonicalRecord(envelope).digest, sequence: "2",
    previousCheckpointDigest: request.previousCheckpointDigest,
    issuedAtMs: String(ACCEPT_AT_MS), expiresAtMs: checkpointExpiresAtMs ? String(checkpointExpiresAtMs(windowEndMs)) : payload.expiresAtMs,
    signerAddress: ADDRESSES.responder,
    signature: { address: ADDRESSES.responder, algorithm: "eip191", value: sig(7, "responder") },
  };
  return {
    harness, windowEndMs, checkpoint, role: "responder", operation: "acceptance", field: "acceptanceCheckpoint",
    submitCheckpoint: () => harness.coordinator.submitCheckpoint({ access: harness.accesses.responder, artifactSignatureHex: sig(3, "responder"), checkpoint }),
  };
}

// Runs `effect` at the n-th signer recovery (1: the artifact signer, 2: the checkpoint signer).
function atRecovery(harness, n, effect) {
  let seen = 0;
  harness.hooks.onRecover = () => {
    seen += 1;
    if (seen === n) {
      delete harness.hooks.onRecover;
      effect();
    }
  };
}

// Runs `effect` at the first attempt to post the checkpoint and answers it with a sequence conflict.
function atConflictingPostAttempt(harness, effect) {
  harness.hooks.onRelayPost = (envelope) => {
    if (envelope.kind !== KIND) return undefined;
    delete harness.hooks.onRelayPost;
    effect();
    return "conflict";
  };
}

async function assertNothingPosted({ harness, role, operation, field }, attempts = 0) {
  assert.equal(harness.sends.filter((send) => send.kind === KIND && send.role === role).length, attempts, "no post attempt after the refused read");
  assert.equal(harness.posted(KIND, role).length, 0, "nothing is published");
  const record = await harness.record(role);
  assert.equal(record.data.pending?.operation, operation, "the pending item is kept");
  assert.equal(record.data[field], undefined, "the checkpoint is not recorded");
}

for (const [label, setup] of [["proposal", pendingProposalCheckpoint], ["acceptance", pendingAcceptanceCheckpoint]]) {
  test(`H-REQ-07: ${label} checkpoint — submitted 1 ms before the window ends, it is published and recorded`, async () => {
    const pending = await setup();
    pending.harness.setClock(pending.windowEndMs - 1);
    assert.equal((await pending.submitCheckpoint()).stage, `${pending.operation}_checkpoint_submitted`);
    assert.equal(pending.harness.posted(KIND, pending.role).length, 1);
    assert.notEqual((await pending.harness.record(pending.role)).data[pending.field], undefined);
  });

  test(`H-REQ-07: ${label} checkpoint — submitted at the window end, it is refused and nothing is posted`, async () => {
    const pending = await setup();
    pending.harness.setClock(pending.windowEndMs);
    await assert.rejects(pending.submitCheckpoint, isRefused);
    await assertNothingPosted(pending);
  });

  test(`H-REQ-07: ${label} checkpoint — submitted at the window end with a later checkpoint expiry, it is refused and nothing is posted`, async () => {
    const pending = await setup((windowEndMs) => windowEndMs + 60_000);
    pending.harness.setClock(pending.windowEndMs);
    await assert.rejects(pending.submitCheckpoint, isWindowExpired);
    await assertNothingPosted(pending);
  });

  for (const [n, recovery] of [[1, "artifact-signer"], [2, "checkpoint-signer"]]) {
    test(`H-REQ-07: ${label} checkpoint — the window end reached during the ${recovery} recovery refuses it, nothing posted`, async () => {
      const pending = await setup();
      pending.harness.setClock(pending.windowEndMs - 1);
      atRecovery(pending.harness, n, () => pending.harness.setClock(pending.windowEndMs));
      await assert.rejects(pending.submitCheckpoint, isWindowExpired);
      await assertNothingPosted(pending);
    });
  }

  test(`H-REQ-07: ${label} checkpoint — the checkpoint's own earlier expiry reached during recovery refuses it, nothing posted`, async () => {
    const pending = await setup((windowEndMs) => windowEndMs - 5);
    pending.harness.setClock(pending.windowEndMs - 6);
    atRecovery(pending.harness, 1, () => pending.harness.setClock(pending.windowEndMs - 5));
    await assert.rejects(pending.submitCheckpoint, refusedWith("checkpoint.expiresAtMs"));
    await assertNothingPosted(pending);
  });

  test(`H-REQ-07: ${label} checkpoint — the window end reached at the relay client's read before posting sends nothing`, async () => {
    const pending = await setup();
    pending.harness.setClock(pending.windowEndMs - 1);
    pending.harness.hooks.onRelayClientRead = () => {
      delete pending.harness.hooks.onRelayClientRead;
      pending.harness.setClock(pending.windowEndMs);
    };
    await assert.rejects(pending.submitCheckpoint, isWindowExpired);
    await assertNothingPosted(pending);
  });

  test(`H-REQ-07: ${label} checkpoint — the window end reached between post attempts stops the retry`, async () => {
    const pending = await setup();
    pending.harness.setClock(pending.windowEndMs - 1);
    atConflictingPostAttempt(pending.harness, () => pending.harness.setClock(pending.windowEndMs));
    await assert.rejects(pending.submitCheckpoint, isWindowExpired);
    await assertNothingPosted(pending, 1);
  });

  test(`H-REQ-07: ${label} checkpoint — the window end reached inside the state write after publication refuses the write`, async () => {
    const pending = await setup();
    pending.harness.setClock(pending.windowEndMs - 1);
    pending.harness.hooks.onRelayPost = (envelope) => {
      if (envelope.kind !== KIND) return undefined;
      delete pending.harness.hooks.onRelayPost;
      // The post lands inside the window; the window ends before the checkpoint is recorded.
      pending.harness.hooks.onStateUpdate = () => {
        delete pending.harness.hooks.onStateUpdate;
        pending.harness.setClock(pending.windowEndMs);
      };
      return undefined;
    };
    await assert.rejects(pending.submitCheckpoint, isWindowExpired);
    assert.equal(pending.harness.posted(KIND, pending.role).length, 1, "published once, inside the window");
    assert.equal((await pending.harness.record(pending.role)).data[pending.field], undefined, "not recorded after the window");
  });

  test(`H-REQ-07: ${label} checkpoint — a clock read 1 ms earlier than the one before it during recovery is refused with coordination_failed`, async () => {
    const pending = await setup();
    const start = pending.windowEndMs - 10;
    pending.harness.setClock(start);
    atRecovery(pending.harness, 1, () => pending.harness.setClock(start - 1));
    await assert.rejects(pending.submitCheckpoint, refusedWith("clock_backwards"));
    await assertNothingPosted(pending);
  });

  test(`H-REQ-07: ${label} checkpoint — a clock read 1 ms earlier than the one before it between post attempts is refused with coordination_failed`, async () => {
    const pending = await setup();
    const start = pending.windowEndMs - 10;
    pending.harness.setClock(start);
    atConflictingPostAttempt(pending.harness, () => pending.harness.setClock(start - 1));
    await assert.rejects(pending.submitCheckpoint, refusedWith("clock_backwards"));
    await assertNothingPosted(pending, 1);
  });

  test(`H-REQ-07: ${label} checkpoint — a non-integer clock read during recovery is refused with coordination_failed`, async () => {
    const pending = await setup();
    const start = pending.windowEndMs - 10;
    pending.harness.setClock(start);
    atRecovery(pending.harness, 2, () => pending.harness.setClock(start + 0.5));
    await assert.rejects(pending.submitCheckpoint, refusedWith("clock_invalid"));
    await assertNothingPosted(pending);
  });
}
