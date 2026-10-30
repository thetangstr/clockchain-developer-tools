// H-REQ-07: one agent_handshake_submit reads one clock from authorization
// through signer recovery to publication. Every read must be a safe integer
// no earlier than the read before it. A read that is not an integer, or that
// is earlier than the one before it, refuses the submission with the generic
// coordination_failed reason (V2CoordinatorError) before anything further is
// sent, and the pending item is kept. Equal reads are accepted.
import assert from "node:assert/strict";
import test from "node:test";

import { PENDING_SUBMISSIONS } from "./helpers/agent-handshake-v2-pending-submissions.mjs";

const refusedWith = (detail) => (error) => error?.name === "V2CoordinatorError" && error.detail === detail;

// Runs `effect` once, the first time the coordinator reaches `point`.
function once(harness, point, effect) {
  harness.hooks[point] = (...args) => {
    delete harness.hooks[point];
    return effect(...args);
  };
}

// Where the clock is moved, and how many sends of the item are begun before.
const READS = [
  ["the state read during authorization", 0, (harness, instant) => once(harness, "onStateRead", () => { harness.setClock(instant); })],
  ["signer recovery", 0, (harness, instant) => once(harness, "onRecover", () => { harness.setClock(instant); })],
  ["the state read before publication", 0, (harness, instant) => harness.afterRecovery("onStateRead", () => { harness.setClock(instant); })],
  ["a sequence conflict between post attempts", 1, (harness, instant) => harness.afterRecovery("onRelayPost", () => { harness.setClock(instant); return "conflict"; })],
];

async function assertRefusedAndKept({ harness, role, kind }, operation, sent) {
  assert.equal(harness.sends.filter((send) => send.kind === kind && send.role === role).length, sent, "no send after the refused read");
  assert.equal(harness.posted(kind, role).length, 0, "nothing is published");
  const record = await harness.record(role);
  assert.equal(record.data.pending?.operation, operation, "the pending item is kept");
}

for (const [operation, label, setup] of PENDING_SUBMISSIONS) {
  for (const [point, sent, moveAt] of READS) {
    test(`H-REQ-07: ${label} — a clock read 1 ms earlier than the one before it, at ${point}, refuses the submission with coordination_failed`, async () => {
      const pending = await setup();
      const start = pending.windowEndMs - 10;
      pending.harness.setClock(start);
      moveAt(pending.harness, start - 1);

      await assert.rejects(pending.submit, refusedWith("clock_backwards"));
      await assertRefusedAndKept(pending, operation, sent);
    });
  }

  for (const [point, sent, moveAt] of READS.filter(([name]) => name !== "the state read during authorization")) {
    test(`H-REQ-07: ${label} — a non-integer clock read, at ${point}, refuses the submission with coordination_failed`, async () => {
      const pending = await setup();
      const start = pending.windowEndMs - 10;
      pending.harness.setClock(start);
      moveAt(pending.harness, start + 0.5);

      await assert.rejects(pending.submit, refusedWith("clock_invalid"));
      await assertRefusedAndKept(pending, operation, sent);
    });
  }

  test(`H-REQ-07: ${label} — a clock that reads the same instant from authorization to publication completes the submission`, async () => {
    const { harness, windowEndMs, role, kind, stage, submit } = await setup();
    harness.setClock(windowEndMs - 10);

    assert.equal((await submit()).stage, stage);
    assert.equal(harness.posted(kind, role).length, 1);
    assert.equal((await harness.record(role)).data.pending, null);
  });
}
