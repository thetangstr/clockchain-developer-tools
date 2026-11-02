// H-REQ-07: agent_handshake_submit publishes only inside the signing window.
// The window is checked after every awaited step of publication — the state
// read, the relay read, the relay client's own sequence read — immediately
// before each post attempt, and again before the submission completes and its
// pending item is cleared. A submission whose window closes at any of these
// points is refused with signing_window_expired, sends nothing further and
// keeps its pending item. Posts go through the production relay client.
import assert from "node:assert/strict";
import test from "node:test";

import { PENDING_SUBMISSIONS } from "./helpers/agent-handshake-v2-pending-submissions.mjs";

const isWindowExpired = (error) => error?.name === "V2SigningWindowExpiredError";

// ---- where the clock reaches the instant ----------------------------------
// `sent`: sends of the item begun before the instant; `delivered`: how many of
// them the relay holds.

const POINTS = [
  ["the state read before publication", { sent: 0, delivered: 0 }, (harness, instant) => harness.afterRecovery("onStateRead", () => { harness.setClock(instant); })],
  ["the relay read before publication", { sent: 0, delivered: 0 }, (harness, instant) => harness.afterRecovery("onRelayRead", () => { harness.setClock(instant); })],
  ["the relay client's sequence read", { sent: 0, delivered: 0 }, (harness, instant) => harness.afterRecovery("onRelayClientRead", () => { harness.setClock(instant); })],
  ["a sequence conflict between post attempts", { sent: 1, delivered: 0 }, (harness, instant) => harness.afterRecovery("onRelayPost", () => { harness.setClock(instant); return "conflict"; })],
  ["the post attempt that delivers the item", { sent: 1, delivered: 1 }, (harness, instant) => harness.afterRecovery("onRelayPost", () => { harness.setClock(instant); })],
];

for (const [operation, label, setup] of PENDING_SUBMISSIONS) {
  for (const [point, before, reachAt] of POINTS) {
    test(`H-REQ-07: ${label} — the window closing during ${point} refuses the submission, sends nothing further and keeps the pending item`, async () => {
      const { harness, windowEndMs, role, kind, submit } = await setup();
      harness.setClock(windowEndMs - 2);
      reachAt(harness, windowEndMs);

      await assert.rejects(submit, isWindowExpired);

      const sends = harness.sends.filter((send) => send.kind === kind && send.role === role);
      assert.equal(sends.length, before.sent, "only sends begun inside the window");
      assert.ok(sends.every((send) => send.atMs < windowEndMs), "no send at or after the window end");
      assert.equal(harness.posted(kind, role).length, before.delivered);
      const record = await harness.record(role);
      assert.equal(record.data.pending?.operation, operation, "the pending item is kept");
    });

    test(`H-REQ-07: ${label} — reaching 1 ms before the window end during ${point} publishes once and completes`, async () => {
      const { harness, windowEndMs, role, kind, stage, submit } = await setup();
      harness.setClock(windowEndMs - 2);
      reachAt(harness, windowEndMs - 1);

      assert.equal((await submit()).stage, stage);

      assert.ok(harness.sends.filter((send) => send.kind === kind).every((send) => send.atMs < windowEndMs));
      assert.equal(harness.posted(kind, role).length, 1);
      const record = await harness.record(role);
      assert.equal(record.data.pending, null, "the pending item is cleared");
    });
  }
}
