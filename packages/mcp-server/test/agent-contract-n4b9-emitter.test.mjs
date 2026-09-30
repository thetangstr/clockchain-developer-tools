import assert from "node:assert/strict";
import test from "node:test";

import { createCloseEmitter } from "../dist/agent-contract/close-emitter.js";
import { SIGNER } from "./n4b9-harness.mjs";

// N4b-9 — F12: a per-attempt deadline covering connection, headers AND body,
// plus a total delivery deadline; attempts counted at dispatch; bounded
// final failure. All stalls are fake — no network.

test("F12: a stalled fetch (headers never arrive) counts the attempt and fails bounded", async () => {
  const states = new Map();
  let fetchCalls = 0;
  const emitter = createCloseEmitter({
    signer: SIGNER,
    closeUrl: "http://127.0.0.1:1",
    backoffMs: [0],
    attemptTimeoutMs: 40,
    deadlineMs: 500,
    fetchImpl: () => { fetchCalls += 1; return new Promise(() => {}); }, // never resolves
    setState: (runId, st) => states.set(runId, { ...st }),
  });
  emitter.notify({ runId: "run-stall-h", terminalState: "settled", ts: "2026-09-01T00:00:00Z" });
  await emitter.flush();
  assert.ok(fetchCalls >= 1);
  const st = states.get("run-stall-h");
  assert.equal(st.status, "failed");
  assert.ok(st.attempts >= 1, "the timed-out attempt was counted at dispatch");
});

test("F12: a stalled response body counts the attempt and fails bounded", async () => {
  const states = new Map();
  const emitter = createCloseEmitter({
    signer: SIGNER,
    closeUrl: "http://127.0.0.1:1",
    backoffMs: [0],
    attemptTimeoutMs: 40,
    deadlineMs: 500,
    // Headers arrive; the body never completes.
    fetchImpl: async () => ({ status: 200, text: () => new Promise(() => {}) }),
    setState: (runId, st) => states.set(runId, { ...st }),
  });
  emitter.notify({ runId: "run-stall-b", terminalState: "settled", ts: "2026-09-01T00:00:00Z" });
  await emitter.flush();
  const st = states.get("run-stall-b");
  assert.equal(st.status, "failed");
  assert.ok(st.attempts >= 1);
});

test("F12: the total delivery deadline bounds a stall even with retries remaining", async () => {
  const states = new Map();
  const emitter = createCloseEmitter({
    signer: SIGNER,
    closeUrl: "http://127.0.0.1:1",
    backoffMs: [0, 0, 0, 0, 0, 0, 0],
    attemptTimeoutMs: 60,
    deadlineMs: 150,
    fetchImpl: () => new Promise(() => {}),
    setState: (runId, st) => states.set(runId, { ...st }),
  });
  const t0 = Date.now();
  emitter.notify({ runId: "run-stall-t", terminalState: "settled", ts: "2026-09-01T00:00:00Z" });
  await emitter.flush();
  assert.ok(Date.now() - t0 < 5_000, "bounded, no hang");
  const st = states.get("run-stall-t");
  assert.equal(st.status, "failed");
  assert.match(st.lastError, /deadline/i);
});

test("F12: a stalled sink ends as a bounded failed close — attempts counted at dispatch", async () => {
  const states = new Map();
  const outcomes = [];
  const emitter = createCloseEmitter({
    signer: SIGNER, closeUrl: "http://127.0.0.1:1",
    backoffMs: [0], attemptTimeoutMs: 30, deadlineMs: 200,
    fetchImpl: () => new Promise(() => {}),
    setState: (rid, st) => states.set(rid, { ...st }),
    recordOutcome: (outcome, d) => outcomes.push({ outcome, ...d }),
  });
  emitter.notify({ runId: "run-x1", terminalState: "no_agreement", ts: "2026-09-01T00:00:00Z" });
  // A second notify while the stall is in flight is a no-op (F11 dedupe).
  emitter.notify({ runId: "run-x1", terminalState: "no_agreement", ts: "2026-09-01T00:00:01Z" });
  await emitter.flush();
  const st = states.get("run-x1");
  assert.equal(st.status, "failed");
  assert.equal(outcomes.length, 1);
  assert.equal(outcomes[0].outcome, "failed");
  assert.ok(outcomes[0].attempts >= 1);
});
