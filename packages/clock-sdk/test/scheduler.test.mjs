// Unit tests for ClockScheduler. Fake clock + fake timer + mock core client.
// No real time, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ClockScheduler, timer } from "../dist/index.js";

// A clock whose epochMs we set directly.
function fakeClock(start = 0) {
  return {
    epochMs: start,
    uncertaintyMs: 10,
    now() {
      return { epochMs: this.epochMs, uncertaintyMs: this.uncertaintyMs };
    },
  };
}

// A timer that does NOT run on real time: pending callbacks fire only when we
// call flush(). Each set() returns a handle; clear() removes it.
function fakeTimer() {
  let nextHandle = 1;
  const pending = new Map(); // handle -> callback
  return {
    set(handler) {
      const h = nextHandle++;
      pending.set(h, handler);
      return h;
    },
    clear(h) {
      pending.delete(h);
    },
    // Fire all currently-pending callbacks once (callbacks may schedule more).
    async flush() {
      const batch = [...pending.entries()];
      for (const [h, cb] of batch) {
        pending.delete(h);
        cb();
        await new Promise((r) => setImmediate(r)); // let async onTick settle
      }
    },
    size() {
      return pending.size;
    },
  };
}

function mockClient() {
  return {
    attestCalls: [],
    async attestAction(input) {
      this.attestCalls.push(input);
      return {
        schema: "clockchain.receipt/v1",
        network: "testnet",
        agentId: input.agentId,
        action: input.action,
        eventHash: "deadbeef",
        hashType: "SHA-256",
        payload: { inputs: input.inputs, outputs: input.outputs },
        anchor: {
          ledgerId: "L1",
          assetReferenceId: "r",
          blockHeight: "100",
          recordedAt: "x",
          consensusTime: null,
          confirmed: true,
        },
        attestation: { validators: 1, trustPct: null, status: "single-validator-testnet", note: "" },
        identity: { resolved: false, status: "unknown", note: "" },
        verify: { how: "" },
        disclaimer: "",
      };
    },
  };
}

test("job does NOT fire before disciplined time crosses fireAt", async () => {
  const clock = fakeClock(1000);
  const timerImpl = fakeTimer();
  let fired = false;
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  sch.schedule({ id: "j1", fireAt: 5000, action: () => (fired = true) });

  await timerImpl.flush(); // clock still 1000 < 5000
  assert.equal(fired, false);
  assert.equal(sch.getStatus("j1").state, "scheduled");
  assert.equal(sch.getStatus("j1").fireCount, 0);
});

test("job fires exactly when disciplined time reaches fireAt + attests", async () => {
  const clock = fakeClock(1000);
  const timerImpl = fakeTimer();
  const client = mockClient();
  let fired = false;
  const sch = new ClockScheduler({ clock, timer: timerImpl, client, pollMs: 1 });
  sch.schedule({
    id: "j1",
    fireAt: 5000,
    action: () => (fired = true),
    agentId: "agent-x",
  });

  await timerImpl.flush(); // not yet
  assert.equal(fired, false);

  clock.epochMs = 5000; // cross the boundary
  await timerImpl.flush();

  assert.equal(fired, true);
  const st = sch.getStatus("j1");
  assert.equal(st.state, "fired");
  assert.equal(st.fireCount, 1);
  assert.equal(st.firedAt, 5000);
  assert.equal(client.attestCalls.length, 1);
  assert.equal(client.attestCalls[0].agentId, "agent-x");
  assert.equal(client.attestCalls[0].action, "scheduler.fire");
  assert.ok(st.receipt);
  assert.equal(st.receipt.eventHash, "deadbeef");
});

test("confirmed mode waits for the boundary getTimestamp before firing", async () => {
  // fireAt corresponds to 23:00:00 the same day.
  const fireAt = Date.UTC(2026, 5, 24, 23, 0, 0, 0);
  // disciplined clock is already past fireAt, so onTick reaches the confirm path.
  const clock = fakeClock(fireAt + 1000);
  const timerImpl = fakeTimer();
  // consensus source still reports BEFORE the boundary first, then AFTER.
  let consensus = "24-06-2026_22:00:00:000";
  const confirmSource = {
    calls: 0,
    async getTimestamp() {
      this.calls++;
      return { madMarzulloTime: consensus, AbsTimeDifference: 0, blockHeight: 1 };
    },
  };
  let fired = false;
  const sch = new ClockScheduler({ clock, timer: timerImpl, confirmSource, pollMs: 1 });
  sch.schedule({ id: "c1", fireAt, action: () => (fired = true), mode: "confirmed" });

  await timerImpl.flush(); // consensus 22:00 < fireAt 23:00 -> hold
  assert.equal(fired, false);
  assert.equal(confirmSource.calls, 1);

  consensus = "24-06-2026_23:00:00:000"; // consensus crosses boundary
  await timerImpl.flush();
  assert.equal(fired, true);
  assert.equal(sch.getStatus("c1").state, "fired");
});

test("cancel disarms a scheduled job", async () => {
  const clock = fakeClock(0);
  const timerImpl = fakeTimer();
  let fired = false;
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  sch.schedule({ id: "j1", fireAt: 100, action: () => (fired = true) });
  assert.equal(sch.cancel("j1"), true);
  assert.equal(sch.getStatus("j1").state, "cancelled");

  clock.epochMs = 1000;
  await timerImpl.flush();
  assert.equal(fired, false);
  assert.equal(timerImpl.size(), 0);
  assert.equal(sch.cancel("nope"), false);
});

test("runNow fires immediately regardless of fireAt", async () => {
  const clock = fakeClock(0);
  const timerImpl = fakeTimer();
  const client = mockClient();
  let fired = false;
  const sch = new ClockScheduler({ clock, timer: timerImpl, client, pollMs: 1 });
  sch.schedule({ id: "j1", fireAt: 999999, action: () => (fired = true) });

  const st = await sch.runNow("j1");
  assert.equal(fired, true);
  assert.equal(st.state, "fired");
  assert.equal(st.fireCount, 1);
  assert.equal(client.attestCalls.length, 1);
  await assert.rejects(() => sch.runNow("missing"), /unknown job/);
});

test("getStatus + list snapshot job state; action errors are captured", async () => {
  const clock = fakeClock(5000);
  const timerImpl = fakeTimer();
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  sch.schedule({
    id: "boom",
    fireAt: 1000,
    action: () => {
      throw new Error("kaboom");
    },
  });
  await timerImpl.flush();
  const st = sch.getStatus("boom");
  assert.equal(st.state, "error");
  assert.match(st.error, /kaboom/);
  assert.equal(sch.list().length, 1);
  assert.equal(sch.getStatus("ghost"), null);
});

test("recurring everyMs job re-arms and fires multiple times", async () => {
  const clock = fakeClock(1000);
  const timerImpl = fakeTimer();
  let count = 0;
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  // everyMs -> first fireAt = now()+everyMs = 1000+1000 = 2000.
  sch.schedule({ id: "r1", everyMs: 1000, action: () => count++ });

  clock.epochMs = 2000;
  await timerImpl.flush();
  assert.equal(count, 1);
  assert.equal(sch.getStatus("r1").fireAt, 3000); // re-armed

  clock.epochMs = 3000;
  await timerImpl.flush();
  assert.equal(count, 2);
  assert.equal(sch.getStatus("r1").fireCount, 2);
  sch.clearAll();
});

test("timer() convenience schedules a one-shot at now()+duration", async () => {
  const clock = fakeClock(1000);
  const timerImpl = fakeTimer();
  let fired = false;
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  const id = timer(sch, clock, 500, () => (fired = true));
  assert.equal(sch.getStatus(id).fireAt, 1500);

  clock.epochMs = 1500;
  await timerImpl.flush();
  assert.equal(fired, true);
});

// --- CLO-73: FireContext exposes epochMs + uncertaintyMs (Invalid Date / NaN fix) ---
test("CLO-73: FireContext exposes epochMs + uncertaintyMs populated from the clock", async () => {
  const clock = fakeClock(5000);
  clock.uncertaintyMs = 42; // distinct from the scheduled time so we know it's the clock's
  const timerImpl = fakeTimer();
  let ctx = null;
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  sch.schedule({ id: "j1", fireAt: 5000, action: (c) => (ctx = c) });

  await timerImpl.flush();
  assert.ok(ctx, "action received a FireContext");
  // The examples format `new Date(ctx.epochMs)` and `Math.round(ctx.uncertaintyMs)`.
  assert.equal(ctx.epochMs, 5000);
  assert.equal(ctx.uncertaintyMs, 42);
  assert.equal(ctx.firedAt, 5000);
  assert.equal(ctx.fireAt, 5000);
  // Proves the example output is a real date + a real ± number (not Invalid Date / NaN).
  assert.equal(new Date(ctx.epochMs).toString() !== "Invalid Date", true);
  assert.equal(Number.isNaN(Math.round(ctx.uncertaintyMs)), false);
});

// --- CLO-74: recurring everyMs catch-up storm -> fast-forward to next future slot ---
test("CLO-74: a missed recurring window fires once and resumes on the next future slot", async () => {
  const clock = fakeClock(1000);
  const timerImpl = fakeTimer();
  let count = 0;
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  // first fireAt = now()+everyMs = 1000+1000 = 2000.
  sch.schedule({ id: "r1", everyMs: 1000, action: () => count++ });

  // Simulate downtime/blocking: the disciplined clock jumps far past many slots
  // (2000, 3000, ... 10000 are all "due"). Old code replayed all of them.
  clock.epochMs = 10_000;
  await timerImpl.flush();

  assert.equal(count, 1, "fires at most once on catch-up, not once per missed slot");
  assert.equal(sch.getStatus("r1").fireCount, 1);
  // Resumes strictly in the future (next slot after now = 11000), not 3000.
  assert.equal(sch.getStatus("r1").fireAt, 11_000);

  // No storm: flushing again at the same clock does not fire again.
  await timerImpl.flush();
  assert.equal(count, 1);
  sch.clearAll();
});

// --- CLO-75: long setTimeout overflow -> chunked re-arm hops ---
test("CLO-75: a >24.8-day delay does not overflow/fire early (chunked re-arm)", async () => {
  const MAX = 2_147_483_647; // 2^31 - 1
  const clock = fakeClock(0);
  // A timer that records the delay passed to each set() so we can assert chunking.
  let nextHandle = 1;
  const pending = new Map();
  const delays = [];
  const recTimer = {
    set(handler, delayMs) {
      const h = nextHandle++;
      pending.set(h, handler);
      delays.push(delayMs);
      return h;
    },
    clear(h) {
      pending.delete(h);
    },
    async flush() {
      const batch = [...pending.entries()];
      for (const [h, cb] of batch) {
        pending.delete(h);
        cb();
        await new Promise((r) => setImmediate(r));
      }
    },
    size() {
      return pending.size;
    },
  };
  let fired = false;
  const sch = new ClockScheduler({ clock, timer: recTimer, pollMs: 1 });
  const fireAt = MAX + 1_000_000; // ~24.8 days + a bit
  sch.schedule({ id: "far", fireAt, action: () => (fired = true) });

  // Initial arm must cap at MAX (never pass the full overflowing remaining).
  assert.equal(delays[0], MAX);
  assert.equal(fired, false);

  // The hop fires: it must re-arm (not fire the job). Clock unchanged -> still
  // far away -> still capped at MAX.
  await recTimer.flush();
  assert.equal(fired, false, "far-future hop must not fire early");
  assert.equal(delays[1], MAX);

  // Advance the clock to the boundary; now it re-arms within range, then fires.
  clock.epochMs = fireAt;
  await recTimer.flush(); // hop -> re-arm to a normal onTick poll
  assert.equal(fired, false);
  await recTimer.flush(); // onTick -> fire
  assert.equal(fired, true);
  sch.clearAll();
});

// --- CLO-76: confirmed mode must FAIL CLOSED on a boundary-confirm error ---
test("CLO-76: confirmed mode does NOT fire when boundary getTimestamp throws (fail-closed default)", async () => {
  const fireAt = 5000;
  const clock = fakeClock(fireAt + 1000); // disciplined clock already past the boundary
  const timerImpl = fakeTimer();
  let fired = false;
  const confirmSource = {
    calls: 0,
    async getTimestamp() {
      this.calls++;
      throw new Error("gateway down");
    },
  };
  const sch = new ClockScheduler({ clock, timer: timerImpl, confirmSource, pollMs: 1 });
  sch.schedule({ id: "c1", fireAt, action: () => (fired = true), mode: "confirmed" });

  await timerImpl.flush();
  assert.equal(fired, false, "must not silently downgrade confirmed -> soft");
  assert.equal(sch.getStatus("c1").state, "scheduled"); // held, not fired/error
  assert.ok(confirmSource.calls >= 1);
  assert.equal(timerImpl.size(), 1, "re-armed to retry on the next tick");
  sch.clearAll();
});

test("CLO-76: confirmFailOpen makes confirmed mode fire when boundary getTimestamp throws", async () => {
  const fireAt = 5000;
  const clock = fakeClock(fireAt + 1000);
  const timerImpl = fakeTimer();
  let fired = false;
  const confirmSource = {
    async getTimestamp() {
      throw new Error("gateway down");
    },
  };
  const sch = new ClockScheduler({
    clock,
    timer: timerImpl,
    confirmSource,
    confirmFailOpen: true,
    pollMs: 1,
  });
  sch.schedule({ id: "c1", fireAt, action: () => (fired = true), mode: "confirmed" });

  await timerImpl.flush();
  assert.equal(fired, true, "explicit fail-open fires on the disciplined clock");
  assert.equal(sch.getStatus("c1").state, "fired");
  sch.clearAll();
});

// --- review Low #1: fail-closed confirmed-hold backs off exponentially ---
test("Low#1: fail-closed confirmed-hold backs off (pollMs, 2x, 4x, ... capped) and resets after a successful confirm", async () => {
  // fireAt at a real 2026 boundary so a readable consensus BEFORE it holds
  // (rather than fires) — lets us prove the reset path without firing.
  const fireAt = Date.UTC(2026, 5, 24, 23, 0, 0, 0);
  const clock = fakeClock(fireAt + 1000); // disciplined clock already past -> reach confirm path

  // Recording timer: capture the delay passed to each set().
  let nextHandle = 1;
  const pending = new Map();
  const delays = [];
  const recTimer = {
    set(handler, delayMs) {
      const h = nextHandle++;
      pending.set(h, handler);
      delays.push(delayMs);
      return h;
    },
    clear(h) {
      pending.delete(h);
    },
    async flush() {
      const batch = [...pending.entries()];
      for (const [h, cb] of batch) {
        pending.delete(h);
        cb();
        await new Promise((r) => setImmediate(r));
      }
    },
    size() {
      return pending.size;
    },
  };

  let throwIt = true;
  let fired = false;
  const confirmSource = {
    async getTimestamp() {
      if (throwIt) throw new Error("gateway down");
      // readable, but BEFORE the boundary -> a normal hold (confirm succeeded).
      return { madMarzulloTime: "24-06-2026_22:00:00:000", AbsTimeDifference: 0, blockHeight: 1 };
    },
  };
  const sch = new ClockScheduler({
    clock,
    timer: recTimer,
    confirmSource,
    pollMs: 100,
    maxConfirmHoldMs: 500,
  });
  sch.schedule({ id: "c1", fireAt, action: () => (fired = true), mode: "confirmed" });

  // delays[0] is the initial poll arm (pollMs); delays[1..] are the hold re-arms.
  assert.equal(delays[0], 100);

  await recTimer.flush(); // hold #1 -> pollMs
  await recTimer.flush(); // hold #2 -> 2x
  await recTimer.flush(); // hold #3 -> 4x
  await recTimer.flush(); // hold #4 -> 8x capped to maxConfirmHoldMs
  await recTimer.flush(); // hold #5 -> capped
  assert.equal(fired, false, "fail-closed: never fires while consensus is unreadable");
  assert.deepEqual(
    delays.slice(1, 6),
    [100, 200, 400, 500, 500],
    "hold re-arm grows exponentially, capped at maxConfirmHoldMs",
  );

  // A successful confirm (readable consensus, still before the boundary) resets the backoff.
  throwIt = false;
  await recTimer.flush(); // confirm succeeds -> normal arm (pollMs), holdCount reset to 0
  // Back to unreadable: the next hold delay must restart at pollMs.
  throwIt = true;
  await recTimer.flush(); // hold -> pollMs again (reset proven)
  assert.equal(
    delays[delays.length - 1],
    100,
    "hold delay resets to pollMs after a successful confirm",
  );
  assert.equal(fired, false);
  assert.equal(sch.getStatus("c1").state, "scheduled");
  sch.clearAll();
});

// --- review Low #3: schedule rejects a non-positive everyMs ---
test("Low#3: schedule rejects everyMs <= 0 and still accepts a valid interval", () => {
  const clock = fakeClock(1000);
  const sch = new ClockScheduler({ clock, timer: fakeTimer(), pollMs: 1 });
  assert.throws(() => sch.schedule({ everyMs: 0, action: () => {} }), /everyMs must be > 0/);
  assert.throws(() => sch.schedule({ everyMs: -5, action: () => {} }), /everyMs must be > 0/);
  // a valid everyMs still works: first fireAt = now()+everyMs = 1000+1000 = 2000.
  const id = sch.schedule({ everyMs: 1000, action: () => {} });
  assert.equal(sch.getStatus(id).fireAt, 2000);
  sch.clearAll();
});

test("schedule validates fireAt/everyMs exclusivity and duplicate ids", () => {
  const clock = fakeClock(0);
  const sch = new ClockScheduler({ clock, timer: fakeTimer(), pollMs: 1 });
  assert.throws(() => sch.schedule({ action: () => {} }), /either fireAt or everyMs/);
  assert.throws(
    () => sch.schedule({ fireAt: 1, everyMs: 1, action: () => {} }),
    /only one of/,
  );
  sch.schedule({ id: "dup", fireAt: 1, action: () => {} });
  assert.throws(() => sch.schedule({ id: "dup", fireAt: 2, action: () => {} }), /already exists/);
});
