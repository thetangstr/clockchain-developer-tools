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
