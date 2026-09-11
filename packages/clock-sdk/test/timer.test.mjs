// Unit gates for the timer (duration) and alarm (absolute time) one-shots —
// GATES.md G2/G3 semantics. Fake clock + fake timer + mock core client. No real
// time, no network. Self-contained on purpose: node --test treats every file
// under test/ as a test file, so helpers are not shared via a module here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ClockScheduler, timer } from "../dist/index.js";

function fakeClock(start = 0) {
  return {
    epochMs: start,
    uncertaintyMs: 10,
    now() {
      return { epochMs: this.epochMs, uncertaintyMs: this.uncertaintyMs };
    },
  };
}

function fakeTimer() {
  let nextHandle = 1;
  const pending = new Map();
  return {
    set(handler) {
      const h = nextHandle++;
      pending.set(h, handler);
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
}

function mockClient() {
  return {
    attestCalls: [],
    async attestAction(input) {
      this.attestCalls.push(input);
      return {
        schema: "clockchain.receipt/v1",
        network: "testnet",
        status: "anchored",
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

// A disciplined epoch deliberately far from Date.now() so any accidental use of
// the system clock in fireAt math is caught (G2.2).
const DISCIPLINED_NOW = Date.UTC(2030, 0, 1, 0, 0, 0, 0);

// ---------------------------------------------------------------- G2: timer

test("G2.2: timer fireAt = disciplined now + D (not Date.now())", () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const sch = new ClockScheduler({ clock, timer: fakeTimer(), pollMs: 1 });
  const id = timer(sch, clock, 8000, () => {});
  const st = sch.getStatus(id);
  assert.equal(st.fireAt, DISCIPLINED_NOW + 8000);
  assert.ok(Math.abs(st.fireAt - (Date.now() + 8000)) > 60_000, "fireAt must not be derived from the system clock");
  assert.equal(st.state, "scheduled");
  assert.equal(st.everyMs, null, "a timer is a one-shot, not recurring");
});

test("G2.3/G2.4: timer never fires early, fires exactly once when D elapses", async () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  const fires = [];
  const id = timer(sch, clock, 8000, (ctx) => fires.push(ctx));

  clock.epochMs = DISCIPLINED_NOW + 7999; // one ms short
  await timerImpl.flush();
  assert.equal(fires.length, 0, "must not fire before D has elapsed");

  clock.epochMs = DISCIPLINED_NOW + 8000; // exactly D
  await timerImpl.flush();
  assert.equal(fires.length, 1);
  assert.ok(fires[0].firedAt >= fires[0].fireAt, "G2.4 never early");
  assert.equal(fires[0].fireAt, DISCIPLINED_NOW + 8000);
  assert.equal(fires[0].id, id);

  // One-shot: nothing re-armed, no second fire on further ticks.
  assert.equal(timerImpl.size(), 0, "no pending timer after a one-shot fires");
  clock.epochMs = DISCIPLINED_NOW + 20_000;
  await timerImpl.flush();
  assert.equal(fires.length, 1);
  assert.equal(sch.getStatus(id).fireCount, 1);
  assert.equal(sch.getStatus(id).state, "fired");
});

test("G2: a zero-duration timer fires on the next tick, once", async () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  let fired = 0;
  const id = timer(sch, clock, 0, () => fired++);
  await timerImpl.flush();
  assert.equal(fired, 1);
  await timerImpl.flush();
  assert.equal(fired, 1);
  assert.equal(sch.getStatus(id).state, "fired");
});

test("G2: cancelling by the returned id prevents the fire", async () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  let fired = false;
  const id = timer(sch, clock, 5000, () => (fired = true));
  assert.equal(sch.cancel(id), true);
  assert.equal(timerImpl.size(), 0, "cancel disarms the timer");

  clock.epochMs = DISCIPLINED_NOW + 10_000;
  await timerImpl.flush();
  assert.equal(fired, false);
  assert.equal(sch.getStatus(id).state, "cancelled");
});

test("G2: options pass through — id, agentId, mode", async () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const client = mockClient();
  const sch = new ClockScheduler({ clock, timer: timerImpl, client, pollMs: 1 });
  const id = timer(sch, clock, 1000, () => "done", { id: "my-timer", agentId: "agent-7", mode: "soft" });
  assert.equal(id, "my-timer");
  assert.equal(sch.getStatus(id).mode, "soft");

  clock.epochMs = DISCIPLINED_NOW + 1000;
  await timerImpl.flush();
  assert.equal(client.attestCalls.length, 1);
  assert.equal(client.attestCalls[0].agentId, "agent-7");
  assert.equal(sch.getStatus(id).result, "done");
});

test("G2.6/G2.8: a fired timer carries an anchored receipt for THIS job's fire", async () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const client = mockClient();
  const sch = new ClockScheduler({ clock, timer: timerImpl, client, pollMs: 1 });
  const id = timer(sch, clock, 1000, () => {}, { id: "t-1" });

  clock.epochMs = DISCIPLINED_NOW + 1000;
  await timerImpl.flush();

  const st = sch.getStatus(id);
  assert.equal(st.state, "fired");
  assert.equal(st.receipt.status, "anchored");
  assert.notEqual(st.receipt.anchor.blockHeight, null);
  assert.equal(st.receipt.action, "scheduler.fire");
  assert.equal(st.receipt.payload.inputs.id, "t-1");
  assert.equal(st.receipt.payload.inputs.fireAt, DISCIPLINED_NOW + 1000);
  assert.equal(st.receipt.payload.outputs.firedAt, DISCIPLINED_NOW + 1000);
  assert.equal(st.receipt.payload.outputs.fireCount, 1);
});

test("G2: a confirmed-mode timer holds until consensus has crossed fireAt", async () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  // Consensus reported in the gateway's CURRENT (ISO 8601) shape.
  let consensus = new Date(DISCIPLINED_NOW + 500).toISOString();
  const confirmSource = {
    calls: 0,
    async getTimestamp() {
      this.calls++;
      return { madMarzulloTime: consensus, blockHeight: "136", totalNodes: 1, nodeParticipation: 100, votes: 1 };
    },
  };
  const sch = new ClockScheduler({ clock, timer: timerImpl, confirmSource, pollMs: 1 });
  let fired = false;
  const id = timer(sch, clock, 1000, () => (fired = true), { mode: "confirmed" });

  clock.epochMs = DISCIPLINED_NOW + 1000; // local estimate says "now" — consensus lags at +500
  await timerImpl.flush();
  assert.equal(fired, false, "must not fire off the local estimate alone");
  assert.equal(confirmSource.calls, 1);

  consensus = new Date(DISCIPLINED_NOW + 1000).toISOString();
  await timerImpl.flush();
  assert.equal(fired, true);
  assert.equal(sch.getStatus(id).state, "fired");
});

// ---------------------------------------------------------------- G3: alarm

test("G3.2/G3.3: alarm at absolute T fires once, only after consensus >= T", async () => {
  const T = DISCIPLINED_NOW + 10_000;
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const client = mockClient();
  const readings = [];
  let consensus = new Date(DISCIPLINED_NOW).toISOString();
  const confirmSource = {
    async getTimestamp() {
      readings.push(consensus);
      return { madMarzulloTime: consensus, blockHeight: "136", totalNodes: 1, nodeParticipation: 100, votes: 1 };
    },
  };
  const sch = new ClockScheduler({ clock, timer: timerImpl, client, confirmSource, pollMs: 1 });
  const fires = [];
  sch.schedule({ id: "alarm", fireAt: T, mode: "confirmed", agentId: "agent-a", action: (ctx) => fires.push(ctx) });

  // Local clock crosses T, consensus still stale (a quiet chain).
  clock.epochMs = T + 50;
  await timerImpl.flush();
  assert.equal(fires.length, 0, "held: consensus has not crossed T");
  await timerImpl.flush();
  assert.equal(fires.length, 0, "still held on the next tick");
  assert.ok(readings.length >= 2, "G3.4: boundary re-reads consensus each tick while holding");

  // Consensus crosses T.
  consensus = new Date(T + 1).toISOString();
  await timerImpl.flush();
  assert.equal(fires.length, 1);
  assert.ok(fires[0].firedAt >= T, "G3.2 never early on the disciplined clock");
  assert.equal(Date.parse(readings[readings.length - 1]) >= T, true, "G3.3 last consensus read before fire >= T");

  const st = sch.getStatus("alarm");
  assert.equal(st.fireCount, 1);
  assert.equal(st.receipt.status, "anchored");
  assert.equal(client.attestCalls[0].inputs.mode, "confirmed");

  // One-shot: never fires again.
  clock.epochMs = T + 60_000;
  await timerImpl.flush();
  assert.equal(fires.length, 1);
  assert.equal(timerImpl.size(), 0);
});

test("G3.7: a missed alarm (T already past at arm time) fires once, is never silently dropped", async () => {
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const sch = new ClockScheduler({ clock, timer: timerImpl, pollMs: 1 });
  const fires = [];
  sch.schedule({ id: "late", fireAt: DISCIPLINED_NOW - 60_000, action: (ctx) => fires.push(ctx) });
  assert.equal(sch.getStatus("late").state, "scheduled");

  await timerImpl.flush();
  assert.equal(fires.length, 1, "fires on the first tick");
  assert.equal(fires[0].fireAt, DISCIPLINED_NOW - 60_000, "ctx reports the ORIGINAL target so the caller can see it was late");
  assert.ok(fires[0].firedAt - fires[0].fireAt >= 60_000, "lateness is observable from the context");

  await timerImpl.flush();
  assert.equal(fires.length, 1, "once only");
  assert.equal(sch.getStatus("late").fireCount, 1);
});

test("G3.7: a cancelled alarm never fires, even after T", async () => {
  const T = DISCIPLINED_NOW + 5000;
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const client = mockClient();
  const sch = new ClockScheduler({ clock, timer: timerImpl, client, pollMs: 1 });
  let fired = false;
  sch.schedule({ id: "a", fireAt: T, action: () => (fired = true) });
  sch.cancel("a");

  clock.epochMs = T + 1000;
  await timerImpl.flush();
  assert.equal(fired, false);
  assert.equal(client.attestCalls.length, 0, "nothing is anchored for a cancelled alarm");
  assert.equal(sch.getStatus("a").state, "cancelled");
});

test("G3: the alarm's action error is captured, the job is not retried, and no receipt is attached", async () => {
  const T = DISCIPLINED_NOW + 1000;
  const clock = fakeClock(DISCIPLINED_NOW);
  const timerImpl = fakeTimer();
  const client = mockClient();
  const sch = new ClockScheduler({ clock, timer: timerImpl, client, pollMs: 1 });
  sch.schedule({
    id: "boom",
    fireAt: T,
    action: () => {
      throw new Error("handler failed");
    },
  });

  clock.epochMs = T;
  await timerImpl.flush();
  const st = sch.getStatus("boom");
  assert.equal(st.state, "error");
  assert.equal(st.error, "handler failed");
  assert.equal(st.receipt, null, "a failed action is not attested as a fire");
  assert.equal(client.attestCalls.length, 0);
  assert.equal(timerImpl.size(), 0, "one-shot: not re-armed after an error");
});
