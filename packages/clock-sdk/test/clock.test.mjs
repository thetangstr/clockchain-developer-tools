// Unit tests for ClockchainClock. Fake getTimestamp + injected monotonic clock.
// No network, no real timers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ClockchainClock, parseGatewayTime } from "../dist/index.js";

// A monotonic clock we control: each read returns the next queued value.
function fakeMonotonic(values) {
  let i = 0;
  return () => (i < values.length ? values[i++] : values[values.length - 1]);
}

function fakeSource(madMarzulloTime, absTimeDifference = 0, blockHeight = 100) {
  return {
    calls: 0,
    async getTimestamp() {
      this.calls++;
      return {
        consentedOffset: 0,
        positiveVotesPercentage: 100,
        blockHeight,
        madMarzulloTime,
        nodeStatus: "ok",
        systemTime: madMarzulloTime,
        AbsTimeDifference: absTimeDifference,
        negativeVotesPercentage: 0,
        "nodeParticipation%": 100,
        totalNodes: 1,
      };
    },
  };
}

const TIME = "24-06-2026_22:49:40:092";
const TIME_MS = parseGatewayTime(TIME);

test("sync computes offset from consensus midpoint and monotonic mid", async () => {
  // monotonic: t0=1000 (before), t1=1200 (after) -> rtt=200, mid=1100.
  const source = fakeSource(TIME, 30);
  const clock = new ClockchainClock(source, {
    monotonic: fakeMonotonic([1000, 1200, /* now() */ 1100]),
  });
  const r = await clock.sync();

  assert.equal(r.rttMs, 200);
  assert.equal(r.monotonicMidMs, 1100);
  assert.equal(r.epochMs, TIME_MS);
  assert.equal(r.offsetMs, TIME_MS - 1100);
  // uncertainty = rtt/2 + AbsTimeDifference = 100 + 30
  assert.equal(r.uncertaintyMs, 130);
  assert.equal(r.absTimeDifferenceMs, 30);
});

test("now() = monotonic + offset and advances with the monotonic clock", async () => {
  const source = fakeSource(TIME, 0);
  // sync reads t0=0, t1=0 (rtt 0, mid 0 -> offset = TIME_MS).
  // then now() reads 5000, then 8000.
  const clock = new ClockchainClock(source, {
    monotonic: fakeMonotonic([0, 0, 5000, 8000]),
  });
  await clock.sync();

  const a = clock.now();
  assert.equal(a.epochMs, TIME_MS + 5000);
  const b = clock.now();
  assert.equal(b.epochMs, TIME_MS + 8000);
  assert.ok(b.epochMs > a.epochMs);
});

test("uncertainty band = rtt/2 + AbsTimeDifference is exposed on now()", async () => {
  const source = fakeSource(TIME, 12);
  const clock = new ClockchainClock(source, {
    monotonic: fakeMonotonic([100, 140, 200]), // rtt=40 -> rtt/2=20; +12 = 32
  });
  await clock.sync();
  assert.equal(clock.now().uncertaintyMs, 32);
});

test("now() throws before the first sync; isSynced/lastSync track state", () => {
  const clock = new ClockchainClock(fakeSource(TIME), {
    monotonic: fakeMonotonic([0, 0]),
  });
  assert.equal(clock.isSynced, false);
  assert.equal(clock.lastSync, null);
  assert.throws(() => clock.now(), /sync\(\) before now\(\)/);
});

test("sync throws on an unparseable consensus time", async () => {
  const clock = new ClockchainClock(fakeSource("garbage"), {
    monotonic: fakeMonotonic([0, 0]),
  });
  await assert.rejects(() => clock.sync(), /unparseable madMarzulloTime/);
});

test("auto-resync uses the injected interval scheduler (no real timers)", async () => {
  const source = fakeSource(TIME, 0);
  let handler = null;
  const intervalScheduler = {
    set: (h) => {
      handler = h;
      return 1;
    },
    clear: () => {
      handler = null;
    },
  };
  const clock = new ClockchainClock(source, {
    monotonic: fakeMonotonic([0, 0, 0, 0, 0, 0]),
    autoResyncMs: 1000,
    intervalScheduler,
  });
  await clock.sync();
  assert.equal(source.calls, 1);
  // Fire the interval handler manually; it triggers another sync.
  handler();
  await new Promise((r) => setImmediate(r));
  assert.equal(source.calls, 2);
  clock.stopAutoResync();
  assert.equal(handler, null);
});
