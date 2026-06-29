// End-to-end keeper data-plane behaviour, fully offline:
//   schedule -> fire -> deliver (mock webhook) -> anchor; truthful anchoring "not done until
//   anchored"; anchor-once-then-poll (no credit re-charge); due-trigger-never-
//   dropped; re-arm on restart; dead-letter across ticks; cancel scoping; interval
//   re-arm + fast-forward; no double-delivery across an anchor retry.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keeper, MemoryStore, nextIntervalSlot, verifyWebhook } from "../dist/index.js";

const SECRET = "whsec_dGVzdHNlY3JldA==";

// A controllable clock.
function clockAt(start) {
  let t = start;
  return { now: () => t, set: (v) => (t = v), advance: (d) => (t += d) };
}

// A mock webhook endpoint: records every POST and replies with `status`.
function mockFetch(status = 200) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, headers: init.headers, body: init.body });
    return { status: typeof status === "function" ? status(calls.length) : status };
  };
  return { fn, calls };
}

// Anchorer fakes that track anchorFire (chargeable) vs pollAnchor (read-only).
function anchorOk() {
  const calls = { anchorFire: 0, pollAnchor: 0 };
  return {
    calls,
    anchorFire: async () => {
      calls.anchorFire++;
      return { status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "100", receiptSchema: "clockchain.receipt/v1", receipt: { r: 1 } };
    },
    pollAnchor: async () => {
      calls.pollAnchor++;
      return { status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "100", receiptSchema: "clockchain.receipt/v1", receipt: { r: 1 } };
    },
  };
}
function anchorPendingThenAnchored() {
  const calls = { anchorFire: 0, pollAnchor: 0 };
  return {
    calls,
    anchorFire: async () => {
      calls.anchorFire++;
      return { status: "pending", eventHash: "h", ledgerId: "L1", blockHeight: null, receiptSchema: "clockchain.receipt/v1", receipt: { r: 1 } };
    },
    pollAnchor: async () => {
      calls.pollAnchor++;
      return { status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "101", receiptSchema: "clockchain.receipt/v1", receipt: { r: 1 } };
    },
  };
}
function anchorThrowOnce() {
  const calls = { anchorFire: 0, pollAnchor: 0 };
  return {
    calls,
    anchorFire: async () => {
      calls.anchorFire++;
      if (calls.anchorFire < 2) throw new Error("gateway down");
      return { status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "102", receiptSchema: "clockchain.receipt/v1", receipt: { r: 1 } };
    },
    pollAnchor: async () => {
      calls.pollAnchor++;
      return { status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "102", receiptSchema: "clockchain.receipt/v1", receipt: { r: 1 } };
    },
  };
}

function makeKeeper(over = {}) {
  const store = over.store ?? new MemoryStore();
  const clock = over.clock ?? clockAt(10_000);
  const fetch = over.fetch ?? mockFetch(200);
  const anchorer = over.anchorer ?? anchorOk();
  const keeper = new Keeper({
    store,
    anchorer,
    nowMs: clock.now,
    nowUncertaintyMs: () => 7,
    fetchFn: fetch.fn,
    idGen: over.idGen,
    config: {
      agentId: "agent:test-keeper",
      webhookSecret: SECRET,
      ssrf: { allowLoopback: true },
      maxAttempts: 3,
      baseDelayMs: 0, // no across-tick wait in tests (clock is fixed)
      anchorRetryDelayMs: 0,
      ...over.config,
    },
  });
  return { keeper, store, clock, fetch, anchorer };
}

test("schedule -> fire -> deliver (signed) -> anchor; trigger done in one tick", async () => {
  const { keeper, store, fetch, anchorer } = makeKeeper({ clock: clockAt(10_000), idGen: () => "trg1" });
  const t = await keeper.schedule({
    sub: "u1",
    fireAtMs: 9_000, // already due
    target: "https://127.0.0.1/hook",
    payload: { hello: "world" },
  });
  assert.equal(t.status, "scheduled");

  const sum = await keeper.tick();
  assert.equal(sum.fired, 1);
  assert.equal(sum.delivered, 1);
  assert.equal(sum.anchored, 1);

  assert.equal(fetch.calls.length, 1);
  const call = fetch.calls[0];
  assert.equal(call.url, "https://127.0.0.1/hook");
  const ok = verifyWebhook({
    id: call.headers["webhook-id"],
    timestampSec: Number(call.headers["webhook-timestamp"]),
    body: call.body,
    secret: SECRET,
    signatureHeader: call.headers["webhook-signature"],
  });
  assert.ok(ok, "delivered payload carries a verifiable signature");
  const sent = JSON.parse(call.body);
  assert.equal(sent.type, "keeper.fire");
  assert.deepEqual(sent.payload, { hello: "world" });
  assert.equal(sent.firedAtMs, 10_000);

  const stored = await store.get("trg1");
  assert.equal(stored.status, "done");
  assert.equal(stored.fires[0].delivery.status, "delivered");
  assert.equal(stored.fires[0].anchor.status, "anchored");
  assert.equal(stored.fires[0].fireId, "trg1#9000");
  assert.equal(anchorer.calls.anchorFire, 1);
  assert.equal(anchorer.calls.pollAnchor, 0);

  // Terminal: a second tick is a no-op (no re-fire, no second delivery/charge).
  const sum2 = await keeper.tick();
  assert.equal(sum2.fired, 0);
  assert.equal(fetch.calls.length, 1);
  assert.equal(anchorer.calls.anchorFire, 1);
});

test("not-due triggers are not fired", async () => {
  const { keeper, fetch } = makeKeeper({ clock: clockAt(1_000), idGen: () => "future" });
  await keeper.schedule({ sub: "u1", fireAtMs: 10_000, target: "https://127.0.0.1/h" });
  const sum = await keeper.tick();
  assert.equal(sum.fired, 0);
  assert.equal(fetch.calls.length, 0);
});

test("truthful anchoring + credit-safety: anchored ONCE, then polled read-only (no re-charge)", async () => {
  const anchorer = anchorPendingThenAnchored();
  const { keeper, store } = makeKeeper({ anchorer, idGen: () => "trgP" });
  await keeper.schedule({ sub: "u1", fireAtMs: 0, target: "https://127.0.0.1/h" });

  const s1 = await keeper.tick();
  assert.equal(s1.pendingAnchor, 1);
  assert.equal(s1.anchored, 0);
  let stored = await store.get("trgP");
  assert.equal(stored.status, "firing", "still firing — NOT done until anchored");
  assert.equal(stored.fires[0].anchor.status, "pending");
  assert.ok(stored.fires[0].anchor.receipt, "pending receipt persisted for read-only polling");
  assert.equal(anchorer.calls.anchorFire, 1);
  assert.equal(anchorer.calls.pollAnchor, 0);

  const s2 = await keeper.tick();
  assert.equal(s2.anchored, 1);
  stored = await store.get("trgP");
  assert.equal(stored.status, "done");
  assert.equal(stored.fires[0].anchor.status, "anchored");
  // The chargeable write happened ONCE; confirmation came from a read-only poll.
  assert.equal(anchorer.calls.anchorFire, 1, "no re-anchor (no duplicate credit)");
  assert.equal(anchorer.calls.pollAnchor, 1, "polled via completeReceipt");
});

test("due-trigger never dropped: anchor throws then recovers, fire completes", async () => {
  const anchorer = anchorThrowOnce();
  const { keeper, store, fetch } = makeKeeper({ anchorer, idGen: () => "trgT" });
  await keeper.schedule({ sub: "u1", fireAtMs: 0, target: "https://127.0.0.1/h" });

  await keeper.tick(); // delivers; anchorFire throws -> stays armed (no receipt)
  let stored = await store.get("trgT");
  assert.equal(stored.status, "firing");
  assert.match(stored.lastError, /gateway down/);
  assert.equal(fetch.calls.length, 1, "delivered once");

  await keeper.tick(); // anchorFire retried (no receipt persisted) -> anchored; NO re-delivery
  stored = await store.get("trgT");
  assert.equal(stored.status, "done");
  assert.equal(stored.fires[0].anchor.status, "anchored");
  assert.equal(fetch.calls.length, 1, "no double-delivery across the anchor retry");
  assert.equal(anchorer.calls.anchorFire, 2);
  assert.equal(anchorer.calls.pollAnchor, 0);
});

test("re-arm on restart: a due trigger persisted by a prior run fires on the next boot's tick", async () => {
  const seed = {
    id: "boot1",
    sub: "u1",
    fireAtMs: 5_000,
    target: "https://127.0.0.1/h",
    payload: { x: 1 },
    mode: "once",
    status: "scheduled",
    createdAtMs: 0,
    updatedAtMs: 0,
    attempts: 0,
    nextAttemptAtMs: 0,
    lastError: null,
    fires: [],
  };
  const store = new MemoryStore([seed]);
  const { keeper, fetch } = makeKeeper({ store, clock: clockAt(9_999) });
  const sum = await keeper.tick();
  assert.equal(sum.fired, 1);
  assert.equal(sum.anchored, 1);
  assert.equal(fetch.calls.length, 1);
  assert.equal((await store.get("boot1")).status, "done");
});

test("dead-letter: delivery retries ACROSS ticks, exhausts, fire still anchored, trigger dead", async () => {
  const fetch = mockFetch(500); // always fails
  const { keeper, store } = makeKeeper({ fetch, idGen: () => "trgD" });
  await keeper.schedule({ sub: "u1", fireAtMs: 0, target: "https://127.0.0.1/h" });

  // maxAttempts=3 -> one POST per tick, dead-lettered on the 3rd.
  let stored;
  for (let i = 0; i < 3; i++) {
    await keeper.tick();
    stored = await store.get("trgD");
  }
  assert.equal(fetch.calls.length, 3, "one delivery attempt per tick (no in-tick sleeps)");
  assert.equal(stored.status, "dead");
  assert.equal(stored.fires[0].delivery.status, "dead");
  assert.equal(stored.fires[0].delivery.attempts, 3);
  assert.equal(stored.fires[0].anchor.status, "anchored", "a dead-lettered fire is STILL anchored");
});

test("interval mode re-arms fireAtMs after a successful anchored fire", async () => {
  const { keeper, store, clock } = makeKeeper({ clock: clockAt(1_000), idGen: () => "trgI" });
  await keeper.schedule({ sub: "u1", fireAtMs: 1_000, target: "https://127.0.0.1/h", mode: "interval", intervalMs: 5_000 });
  await keeper.tick();
  let stored = await store.get("trgI");
  assert.equal(stored.status, "scheduled", "re-armed, not done");
  assert.equal(stored.fireAtMs, 6_000);
  assert.equal(stored.fires.length, 1);

  assert.equal((await keeper.tick()).fired, 0); // not due at t=1000
  clock.set(6_000);
  await keeper.tick();
  stored = await store.get("trgI");
  assert.equal(stored.fireAtMs, 11_000);
  assert.equal(stored.fires.length, 2);
});

test("interval fast-forward: after downtime, jump to the next FUTURE slot (no catch-up storm)", async () => {
  // Pure helper: 20 intervals elapsed -> skip straight to slot 101000, not 6000.
  assert.equal(nextIntervalSlot(1_000, 5_000, 100_000), 101_000);

  const { keeper, store } = makeKeeper({ clock: clockAt(100_000), idGen: () => "trgFF" });
  await keeper.schedule({ sub: "u1", fireAtMs: 1_000, target: "https://127.0.0.1/h", mode: "interval", intervalMs: 5_000 });
  await keeper.tick();
  const stored = await store.get("trgFF");
  assert.equal(stored.fires.length, 1, "fired exactly once, not once per missed slot");
  assert.equal(stored.fireAtMs, 101_000, "fast-forwarded past now to the next slot");
});

test("interval re-arms even through a dead-lettered delivery (fire is anchored)", async () => {
  const fetch = mockFetch(500);
  const { keeper, store } = makeKeeper({ fetch, clock: clockAt(1_000), idGen: () => "trgID" });
  await keeper.schedule({ sub: "u1", fireAtMs: 1_000, target: "https://127.0.0.1/h", mode: "interval", intervalMs: 5_000 });
  for (let i = 0; i < 3; i++) await keeper.tick(); // exhaust delivery
  const stored = await store.get("trgID");
  assert.equal(stored.status, "scheduled", "interval survives a dead-letter");
  assert.equal(stored.fireAtMs, 6_000);
});

test("cancel is owner-scoped and stops a trigger from firing", async () => {
  const { keeper, store, fetch } = makeKeeper({ clock: clockAt(10_000), idGen: () => "trgC" });
  await keeper.schedule({ sub: "owner", fireAtMs: 0, target: "https://127.0.0.1/h" });

  assert.equal(await keeper.cancel("trgC", "intruder"), null);
  assert.equal((await store.get("trgC")).status, "scheduled");

  const c = await keeper.cancel("trgC", "owner");
  assert.equal(c.status, "cancelled");

  const sum = await keeper.tick();
  assert.equal(sum.fired, 0);
  assert.equal(fetch.calls.length, 0);
});

test("list is owner-scoped and sorted by fire time", async () => {
  const { keeper } = makeKeeper({ idGen: (() => { let i = 0; return () => `id${i++}`; })() });
  await keeper.schedule({ sub: "a", fireAtMs: 3000, target: "https://127.0.0.1/h" });
  await keeper.schedule({ sub: "a", fireAtMs: 1000, target: "https://127.0.0.1/h" });
  await keeper.schedule({ sub: "b", fireAtMs: 2000, target: "https://127.0.0.1/h" });

  const aList = await keeper.list("a");
  assert.equal(aList.length, 2);
  assert.deepEqual(aList.map((t) => t.fireAtMs), [1000, 3000]);
  assert.equal((await keeper.list("b")).length, 1);
  assert.equal((await keeper.list()).length, 3);
});

test("schedule rejects an SSRF-blocked target at registration", async () => {
  const { keeper } = makeKeeper({ config: { ssrf: {} } }); // no allowLoopback
  await assert.rejects(
    () => keeper.schedule({ sub: "u1", fireAtMs: 0, target: "http://169.254.169.254/latest/meta-data" }),
    /private\/loopback\/metadata/,
  );
});

test("schedule validates mode/interval and fireAt", async () => {
  const { keeper } = makeKeeper();
  await assert.rejects(() => keeper.schedule({ sub: "u1", fireAtMs: NaN, target: "https://127.0.0.1/h" }), /finite/);
  await assert.rejects(
    () => keeper.schedule({ sub: "u1", fireAtMs: 1, target: "https://127.0.0.1/h", mode: "interval" }),
    /intervalMs/,
  );
});

test("schedule enforces payload-size and per-owner trigger caps", async () => {
  const { keeper } = makeKeeper({ config: { maxPayloadBytes: 50, maxTriggersPerSub: 2 } });
  await assert.rejects(
    () => keeper.schedule({ sub: "u1", fireAtMs: 1, target: "https://127.0.0.1/h", payload: { big: "x".repeat(100) } }),
    /payload too large/,
  );
  await keeper.schedule({ sub: "u1", fireAtMs: 9e12, target: "https://127.0.0.1/h" });
  await keeper.schedule({ sub: "u1", fireAtMs: 9e12, target: "https://127.0.0.1/h" });
  await assert.rejects(
    () => keeper.schedule({ sub: "u1", fireAtMs: 9e12, target: "https://127.0.0.1/h" }),
    /trigger limit reached/,
  );
});

test("fires history is capped (ring buffer) on a long-running interval", async () => {
  const { keeper, store, clock } = makeKeeper({ clock: clockAt(0), idGen: () => "trgRing", config: { maxRetainedFires: 3 } });
  await keeper.schedule({ sub: "u1", fireAtMs: 0, target: "https://127.0.0.1/h", mode: "interval", intervalMs: 10 });
  for (let i = 0; i < 6; i++) {
    const t = await store.get("trgRing");
    clock.set(t.fireAtMs);
    await keeper.tick();
  }
  const stored = await store.get("trgRing");
  assert.ok(stored.fires.length <= 3, `fires capped at 3 (got ${stored.fires.length})`);
});
