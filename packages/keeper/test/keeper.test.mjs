// End-to-end keeper data-plane behaviour, fully offline:
//   schedule -> fire -> deliver (mock webhook) -> anchor; AGE-193 "not done until
//   anchored"; due-trigger-never-dropped; re-arm on restart; dead-letter; cancel
//   scoping; interval re-arm; no double-delivery across an anchor retry.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keeper, MemoryStore, verifyWebhook } from "../dist/index.js";

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

// Anchorer fakes.
const okAnchorer = {
  anchorFire: async () => ({
    status: "anchored",
    eventHash: "deadbeef",
    ledgerId: "L1",
    blockHeight: "100",
    receiptSchema: "clockchain.receipt/v1",
  }),
};
function pendingThenAnchored() {
  let n = 0;
  return {
    anchorFire: async () => {
      n++;
      return n < 2
        ? { status: "pending", eventHash: "h", ledgerId: "L1", blockHeight: null, receiptSchema: "clockchain.receipt/v1" }
        : { status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "101", receiptSchema: "clockchain.receipt/v1" };
    },
    get calls() {
      return n;
    },
  };
}
function throwOnceAnchorer() {
  let n = 0;
  return {
    anchorFire: async () => {
      n++;
      if (n < 2) throw new Error("gateway down");
      return { status: "anchored", eventHash: "h", ledgerId: "L1", blockHeight: "102", receiptSchema: "clockchain.receipt/v1" };
    },
  };
}

function makeKeeper(over = {}) {
  const store = over.store ?? new MemoryStore();
  const clock = over.clock ?? clockAt(10_000);
  const fetch = over.fetch ?? mockFetch(200);
  const anchorer = over.anchorer ?? okAnchorer;
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
      retry: { maxAttempts: 3, sleep: async () => {} },
      anchorRetryDelayMs: 0,
      ...over.config,
    },
  });
  return { keeper, store, clock, fetch, anchorer };
}

test("schedule -> fire -> deliver (signed) -> anchor; trigger done", async () => {
  const { keeper, store, fetch, clock } = makeKeeper({ clock: clockAt(10_000), idGen: () => "trg1" });
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

  // Delivery happened once, with a valid Standard-Webhooks signature.
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
  assert.equal(stored.fires.length, 1);
  assert.equal(stored.fires[0].delivery.status, "delivered");
  assert.equal(stored.fires[0].anchor.status, "anchored");
  assert.equal(stored.fires[0].anchor.blockHeight, "100");
  assert.equal(stored.fires[0].fireId, "trg1#9000");

  // A second tick is a no-op (terminal) — no re-fire, no second delivery.
  const sum2 = await keeper.tick();
  assert.equal(sum2.fired, 0);
  assert.equal(fetch.calls.length, 1);
});

test("not-due triggers are not fired", async () => {
  const { keeper, fetch } = makeKeeper({ clock: clockAt(1_000), idGen: () => "future" });
  await keeper.schedule({ sub: "u1", fireAtMs: 10_000, target: "https://127.0.0.1/h" });
  const sum = await keeper.tick();
  assert.equal(sum.fired, 0);
  assert.equal(fetch.calls.length, 0);
});

test("AGE-193: a fire is NOT done until anchored; pending anchor re-armed and retried", async () => {
  const anchorer = pendingThenAnchored();
  const { keeper, store } = makeKeeper({ anchorer, idGen: () => "trgP" });
  await keeper.schedule({ sub: "u1", fireAtMs: 0, target: "https://127.0.0.1/h" });

  const s1 = await keeper.tick();
  assert.equal(s1.pendingAnchor, 1);
  assert.equal(s1.anchored, 0);
  let stored = await store.get("trgP");
  assert.equal(stored.status, "firing", "still firing — NOT done until anchored");
  assert.equal(stored.fires[0].anchor.status, "pending");

  const s2 = await keeper.tick();
  assert.equal(s2.anchored, 1);
  stored = await store.get("trgP");
  assert.equal(stored.status, "done");
  assert.equal(stored.fires[0].anchor.status, "anchored");
  assert.equal(anchorer.calls, 2);
});

test("due-trigger never dropped: anchor throws then recovers, fire completes", async () => {
  const { keeper, store, fetch } = makeKeeper({ anchorer: throwOnceAnchorer(), idGen: () => "trgT" });
  await keeper.schedule({ sub: "u1", fireAtMs: 0, target: "https://127.0.0.1/h" });

  await keeper.tick(); // delivers; anchor throws -> stays armed
  let stored = await store.get("trgT");
  assert.equal(stored.status, "firing");
  assert.match(stored.lastError, /gateway down/);
  assert.equal(fetch.calls.length, 1, "delivered once");

  await keeper.tick(); // anchor recovers -> done; NO re-delivery
  stored = await store.get("trgT");
  assert.equal(stored.status, "done");
  assert.equal(stored.fires[0].anchor.status, "anchored");
  assert.equal(fetch.calls.length, 1, "no double-delivery across the anchor retry");
});

test("re-arm on restart: a due trigger persisted by a prior run fires on the next boot's tick", async () => {
  // Simulate a store written by an earlier process while the worker was down.
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

test("dead-letter: delivery exhausts retries, fire still anchored, trigger ends dead", async () => {
  const fetch = mockFetch(500); // always fails
  const { keeper, store } = makeKeeper({ fetch, idGen: () => "trgD" });
  await keeper.schedule({ sub: "u1", fireAtMs: 0, target: "https://127.0.0.1/h" });

  const sum = await keeper.tick();
  assert.equal(sum.deadLettered, 1);
  assert.equal(sum.anchored, 1, "a dead-lettered fire is STILL anchored (on the record)");
  const stored = await store.get("trgD");
  assert.equal(stored.status, "dead");
  assert.equal(stored.fires[0].delivery.status, "dead");
  assert.equal(stored.fires[0].delivery.attempts, 3);
  assert.equal(stored.fires[0].anchor.status, "anchored");
  assert.ok(fetch.calls.length === 3, "retried up to maxAttempts");
});

test("interval mode re-arms fireAtMs after a successful anchored fire", async () => {
  const { keeper, store, clock } = makeKeeper({ clock: clockAt(1_000), idGen: () => "trgI" });
  await keeper.schedule({
    sub: "u1",
    fireAtMs: 1_000,
    target: "https://127.0.0.1/h",
    mode: "interval",
    intervalMs: 5_000,
  });
  await keeper.tick();
  let stored = await store.get("trgI");
  assert.equal(stored.status, "scheduled", "re-armed, not done");
  assert.equal(stored.fireAtMs, 6_000);
  assert.equal(stored.fires.length, 1);

  // Not due yet at t=1000; advance past the next occurrence.
  assert.equal((await keeper.tick()).fired, 0);
  clock.set(6_000);
  await keeper.tick();
  stored = await store.get("trgI");
  assert.equal(stored.fireAtMs, 11_000);
  assert.equal(stored.fires.length, 2, "a second fire was recorded");
});

test("cancel is owner-scoped and stops a trigger from firing", async () => {
  const { keeper, store, fetch } = makeKeeper({ clock: clockAt(10_000), idGen: () => "trgC" });
  await keeper.schedule({ sub: "owner", fireAtMs: 0, target: "https://127.0.0.1/h" });

  // Wrong owner cannot cancel.
  assert.equal(await keeper.cancel("trgC", "intruder"), null);
  assert.equal((await store.get("trgC")).status, "scheduled");

  // Right owner cancels.
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
