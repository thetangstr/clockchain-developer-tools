// While Clockchain refuses writes with a 429 (a burst limit or a used-up plan), Shadow pauses every send instead of
// retrying each row on its own, keeps the rows it couldn't send, and catches up in the next pass once writes work again.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ShadowService } from "../dist/shadow/service.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { createLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const O = "acct_AAAAAAAAAAAAAAAAAAAAAA";
const BASE = "https://mcp.example.test";
const MIN = 60_000;
const HOUR = 60 * MIN;

function service() {
  const fake = new FakeLedger();
  const clock = { now: Date.parse("2026-11-16T00:00:00Z") };
  const logs = [];
  const stateDir = mkdtempSync(path.join(tmpdir(), "rate-limit-"));
  const svc = new ShadowService({
    stateDir, ledger: () => fake, budget: () => createLogBudget({}), sleep: async () => {},
    log: (event, f) => logs.push({ event, ...f }), now: () => new Date(clock.now),
  });
  svc.sweep();
  return { svc, fake, clock, logs };
}

async function closedSessions(svc, n) {
  const ids = [];
  for (let i = 0; i < n; i++) {
    const s = await svc.startSession(O, { title: `t${i}`, agents: [{ id: "a" }] }, BASE);
    await svc.record(O, { session_id: s.session_id, agent: "a", kind: "note", content: `n${i}` });
    await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
    ids.push(s.session_id);
  }
  return ids;
}

const eventsOf = (svc, id) => svc.store.readEvents(svc.store.readMeta(ownerKeyOf(O), id)).map((e) => e.body);
const pending = async (svc, id) => (await svc.getSession(O, { session_id: id }, BASE)).pending_anchors;

test("one 429 pauses every send: 20 sessions closed under a refusal, then an hourly pass, send a handful of writes, not 60 each", async () => {
  const { svc, fake, clock } = service();
  fake.rateLimited = {};
  await closedSessions(svc, 20);
  assert.ok(fake.refusedLogs <= 3, `closing 20 sessions under a 429 sent ${fake.refusedLogs} writes`);
  for (let h = 0; h < 3; h++) {
    const before = fake.refusedLogs;
    clock.now += HOUR;
    await svc.closeIdle();
    assert.ok(fake.refusedLogs - before <= 3, `an hourly pass sent ${fake.refusedLogs - before} writes into a 429`);
  }
});

test("an open session's anchors wait out a 429 however many times the agent calls, and never fail for good", async () => {
  const { svc, fake, clock } = service();
  fake.rateLimited = {};
  const s = await svc.startSession(O, { title: "open", agents: [{ id: "a" }] }, BASE);
  for (let i = 0; i < 14; i++) {
    clock.now += 2 * MIN;
    const before = fake.refusedLogs;
    await svc.record(O, { session_id: s.session_id, agent: "a", kind: "note", content: `n${i}` });
    await svc.checkpoint(O, { session_id: s.session_id });
    assert.ok(fake.refusedLogs - before <= 3, `call ${i} sent ${fake.refusedLogs - before} writes into a 429`);
  }
  const rows = await pending(svc, s.session_id);
  assert.ok(rows.length > 0);
  assert.deepEqual(rows.filter((r) => r.status === "failed"), [], "a row failed for good over a 429");
  // Writes work again: the next checkpoint anchors what is still owed.
  fake.rateLimited = null;
  clock.now += 2 * MIN;
  await svc.checkpoint(O, { session_id: s.session_id });
  const after = await svc.getSession(O, { session_id: s.session_id }, BASE);
  assert.ok(after.anchors.some((a) => a.marker === "start"), "the start marker never anchored");
});

test("once writes work again, a backlog of closed sessions lands in the next hourly pass, not hours later", async () => {
  const { svc, fake, clock } = service();
  fake.rateLimited = {};
  const ids = await closedSessions(svc, 20);
  for (let h = 0; h < 12; h++) {
    clock.now += HOUR;
    await svc.closeIdle();
  }
  fake.rateLimited = null;
  clock.now += HOUR;
  await svc.closeIdle();
  for (const id of ids) assert.deepEqual((await pending(svc, id)).map((r) => [r.marker, r.status]), [], `session ${id} still owes anchors`);
});

test("a used-up plan (QUOTA_EXHAUSTED) is sent once, named as such, and pauses sends for 15 minutes", async () => {
  const { svc, fake, clock, logs } = service();
  fake.rateLimited = { body: { code: "PLAN_QUOTA_EXHAUSTED" } };
  const s = await svc.startSession(O, { title: "q", agents: [{ id: "a" }] }, BASE);
  assert.equal(fake.refusedLogs, 1, "a used-up plan was retried within the call");
  assert.ok(logs.some((l) => l.event === "shadow_sends_paused" && l.code === "quota_exhausted" && l.seconds === 900));
  assert.match((await pending(svc, s.session_id))[0].reason, /quota_exhausted/);
  clock.now += 10 * MIN;
  await svc.checkpoint(O, { session_id: s.session_id });
  assert.equal(fake.refusedLogs, 1, "a send went out during the pause");
  clock.now += 10 * MIN;
  fake.rateLimited = null;
  await svc.checkpoint(O, { session_id: s.session_id });
  assert.ok((await svc.getSession(O, { session_id: s.session_id }, BASE)).anchors.some((a) => a.marker === "start"));
});

test("a Retry-After longer than a call can wait pauses sends for that long", async () => {
  const { svc, fake, clock } = service();
  fake.rateLimited = { retryAfter: 900 };
  const s = await svc.startSession(O, { title: "ra", agents: [{ id: "a" }] }, BASE);
  assert.equal(fake.refusedLogs, 1);
  clock.now += 10 * MIN;
  await svc.checkpoint(O, { session_id: s.session_id });
  assert.equal(fake.refusedLogs, 1, "a send went out before Retry-After was up");
  clock.now += 10 * MIN;
  await svc.checkpoint(O, { session_id: s.session_id });
  assert.equal(fake.refusedLogs, 2);
});

test("a long 429 outage records each refused row once, and a send held by the pause records nothing", async () => {
  const { svc, fake, clock } = service();
  fake.rateLimited = {};
  const s = await svc.startSession(O, { title: "long", agents: [{ id: "a" }] }, BASE);
  // Started while paused: no refusal is claimed for a start marker that was never sent.
  const p = await svc.startSession(O, { title: "paused", agents: [{ id: "a" }] }, BASE);
  assert.equal(eventsOf(svc, p.session_id).find((e) => e.kind === "session.opened").payload.error, undefined);
  for (let i = 0; i < 40; i++) {
    clock.now += 2 * MIN;
    await svc.record(O, { session_id: s.session_id, agent: "a", kind: "note", content: `n${i}` });
    await svc.checkpoint(O, { session_id: s.session_id });
  }
  const errors = eventsOf(svc, s.session_id).filter((e) => e.kind === "clockchain.error");
  const hashes = errors.map((e) => e.payload.hash);
  assert.equal(new Set(hashes).size, hashes.length, "a row's 429 was recorded more than once");
  assert.ok(errors.every((e) => e.payload.errorCode !== "sends_paused"), "a send the pause held was recorded as refused");
  assert.equal(eventsOf(svc, p.session_id).filter((e) => e.kind === "clockchain.error").length, 0);
});
