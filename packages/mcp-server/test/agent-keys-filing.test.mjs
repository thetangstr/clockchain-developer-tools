// Each agent key is filed on Clockchain before any record it owns or signed is anchored, so a checker can see the key existed
// before the record. New agents (ak: owners) share one daily Starter allowance of anchors, filings included, apart from accounts.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { ApiError } from "@clockchain/core";

import { ShadowService } from "../dist/shadow/service.js";
import { createLogBudget } from "../dist/budget.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { StarterAnchors, fileKey } from "../dist/agent-keys/filing.js";
import { StarterLimitError } from "../dist/shadow/ledger.js";
import { hash } from "../dist/shadow/lib/profile.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const BASE = "https://mcp.example.test";
const FILING_FIRST = "Filing this agent's key on Clockchain first.";
const STARTER_USED_UP = "Today's free allowance for new agents is used up. Try again tomorrow (UTC), or sign in to a Clockchain account.";
const SHARE_USED_UP = "Agents from this address have used their share of today's Starter allowance. Try again tomorrow (UTC), or sign in to a Clockchain account.";
const ACCOUNT = "user:account-owner";

function setup(o = {}) {
  const dir = o.dir ?? mkdtempSync(path.join(tmpdir(), "agent-keys-filing-"));
  const keysDir = o.keysDir ?? mkdtempSync(path.join(tmpdir(), "agent-keys-filing-keys-"));
  const fake = o.fake ?? new FakeLedger();
  const clock = o.clock ?? { t: Date.UTC(2026, 10, 13, 12, 0, 0) };
  const book = o.noBook ? undefined : new AgentKeyBook({ dir: keysDir, now: () => new Date(clock.t) });
  const svc = new ShadowService({
    stateDir: dir, ledger: () => fake, budget: () => createLogBudget({}), limits: o.limits, now: () => new Date(clock.t),
    sleep: async () => {}, log: () => {}, ...(book ? { agentKeys: book } : {}),
  });
  svc.sweep();
  return { svc, fake, clock, dir, keysDir, book };
}

function agentIn(book) {
  const key = makeAgentKey();
  const { entry } = book.admit(key.publicKeyPem);
  return { key, owner: `ak:${entry.root}`, akf: entry.fingerprint };
}

async function started(svc, owner) {
  const s = await svc.startSession(owner, { title: "an agent's", agents: [{ id: "planner" }] }, BASE);
  await svc.record(owner, { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" });
  return s;
}

/** Asks for the checkpoint hash and signs it with `key` (fingerprint `akf`). */
async function signed(svc, owner, sessionId, key, akf) {
  const { sign } = await svc.checkpoint(owner, { session_id: sessionId });
  return svc.signCheckpoint(owner, akf, { session_id: sessionId, hash: sign.hash, signature: key.signHash(sign.hash) });
}

const keyRef = (fp) => `agent-key:v1:${fp}`;
const sessionRef = (id) => `shadow:v1:${id}`;
const metaOf = (svc, owner, id) => svc.store.readMeta(ownerKeyOf(owner), id);
const filedEvents = (book, fp) => book.get(fp).events.filter((e) => e.action === "filed");
const day = (clock) => new Date(clock.t).toISOString().slice(0, 10);

test("first anchor of a new agent files its key first", async () => {
  const { svc, fake, book } = setup();
  const ag = agentIn(book);
  const s = await svc.startSession(ag.owner, { title: "an agent's", agents: [{ id: "planner" }] }, BASE);
  assert.equal(s.start_anchor.status, "anchored");
  assert.deepEqual(fake.records.map((r) => r.assetReferenceId), [keyRef(ag.akf), sessionRef(s.session_id)], "the key, then the start marker");
  const [key, start] = fake.records;
  assert.equal(key.assetHash, ag.akf, "a filing's hash is the key's fingerprint");
  assert.equal(key.additionalInfo, "agent key filed");
  assert.ok(Number(key.blockHeight) <= Number(start.blockHeight), "the key's block is never later than the record's");
  const entry = book.get(ag.akf);
  assert.equal(entry.filing.state, "filed");
  assert.equal(entry.filing.ledgerId, key.ledgerId);
  assert.equal(entry.filing.block, Number(key.blockHeight));
  assert.equal(typeof entry.filing.filedAt, "string");
  assert.equal(filedEvents(book, ag.akf).length, 1);
  assert.equal(filedEvents(book, ag.akf)[0].ledgerId, key.ledgerId);
});

test("a filed key is not filed again", async () => {
  const { svc, fake, book, dir, keysDir, clock } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  const s2 = await started(svc, ag.owner);
  const cp = await signed(svc, ag.owner, s2.session_id, ag.key, ag.akf);
  assert.equal(cp.checkpoint.status, "anchored");
  // After a restart too: the book says it is filed.
  const again = setup({ dir, keysDir, clock, fake });
  const s3 = await started(again.svc, ag.owner);
  assert.equal(fake.writes.filter((w) => w.assetReferenceId === keyRef(ag.akf)).length, 1, "one filing");
  assert.equal(fake.writes.length, 5, "the filing, three start markers and a checkpoint");
  assert.equal(filedEvents(again.book, ag.akf).length, 1, "one filed event");
  assert.ok([s, s2, s3].every((x) => x.start_anchor.status === "anchored"));
});

test("a failed filing holds the session rows and retries on the next checkpoint", async () => {
  const { svc, fake, book } = setup();
  const ag = agentIn(book);
  let failKeys = true;
  const log = fake.log.bind(fake);
  fake.log = async (e) => {
    if (failKeys && e.assetReferenceId.startsWith("agent-key:")) throw new ApiError("Clockchain API error (503)", 503);
    return log(e);
  };
  const s = await started(svc, ag.owner);
  assert.equal(s.start_anchor.status, "pending");
  assert.equal(fake.writes.length, 0, "nothing anchored ahead of its key");
  assert.equal(book.get(ag.akf).filing.state, "pending", "a send was tried, so the next try asks the ledger first");
  const view = await svc.getSession(ag.owner, { session_id: s.session_id }, BASE);
  assert.equal(view.pending_anchors.length, 1);
  assert.equal(view.pending_anchors[0].reason, FILING_FIRST);

  const cp = await signed(svc, ag.owner, s.session_id, ag.key, ag.akf);
  assert.equal(cp.checkpoint.status, "pending");
  assert.equal(cp.checkpoint.reason, FILING_FIRST);
  assert.equal(fake.writes.length, 0);
  const meta = metaOf(svc, ag.owner, s.session_id);
  assert.ok(meta.outbox.every((r) => r.state === "queued" && r.attempts === 0 && r.lastErrorCode === "key_filing"), "the rows wait, unspent");
  const events = svc.store.readEvents(meta);
  assert.equal(events.filter((e) => e.body.kind === "clockchain.error").length, 0, "waiting for the key is not a Clockchain failure");

  failKeys = false;
  const retried = await svc.checkpoint(ag.owner, { session_id: s.session_id });
  assert.equal(retried.checkpoint.status, "anchored");
  assert.deepEqual(fake.records.map((r) => r.assetReferenceId), [keyRef(ag.akf), sessionRef(s.session_id), sessionRef(s.session_id)], "the key, then the session's rows");
  assert.ok(Number(fake.records[0].blockHeight) <= Number(fake.records[1].blockHeight));
  assert.equal(book.get(ag.akf).filing.state, "filed");
  assert.equal(filedEvents(book, ag.akf).length, 1);
  assert.equal(metaOf(svc, ag.owner, s.session_id).outbox.length, 0);
});

test("a checkpoint signed by a replacement key files that key before the checkpoint", async () => {
  const { svc, fake, book } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  const next = makeAgentKey();
  book.replace(ag.akf, next.publicKeyPem);
  const before = fake.records.length;
  const cp = await signed(svc, ag.owner, s.session_id, next, next.fingerprint);
  assert.equal(cp.checkpoint.status, "anchored");
  assert.deepEqual(fake.records.slice(before).map((r) => r.assetReferenceId), [keyRef(next.fingerprint), sessionRef(s.session_id)]);
  assert.equal(book.get(next.fingerprint).filing.state, "filed");
  assert.equal(fake.writes.filter((w) => w.assetReferenceId === keyRef(ag.akf)).length, 1, "the root is not filed again");
});

test("the Starter budget stops agent anchors but not account anchors", async () => {
  const { svc, fake, book, dir, keysDir, clock } = setup({ limits: { maxStarterAnchorsPerDay: 3 } });
  const a = agentIn(book);
  await started(svc, a.owner); // its filing and its start marker
  const b = agentIn(book);
  const s = await started(svc, b.owner); // its filing is the third; its start marker is over
  assert.equal(s.start_anchor.status, "pending");
  assert.equal(fake.writes.length, 3);
  assert.equal(book.get(b.akf).filing.state, "filed");
  const view = await svc.getSession(b.owner, { session_id: s.session_id }, BASE);
  assert.equal(view.pending_anchors[0].reason, STARTER_USED_UP);
  const cp = await signed(svc, b.owner, s.session_id, b.key, b.akf);
  assert.equal(cp.checkpoint.status, "over_limit");
  assert.equal(cp.checkpoint.reason, STARTER_USED_UP);
  assert.equal(fake.writes.length, 3);

  // Accounts never draw on it.
  const acct = await svc.startSession(ACCOUNT, { title: "an account's", agents: [{ id: "planner" }] }, BASE);
  assert.equal(acct.start_anchor.status, "anchored");
  assert.equal(fake.writes.length, 4);

  // The count survives a restart.
  assert.ok(existsSync(path.join(dir, "starter-anchors.json")));
  const again = setup({ dir, keysDir, clock, fake, limits: { maxStarterAnchorsPerDay: 3 } });
  const c = agentIn(again.book);
  const sc = await started(again.svc, c.owner);
  assert.equal(sc.start_anchor.status, "pending");
  assert.equal(fake.writes.length, 4, "a new agent's filing is refused too");
  assert.equal(again.book.get(c.akf).filing.state, "unfiled", "nothing was sent");

  // A new UTC day has a new allowance.
  clock.t += 24 * 3_600_000;
  const retried = await again.svc.checkpoint(b.owner, { session_id: s.session_id });
  assert.equal(retried.checkpoint.status, "anchored");
});

test("filing counts toward the owner's daily anchors", async () => {
  const { svc, fake, book, clock } = setup();
  const a = agentIn(book);
  await started(svc, a.owner);
  assert.equal(svc.store.anchorsToday(ownerKeyOf(a.owner), day(clock)), 2, "the filing and the start marker");

  const tight = setup({ limits: { maxAnchorsPerOwnerPerDay: 1 } });
  const b = agentIn(tight.book);
  const s = await started(tight.svc, b.owner);
  assert.equal(s.start_anchor.status, "pending");
  assert.deepEqual(tight.fake.records.map((r) => r.assetReferenceId), [keyRef(b.akf)], "the filing took the day's one anchor");
  assert.equal(tight.svc.store.anchorsToday(ownerKeyOf(b.owner), day(tight.clock)), 1);
  assert.equal(metaOf(tight.svc, b.owner, s.session_id).outbox[0].lastErrorCode, "anchor_limit");
  assert.equal(fake.writes.length, 2);
});

test("with agent keys off, accounts anchor as before and no Starter file appears", async () => {
  const { svc, fake, dir } = setup({ noBook: true });
  const s = await svc.startSession(ACCOUNT, { title: "an account's", agents: [{ id: "planner" }] }, BASE);
  assert.equal(s.start_anchor.status, "anchored");
  assert.deepEqual(fake.records.map((r) => r.assetReferenceId), [sessionRef(s.session_id)]);
  assert.equal(existsSync(path.join(dir, "starter-anchors.json")), false);
});

test("fileKey writes replaced and revoked events under the key's reference, once per event", async () => {
  const { book } = setup();
  const fake = new FakeLedger();
  const ctx = {
    ledger: fake, budget: createLogBudget({}), reserve: () => {}, refund: () => {}, waitMs: 1000, tries: 3, backoffMs: [0],
    sleep: async () => {}, deadline: Date.now() + 10_000,
  };
  const ag = agentIn(book);
  const next = makeAgentKey();
  book.replace(ag.akf, next.publicKeyPem);
  const r = await fileKey(book, ctx, ag.akf, "replaced", { newFp: next.fingerprint });
  assert.equal(r.state, "filed");
  const at = book.get(ag.akf).events.find((e) => e.action === "replaced").at;
  assert.equal(fake.records[0].assetReferenceId, keyRef(ag.akf));
  assert.equal(fake.records[0].assetHash, hash("agent-key-event:v1", { fp: ag.akf, event: "replaced", newFp: next.fingerprint, at }));
  assert.equal(fake.records[0].additionalInfo, "agent key replaced");
  // Asked again, it finds its own write rather than paying twice.
  await fileKey(book, ctx, ag.akf, "replaced", { newFp: next.fingerprint });
  assert.equal(fake.writes.length, 1);
  book.revoke(next.fingerprint);
  await fileKey(book, ctx, next.fingerprint, "revoked");
  assert.equal(fake.records[1].additionalInfo, "agent key revoked");
  assert.equal(fake.records[1].assetHash, hash("agent-key-event:v1", { fp: next.fingerprint, event: "revoked", newFp: null, at: book.get(next.fingerprint).revokedAt }));
});

const STARTER_FILE = "starter-anchors.json";
const corruptCopies = (dir) => readdirSync(dir).filter((n) => n.startsWith(`${STARTER_FILE}.corrupt-`)).length;

test("a damaged Starter count file never overwrites its good backup", async () => {
  const { svc, book, dir, keysDir, clock, fake } = setup();
  await started(svc, agentIn(book).owner); // two anchors: a main file and its backup
  const main = path.join(dir, STARTER_FILE);
  writeFileSync(main, "not json", { mode: 0o600 });
  const again = setup({ dir, keysDir, clock, fake });
  const b = agentIn(again.book);
  const s = await started(again.svc, b.owner);
  assert.equal(s.start_anchor.status, "anchored", "the backup's count is used");
  const bak = JSON.parse(readFileSync(`${main}.bak`, "utf8"));
  assert.equal(bak.schema, "shadow-starter-anchors-v1");
  assert.ok(Number.isSafeInteger(bak.value.anchors), "the backup still holds a count");
  assert.equal(corruptCopies(dir), 1, "the damaged file is set aside once");
  await started(again.svc, b.owner);
  await signed(again.svc, b.owner, s.session_id, b.key, b.akf);
  assert.equal(corruptCopies(dir), 1, "checking again doesn't set it aside again");
  assert.equal(JSON.parse(readFileSync(main, "utf8")).value.anchors, 5, "the count goes on from the backup's");
});

test("an unreadable Starter count refuses agent anchors as over the allowance", async () => {
  const first = setup();
  await started(first.svc, agentIn(first.book).owner);
  const main = path.join(first.dir, STARTER_FILE);
  writeFileSync(main, "not json", { mode: 0o600 });
  writeFileSync(`${main}.bak`, "not json either", { mode: 0o600 });
  const fake = new FakeLedger();
  const { svc, book } = setup({ dir: first.dir, keysDir: first.keysDir, clock: first.clock, fake });
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  assert.equal(s.start_anchor.status, "pending");
  assert.equal(fake.writes.length, 0, "nothing is written");
  const cp = await signed(svc, ag.owner, s.session_id, ag.key, ag.akf);
  assert.equal(cp.checkpoint.status, "over_limit");
  assert.equal(cp.checkpoint.reason, STARTER_USED_UP);
  const meta = metaOf(svc, ag.owner, s.session_id);
  assert.ok(meta.outbox.every((r) => r.state === "queued" && r.attempts === 0 && r.lastErrorCode === "starter_limit"));
  assert.equal(svc.store.readEvents(meta).filter((e) => e.body.kind === "clockchain.error").length, 0, "no Clockchain error is recorded");
  // Accounts never draw on it.
  const acct = await svc.startSession(ACCOUNT, { title: "an account's", agents: [{ id: "planner" }] }, BASE);
  assert.equal(acct.start_anchor.status, "anchored");
  // The next UTC day's count starts afresh.
  first.clock.t += 24 * 3_600_000;
  assert.equal((await svc.checkpoint(ag.owner, { session_id: s.session_id })).checkpoint.status, "anchored");
  assert.equal(JSON.parse(readFileSync(main, "utf8")).value.anchors, 3, "the filing, the start marker and the checkpoint");
});

// ---- the Starter allowance per address ---------------------------------------------------------------------------------

const SRC_A = "a".repeat(32);
const SRC_B = "b".repeat(32);
const counter = (o = {}) => {
  const clock = o.clock ?? { day: "2026-11-13" };
  const stateDir = o.stateDir ?? mkdtempSync(path.join(tmpdir(), "starter-anchors-"));
  return { clock, stateDir, starter: new StarterAnchors({ stateDir, max: o.max ?? 2000, perSource: o.perSource ?? 200, today: () => clock.day }) };
};
const refused = (reason) => (e) => e instanceof StarterLimitError && e.reason === reason;

test("an address's share refuses at 200 while another address, and an agent with no address, still pass", () => {
  const { starter } = counter();
  for (let i = 0; i < 200; i++) {
    starter.check(SRC_A);
    starter.record(SRC_A);
  }
  assert.throws(() => starter.check(SRC_A), refused("source"));
  starter.check(SRC_B);
  starter.record(SRC_B);
  starter.check();
  starter.record();
  assert.equal(starter.used(), 202, "every anchor counts toward the shared allowance");
});

test("the shared allowance still refuses, as daily, before any address's share", () => {
  const { starter } = counter({ max: 3, perSource: 2 });
  starter.record(SRC_A);
  starter.record(SRC_B);
  starter.record();
  assert.throws(() => starter.check(), refused("daily"));
  assert.throws(() => starter.check(SRC_A), refused("daily"));
  assert.throws(() => starter.check("c".repeat(32)), refused("daily"));
});

test("a new UTC day resets the shared count and every address's share, and keeps only today's", () => {
  const { starter, clock, stateDir } = counter({ max: 3, perSource: 1 });
  starter.record(SRC_A);
  starter.record(SRC_B);
  assert.throws(() => starter.check(SRC_A), refused("source"));
  clock.day = "2026-11-14";
  starter.check(SRC_A);
  starter.check(SRC_B);
  assert.equal(starter.used(), 0);
  starter.record(SRC_A);
  const stored = JSON.parse(readFileSync(path.join(stateDir, STARTER_FILE), "utf8"));
  assert.deepEqual(stored.value, { day: "2026-11-14", anchors: 1, sources: { [SRC_A]: 1 } }, "yesterday's addresses are gone");
  // And a restart reads the shares back.
  const again = counter({ stateDir, clock, max: 3, perSource: 1 }).starter;
  assert.throws(() => again.check(SRC_A), refused("source"));
  again.check(SRC_B);
});

test("a count file from before address shares loads, and its count goes on", () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "starter-anchors-"));
  writeFileSync(path.join(stateDir, STARTER_FILE), `${JSON.stringify({ schema: "shadow-starter-anchors-v1", value: { day: "2026-11-13", anchors: 5 } })}\n`, { mode: 0o600 });
  const { starter } = counter({ stateDir, max: 6, perSource: 1 });
  assert.equal(starter.used(), 5);
  starter.check(SRC_A);
  starter.record(SRC_A);
  assert.throws(() => starter.check(SRC_B), refused("daily"));
  assert.deepEqual(JSON.parse(readFileSync(path.join(stateDir, STARTER_FILE), "utf8")).value, { day: "2026-11-13", anchors: 6, sources: { [SRC_A]: 1 } });
});

test("an unreadable count file still refuses every agent, with or without an address", () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "starter-anchors-"));
  const main = path.join(stateDir, STARTER_FILE);
  writeFileSync(main, "not json", { mode: 0o600 });
  writeFileSync(`${main}.bak`, "not json either", { mode: 0o600 });
  const { starter } = counter({ stateDir });
  assert.throws(() => starter.check(), refused("daily"));
  assert.throws(() => starter.check(SRC_A), refused("daily"));
  starter.record(SRC_A);
  assert.equal(readFileSync(main, "utf8"), "not json", "nothing is written over it");
  // A bad share in the file makes it unreadable too.
  const badShare = mkdtempSync(path.join(tmpdir(), "starter-anchors-"));
  writeFileSync(path.join(badShare, STARTER_FILE), `${JSON.stringify({ schema: "shadow-starter-anchors-v1", value: { day: "2026-11-13", anchors: 1, sources: { [SRC_A]: -1 } } })}\n`, { mode: 0o600 });
  assert.throws(() => counter({ stateDir: badShare }).starter.check(SRC_B), refused("daily"));
});

test("a key's filing payload carries nothing of its source", async () => {
  const { book } = setup();
  const fake = new FakeLedger();
  const ctx = {
    ledger: fake, budget: createLogBudget({}), reserve: () => {}, refund: () => {}, waitMs: 1000, tries: 3, backoffMs: [0],
    sleep: async () => {}, deadline: Date.now() + 10_000,
  };
  const source = "d".repeat(32);
  const key = makeAgentKey();
  const { entry } = book.admit(key.publicKeyPem, source);
  assert.equal(book.get(entry.fingerprint).source, source);
  assert.equal((await fileKey(book, ctx, entry.fingerprint, "filed")).state, "filed");
  const next = makeAgentKey();
  book.replace(entry.fingerprint, next.publicKeyPem);
  await fileKey(book, ctx, entry.fingerprint, "replaced", { newFp: next.fingerprint });
  assert.equal(fake.records.length, 2);
  for (const sent of [JSON.stringify(fake.records), JSON.stringify(fake.writes)]) {
    assert.ok(!sent.includes(source), "the source value is not sent");
    assert.ok(!sent.includes("source"), "nor a source field");
  }
});

test("a step deferred while the address's share is used up says so, not that the whole allowance is gone", async () => {
  const { svc, book } = setup({ limits: { maxStarterAnchorsPerSourcePerDay: 2 } });
  const key = makeAgentKey();
  const { entry } = book.admit(key.publicKeyPem, "e".repeat(32));
  const owner = `ak:${entry.root}`;
  const s = await svc.logStep(owner, { kind: "task", content: "Find flights", log_level: "turn" }, BASE);
  const cp = await signed(svc, owner, s.session_id, key, entry.fingerprint);
  assert.equal(cp.checkpoint.status, "over_limit", JSON.stringify(cp));
  // A tool call at the turn level has no anchor of its own, and says why the later anchor isn't coming.
  const step = await svc.logStep(owner, { session_id: s.session_id, kind: "tool_call", content: { tool: "search" } }, BASE);
  assert.equal(step.anchor_status, "deferred", JSON.stringify(step));
  assert.match(step.anchor_reason, /Agents from this address have used their share of today's Starter allowance, so this stays unanchored unless a later anchor lands\./);
  assert.doesNotMatch(step.anchor_reason, /free allowance for new agents is used up/);
});

test("a session started over the Starter allowance says why its start marker waits", async () => {
  const { svc, book } = setup({ limits: { maxStarterAnchorsPerDay: 3 } });
  await started(svc, agentIn(book).owner); // its filing and its start marker
  const s = await started(svc, agentIn(book).owner); // its filing is the third; its start marker is over
  assert.equal(s.start_anchor.status, "pending");
  assert.equal(s.start_anchor.reason, STARTER_USED_UP);

  const shared = setup({ limits: { maxStarterAnchorsPerSourcePerDay: 1 } });
  const key = makeAgentKey();
  const { entry } = shared.book.admit(key.publicKeyPem, "f".repeat(32));
  const s2 = await started(shared.svc, `ak:${entry.root}`); // its filing is the address's one; its start marker is over
  assert.equal(s2.start_anchor.status, "pending");
  assert.equal(s2.start_anchor.reason, SHARE_USED_UP);

  // A start marker that simply anchors, or waits for no limit, has no reason.
  const plain = setup();
  const fine = await started(plain.svc, agentIn(plain.book).owner);
  assert.equal(fine.start_anchor.status, "anchored");
  assert.equal(fine.start_anchor.reason, undefined);
});

test("an open agent session held by the Starter allowance is anchored by the hourly pass once the UTC day turns", async () => {
  const { svc, fake, book, clock } = setup({ limits: { maxStarterAnchorsPerDay: 3 } });
  await started(svc, agentIn(book).owner);
  const b = agentIn(book);
  const s = await started(svc, b.owner);
  const cp = await signed(svc, b.owner, s.session_id, b.key, b.akf);
  assert.equal(cp.checkpoint.status, "over_limit");
  const writes = fake.writes.length;

  // Still the same day: the pass tries, the allowance refuses, and nothing is written.
  await svc.closeIdle();
  assert.equal(fake.writes.length, writes);
  assert.equal(metaOf(svc, b.owner, s.session_id).anchors.length, 0);

  // A new UTC day: the agent doesn't call again, and the pass anchors what it signed.
  clock.t += 24 * 3_600_000;
  await svc.closeIdle();
  const meta = metaOf(svc, b.owner, s.session_id);
  assert.equal(meta.state, "open", "the session stays open");
  assert.ok(meta.anchors.some((a) => a.marker === "checkpoint" && a.hash === cp.checkpoint.checkpoint_hash), JSON.stringify(meta.anchors));
  assert.equal(meta.outbox.filter((r) => r.state !== "failed").length, 0, "nothing is left waiting");
});

test("the hourly pass leaves open sessions alone when nothing in them waits on a Starter hold", async () => {
  const { svc, fake, book, clock } = setup();
  const a = agentIn(book);
  const s = await started(svc, a.owner);
  const { sign } = await svc.checkpoint(a.owner, { session_id: s.session_id }); // asked for, never signed
  assert.ok(sign.hash);
  const writes = fake.writes.length;
  const before = JSON.stringify(metaOf(svc, a.owner, s.session_id));
  clock.t += 24 * 3_600_000;
  await svc.closeIdle();
  assert.equal(fake.writes.length, writes);
  assert.equal(JSON.stringify(metaOf(svc, a.owner, s.session_id)), before, "the session isn't touched");
});
