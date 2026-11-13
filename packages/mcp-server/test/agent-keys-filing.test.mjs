// Each agent key is filed on Clockchain before any record it owns or signed is anchored, so a checker can see the key existed
// before the record. New agents (ak: owners) share one daily Starter allowance of anchors, filings included, apart from accounts.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { ApiError } from "@clockchain/core";

import { ShadowService } from "../dist/shadow/service.js";
import { createLogBudget } from "../dist/budget.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { fileKey } from "../dist/agent-keys/filing.js";
import { hash } from "../dist/shadow/lib/profile.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const BASE = "https://mcp.example.test";
const FILING_FIRST = "Filing this agent's key on Clockchain first.";
const STARTER_USED_UP = "Today's free allowance for new agents is used up.";
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
