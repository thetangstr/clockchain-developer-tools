// Agents sign their own Shadow checkpoints. For an agent-key owner (ak:<root>) the server builds the checkpoint body and
// returns its hash; the agent signs it with its own Ed25519 key and calls shadow_sign_checkpoint. Only agent-signed
// checkpoints are anchored, and steps after the last one are shown as not signed by the agent. Account owners are as before.
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ShadowService, ShadowError } from "../dist/shadow/service.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { DOMAIN, hash, parseStrict } from "../dist/shadow/lib/profile.js";
import { createLogBudget } from "../dist/budget.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const A = "jti:11111111-1111-4111-8111-111111111111";
const BASE = "https://mcp.example.test";
const SIGN_NOTE = "Sign this hash with your key and call shadow_sign_checkpoint.";
const strict = (v) => parseStrict(JSON.stringify(v));

function setup(o = {}) {
  const dir = o.dir ?? mkdtempSync(path.join(tmpdir(), "shadow-agent-sign-"));
  const keysDir = o.keysDir ?? mkdtempSync(path.join(tmpdir(), "shadow-agent-sign-keys-"));
  const fake = o.fake ?? new FakeLedger();
  const clock = o.clock ?? { t: Math.floor(Date.now() / 1000) * 1000 };
  const logs = o.logs ?? [];
  const book = new AgentKeyBook({ dir: keysDir, now: () => new Date(clock.t) });
  const svc = new ShadowService({
    stateDir: dir, ledger: () => fake, budget: () => createLogBudget({}), limits: o.limits, now: () => new Date(clock.t),
    sleep: async () => {}, log: (event, fields) => logs.push({ event, ...fields }), agentKeys: book,
    ...(o.autoLog ? { autoLog: true } : {}),
  });
  svc.sweep();
  return { svc, fake, clock, dir, keysDir, logs, book };
}

/** An agent admitted to the book: its owner id and the fingerprint its token carries (akf). */
function agentIn(book) {
  const key = makeAgentKey();
  const { entry } = book.admit(key.publicKeyPem);
  return { key, owner: `ak:${entry.root}`, akf: entry.fingerprint };
}

async function rejects(p, code) {
  let err;
  await assert.rejects(p, (e) => {
    assert.ok(e instanceof ShadowError, `expected ShadowError ${code}, got ${e?.name}: ${e?.message}`);
    assert.equal(e.code, code, e.message);
    err = e;
    return true;
  });
  return err;
}

const capOf = (links) => new URL(links.packet).pathname.split("/").pop().replace(/\.json$/, "");
const metaOf = (svc, owner, id) => svc.store.readMeta(ownerKeyOf(owner), id);

async function started(svc, owner) {
  const s = await svc.startSession(owner, { title: "an agent's", agents: [{ id: "planner" }] }, BASE);
  await svc.record(owner, { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" });
  return s;
}

test("checkpoint returns a hash to sign; signing it anchors", async () => {
  const { svc, fake, book } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  const writes = fake.writes.length;
  const r = await svc.checkpoint(ag.owner, { session_id: s.session_id });
  assert.match(r.sign.hash, /^[0-9a-f]{64}$/);
  assert.equal(r.sign.note, SIGN_NOTE);
  assert.equal(fake.writes.length, writes, "nothing is anchored before the agent signs");
  const pending = metaOf(svc, ag.owner, s.session_id);
  assert.equal(pending.checkpoint, null);
  assert.equal(pending.awaitingSignature.hash, r.sign.hash);
  assert.equal(pending.awaitingSignature.final, false);
  assert.equal(hash(DOMAIN.checkpoint, pending.awaitingSignature.body), r.sign.hash);
  assert.equal(pending.outbox.filter((x) => x.kind === "checkpoint").length, 0, "nothing queued");

  // Asking again with no new step gives the same hash, so a signature in flight stays good.
  assert.equal((await svc.checkpoint(ag.owner, { session_id: s.session_id })).sign.hash, r.sign.hash);

  const signed = await svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: r.sign.hash, signature: ag.key.signHash(r.sign.hash) });
  assert.equal(signed.checkpoint.status, "anchored");
  assert.equal(signed.checkpoint.checkpoint_hash, r.sign.hash);
  const meta = metaOf(svc, ag.owner, s.session_id);
  assert.equal(meta.awaitingSignature, undefined);
  assert.equal(meta.checkpoint.hash, r.sign.hash);
  assert.equal(meta.checkpoint.publicKey, ag.key.publicKeyPem);
  assert.ok(fake.writes.some((w) => JSON.stringify(w).includes(r.sign.hash)), "the agent-signed hash reached the ledger");
  assert.ok(meta.anchors.some((a) => a.hash === r.sign.hash));
  // Signing twice: nothing is waiting any more.
  await rejects(svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: r.sign.hash, signature: ag.key.signHash(r.sign.hash) }), "hash_mismatch");
});

test("sign shows count and head, so a step the agent didn't record changes them before it signs", async () => {
  const { svc, book } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  const mine = await svc.record(ag.owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
  const first = await svc.checkpoint(ag.owner, { session_id: s.session_id });
  // The agent's own record: its last step's seq is the count, and that step's hash the head.
  assert.equal(first.sign.count, mine.seq);
  assert.equal(first.sign.head, mine.hash);
  const body = metaOf(svc, ag.owner, s.session_id).awaitingSignature.body;
  assert.equal(first.sign.count, body.count);
  assert.equal(first.sign.head, body.head);
  // A step appended with the same token, between the agent's own steps: count and head no longer match the agent's record.
  const next = await svc.record(ag.owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "Booked." });
  const injected = await svc.record(ag.owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "Also sent the card number." });
  const second = await svc.checkpoint(ag.owner, { session_id: s.session_id });
  assert.notEqual(second.sign.count, next.seq);
  assert.notEqual(second.sign.head, next.hash);
  assert.equal(second.sign.count, injected.seq);
  assert.equal(second.sign.head, injected.hash);
  // The close's final checkpoint shows them too.
  const closed = await svc.close(ag.owner, { session_id: s.session_id, status: "succeeded" }, BASE);
  const final = metaOf(svc, ag.owner, s.session_id).awaitingSignature.body;
  assert.equal(closed.sign.count, final.count);
  assert.equal(closed.sign.head, final.head);
  assert.equal(closed.sign.count, closed.steps);
});

test("a signature by another key is refused", async () => {
  const { svc, book } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  const { sign } = await svc.checkpoint(ag.owner, { session_id: s.session_id });
  const forged = makeAgentKey().signHash(sign.hash);
  const e = await rejects(svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: sign.hash, signature: forged }), "bad_signature");
  assert.ok(!e.message.includes(forged), "the signature is never echoed");
  await rejects(svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: sign.hash, signature: "not a signature" }), "bad_signature");
  // A token whose key belongs to another agent (another root) is not this owner's, even with a good signature from it.
  const other = agentIn(book);
  await rejects(svc.signCheckpoint(ag.owner, other.akf, { session_id: s.session_id, hash: sign.hash, signature: other.key.signHash(sign.hash) }), "not_agent_owner");
  // A key that is no longer active can't sign, nor can a token with no key.
  await rejects(svc.signCheckpoint(ag.owner, undefined, { session_id: s.session_id, hash: sign.hash, signature: ag.key.signHash(sign.hash) }), "not_agent_owner");
  const next = makeAgentKey();
  book.replace(ag.akf, next.publicKeyPem);
  await rejects(svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: sign.hash, signature: ag.key.signHash(sign.hash) }), "not_agent_owner");
  // The replacing key shares the root, so it signs for the same records.
  const ok = await svc.signCheckpoint(ag.owner, next.fingerprint, { session_id: s.session_id, hash: sign.hash, signature: next.signHash(sign.hash) });
  assert.equal(ok.checkpoint.status, "anchored");
  assert.equal(metaOf(svc, ag.owner, s.session_id).checkpoint.publicKey, next.publicKeyPem);
});

test("a stale hash is refused with the current hash named", async () => {
  const { svc, book } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  const first = (await svc.checkpoint(ag.owner, { session_id: s.session_id })).sign.hash;
  await svc.record(ag.owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
  const current = (await svc.checkpoint(ag.owner, { session_id: s.session_id })).sign.hash;
  assert.notEqual(first, current);
  const e = await rejects(svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: first, signature: ag.key.signHash(first) }), "hash_mismatch");
  assert.ok(e.message.includes(current), e.message);
  assert.equal(metaOf(svc, ag.owner, s.session_id).checkpoint, null);
  const ok = await svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: current, signature: ag.key.signHash(current) });
  assert.equal(ok.checkpoint.status, "anchored");
});

test("pending body survives a new ShadowService over the same dir", async () => {
  const first = setup();
  const ag = agentIn(first.book);
  const s = await started(first.svc, ag.owner);
  const { sign } = await first.svc.checkpoint(ag.owner, { session_id: s.session_id });
  first.clock.t += 60_000; // a body rebuilt after the restart would have another createdAt, and so another hash
  const second = setup({ dir: first.dir, keysDir: first.keysDir, fake: first.fake, clock: first.clock });
  const signed = await second.svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: sign.hash, signature: ag.key.signHash(sign.hash) });
  assert.equal(signed.checkpoint.status, "anchored");
  assert.equal(metaOf(second.svc, ag.owner, s.session_id).checkpoint.hash, sign.hash);
});

test("steps after the last signed checkpoint are not proven", async () => {
  const { svc, book } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  const { sign } = await svc.checkpoint(ag.owner, { session_id: s.session_id });
  await svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: sign.hash, signature: ag.key.signHash(sign.hash) });
  // Only the checkpoint's own receipt follows it: no unsigned steps, so verify says nothing of them.
  const before = await svc.verify(ag.owner, { session_id: s.session_id }, BASE);
  assert.equal("unsigned_steps" in before, false);
  assert.equal("unsigned_note" in before, false);
  await svc.record(ag.owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
  await svc.record(ag.owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "Booked." });
  const meta = metaOf(svc, ag.owner, s.session_id);
  const doc = JSON.parse(await svc.packetForCap(capOf(s.links)));
  const packet = strict(doc.packet), pin = strict(doc.pin);
  assert.equal(packet.checkpoint.hash, sign.hash);
  assert.equal(packet.events.length, packet.checkpoint.body.count);
  assert.ok(meta.seq > packet.checkpoint.body.count, "the record holds more than the agent signed");
  const report = await verifyPacket(packet, { pin });
  for (const name of ["content", "sequence", "membership", "signature", "trust"]) assert.equal(report.checks.find((c) => c.name === name).status, "pass", name);
  const html = await svc.summaryForCap(capOf(s.links));
  assert.match(html, /not signed by the agent/);
  // The server never signs for the agent, whatever reads the record.
  await svc.getSession(ag.owner, { session_id: s.session_id }, BASE);
  const v = await svc.verify(ag.owner, { session_id: s.session_id }, BASE);
  // The signed prefix is checked; the session is still open, so it isn't established. The tail is said, not hidden.
  assert.equal(v.result, "indeterminate", v.summary);
  assert.equal(v.unsigned_steps, 2);
  assert.equal(v.unsigned_note, "2 steps were recorded after the last checkpoint the agent signed. They are not signed by the agent, so they are not in what was verified.");
  assert.match(html, /2 steps were recorded after the last checkpoint the agent signed\. They are not signed by the agent, so they are not on this page\./);
  assert.equal(metaOf(svc, ag.owner, s.session_id).checkpoint.hash, sign.hash);
});

test("close then sign gives a closed, proven session", async () => {
  const { svc, fake, book, logs } = setup();
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  await svc.record(ag.owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
  const closed = await svc.close(ag.owner, { session_id: s.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.status, "closed");
  assert.match(closed.sign.hash, /^[0-9a-f]{64}$/);
  assert.equal(closed.sign.note, SIGN_NOTE);
  assert.equal(closed.pin, null, "no pin until the agent signs the final checkpoint");
  const writes = fake.writes.length;
  const meta = metaOf(svc, ag.owner, s.session_id);
  assert.equal(meta.state, "closed");
  assert.equal(meta.awaitingSignature.final, true);
  assert.equal(meta.awaitingSignature.body.count, meta.seq);
  // A closed agent session with nothing signed hands back the same hash, from checkpoint or close, and queues nothing.
  assert.equal((await svc.checkpoint(ag.owner, { session_id: s.session_id })).sign.hash, closed.sign.hash);
  assert.equal((await svc.close(ag.owner, { session_id: s.session_id }, BASE)).sign.hash, closed.sign.hash);
  // The idle pass never throws or logs a failure over it.
  await svc.closeIdle();
  await svc.closeIdle();
  assert.equal(logs.filter((l) => /failed|unreadable|inconsistent/.test(l.event)).length, 0, JSON.stringify(logs));
  assert.equal(fake.writes.length, writes);

  const signed = await svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: closed.sign.hash, signature: ag.key.signHash(closed.sign.hash) });
  assert.equal(signed.status, "closed");
  assert.equal(signed.checkpoint.status, "anchored");
  assert.equal(signed.pin.checkpointHash, closed.sign.hash);
  const got = await svc.getSession(ag.owner, { session_id: s.session_id }, BASE);
  assert.equal(got.status, "closed");
  assert.equal(got.pin.checkpointHash, closed.sign.hash);
  const doc = JSON.parse(await svc.packetForCap(capOf(s.links)));
  const report = await verifyPacket(strict(doc.packet), { pin: strict(got.pin) });
  assert.equal(report.result, "pass", JSON.stringify(report.checks));
  // Everything but the final checkpoint's own receipt is signed: verify names no unsigned steps.
  const v = await svc.verify(ag.owner, { session_id: s.session_id }, BASE);
  assert.equal(v.result, "pass", v.summary);
  assert.equal("unsigned_steps" in v, false);
  assert.equal("unsigned_note" in v, false);
  // Nothing more is owed: retrying the close finds nothing to do.
  await rejects(svc.close(ag.owner, { session_id: s.session_id }, BASE), "SHADOW_SESSION_CLOSED");
});

test("a close cut short after session.closed gives the hash to sign on the next call", async () => {
  const first = setup();
  const ag = agentIn(first.book);
  const s = await started(first.svc, ag.owner);
  const metaPath = path.join(first.dir, "owners", ownerKeyOf(ag.owner), "sessions", s.session_id, "meta.json");
  copyFileSync(metaPath, `${metaPath}.before`);
  await first.svc.close(ag.owner, { session_id: s.session_id }, BASE);
  // A crash after session.closed was appended and before the metadata was written.
  copyFileSync(`${metaPath}.before`, metaPath);
  rmSync(`${metaPath}.bak`, { force: true });
  const second = setup({ dir: first.dir, keysDir: first.keysDir, fake: first.fake, clock: first.clock, logs: first.logs });
  const { sign, status } = await second.svc.checkpoint(ag.owner, { session_id: s.session_id });
  assert.equal(status, "closed");
  assert.match(sign.hash, /^[0-9a-f]{64}$/);
  const meta = metaOf(second.svc, ag.owner, s.session_id);
  assert.equal(meta.awaitingSignature.final, true);
  assert.equal(meta.awaitingSignature.body.count, meta.seq);
  const signed = await second.svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: sign.hash, signature: ag.key.signHash(sign.hash) });
  assert.equal(signed.checkpoint.status, "anchored");
  assert.equal(signed.pin.checkpointHash, sign.hash);
});

test("a session the idle closer closes waits for the agent's signature", async () => {
  const { svc, clock, book, logs } = setup({ limits: { idleCloseMs: 60_000 } });
  const ag = agentIn(book);
  const s = await started(svc, ag.owner);
  clock.t += 120_000;
  assert.equal(await svc.closeIdle(), 1);
  const meta = metaOf(svc, ag.owner, s.session_id);
  assert.equal(meta.state, "closed");
  assert.equal(meta.awaitingSignature.final, true);
  assert.equal(logs.filter((l) => /failed/.test(l.event)).length, 0, JSON.stringify(logs));
  const { sign } = await svc.checkpoint(ag.owner, { session_id: s.session_id });
  assert.equal(sign.hash, meta.awaitingSignature.hash);
  const signed = await svc.signCheckpoint(ag.owner, ag.akf, { session_id: s.session_id, hash: sign.hash, signature: ag.key.signHash(sign.hash) });
  assert.equal(signed.checkpoint.status, "anchored");
});

test("logging a step for an agent appends and makes no checkpoint", async () => {
  const { svc, fake, book } = setup({ autoLog: true });
  const ag = agentIn(book);
  const r = await svc.logStep(ag.owner, { kind: "task", content: "Find flights" }, BASE);
  assert.equal(r.anchor_status, "not_anchored");
  assert.match(r.anchor_reason, /shadow_sign_checkpoint/);
  const meta = metaOf(svc, ag.owner, r.session_id);
  assert.equal(meta.checkpoint, null);
  assert.equal(meta.awaitingSignature, undefined);
  assert.equal(meta.outbox.filter((x) => x.kind === "checkpoint").length, 0);
  assert.ok(!fake.writes.some((w) => JSON.stringify(w).includes("shadow checkpoint")));
});

test("account owners are unaffected", async () => {
  const { svc, book } = setup();
  const s = await started(svc, A);
  const r = await svc.checkpoint(A, { session_id: s.session_id });
  assert.equal(r.sign, undefined);
  assert.equal(r.checkpoint.status, "anchored");
  const meta = metaOf(svc, A, s.session_id);
  assert.equal(meta.awaitingSignature, undefined);
  assert.equal(meta.checkpoint.hash, r.checkpoint.checkpoint_hash);
  // An account can't sign through the agent tool, whatever key it names.
  const ag = agentIn(book);
  await rejects(svc.signCheckpoint(A, ag.akf, { session_id: s.session_id, hash: r.checkpoint.checkpoint_hash, signature: ag.key.signHash(r.checkpoint.checkpoint_hash) }), "not_agent_owner");
  const closed = await svc.close(A, { session_id: s.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.sign, undefined);
  assert.equal(closed.final_checkpoint.status, "anchored");
  assert.ok(closed.pin);
});
