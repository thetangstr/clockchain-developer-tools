// The viewer and shadow_verify check an agent's key automatically: the checkpoint's signing key is looked up in the
// public book of agent keys, and the record reads "made by this agent, unchanged, at this time", or why not. The server is
// checking its own book, so each line says "Checked against Clockchain's public key list" and never claims independence.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { checkAgentKey, plainDate } from "../dist/agent-keys/check.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { ShadowService } from "../dist/shadow/service.js";
import { DOMAIN, hash } from "../dist/shadow/lib/profile.js";
import { fingerprint } from "../dist/shadow/lib/keys.js";
import { SUMMARY_CSP } from "../dist/shadow/lib/summary.js";
import { HOSTED_LIMITS } from "../dist/shadow/recorder.js";
import { createLogBudget } from "../dist/budget.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { keyProvider } from "../dist/shadow/witness.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const CHECKED = " Checked against Clockchain's public key list.";
const BASE = "https://mcp.example.test";
const T0 = Date.UTC(2026, 10, 13, 12, 0, 0);
const iso = (t) => new Date(t).toISOString();

function bookAt(clock, dir = mkdtempSync(path.join(tmpdir(), "agent-keys-check-"))) {
  return new AgentKeyBook({ dir, now: () => new Date(clock.t) });
}

/** An agent's key in a book, filed (or not) as `filing` says. */
function agentIn(book, filing = { state: "filed", ledgerId: "led-key", block: 10, filedAt: iso(T0) }) {
  const key = makeAgentKey();
  const { entry } = book.admit(key.publicKeyPem);
  if (filing.state !== "unfiled") book.setFiling(entry.fingerprint, filing);
  return { key, fp: entry.fingerprint, root: entry.root, id: entry.root.slice(0, 16) };
}

/** A checkpoint of the agent's session, signed by `signer` (the agent's own key unless given). */
function agentCp(ag, { createdAt = iso(T0 + 60_000), signer = ag.key, operatorRoot = ag.root } = {}) {
  const body = { profile: "shadow-v1", operatorId: `agent-${operatorRoot.slice(0, 32)}`, sessionId: "s1", count: 2, createdAt };
  const h = hash(DOMAIN.checkpoint, body);
  return { body, hash: h, publicKey: signer.publicKeyPem, signature: signer.signHash(h) };
}

test("made_by_agent: a filed key that signed the record", () => {
  const clock = { t: T0 };
  const book = bookAt(clock);
  const ag = agentIn(book);
  const cp = agentCp(ag);
  const r = checkAgentKey(book.get(ag.fp), cp, 12, { anchoredAt: "2026-11-14T03:00:00Z" });
  assert.equal(r.verdict, "made_by_agent");
  assert.equal(r.text, `Made by agent ${ag.id}, unchanged since 14 November 2026. Key filed 13 November 2026.${CHECKED}`);
  // An anchor still to land: the checkpoint's own time, and still not key_filed_after (its block is unknown).
  const pending = checkAgentKey(book.get(ag.fp), agentCp(ag, { createdAt: "2026-12-01T23:59:59Z" }), null);
  assert.equal(pending.verdict, "made_by_agent");
  assert.equal(pending.text, `Made by agent ${ag.id}, unchanged since 1 December 2026. Key filed 13 November 2026.${CHECKED}`);
});

test("key_not_filed: the key is in the book but not on Clockchain yet", () => {
  const clock = { t: T0 };
  const book = bookAt(clock);
  for (const filing of [{ state: "unfiled" }, { state: "pending", ledgerId: "led-1" }]) {
    const ag = agentIn(book, filing);
    const r = checkAgentKey(book.get(ag.fp), agentCp(ag), 12);
    assert.equal(r.verdict, "key_not_filed");
    assert.equal(r.text, `Signed by agent ${ag.id}. Its key isn't filed on Clockchain yet.${CHECKED}`);
  }
});

test("key_filed_after: the key's filing block is later than the record's", () => {
  const clock = { t: T0 };
  const book = bookAt(clock);
  const ag = agentIn(book, { state: "filed", ledgerId: "led-key", block: 20, filedAt: iso(T0) });
  const r = checkAgentKey(book.get(ag.fp), agentCp(ag), 12);
  assert.equal(r.verdict, "key_filed_after");
  assert.equal(r.text, `Signed by agent ${ag.id}, but its key was filed after this record.${CHECKED}`);
  assert.equal(checkAgentKey(book.get(ag.fp), agentCp(ag), 20).verdict, "made_by_agent", "the same block is not after");
  assert.equal(checkAgentKey(book.get(ag.fp), agentCp(ag), null).verdict, "made_by_agent", "no block for the record: not judged after");
});

test("key_revoked_before: the key was cancelled before the record", () => {
  const clock = { t: T0 };
  const book = bookAt(clock);
  const ag = agentIn(book);
  clock.t = T0 + 30_000;
  book.revoke(ag.fp);
  const r = checkAgentKey(book.get(ag.fp), agentCp(ag, { createdAt: iso(T0 + 60_000) }), 12);
  assert.equal(r.verdict, "key_revoked_before");
  assert.equal(r.text, `Signed by agent ${ag.id}, but that key was cancelled before this record.${CHECKED}`);
  // Cancelled after the record: the record still stands.
  assert.equal(checkAgentKey(book.get(ag.fp), agentCp(ag, { createdAt: iso(T0 + 1000) }), 12).verdict, "made_by_agent");
});

test("a key replaced before the record counts as cancelled; replaced after, the record stands", () => {
  const clock = { t: T0 };
  const book = bookAt(clock);
  const ag = agentIn(book);
  clock.t = T0 + 30_000;
  book.replace(ag.fp, makeAgentKey().publicKeyPem);
  const r = checkAgentKey(book.get(ag.fp), agentCp(ag, { createdAt: iso(T0 + 60_000) }), 12);
  assert.deepEqual(r, { verdict: "key_revoked_before", text: `Signed by agent ${ag.id}, but that key was cancelled before this record.${CHECKED}` });
  assert.equal(checkAgentKey(book.get(ag.fp), agentCp(ag, { createdAt: iso(T0 + 1000) }), 12).verdict, "made_by_agent");
});

test("not_from_agent: a bad signature, a changed body, another agent's key, or a key not in the book", () => {
  const clock = { t: T0 };
  const book = bookAt(clock);
  const ag = agentIn(book);
  const text = `Not from agent ${ag.id}: the signature doesn't match its key.${CHECKED}`;
  // Another key's signature under the agent's public key.
  const forged = { ...agentCp(ag), signature: makeAgentKey().signHash(agentCp(ag).hash) };
  assert.deepEqual(checkAgentKey(book.get(ag.fp), forged, 12), { verdict: "not_from_agent", text });
  // The body changed after signing.
  const cp = agentCp(ag);
  const changed = { ...cp, body: { ...cp.body, count: 3 } };
  assert.deepEqual(checkAgentKey(book.get(ag.fp), changed, 12), { verdict: "not_from_agent", text });
  // A good signature by a key of another agent, on this agent's record.
  const other = agentIn(book);
  const theirs = agentCp(ag, { signer: other.key });
  assert.deepEqual(checkAgentKey(book.get(other.fp), theirs, 12), { verdict: "not_from_agent", text });
  // A key the book doesn't have ties the record to no key of this agent's.
  assert.deepEqual(checkAgentKey(null, agentCp(ag), 12), { verdict: "not_from_agent", text });
});

test("precedence: not_from_agent, then key_revoked_before, then key_filed_after", () => {
  const clock = { t: T0 };
  const book = bookAt(clock);
  const ag = agentIn(book, { state: "filed", ledgerId: "led-key", block: 20, filedAt: iso(T0) });
  clock.t = T0 + 30_000;
  book.revoke(ag.fp);
  const cp = agentCp(ag);
  assert.equal(checkAgentKey(book.get(ag.fp), cp, 12).verdict, "key_revoked_before", "revoked beats filed after");
  assert.equal(checkAgentKey(book.get(ag.fp), { ...cp, signature: makeAgentKey().signHash(cp.hash) }, 12).verdict, "not_from_agent", "a bad signature beats everything");
});

test("witnessed: an account's checkpoint under Clockchain's published witness key", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const body = { operatorId: "4f0c6a8e-1111-4111-8111-111111111111", createdAt: iso(T0) };
  const h = hash(DOMAIN.checkpoint, body);
  const cp = { body, hash: h, publicKey: pem, signature: sign(null, Buffer.from(h, "hex"), privateKey).toString("base64") };
  const r = checkAgentKey(null, cp, 12, { witness: fingerprint(pem) });
  assert.deepEqual(r, { verdict: "witnessed", text: `Witnessed by Clockchain for a signed-in account.${CHECKED}` });
  // A per-owner key of before: today's text, with no claim about a key list.
  const legacy = checkAgentKey(null, cp, 12);
  assert.deepEqual(legacy, { verdict: "legacy", text: HOSTED_LIMITS.at(-1) });
  assert.ok(!legacy.text.endsWith(CHECKED));
  assert.equal(checkAgentKey(null, cp, 12, { witness: "00".repeat(32) }).verdict, "legacy", "another key than the published one is not the witness");
});

test("dates read as plain UTC dates", () => {
  assert.equal(plainDate("2026-11-13T00:00:00Z"), "13 November 2026");
  assert.equal(plainDate("2026-11-13T23:30:00-05:00"), "14 November 2026");
  assert.equal(plainDate("2027-01-01T00:00:00.000Z"), "1 January 2027");
});

// ---- the service ---------------------------------------------------------------------------------------------------

function setup(o = {}) {
  const clock = { t: T0 };
  const fake = new FakeLedger();
  fake.base = T0;
  const keysDir = mkdtempSync(path.join(tmpdir(), "agent-keys-check-"));
  const book = bookAt(clock, keysDir);
  const svc = new ShadowService({
    stateDir: mkdtempSync(path.join(tmpdir(), "agent-keys-check-svc-")), ledger: () => fake, budget: () => createLogBudget({}),
    now: () => new Date(clock.t), sleep: async () => {}, log: () => {}, agentKeys: book, ...(o.autoLog ? { autoLog: true } : {}),
    ...(o.witness ? { witness: o.witness } : {}),
  });
  svc.sweep();
  return { svc, fake, book, clock, keysDir };
}

/** An agent with a session of one step and a checkpoint it signed. */
async function agentSession(env) {
  const key = makeAgentKey();
  const { entry } = env.book.admit(key.publicKeyPem);
  const owner = `ak:${entry.root}`;
  const s = await env.svc.startSession(owner, { title: "an agent's", agents: [{ id: "planner" }] }, BASE);
  await env.svc.record(owner, { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" });
  const { sign: toSign } = await env.svc.checkpoint(owner, { session_id: s.session_id });
  await env.svc.signCheckpoint(owner, entry.fingerprint, { session_id: s.session_id, hash: toSign.hash, signature: key.signHash(toSign.hash) });
  return { key, owner, fp: entry.fingerprint, id: entry.root.slice(0, 16), sessionId: s.session_id };
}

const metaOf = (svc, owner, id) => svc.store.readMeta(ownerKeyOf(owner), id);
const viewer = async (svc, owner, id) => (await svc.linkBody(metaOf(svc, owner, id).cap, "summary")).toString();

test("shadow_verify says who made an agent's record, and where its key is listed", async () => {
  const env = setup({ autoLog: true });
  const ag = await agentSession(env);
  const v = await env.svc.verify(ag.owner, { session_id: ag.sessionId }, BASE);
  assert.equal(v.agent_key.verdict, "made_by_agent");
  assert.equal(v.agent_key.text, `Made by agent ${ag.id}, unchanged since 13 November 2026. Key filed 13 November 2026.${CHECKED}`);
  assert.equal(v.agent_key.lookup, `/agent-keys/${ag.fp}.json`);
  // The own-pin wording is the server's, which didn't sign here: the agent-key line replaces it.
  const trust = v.checks.find((c) => c.name === "trust");
  assert.equal(trust.reason, v.agent_key.text);
  assert.ok(!JSON.stringify(v).includes("Matches the pin from this server"));
  assert.ok(!/verified by|independent(ly)? /i.test(v.agent_key.text));
});

test("the viewer HTML contains the verdict text and no script tag", async () => {
  const env = setup();
  const ag = await agentSession(env);
  const html = await viewer(env.svc, ag.owner, ag.sessionId);
  const text = `Made by agent ${ag.id}, unchanged since 13 November 2026. Key filed 13 November 2026.${CHECKED}`;
  assert.ok(html.includes(`<h1>Shadow evidence summary</h1>\n<p><b>${text.replaceAll("'", "&#39;")}</b></p>`), "the first line under the title");
  assert.ok(!/<script/i.test(html));
  assert.ok(html.includes(`content="${SUMMARY_CSP.replaceAll("'", "&#39;")}"`), "the page's CSP is unchanged");
  assert.ok(!html.includes("Matches what the server signed"), "the server didn't sign an agent's record");
  assert.ok(!html.includes("Matches the pin from this server"));
  assert.ok(!html.includes("<b>Proven:</b>") && !html.includes('<td class="tag">Proven</td>'));
});

test("a filing that lands later, or a cancellation, refreshes the viewer", async () => {
  const env = setup();
  const ag = await agentSession(env);
  const filed = env.book.get(ag.fp).filing;
  env.book.setFiling(ag.fp, { state: "pending", ledgerId: filed.ledgerId });
  assert.ok((await viewer(env.svc, ag.owner, ag.sessionId)).includes(`Signed by agent ${ag.id}. Its key isn&#39;t filed on Clockchain yet.`));
  env.book.setFiling(ag.fp, filed);
  assert.ok((await viewer(env.svc, ag.owner, ag.sessionId)).includes(`Made by agent ${ag.id}, unchanged since`));
  // Cancelled now, after the record: it still stands, and the page is rebuilt from the book as it is.
  const builds = env.svc.linkBuildCount;
  env.clock.t += 60_000;
  env.book.revoke(ag.fp);
  assert.ok((await viewer(env.svc, ag.owner, ag.sessionId)).includes(`Made by agent ${ag.id}, unchanged since`));
  assert.equal(env.svc.linkBuildCount, builds + 1);
});

test("an agent checkpoint whose receipt hasn't landed reads the key verdict and the anchoring caveat, not proven", async () => {
  const env = setup();
  const ag = await agentSession(env);
  env.fake.confirm = false;
  env.clock.t = Date.UTC(2026, 10, 15, 9, 0, 0);
  await env.svc.record(ag.owner, { session_id: ag.sessionId, agent: "planner", kind: "message", content: "Found one" });
  const { sign: toSign } = await env.svc.checkpoint(ag.owner, { session_id: ag.sessionId });
  await env.svc.signCheckpoint(ag.owner, ag.fp, { session_id: ag.sessionId, hash: toSign.hash, signature: ag.key.signHash(toSign.hash) });
  assert.ok(!metaOf(env.svc, ag.owner, ag.sessionId).anchors.some((a) => a.hash === toSign.hash), "its receipt hasn't landed");
  const html = await viewer(env.svc, ag.owner, ag.sessionId);
  assert.ok(html.includes(`Made by agent ${ag.id}, unchanged since 15 November 2026. Key filed 13 November 2026.`));
  assert.ok(html.includes("This command doesn&#39;t check anchoring"), "the anchoring caveat stays");
  assert.ok(!html.includes(">Proven<") && !html.includes("<b>Proven:</b>"));
});

const ACCOUNT = "jti:11111111-1111-4111-8111-111111111111";

async function accountSession(env) {
  const s = await env.svc.startSession(ACCOUNT, { title: "an account's", agents: [{ id: "planner" }] }, BASE);
  await env.svc.record(ACCOUNT, { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" });
  return s.session_id;
}

test("a witnessed account's record says so, with where the witness key is published", async () => {
  const witness = keyProvider(generateKeyPairSync("ed25519").privateKey);
  const env = setup({ witness, autoLog: true });
  const id = await accountSession(env);
  const v = await env.svc.verify(ACCOUNT, { session_id: id }, BASE);
  assert.deepEqual(v.agent_key, { verdict: "witnessed", text: `Witnessed by Clockchain for a signed-in account.${CHECKED}`, lookup: "/.well-known/clockchain-witness-key.json" });
  // The server did sign this one, so its own-pin wording stays.
  assert.equal(v.checks.find((c) => c.name === "trust").reason.startsWith("Matches the pin from this server."), true);
  const html = await viewer(env.svc, ACCOUNT, id);
  assert.ok(html.includes(`<h1>Shadow evidence summary</h1>\n<p><b>Witnessed by Clockchain for a signed-in account. Checked against Clockchain&#39;s public key list.</b></p>`));
  assert.ok(html.includes("Matches what the server signed"));
  assert.ok(!/<script/i.test(html));
});

test("a legacy account's record keeps today's text, and its viewer has no key line", async () => {
  const env = setup();
  const id = await accountSession(env);
  const v = await env.svc.verify(ACCOUNT, { session_id: id }, BASE);
  assert.deepEqual(v.agent_key, { verdict: "legacy", text: HOSTED_LIMITS.at(-1), lookup: null });
  const html = await viewer(env.svc, ACCOUNT, id);
  assert.ok(html.includes("<h1>Shadow evidence summary</h1>\n<p class=\"meta\">Session"), "the title is followed by the library's own line");
  assert.ok(!html.includes(CHECKED.trim().replaceAll("'", "&#39;")));
});

// ---- the key check decides a failed verify -------------------------------------------------------------------------

const verifyOf = (env, ag) => env.svc.verify(ag.owner, { session_id: ag.sessionId }, BASE);

/** An agent's closed session with its final checkpoint signed: a record that passes. */
async function closedAgentSession(env) {
  const key = makeAgentKey();
  const { entry } = env.book.admit(key.publicKeyPem);
  const owner = `ak:${entry.root}`;
  const s = await env.svc.startSession(owner, { title: "an agent's", agents: [{ id: "planner" }] }, BASE);
  await env.svc.record(owner, { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" });
  await env.svc.record(owner, { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
  const closed = await env.svc.close(owner, { session_id: s.session_id, status: "succeeded" }, BASE);
  await env.svc.signCheckpoint(owner, entry.fingerprint, { session_id: s.session_id, hash: closed.sign.hash, signature: key.signHash(closed.sign.hash) });
  return { key, owner, fp: entry.fingerprint, id: entry.root.slice(0, 16), sessionId: s.session_id };
}

async function closedAccountSession(env) {
  const id = await accountSession(env);
  await env.svc.record(ACCOUNT, { session_id: id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
  await env.svc.close(ACCOUNT, { session_id: id, status: "succeeded" }, BASE);
  return id;
}

/** Each way the book can say the record isn't this agent's, set up after a good record. */
const FAILING = {
  not_from_agent: (env, ag) => {
    rmSync(path.join(env.keysDir, `${ag.fp}.json`), { force: true });
    rmSync(path.join(env.keysDir, `${ag.fp}.json.bak`), { force: true });
  },
  key_revoked_before: (env, ag) => {
    env.clock.t = T0 - 60_000;
    env.book.revoke(ag.fp);
  },
  key_filed_after: (env, ag) => env.book.setFiling(ag.fp, { ...env.book.get(ag.fp).filing, block: 1_000_000 }),
};

for (const [verdict, make] of Object.entries(FAILING)) {
  test(`${verdict} fails shadow_verify, and the viewer shows nothing as matching`, async () => {
    const env = setup();
    const ag = await closedAgentSession(env);
    const before = await verifyOf(env, ag);
    assert.equal(before.result, "pass", before.summary);
    make(env, ag);
    const v = await verifyOf(env, ag);
    assert.equal(v.agent_key.verdict, verdict);
    assert.equal(v.result, "fail");
    assert.equal(v.summary, v.agent_key.text, "the summary says why, in the verdict's words");
    assert.deepEqual(v.checks.find((c) => c.name === "agent_key"), { name: "agent_key", status: "fail", reason: v.agent_key.text });
    const html = await viewer(env.svc, ag.owner, ag.sessionId);
    assert.ok(html.includes(`<p><b>${v.agent_key.text.replaceAll("'", "&#39;")}</b></p>`));
    assert.ok(html.includes('class="result fail"'));
    assert.ok(!html.includes("Matches the signing key") && !html.includes("Proven"), "nothing reads as matching or proven");
  });
}

test("key_not_filed makes shadow_verify at most indeterminate", async () => {
  const env = setup();
  const ag = await closedAgentSession(env);
  env.book.setFiling(ag.fp, { state: "pending", ledgerId: env.book.get(ag.fp).filing.ledgerId });
  const v = await verifyOf(env, ag);
  assert.equal(v.agent_key.verdict, "key_not_filed");
  assert.equal(v.result, "indeterminate");
  assert.equal(v.summary, v.agent_key.text);
  assert.deepEqual(v.checks.find((c) => c.name === "agent_key"), { name: "agent_key", status: "indeterminate", reason: v.agent_key.text });
  assert.ok((await viewer(env.svc, ag.owner, ag.sessionId)).includes('class="result indeterminate"'));
});

test("made_by_agent, witnessed and legacy results are as computed", async () => {
  const env = setup();
  const ag = await closedAgentSession(env);
  const v = await verifyOf(env, ag);
  assert.equal(v.agent_key.verdict, "made_by_agent");
  assert.equal(v.result, "pass", v.summary);
  assert.ok(!v.checks.some((c) => c.name === "agent_key"));
  for (const o of [{ witness: keyProvider(generateKeyPairSync("ed25519").privateKey) }, {}]) {
    const acct = setup(o);
    const id = await closedAccountSession(acct);
    const r = await acct.svc.verify(ACCOUNT, { session_id: id }, BASE);
    assert.equal(r.agent_key.verdict, o.witness ? "witnessed" : "legacy");
    assert.equal(r.result, "pass", r.summary);
    assert.ok(!r.checks.some((c) => c.name === "agent_key"));
  }
});
