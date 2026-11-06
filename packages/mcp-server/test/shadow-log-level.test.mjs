// How much detail a session anchors, set by the person for the account and by the agent for a session; and the three
// default agent fields. The person's level is a minimum, deferred steps are covered by the close, and budgets move only
// when an anchor really happens.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ownerKeyOf } from "../dist/shadow/store.js";
import { ShadowService } from "../dist/shadow/service.js";
import { anchorsNow, effectiveLevel, finer } from "../dist/shadow/log-level.js";
import { createLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const O = "acct_AAAAAAAAAAAAAAAAAAAAAA";
const BASE = "https://mcp.example.test";

function service(o = {}) {
  const fake = new FakeLedger();
  const stateDir = o.stateDir ?? mkdtempSync(path.join(tmpdir(), "level-"));
  const svc = new ShadowService({ stateDir, ledger: () => fake, budget: () => createLogBudget({}), sleep: async () => {}, log: () => {}, autoLog: true, ...o });
  svc.sweep();
  return { svc, fake, stateDir };
}
const notes = (svc, id) => svc.store.readEvents(svc.store.readMeta(ownerKeyOf(O), id))
  .filter((e) => e.body.kind === "agent.message" && e.body.payload.note === true).map((e) => e.body.payload.content.text ?? e.body.payload.content);
const said = (list) => JSON.stringify(list);

test("the levels: finer, who wins, and when a call anchors", () => {
  assert.equal(finer("step", "milestone"), "step");
  assert.equal(finer("milestone", "turn"), "turn");
  assert.deepEqual(effectiveLevel(null, null), { level: "step", by: "agent" });
  assert.deepEqual(effectiveLevel("turn", null), { level: "turn", by: "person" });
  assert.deepEqual(effectiveLevel(null, "milestone"), { level: "milestone", by: "agent" });
  assert.deepEqual(effectiveLevel("turn", "milestone"), { level: "turn", by: "person" }, "an agent can't log in less detail");
  assert.deepEqual(effectiveLevel("milestone", "step"), { level: "step", by: "agent" }, "an agent can log in more detail");
  assert.equal(anchorsNow("step", false, ["note"]), true);
  assert.equal(anchorsNow("turn", false, ["tool_call"]), false);
  assert.equal(anchorsNow("turn", false, ["message"]), true);
  assert.equal(anchorsNow("turn", true, ["tool_call"]), true);
  assert.equal(anchorsNow("milestone", false, ["message"]), false);
  assert.equal(anchorsNow("milestone", true, ["message"]), false);
  assert.equal(anchorsNow("milestone", false, ["task"]), true);
});

test("with no setting a session is exactly as before: step level, no note, every step anchored", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do it" }, BASE);
  assert.equal(a.anchor_status, "anchored");
  assert.equal("log_level" in a, false);
  assert.doesNotMatch(a.show_user, /Logging level/);
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(b.anchor_status, "anchored");
  assert.deepEqual(notes(svc, a.session_id), []);
  assert.equal(fake.writes.length, 3, "the start marker and one anchor per step");
  const meta = svc.store.readMeta(ownerKeyOf(O), a.session_id);
  assert.equal("logLevel" in meta, false);
  assert.equal((await svc.getSession(O, { session_id: a.session_id }, BASE)).log_level, "step");
});

test("turn level: steps wait, the reply anchors them, and the footer never claims an anchor it hasn't got", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "turn" }, BASE);
  assert.equal(a.log_level, "turn");
  assert.equal(a.anchor_status, "deferred");
  assert.equal(a.block_height, null);
  assert.equal(a.ledger_id, null);
  assert.match(a.anchor_reason, /turn level/);
  assert.match(a.show_user, /Logging level: turn\./);
  assert.match(a.show_user, /recorded, but it has no anchor yet, so it has no block or ledger ID/);
  assert.equal(fake.writes.length, 1, "only the start marker");
  const call = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(call.anchor_status, "deferred");
  assert.equal(fake.writes.length, 1);
  const reply = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "Done" }, BASE);
  assert.equal(reply.anchor_status, "anchored");
  assert.ok(reply.block_height);
  assert.equal(fake.writes.length, 2, "one anchor for the whole turn");
  assert.match(said(notes(svc, a.session_id)), /Logging level: turn \(set by the agent\)/);
});

test("a shadow_log_turn call anchors at turn level and waits at milestone level, and says so", async () => {
  const { svc, fake } = service();
  const a = await svc.logTurn(O, { log_level: "turn", steps: [{ kind: "prompt", content: "hi" }, { kind: "tool_call", content: { tool: "x" } }] }, BASE);
  assert.equal(a.evidence.anchor_status, "anchored");
  assert.equal(a.shared_anchor, true);
  const before = fake.writes.length;
  const b = await svc.logTurn(O, { log_level: "milestone", steps: [{ kind: "message", content: "a" }, { kind: "note", content: "b" }] }, BASE);
  assert.equal(b.evidence.anchor_status, "deferred");
  assert.equal(b.shared_anchor, false);
  assert.match(b.anchor_note, /no anchor yet/);
  assert.match(b.show_user, /not anchored yet/);
  assert.doesNotMatch(b.show_user, /one shared anchor/);
  assert.match(b.show_user, /not anchored \| not anchored \| not anchored/, "the table says so row by row");
  assert.equal(fake.writes.length, before + 1, "only the new session's start marker");
});

test("milestone level: tasks anchor; shadow_checkpoint and the close always anchor; the close covers every deferred step and verifies", async () => {
  const { svc, fake } = service();
  const s = await svc.startSession(O, { title: "t", log_level: "milestone" }, BASE);
  assert.equal(s.log_level, "milestone");
  assert.equal(s.log_level_set_by, "agent");
  const first = await svc.logStep(O, { session_id: s.session_id, kind: "task", content: "Do it" }, BASE);
  assert.equal(first.anchor_status, "anchored");
  const writes = fake.writes.length;
  for (const content of ["a", "b", "c"]) {
    const r = await svc.logStep(O, { session_id: s.session_id, kind: "message", content }, BASE);
    assert.equal(r.anchor_status, "deferred");
    assert.match(r.anchor_reason, /milestone level/);
  }
  assert.equal(fake.writes.length, writes);
  const cp = await svc.checkpoint(O, { session_id: s.session_id });
  assert.equal(cp.checkpoint.status, "anchored");
  assert.equal(fake.writes.length, writes + 1);
  const late = await svc.logStep(O, { session_id: s.session_id, kind: "note", content: "after the checkpoint" }, BASE);
  assert.equal(late.anchor_status, "deferred");
  const closed = await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "anchored");
  assert.equal(fake.writes.length, writes + 2);
  assert.match(closed.summary, /Logging level: milestone/);
  const checked = await svc.verify(O, { session_id: s.session_id }, BASE);
  assert.equal(checked.result, "pass", JSON.stringify(checked.checks.filter((c) => c.status !== "pass")));
  const log = JSON.parse((await svc.linkBody(svc.store.readMeta(ownerKeyOf(O), s.session_id).cap, "log-json")).toString());
  assert.equal(log.log_level, "milestone");
  assert.deepEqual(log.steps.filter((x) => x.status !== "anchored"), [], "the close covers every step");
});

test("the person's level is the minimum: new sessions start there, an agent can go finer, never coarser", async () => {
  const { svc } = service();
  assert.equal(svc.setLogLevel(O, "turn").log_level, "turn");
  const plain = await svc.startSession(O, { title: "t" }, BASE);
  assert.equal(plain.log_level, "turn");
  assert.equal(plain.log_level_set_by, "person");
  assert.match(said(notes(svc, plain.session_id)), /Logging level: turn \(set by the person\)/);
  const coarser = await svc.startSession(O, { title: "t", log_level: "milestone" }, BASE);
  assert.equal(coarser.log_level, "turn");
  const finerOne = await svc.startSession(O, { title: "t", log_level: "step" }, BASE);
  assert.equal("log_level" in finerOne, false, "step is the default, so it adds nothing");
  assert.equal((await svc.getSession(O, { session_id: finerOne.session_id }, BASE)).log_level, "step");
  const stepped = await svc.logStep(O, { session_id: finerOne.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(stepped.anchor_status, "anchored", "the agent's finer level holds, though the person's is coarser");
  svc.setLogLevel(O, "step");
  const forced = await svc.startSession(O, { title: "t", log_level: "milestone" }, BASE);
  assert.equal("log_level" in forced, false, "the person asked for each step, so a coarser choice has no effect");
});

test("tightening: an open session follows on its next step, in the record; loosening leaves it alone", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "milestone" }, BASE);
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(b.anchor_status, "deferred");
  svc.setLogLevel(O, "step");
  const writes = fake.writes.length;
  const c = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "y" } }, BASE);
  assert.equal(c.anchor_status, "anchored", "the person's finer level applies to this step");
  assert.equal(fake.writes.length, writes + 1);
  assert.match(said(notes(svc, a.session_id)), /Logging level: step \(set by the person\)/);
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.equal(got.log_level, "step");
  assert.equal(got.log_level_set_by, "person");
  svc.setLogLevel(O, "milestone");
  const d = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "z" } }, BASE);
  assert.equal(d.anchor_status, "anchored", "a coarser level doesn't reach an open session");
  assert.equal(notes(svc, a.session_id).filter((n) => /Logging level/.test(said([n]))).length, 2, "one note per change");
  await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  assert.equal((await svc.verify(O, { session_id: a.session_id }, BASE)).result, "pass");
});

test("tightening reaches a session on the shadow_record path too", async () => {
  const { svc } = service();
  const s = await svc.startSession(O, { title: "t", log_level: "milestone", agents: [{ id: "a" }] }, BASE);
  svc.setLogLevel(O, "turn");
  await svc.record(O, { session_id: s.session_id, agent: "a", kind: "task", content: "x" });
  assert.equal((await svc.getSession(O, { session_id: s.session_id }, BASE)).log_level, "turn");
});

test("budgets: a deferred step spends no anchor, and a session out of anchors still records deferred steps", async () => {
  const { svc, fake } = service({ limits: { maxAnchorsPerSession: 3 } });
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "turn" }, BASE);
  const today = () => svc.store.anchorsToday(ownerKeyOf(O), new Date().toISOString().slice(0, 10));
  const spent = today();
  for (let i = 0; i < 6; i++) await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: `t${i}` } }, BASE);
  assert.equal(today(), spent, "the daily count doesn't move");
  assert.equal(fake.writes.length, 1);
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "end of turn" }, BASE);
  assert.equal(today(), spent + 1);
  await assert.rejects(svc.logStep(O, { session_id: a.session_id, kind: "message", content: "would anchor" }, BASE), (e) => e.code === "SHADOW_LIMIT_SESSION_ANCHORS");
  const held = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "still fine" } }, BASE);
  assert.equal(held.anchor_status, "deferred", "the last anchor is kept for the close");
  assert.equal((await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE)).final_checkpoint.status, "anchored");
});

test("a bad level is refused and leaves no session behind", async () => {
  const { svc } = service();
  await assert.rejects(svc.logStep(O, { kind: "task", content: "x", log_level: "sometimes" }, BASE), (e) => e.code === "SHADOW_BAD_INPUT" || /log_level/.test(e.message));
  await assert.rejects(svc.startSession(O, { title: "t", log_level: 3 }, BASE), /log_level/);
  assert.throws(() => svc.setLogLevel(O, "loud"), /log_level|level/);
  assert.equal((await svc.listSessions(O)).sessions.length, 0);
});

test("settings: an old file still works, the level survives a restart, and logging on or off keeps it", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "level-settings-"));
  const first = service({ stateDir });
  first.svc.setLogging(O, false);
  const found = readFileSync(findSettings(stateDir), "utf8");
  assert.doesNotMatch(found, /logLevel/, "a file from before the level has none");
  first.svc.setLogging(O, true);
  assert.equal(first.svc.logLevelOf(O), null);
  first.svc.setLogLevel(O, "milestone");
  first.svc.setLogging(O, false);
  assert.equal(first.svc.logLevelOf(O), "milestone", "turning logging off keeps the level");
  first.svc.setLogging(O, true);
  const second = service({ stateDir });
  assert.equal(second.svc.logLevelOf(O), "milestone", "it survives a restart");
  assert.equal(second.svc.loggingEnabled(O), true);
});

test("an unreadable settings file refuses rather than guessing, and logging can still be turned off", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "level-bad-"));
  const { svc } = service({ stateDir });
  svc.setLogLevel(O, "turn");
  writeFileSync(findSettings(stateDir), "not json");
  await assert.rejects(svc.startSession(O, { title: "t" }, BASE), (e) => e.code === "SHADOW_UNAVAILABLE");
  assert.doesNotThrow(() => svc.setLogging(O, false));
});

test("an old session, with no level and no agent fields, reads as step and Not provided", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do it" }, BASE);
  const meta = svc.store.readMeta(ownerKeyOf(O), a.session_id);
  meta.agents = meta.agents.map(({ id, role }) => ({ id, role }));
  delete meta.logLevel;
  svc.store.writeMeta(meta);
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.equal(got.log_level, "step");
  assert.deepEqual(got.agents, [{ id: "agent", role: null, purpose: "Not provided", accountable_owner: "Not provided" }]);
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "more" }, BASE);
  assert.equal(b.anchor_status, "anchored");
});

test("agent fields: optional, cleaned, hashed in the record, never on the ledger, shown in the viewer", async () => {
  const { svc, fake } = service();
  const s = await svc.startSession(O, { title: "t", agents: [
    { id: "researcher", role: "finds sources", purpose: "Finds trial sources\nfor <b>the team</b>", accountable_owner: "Ops team" },
    { id: "writer" },
  ] }, BASE);
  const [r, w] = s.agents;
  assert.equal(r.accountable_owner, "Ops team");
  assert.deepEqual(w, { id: "writer", role: null, purpose: "Not provided", accountable_owner: "Not provided" });
  const got = await svc.getSession(O, { session_id: s.session_id }, BASE);
  assert.equal(got.agents[0].accountable_owner, "Ops team");
  assert.equal(got.agents[1].purpose, "Not provided");
  assert.match(said(notes(svc, s.session_id)), /Agent researcher: purpose .*accountable owner Ops team/);
  assert.doesNotMatch(said(fake.writes), /Ops team|Finds trial/, "only hashes go to the ledger");
  await svc.logStep(O, { session_id: s.session_id, kind: "task", agent: "researcher", content: "x" }, BASE);
  await svc.logStep(O, { session_id: s.session_id, kind: "message", agent: "researcher", content: "done" }, BASE);
  await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
  const checked = await svc.verify(O, { session_id: s.session_id }, BASE);
  assert.equal(checked.result, "pass", JSON.stringify(checked.checks.filter((c) => c.status !== "pass")));
  const meta = svc.store.readMeta(ownerKeyOf(O), s.session_id);
  const html = (await svc.linkBody(meta.cap, "viewer")).toString();
  assert.match(html, /<h2>Session details<\/h2>/);
  assert.match(html, /Logging level: step/);
  assert.match(html, /Accountable owner/);
  assert.match(html, /Not provided/);
  assert.doesNotMatch(html.slice(html.indexOf("Session details"), html.indexOf("What this record shows")), /<b>the team/, "escaped");
});

test("agent fields are limited and redacted; a wrong type is ignored; hidden reasoning is refused before a session exists", async () => {
  const { svc } = service();
  const key = ["sk", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"].join("-");
  const s = await svc.startSession(O, { title: "t", agents: [{ id: "a", purpose: "p".repeat(500), accountable_owner: `owner ${key}` }, { id: "b", purpose: 7 }] }, BASE);
  assert.equal(s.agents[0].purpose.length <= 200, true);
  assert.equal(s.agents[0].accountable_owner.includes(key), false);
  assert.equal(s.agents[1].purpose, "Not provided");
  const before = (await svc.listSessions(O)).sessions.length;
  await assert.rejects(svc.startSession(O, { title: "t", agents: [{ id: "a", purpose: "<think>private</think>" }] }, BASE));
  assert.equal((await svc.listSessions(O)).sessions.length, before);
});

function findSettings(dir) {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, name.name);
    if (name.isFile() && name.name === "settings.json") return p;
    if (name.isDirectory()) {
      const found = findSettings(p);
      if (found) return found;
    }
  }
  return null;
}
