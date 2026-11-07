// How much detail a session anchors, set for the account and by the agent for a session; and the default agent fields. A
// session runs at the finer of the two, budgets move only when an anchor really happens, and nothing a reader sees says a
// step is anchored, or that it will be, unless that is true. Level and agent details come from hashed server notes.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ownerKeyOf } from "../dist/shadow/store.js";
import { ShadowService } from "../dist/shadow/service.js";
import { anchorsNow, deferredReason, effectiveLevel, finer, levelSetBy, LOG_LEVEL_HELP, LOG_LEVEL_HELP_ASKED } from "../dist/shadow/log-level.js";
import { createLogBudget } from "../dist/budget.js";
import { ApiError } from "@clockchain/core";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const O = "acct_AAAAAAAAAAAAAAAAAAAAAA";
const O2 = "acct_BBBBBBBBBBBBBBBBBBBBBB";
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
const metaOf = (svc, id, o = O) => svc.store.readMeta(ownerKeyOf(o), id);
const eventsOf = (svc, id, o = O) => svc.store.readEvents(metaOf(svc, id, o));
const serverNotes = (svc, id, o = O) => eventsOf(svc, id, o).filter((e) => e.body.payload.server_note);
const viewer = async (svc, id, o = O) => (await svc.linkBody(metaOf(svc, id, o).cap, "summary")).toString();
const logJson = async (svc, id, o = O) => JSON.parse((await svc.linkBody(metaOf(svc, id, o).cap, "log-json")).toString());
const logText = async (svc, id, o = O) => (await svc.linkBody(metaOf(svc, id, o).cap, "log")).toString();
const viewerResult = (html) => /<p class="result [a-z]+">Result: ([a-z]+)\./.exec(html)?.[1];
const check = (report, name) => report.checks.find((c) => c.name === name);

test("the levels: finer, who wins, and when a call anchors", () => {
  assert.equal(finer("step", "milestone"), "step");
  assert.equal(finer("milestone", "turn"), "turn");
  assert.deepEqual(effectiveLevel(null, null), { level: "step", by: "agent" });
  assert.deepEqual(effectiveLevel("turn", null), { level: "turn", by: "account" });
  assert.deepEqual(effectiveLevel(null, "milestone"), { level: "milestone", by: "agent" });
  assert.deepEqual(effectiveLevel("turn", "milestone"), { level: "turn", by: "account" }, "a session runs at the finer of the two");
  assert.deepEqual(effectiveLevel("milestone", "step"), { level: "step", by: "agent" }, "an agent can log in more detail");
  for (const kind of ["task", "prompt", "message", "tool_call", "tool_result", "file", "note"]) assert.equal(anchorsNow("step", false, [kind]), true, kind);
  for (const kind of ["task", "message", "note"]) assert.equal(anchorsNow("turn", false, [kind]), true, `turn anchors on ${kind}`);
  for (const kind of ["prompt", "tool_call", "tool_result", "file"]) assert.equal(anchorsNow("turn", false, [kind]), false, `turn defers ${kind}`);
  assert.equal(anchorsNow("turn", true, ["tool_call"]), true, "a shadow_log_turn call anchors at turn");
  assert.equal(anchorsNow("milestone", false, ["task"]), true);
  for (const kind of ["prompt", "message", "tool_call", "tool_result", "file", "note"]) {
    assert.equal(anchorsNow("milestone", false, [kind]), false, `milestone defers ${kind}`);
    assert.equal(anchorsNow("milestone", true, [kind]), false, `milestone defers a shadow_log_turn call of ${kind}`);
  }
  assert.equal(levelSetBy("person"), "account", "what was stored as the person's reads as the account's");
  assert.equal(levelSetBy("account"), "account");
  assert.equal(levelSetBy("agent"), "agent");
  assert.equal(levelSetBy("someone"), null);
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
  const a = await svc.logStep(O, { kind: "prompt", content: "Do it", log_level: "turn" }, BASE);
  assert.equal(a.log_level, "turn");
  assert.equal(a.anchor_status, "deferred");
  assert.equal(a.block_height, null);
  assert.equal(a.ledger_id, null);
  assert.match(a.anchor_reason, /turn level/);
  assert.match(a.show_user, /Logging level: turn\./);
  assert.match(a.show_user, /recorded, but it has no anchor so far, so it has no block or ledger ID/);
  assert.equal(fake.writes.length, 1, "only the start marker");
  for (const [kind, content] of [["tool_call", { tool: "x" }], ["tool_result", { tool: "x", result: "ok" }], ["file", { path: "a.txt", content: "x" }]]) {
    const r = await svc.logStep(O, { session_id: a.session_id, kind, content }, BASE);
    assert.equal(r.anchor_status, "deferred", kind);
  }
  assert.equal(fake.writes.length, 1);
  const reply = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "Done" }, BASE);
  assert.equal(reply.anchor_status, "anchored");
  assert.ok(reply.block_height);
  assert.equal(fake.writes.length, 2, "one anchor for the whole turn");
  assert.match(said(notes(svc, a.session_id)), /Logging level: turn \(set by the agent\)/);
});

test("turn level is never coarser than milestone: a task anchors, and a reply logged as a note anchors", async () => {
  const { svc, fake } = service();
  const task = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "turn" }, BASE);
  assert.equal(task.anchor_status, "anchored", "a task anchors at milestone, so it anchors at turn");
  const writes = fake.writes.length;
  await svc.logStep(O, { session_id: task.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  const reply = await svc.logStep(O, { session_id: task.session_id, kind: "note", content: "the reply" }, BASE);
  assert.equal(reply.anchor_status, "anchored");
  assert.equal(fake.writes.length, writes + 1);
  assert.equal((await svc.logStep(O, { session_id: task.session_id, kind: "message", content: "and more" }, BASE)).anchor_status, "anchored");
});

test("step level: each logging call gets its own anchor, and the steps in one shadow_log_turn call share it", async () => {
  const { svc, fake } = service();
  const a = await svc.logTurn(O, { steps: [{ kind: "task", content: "go" }, { kind: "tool_call", content: { tool: "x" } }, { kind: "message", content: "done" }] }, BASE);
  assert.equal(a.shared_anchor, true);
  assert.equal(fake.writes.length, 2, "the start marker and one anchor for the call");
  await svc.logStep(O, { session_id: a.session_id, kind: "note", content: "one" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "note", content: "two" }, BASE);
  assert.equal(fake.writes.length, 4, "one per call");
  assert.match(LOG_LEVEL_HELP, /each logging call gets its own anchor, and the steps in one shadow_log_turn call share it/);
  assert.doesNotMatch(LOG_LEVEL_HELP, /each step gets its own anchor|gives each step its own anchor/i);
  assert.doesNotMatch(LOG_LEVEL_HELP_ASKED, /its own anchor|shadow_log_/);
});

test("a shadow_log_turn call anchors at turn level and waits at milestone level, and says so", async () => {
  const { svc, fake } = service();
  const a = await svc.logTurn(O, { log_level: "turn", steps: [{ kind: "prompt", content: "hi" }, { kind: "tool_call", content: { tool: "x" } }] }, BASE);
  assert.equal(a.evidence.anchor_status, "anchored");
  assert.equal(a.shared_anchor, true);
  assert.equal(a.log_level, "turn");
  const before = fake.writes.length;
  const b = await svc.logTurn(O, { log_level: "milestone", steps: [{ kind: "message", content: "a" }, { kind: "note", content: "b" }] }, BASE);
  assert.equal(b.evidence.anchor_status, "deferred");
  assert.equal(b.shared_anchor, false);
  assert.match(b.anchor_note, /no anchor so far/);
  assert.match(b.show_user, /not anchored so far/);
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

test("the account's level applies to its sessions: new sessions start there, and a session runs at the finer of it and the agent's choice", async () => {
  const { svc } = service();
  assert.equal(svc.setLogLevel(O, "turn").log_level, "turn");
  const plain = await svc.startSession(O, { title: "t" }, BASE);
  assert.equal(plain.log_level, "turn");
  assert.equal(plain.log_level_set_by, "account");
  assert.match(said(notes(svc, plain.session_id)), /Logging level: turn \(set by the account\)/);
  assert.doesNotMatch(said(notes(svc, plain.session_id)), /person/);
  const coarser = await svc.startSession(O, { title: "t", log_level: "milestone" }, BASE);
  assert.equal(coarser.log_level, "turn");
  const finerOne = await svc.startSession(O, { title: "t", log_level: "step" }, BASE);
  assert.equal("log_level" in finerOne, false, "step is the default, so it adds nothing");
  assert.equal((await svc.getSession(O, { session_id: finerOne.session_id }, BASE)).log_level, "step");
  const stepped = await svc.logStep(O, { session_id: finerOne.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(stepped.anchor_status, "anchored", "the agent's finer level holds, though the account's is coarser");
  svc.setLogLevel(O, "step");
  const forced = await svc.startSession(O, { title: "t", log_level: "milestone" }, BASE);
  assert.equal("log_level" in forced, false, "the account is at step, so a coarser choice has no effect");
});

test("tightening: an open session follows on its next step, in the record; loosening leaves its level alone and is noted", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "milestone" }, BASE);
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(b.anchor_status, "deferred");
  svc.setLogLevel(O, "step");
  const writes = fake.writes.length;
  const c = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "y" } }, BASE);
  assert.equal(c.anchor_status, "anchored", "the account's finer level applies to this step");
  assert.equal(fake.writes.length, writes + 1);
  assert.match(said(notes(svc, a.session_id)), /Logging level: step \(set by the account\)/);
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.equal(got.log_level, "step");
  assert.equal(got.log_level_set_by, "account");
  svc.setLogLevel(O, "milestone");
  const d = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "z" } }, BASE);
  assert.equal(d.anchor_status, "anchored", "a coarser level doesn't reach an open session");
  assert.equal(notes(svc, a.session_id).filter((n) => /Logging level/.test(said([n]))).length, 2, "the session's level changed once after its start");
  assert.match(said(notes(svc, a.session_id)), /The account's level changed from step to milestone\. This session stays at step\./);
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
  const a = await svc.logStep(O, { kind: "prompt", content: "Do it", log_level: "turn" }, BASE);
  const today = () => svc.store.anchorsToday(ownerKeyOf(O), new Date().toISOString().slice(0, 10));
  const spent = today();
  for (let i = 0; i < 6; i++) await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: `t${i}` } }, BASE);
  assert.equal(today(), spent, "the daily count doesn't move");
  assert.equal(fake.writes.length, 1);
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "end of turn" }, BASE);
  assert.equal(today(), spent + 1);
  const held = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "still fine" } }, BASE);
  assert.equal(held.anchor_status, "deferred", "the last anchor is kept for the close");
  assert.equal((await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE)).final_checkpoint.status, "anchored");
});

test("a bad level is refused and leaves no session behind", async () => {
  const { svc } = service();
  await assert.rejects(svc.logStep(O, { kind: "task", content: "x", log_level: "sometimes" }, BASE), (e) => e.code === "SHADOW_BAD_INPUT" && /log_level/.test(e.message));
  await assert.rejects(svc.startSession(O, { title: "t", log_level: 3 }, BASE), (e) => e.code === "SHADOW_BAD_INPUT" && /log_level/.test(e.message));
  assert.throws(() => svc.setLogLevel(O, "loud"), (e) => e.code === "SHADOW_BAD_INPUT" && /level/.test(e.message));
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

test("an old session has no hashed note: whatever its metadata holds, it reads as step and Not provided, and runs as step", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do it" }, BASE);
  assert.equal(serverNotes(svc, a.session_id).length, 0);
  const meta = metaOf(svc, a.session_id);
  // As the metadata of a session from the build before hashed notes could be.
  Object.assign(meta, { logLevel: "milestone", logLevelBy: "person" });
  meta.agents = meta.agents.map((x) => ({ ...x, purpose: "old purpose", accountableOwner: "old owner" }));
  delete meta.accountLevelSeen;
  svc.store.writeMeta(meta);
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.equal(got.log_level, "step");
  assert.equal(got.log_level_set_by, "account", "a stored person reads as the account");
  assert.deepEqual(got.agents, [{ id: "agent", role: null, purpose: "Not provided", accountable_owner: "Not provided" }]);
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "more" }, BASE);
  assert.equal(b.anchor_status, "anchored", "it runs as what it reads as");
  assert.match(await viewer(svc, a.session_id), /Logging level: step\./);
  svc.setLogLevel(O, "turn");
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "and more" }, BASE);
  assert.equal(serverNotes(svc, a.session_id).length, 0, "it never had a level to compare with");
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
  await svc.logStep(O, { session_id: s.session_id, kind: "task", agent: "researcher", content: "x" }, BASE);
  await svc.logStep(O, { session_id: s.session_id, kind: "message", agent: "researcher", content: "done" }, BASE);
  await svc.checkpoint(O, { session_id: s.session_id });
  await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
  const checked = await svc.verify(O, { session_id: s.session_id }, BASE);
  assert.equal(checked.result, "pass", JSON.stringify(checked.checks.filter((c) => c.status !== "pass")));
  assert.ok(fake.writes.length >= 5, "the start, both steps, a checkpoint and the close all reached the ledger");
  assert.doesNotMatch(said([fake.writes, fake.records]), /Ops team|Finds trial|finds sources/, "only hashes go to the ledger, after a whole session");
  const meta = svc.store.readMeta(ownerKeyOf(O), s.session_id);
  const html = (await svc.linkBody(meta.cap, "viewer")).toString();
  assert.match(html, /<h2>Session details<\/h2>/);
  assert.match(html, /Logging level: step/);
  assert.match(html, /Accountable owner/);
  assert.match(html, /Not provided/);
  assert.doesNotMatch(html.slice(html.indexOf("Session details"), html.indexOf("What this record shows")), /<b>the team/, "escaped");
});

test("the viewer escapes what an agent reports about itself, in the owner column too", async () => {
  const { svc } = service();
  const s = await svc.startSession(O, { title: "t", agents: [{ id: "a", purpose: "<i>x</i>", accountable_owner: "<img src=x onerror=alert(1)>" }] }, BASE);
  const html = await viewer(svc, s.session_id);
  const details = html.slice(html.indexOf("Session details"), html.indexOf("What this record shows"));
  assert.doesNotMatch(details, /<img|<i>/);
  assert.match(details, /&#60;img src=x onerror=alert\(1\)&#62;/);
});

test("an owner on its own is hashed and shown, a purpose on its own too", async () => {
  const { svc } = service();
  const s = await svc.startSession(O, { title: "t", agents: [{ id: "a", accountable_owner: "Ops team" }, { id: "b", purpose: "Writes it" }] }, BASE);
  assert.equal(serverNotes(svc, s.session_id).length, 1);
  assert.deepEqual(serverNotes(svc, s.session_id)[0].body.payload.server_note.agents, [{ agent: "a", accountable_owner: "Ops team" }, { agent: "b", purpose: "Writes it" }]);
  const got = await svc.getSession(O, { session_id: s.session_id }, BASE);
  assert.equal(got.agents[0].accountable_owner, "Ops team");
  assert.equal(got.agents[0].purpose, "Not provided");
  assert.equal(got.agents[1].purpose, "Writes it");
  assert.equal(got.agents[1].accountable_owner, "Not provided");
  assert.match(said(notes(svc, s.session_id)), /Agent a: purpose Not provided; accountable owner Ops team\./, "said in the note's words too");
  const alone = await svc.startSession(O, { title: "t", agents: [{ id: "a", accountable_owner: "Ops team" }] }, BASE);
  assert.match(said(notes(svc, alone.session_id)), /accountable owner Ops team/, "an owner with nothing else still gets a note");
  assert.equal((await svc.getSession(O, { session_id: alone.session_id }, BASE)).agents[0].accountable_owner, "Ops team");
});

test("agent fields are limited and redacted; a wrong type is ignored; hidden reasoning is refused before a session exists", async () => {
  const { svc } = service();
  const key = ["sk", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"].join("-");
  const s = await svc.startSession(O, { title: "t", agents: [{ id: "a", purpose: "p".repeat(500), accountable_owner: `owner ${key}` }, { id: "b", purpose: 7 }] }, BASE);
  assert.equal(s.agents[0].purpose.length <= 200, true);
  assert.equal(s.agents[0].accountable_owner.includes(key), false);
  const long = await svc.startSession(O, { title: "t", agents: [{ id: "a", accountable_owner: "o".repeat(500) }] }, BASE);
  assert.equal(long.agents[0].accountable_owner, "o".repeat(100), "an owner is 100 characters at most");
  assert.equal(s.agents[1].purpose, "Not provided");
  const before = (await svc.listSessions(O)).sessions.length;
  const refused = (e) => e.code === "SHADOW_REASONING_REFUSED";
  await assert.rejects(svc.startSession(O, { title: "t", agents: [{ id: "a", purpose: "<think>private</think>" }] }, BASE), refused);
  assert.equal((await svc.listSessions(O)).sessions.length, before);
});

test("the reasoning check reads a field's whole text, and covers purpose, owner, role and title", async () => {
  const { svc, fake } = service();
  const refused = (e) => e.code === "SHADOW_REASONING_REFUSED";
  const long = `<think ${"x".repeat(5000)}>`;
  for (const field of ["purpose", "accountable_owner", "role"]) {
    await assert.rejects(svc.startSession(O, { title: "t", agents: [{ id: "a", [field]: "<think>private</think>" }] }, BASE), refused, field);
    await assert.rejects(svc.startSession(O, { title: "t", agents: [{ id: "a", [field]: long }] }, BASE), refused, `${field}, with its > past any cut`);
  }
  await assert.rejects(svc.startSession(O, { title: "<think>private</think>" }, BASE), refused);
  await assert.rejects(svc.startSession(O, { title: long }, BASE), refused);
  await assert.rejects(svc.logStep(O, { title: long, kind: "task", content: "x" }, BASE), refused);
  await assert.rejects(svc.logTurn(O, { title: "</reasoning>", steps: [{ kind: "task", content: "x" }] }, BASE), refused);
  assert.equal((await svc.listSessions(O)).sessions.length, 0, "a refused field leaves no session");
  assert.equal(fake.writes.length, 0);
  const plain = await svc.startSession(O, { title: "We think < that > is fine", agents: [{ id: "a", purpose: "<thinker>" }] }, BASE);
  assert.ok(plain.session_id, "only the tags are refused");
  const t = performance.now();
  await assert.rejects(svc.startSession(O, { title: "<think ".repeat(150_000) + ">" }, BASE), refused);
  await svc.startSession(O, { title: "<think ".repeat(150_000) }, BASE);
  assert.ok(performance.now() - t < 1500, "linear on a 1 MB field");
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

// ---- item by item, each with the feature's failure in front of it ------------------------------------------------------

/** A milestone session with `calls` tool calls after its task, so most steps wait for the close. */
async function deferredSession(svc, calls = 20) {
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "milestone" }, BASE);
  for (let i = 0; i < calls; i++) await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: `t${i}` } }, BASE);
  return a.session_id;
}

const permanent = () => new ApiError("Clockchain API error (400)", 400);

function assertNotPass(v, html, { recorded, anchored }) {
  assert.equal(v.result, "indeterminate", v.summary);
  assert.equal(v.anchoring.recorded_steps, recorded);
  assert.equal(v.anchoring.anchored_steps, anchored);
  assert.equal(v.anchoring.unanchored_steps, recorded - anchored);
  assert.match(v.summary, new RegExp(`${anchored} of ${recorded} recorded steps`));
  for (const name of ["format", "content", "sequence", "membership", "signature", "trust", "anchors"]) assert.equal(check(v, name)?.status, "pass", name);
  assert.equal(check(v, "anchoring").status, "indeterminate");
  assert.equal(viewerResult(html), "indeterminate", "the viewer says what verify says");
  assert.match(html, new RegExp(`Anchoring: ${anchored} of ${recorded} recorded steps`));
}

test("verify and the viewer can't pass with a failed close anchor: 20 deferred steps, never anchored", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc);
  fake.failNextLog = permanent();
  const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "failed");
  assert.deepEqual({ ...closed.anchoring, reason: "" }, { recorded_steps: 21, anchored_steps: 1, unanchored_steps: 20, reason: "" });
  assert.match(closed.anchoring.reason, /20 of 21 recorded steps have no checkpoint/);
  assert.match(closed.anchoring.reason, /not anchored/);
  assertNotPass(await svc.verify(O, { session_id: id }, BASE), await viewer(svc, id), { recorded: 21, anchored: 1 });
  assert.equal((await svc.getSession(O, { session_id: id }, BASE)).anchoring.unanchored_steps, 20);
  assert.equal((await logJson(svc, id)).anchoring.unanchored_steps, 20);
  assert.match(await logText(svc, id), /20 of 21 recorded steps have no checkpoint/);
});

test("verify and the viewer can't pass with a pending close anchor, and pass once it lands", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc);
  fake.confirm = false;
  const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "pending");
  assert.equal(closed.anchoring.unanchored_steps, 20);
  assert.match(closed.anchoring.reason, /still waiting/);
  assertNotPass(await svc.verify(O, { session_id: id }, BASE), await viewer(svc, id), { recorded: 21, anchored: 1 });
  fake.confirm = true;
  fake.confirmPending();
  await svc.checkpoint(O, { session_id: id });
  const after = await svc.verify(O, { session_id: id }, BASE);
  assert.equal(after.result, "pass", after.summary);
  assert.equal(after.anchoring.unanchored_steps, 0);
  assert.equal(check(after, "anchoring"), undefined);
  assert.equal(viewerResult(await viewer(svc, id)), "pass");
});

test("the same with Clockchain down for the close, however many retries fail", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 50);
  fake.down = true;
  await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  for (let i = 0; i < 12; i++) await svc.checkpoint(O, { session_id: id });
  fake.down = false;
  assert.equal(metaOf(svc, id).outbox.find((r) => r.kind === "checkpoint").state, "failed");
  assertNotPass(await svc.verify(O, { session_id: id }, BASE), await viewer(svc, id), { recorded: 51, anchored: 1 });
});

test("verify can't pass at the session's anchor limit, when the close has no anchor either", async () => {
  const { svc } = service({ limits: { maxAnchorsPerSession: 1 } });
  const s = await svc.startSession(O, { title: "t", log_level: "milestone" }, BASE);
  await svc.logStep(O, { session_id: s.session_id, kind: "task", content: "go" }, BASE);
  for (let i = 0; i < 23; i++) await svc.logStep(O, { session_id: s.session_id, kind: "tool_call", content: { tool: `t${i}` } }, BASE);
  const closed = await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "not_anchored");
  assert.match(closed.final_checkpoint.reason, /used all 1 of its anchors/);
  assertNotPass(await svc.verify(O, { session_id: s.session_id }, BASE), await viewer(svc, s.session_id), { recorded: 24, anchored: 0 });
});

test("a step-level session whose steps all have anchors keeps today's result with only the close anchor pending", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go", log_level: "step" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "done" }, BASE);
  fake.confirm = false;
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded", person_messages: 1 }, BASE);
  assert.equal(closed.final_checkpoint.status, "pending");
  assert.deepEqual({ ...closed.anchoring, reason: "" }, { recorded_steps: 2, anchored_steps: 2, unanchored_steps: 0, reason: "" }, "the closing steps and the count aren't recorded steps");
  const v = await svc.verify(O, { session_id: a.session_id }, BASE);
  assert.equal(v.result, "pass", v.summary);
  assert.equal(viewerResult(await viewer(svc, a.session_id)), "pass");
});

test("server notes aren't recorded steps, so a note after the last anchor can't hold a session back", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  svc.setLogLevel(O, "turn");
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "done" }, BASE);
  assert.equal(serverNotes(svc, a.session_id).length, 1);
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.deepEqual({ ...got.anchoring, reason: "" }, { recorded_steps: 2, anchored_steps: 2, unanchored_steps: 0, reason: "" });
});

test("listed paths report the counts and keep today's result", async () => {
  const { svc, fake } = service({ autoLog: false });
  const s = await svc.startSession(O, { title: "t", agents: [{ id: "a" }] }, BASE);
  await svc.record(O, { session_id: s.session_id, agent: "a", kind: "task", content: "x" });
  await svc.record(O, { session_id: s.session_id, agent: "a", kind: "message", content: "y" });
  fake.failNextLog = permanent();
  const closed = await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.anchoring.unanchored_steps, 2);
  const v = await svc.verify(O, { session_id: s.session_id }, BASE);
  assert.equal(v.result, "pass", "the result stays the verifier's here");
  assert.equal(v.anchoring.anchored_steps, 0);
  assert.equal(check(v, "anchoring"), undefined);
  const html = await viewer(svc, s.session_id);
  assert.equal(viewerResult(html), "pass");
  assert.match(html, /Anchoring: 0 of 2 recorded steps/);
  assert.equal((await svc.getSession(O, { session_id: s.session_id }, BASE)).anchoring.recorded_steps, 2);
});

test("shadow_record on an auto-log path says it wrote nothing to the ledger, and the counts cover it", async () => {
  for (const level of ["step", "turn", "milestone"]) {
    const { svc, fake } = service();
    const s = await svc.startSession(O, { title: "t", log_level: level }, BASE);
    const writes = fake.writes.length;
    const r = await svc.record(O, { session_id: s.session_id, agent: "agent", kind: "task", content: "x" });
    assert.equal(r.anchor_status, "deferred", level);
    assert.match(r.anchor_reason, /writes nothing to the ledger at any level/, level);
    assert.match(r.anchor_reason, /A later anchor covers this/, level);
    assert.equal(fake.writes.length, writes, `${level}: nothing was written`);
    assert.equal((await svc.getSession(O, { session_id: s.session_id }, BASE)).anchoring.unanchored_steps, 1, level);
    await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
    assert.equal((await svc.getSession(O, { session_id: s.session_id }, BASE)).anchoring.unanchored_steps, 0, level);
  }
  const off = service({ autoLog: false });
  const s = await off.svc.startSession(O, { title: "t" }, BASE);
  assert.equal("anchor_status" in await off.svc.record(O, { session_id: s.session_id, agent: "agent", kind: "note", content: "x" }), false, "as before where the person asks");
});

test("the account's level: no record says a person set it, and old stored values read as the account", async () => {
  const { svc } = service();
  const set = svc.setLogLevel(O, "turn");
  assert.doesNotMatch(said(set), /person/);
  const s = await svc.startSession(O, { title: "t" }, BASE);
  assert.equal(s.log_level_set_by, "account");
  const [start] = serverNotes(svc, s.session_id);
  assert.equal(start.body.payload.server_note.set_by, "account");
  const meta = metaOf(svc, s.session_id);
  assert.equal(meta.logLevelBy, "account");
  meta.logLevelBy = "person";
  svc.store.writeMeta(meta);
  assert.equal(metaOf(svc, s.session_id).logLevelBy, "account", "an old stored person reads as the account");
  assert.equal((await svc.getSession(O, { session_id: s.session_id }, BASE)).log_level_set_by, "account");
  const chose = await svc.startSession(O, { title: "t", log_level: "step" }, BASE);
  assert.equal((await svc.getSession(O, { session_id: chose.session_id }, BASE)).log_level, "step");
  const own = await svc.startSession(O, { title: "t", log_level: "turn" }, BASE);
  assert.equal((await svc.getSession(O, { session_id: own.session_id }, BASE)).log_level_set_by, "account", "tied: the account's");
});

test("a change to the account's level is noted on the session's next step, in either direction, even when nothing moves", async () => {
  const { svc, fake } = service();
  const s = await svc.startSession(O, { title: "t", log_level: "turn" }, BASE);
  await svc.logStep(O, { session_id: s.session_id, kind: "prompt", content: "hi" }, BASE);
  assert.equal(serverNotes(svc, s.session_id).length, 1, "only its start");
  svc.setLogLevel(O, "milestone"); // Coarser than the session: its level stays.
  const r = await svc.logStep(O, { session_id: s.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(r.anchor_status, "deferred");
  assert.equal(r.log_level, "turn");
  let note = serverNotes(svc, s.session_id).at(-1).body.payload;
  assert.deepEqual(note.server_note, { kind: "level_change", log_level: "turn", set_by: "agent", account_level: "milestone", previous_account_level: null });
  assert.match(note.content.text ?? note.content, /changed from none to milestone\. This session stays at turn/);
  await svc.logStep(O, { session_id: s.session_id, kind: "tool_call", content: { tool: "y" } }, BASE);
  assert.equal(serverNotes(svc, s.session_id).length, 2, "one note per change, not one per step");
  svc.setLogLevel(O, "turn"); // Finer than it was, the same as the session.
  await svc.record(O, { session_id: s.session_id, agent: "agent", kind: "note", content: "by shadow_record" });
  note = serverNotes(svc, s.session_id).at(-1).body.payload;
  assert.deepEqual(note.server_note, { kind: "level_change", log_level: "turn", set_by: "agent", account_level: "turn", previous_account_level: "milestone" });
  svc.setLogLevel(O, "step"); // Finer than the session: it moves.
  const moved = await svc.logStep(O, { session_id: s.session_id, kind: "tool_call", content: { tool: "z" } }, BASE);
  assert.equal(moved.anchor_status, "anchored");
  note = serverNotes(svc, s.session_id).at(-1).body.payload;
  assert.deepEqual(note.server_note, { kind: "level_change", log_level: "step", set_by: "account", account_level: "step", previous_account_level: "turn" });
  assert.match(moved.show_user, /Logging level: step\./, "a level that moved stays in the footer, even at step");
  const got = await svc.getSession(O, { session_id: s.session_id }, BASE);
  assert.equal(got.log_level_set_by, "account");
  assert.equal(got.log_level_changes.length, 3);
  assert.deepEqual(got.log_level_changes.at(-1), { seq: got.log_level_changes.at(-1).seq, from: "turn", to: "step", set_by: "account", account_level: "step" });
  await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
  const v = await svc.verify(O, { session_id: s.session_id }, BASE);
  assert.equal(v.result, "pass", v.summary);
  assert.equal(fake.writes.some((w) => /milestone|account/.test(JSON.stringify(w))), false, "none of it reaches the ledger");
});

test("the viewer and the summary show the changes, and keep the level line after a move to step", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go", log_level: "milestone" }, BASE);
  svc.setLogLevel(O, "step");
  await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  const html = await viewer(svc, a.session_id);
  assert.match(html, /Logging level: step\. During this session: at step \d+ this session moved from milestone to step, set by the account\./);
  const text = await logText(svc, a.session_id);
  assert.match(text, /Logging level: step\. Each anchor covers every step up to it\. During this session: at step \d+ this session moved from milestone to step/);
  const closed = await svc.startSession(O, { title: "plain" }, BASE);
  await svc.logStep(O, { session_id: closed.session_id, kind: "task", content: "go" }, BASE);
  assert.doesNotMatch(await logText(svc, closed.session_id), /Logging level/, "the default session says nothing");
  assert.equal((await logJson(svc, a.session_id)).log_level_changes[0].to, "step");
});

test("the viewer shows the level a milestone session really ran at", async () => {
  const { svc } = service();
  const id = await deferredSession(svc, 1);
  assert.match(await viewer(svc, id), /Logging level: milestone\./);
});

test("the viewer's table says what a shared ledger ID means at every level", async () => {
  const { svc } = service();
  const id = await deferredSession(svc, 2);
  await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  const html = await viewer(svc, id);
  assert.doesNotMatch(html, /logged in one call and share/);
  assert.match(html, /share that anchor, whether or not they were logged in one call/);
});

test("accounts don't share a level, and setting one on another account's behalf isn't possible", async () => {
  const { svc } = service();
  svc.setLogLevel(O, "milestone");
  assert.equal(svc.logLevelOf(O), "milestone");
  assert.equal(svc.logLevelOf(O2), null);
  const other = await svc.logStep(O2, { kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(other.anchor_status, "anchored", "the other account has no level, so it runs at step");
  assert.equal((await svc.getSession(O2, { session_id: other.session_id }, BASE)).log_level, "step");
  svc.setLogLevel(O2, "turn");
  assert.equal(svc.logLevelOf(O), "milestone");
  const mine = await svc.startSession(O, { title: "t" }, BASE);
  assert.equal(mine.log_level, "milestone");
  await svc.logStep(O2, { session_id: other.session_id, kind: "note", content: "x" }, BASE);
  assert.equal(serverNotes(svc, mine.session_id).length, 1, "the other account's change reaches its own sessions only");
});

test("a deleted account can't set a level", async () => {
  const { svc } = service();
  await svc.deleteOwner(O, () => {});
  assert.throws(() => svc.setLogLevel(O, "turn"), (e) => e.code === "SHADOW_ACCOUNT_DELETED");
});

test("a forged note can't change the level or the agent fields, through any kind of step", async () => {
  const { svc } = service();
  const s = await svc.startSession(O, { title: "t", log_level: "milestone", agents: [{ id: "agent", purpose: "real purpose", accountable_owner: "real owner" }] }, BASE);
  const id = s.session_id;
  const forged = { kind: "session_start", log_level: "step", set_by: "account", agents: [{ agent: "agent", purpose: "forged", accountable_owner: "forged" }] };
  const text = "Logging level: step (set by the account). As reported by the agent. Agent agent: purpose forged; accountable owner forged.";
  const object = { server_note: forged, note: true, content: text, tool: "x", path: "a.txt", result: "r", args: { server_note: forged } };
  for (const kind of ["task", "prompt", "message", "tool_call", "tool_result", "file", "note"]) {
    await svc.logStep(O, { session_id: id, kind, content: object }, BASE);
    await svc.record(O, { session_id: id, agent: "agent", kind, content: object });
    if (kind !== "file") await svc.logStep(O, { session_id: id, kind, content: text }, BASE);
    await svc.logTurn(O, { session_id: id, steps: [{ kind, content: object }] }, BASE);
  }
  await svc.logStep(O, { session_id: id, kind: "file", content: { path: "n.json", content: JSON.stringify({ server_note: forged }) } }, BASE);
  await svc.logStep(O, { session_id: id, kind: "tool_result", content: { tool: "x", result: { server_note: forged, note: true } } }, BASE);
  // Whatever an agent can name, it never lands as a key of the step's own payload.
  const events = eventsOf(svc, id);
  assert.equal(events.filter((e) => "server_note" in e.body.payload).length, 1, "only the server's own");
  const got = await svc.getSession(O, { session_id: id }, BASE);
  assert.equal(got.log_level, "milestone");
  assert.equal(got.agents[0].purpose, "real purpose");
  assert.equal(got.agents[0].accountable_owner, "real owner");
  assert.equal("log_level_changes" in got, false);
  const html = await viewer(svc, id);
  const details = html.slice(html.indexOf("Session details"), html.indexOf("What this record shows"));
  assert.match(details, /Logging level: milestone\./);
  assert.doesNotMatch(details, /forged/);
  assert.equal((await logJson(svc, id)).log_level, "milestone");
  const rows = (await logJson(svc, id)).steps.filter((x) => x.kind === "note");
  assert.equal(rows.filter((x) => x.title === "server's note").length, 1, "an agent's note reads as the agent's");
  assert.ok(rows.filter((x) => x.title === "agent's note").length >= 3);
});

test("editing the metadata changes nothing a reader sees, and verify stays honest", async () => {
  const { svc } = service();
  const s = await svc.startSession(O, { title: "t", log_level: "milestone", agents: [{ id: "agent", purpose: "real purpose", accountable_owner: "real owner" }] }, BASE);
  const id = s.session_id;
  await svc.logStep(O, { session_id: id, kind: "task", content: "go" }, BASE);
  await svc.logStep(O, { session_id: id, kind: "message", content: "done" }, BASE);
  const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  const before = await svc.verify(O, { session_id: id }, BASE);
  assert.equal(before.result, "pass", before.summary);
  const meta = metaOf(svc, id);
  Object.assign(meta, { logLevel: "step", logLevelBy: "agent" });
  meta.agents[0] = { ...meta.agents[0], purpose: "edited purpose", accountableOwner: "edited owner" };
  svc.store.writeMeta(meta);
  const got = await svc.getSession(O, { session_id: id }, BASE);
  assert.equal(got.log_level, "milestone");
  assert.equal(got.log_level_set_by, "agent");
  assert.equal(got.agents[0].purpose, "real purpose");
  assert.equal(got.agents[0].accountable_owner, "real owner");
  const html = await viewer(svc, id);
  assert.match(html, /Logging level: milestone\./);
  assert.match(html, /real owner/);
  assert.doesNotMatch(html, /edited owner|edited purpose/);
  assert.equal((await logJson(svc, id)).log_level, "milestone");
  assert.match(await logText(svc, id), /Logging level: milestone/);
  assert.equal((await svc.verify(O, { session_id: id }, BASE)).result, "pass");
  assert.equal(closed.anchoring.unanchored_steps, 0);
});

test("the footer reads the level from the record too", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go", log_level: "milestone" }, BASE);
  const meta = metaOf(svc, a.session_id);
  meta.logLevel = "turn";
  svc.store.writeMeta(meta);
  const r = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "m" }, BASE);
  assert.match(r.show_user, /Logging level: milestone\./);
  assert.equal(r.log_level, "milestone");
});

test("a crash during the start wait keeps the level and the agent fields, and the session carries on and verifies", async () => {
  const { svc: first, fake, stateDir } = service();
  // Clockchain never answers, and the process goes away with the call in flight.
  const log = fake.log;
  let reached;
  const asked = new Promise((r) => (reached = r));
  fake.log = () => { reached(); return new Promise(() => {}); };
  void first.startSession(O, { title: "t", log_level: "milestone", agents: [{ id: "a", purpose: "real purpose", accountable_owner: "real owner" }] }, BASE);
  await asked;
  fake.log = log;
  const id = first.store.sessionIds(ownerKeyOf(O))[0];
  const { svc } = service({ stateDir, ledger: () => fake });
  const notesNow = serverNotes(svc, id);
  assert.equal(notesNow.length, 1, "on disk before the wait");
  assert.equal(notesNow[0].body.seq, 2, "right after session.opened");
  assert.equal(metaOf(svc, id).outbox.filter((r) => r.kind === "start").length, 1, "the start marker is owed");
  const got = await svc.getSession(O, { session_id: id }, BASE);
  assert.equal(got.log_level, "milestone");
  assert.equal(got.agents[0].accountable_owner, "real owner");
  await svc.logStep(O, { session_id: id, kind: "task", agent: "a", content: "go" }, BASE);
  await svc.logStep(O, { session_id: id, kind: "message", agent: "a", content: "done" }, BASE);
  assert.equal(metaOf(svc, id).outbox.length, 0, "the start marker went on the next call");
  await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  const v = await svc.verify(O, { session_id: id }, BASE);
  assert.equal(v.result, "pass", v.summary);
  assert.equal(check(v, "anchors").status, "pass");
  assert.match(check(v, "anchors").reason, /The start marker and 2 checkpoint anchor/);
});

test("a crash at the worst moments of a start: before session.opened, and between it and its note", async () => {
  // Before anything reached the log: the next call opens the session and writes the note.
  const a = service();
  a.svc.appendStep = () => { throw new Error("process died"); };
  await a.svc.startSession(O, { title: "t", log_level: "turn", agents: [{ id: "a", purpose: "real purpose" }] }, BASE).catch(() => {});
  const early = a.svc.store.sessionIds(ownerKeyOf(O))[0];
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  const got = await b.svc.getSession(O, { session_id: early }, BASE);
  assert.equal(got.log_level, "turn");
  assert.equal(got.agents[0].purpose, "real purpose");
  assert.equal(serverNotes(b.svc, early).length, 1);
  await b.svc.logStep(O, { session_id: early, kind: "task", agent: "a", content: "go" }, BASE);
  await b.svc.logStep(O, { session_id: early, kind: "message", agent: "a", content: "done" }, BASE);
  await b.svc.close(O, { session_id: early, status: "succeeded" }, BASE);
  assert.equal((await b.svc.verify(O, { session_id: early }, BASE)).result, "pass");

  // session.opened on disk, nothing else, and metadata that doesn't know yet.
  const c = service();
  const s = await c.svc.startSession(O, { title: "t", log_level: "turn", agents: [{ id: "a", accountable_owner: "real owner" }] }, BASE);
  const meta = metaOf(c.svc, s.session_id);
  const path_ = c.svc.store.eventsPath(ownerKeyOf(O), s.session_id);
  const first = readFileSync(path_, "utf8").split("\n")[0];
  truncateSync(path_, Buffer.byteLength(first) + 1);
  Object.assign(meta, { seq: 0, head: null, eventsBytes: 0, outbox: [], anchors: [] });
  c.svc.store.writeMeta(meta);
  const d = service({ stateDir: c.stateDir, ledger: () => c.fake });
  const after = await d.svc.getSession(O, { session_id: s.session_id }, BASE);
  assert.equal(after.log_level, "turn");
  assert.equal(after.agents[0].accountable_owner, "real owner");
  assert.equal(serverNotes(d.svc, s.session_id).length, 1, "written once");
  assert.equal(metaOf(d.svc, s.session_id).outbox.filter((r) => r.kind === "start").length, 1);
  await d.svc.getSession(O, { session_id: s.session_id }, BASE);
  assert.equal(serverNotes(d.svc, s.session_id).length, 1, "and only once");
});

test("a crash after a change note, before its metadata, doesn't write the note twice", async () => {
  const { svc, fake, stateDir } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go", log_level: "milestone" }, BASE);
  const before = metaOf(svc, a.session_id);
  svc.setLogLevel(O, "turn");
  await svc.record(O, { session_id: a.session_id, agent: "agent", kind: "note", content: "x" });
  // The note and the step are on disk; the metadata is what it was.
  svc.store.writeMeta(before);
  const { svc: next } = service({ stateDir, ledger: () => fake });
  await next.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  const changes = serverNotes(next, a.session_id).filter((e) => e.body.payload.server_note.kind === "level_change");
  assert.equal(changes.length, 1);
  assert.equal(metaOf(next, a.session_id).logLevel, "turn");
});

test("a start with a note, on a failing or slow Clockchain, opens and owes its marker, as any other start", async () => {
  for (const outcome of ["failed", "pending"]) {
    const { svc, fake } = service();
    if (outcome === "failed") fake.down = true;
    else fake.confirm = false;
    const s = await svc.startSession(O, { title: "t", log_level: "turn" }, BASE);
    assert.equal(s.start_anchor.status, "pending", outcome);
    assert.equal(metaOf(svc, s.session_id).outbox.filter((r) => r.kind === "start").length, 1, outcome);
    fake.down = false;
    fake.confirm = true;
    fake.confirmPending();
    await svc.logStep(O, { session_id: s.session_id, kind: "task", content: "go" }, BASE);
    await svc.logStep(O, { session_id: s.session_id, kind: "message", content: "done" }, BASE);
    await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
    const v = await svc.verify(O, { session_id: s.session_id }, BASE);
    assert.equal(v.result, "pass", `${outcome}: ${v.summary}`);
  }
});

test("shadow_checkpoint can't spend the close's anchor, so the promise to deferred steps holds", async () => {
  const { svc, fake } = service({ limits: { maxAnchorsPerSession: 3 } });
  const id = await deferredSession(svc, 1);
  assert.equal(metaOf(svc, id).anchors.length, 2, "the start and the task");
  const cp = await svc.checkpoint(O, { session_id: id });
  assert.equal(cp.checkpoint.status, "not_anchored");
  assert.equal(cp.checkpoint.code, "SHADOW_LIMIT_SESSION_ANCHORS");
  assert.match(cp.checkpoint.reason, /last anchor is kept for the close/);
  const r = await svc.logStep(O, { session_id: id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(r.anchor_status, "deferred");
  assert.match(r.anchor_reason, /only the close can still anchor this/);
  assert.doesNotMatch(r.anchor_reason, /a checkpoint|next task/);
  const writes = fake.writes.length;
  const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "anchored");
  assert.equal(fake.writes.length, writes + 1);
  const v = await svc.verify(O, { session_id: id }, BASE);
  assert.equal(v.result, "pass", v.summary);
});

test("at the limit a turn session records the reply as not anchored, instead of leaving actions with no answer", async () => {
  const { svc, fake } = service({ limits: { maxAnchorsPerSession: 3 } });
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "turn" }, BASE);
  assert.equal(a.anchor_status, "anchored");
  const writes = fake.writes.length;
  const call = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.equal(call.anchor_status, "deferred");
  assert.match(call.anchor_reason, /only the close can still anchor this/);
  const reply = await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "Done" }, BASE);
  assert.equal(reply.anchor_status, "not_anchored");
  assert.equal(reply.block_height, null);
  assert.match(reply.anchor_reason, /last anchor is kept for the close/);
  assert.match(reply.show_user, /recorded, but it has no anchor so far/);
  assert.equal(fake.writes.length, writes, "no anchor was spent");
  const turn = await svc.logTurn(O, { session_id: a.session_id, steps: [{ kind: "tool_call", content: { tool: "y" } }, { kind: "message", content: "Again" }] }, BASE);
  assert.equal(turn.evidence.anchor_status, "not_anchored");
  assert.equal(turn.shared_anchor, false);
  assert.doesNotMatch(turn.anchor_note, /share one anchor/);
  assert.doesNotMatch(turn.show_user, /one shared anchor/);
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.equal(got.recorded_steps, 5, "every step is in the record");
  assert.equal(got.anchoring.unanchored_steps, 4);
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "anchored", "the close still has its anchor");
  assert.equal(closed.anchoring.unanchored_steps, 0);
});

test("a step-level session at the limit is still refused: every step there wants its own anchor", async () => {
  const { svc } = service({ limits: { maxAnchorsPerSession: 3 } });
  const a = await svc.logStep(O, { kind: "task", content: "Do it" }, BASE);
  await assert.rejects(svc.logStep(O, { session_id: a.session_id, kind: "message", content: "x" }, BASE), (e) => e.code === "SHADOW_LIMIT_SESSION_ANCHORS");
  assert.equal((await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE)).final_checkpoint.status, "anchored");
});

test("a deferred step's reason follows the state of things: outage, daily limit, and back to normal", async () => {
  const { svc, fake } = service({ limits: { maxAnchorsPerOwnerPerDay: 3 } });
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "milestone" }, BASE);
  const ok = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "a" } }, BASE);
  assert.match(ok.anchor_reason, /A later anchor covers this: the next task, a checkpoint or the close\./);
  fake.down = true;
  await svc.checkpoint(O, { session_id: a.session_id });
  const down = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "b" } }, BASE);
  assert.equal(down.anchor_status, "deferred");
  assert.match(down.anchor_reason, /Clockchain isn't taking anchors right now, so this stays unanchored unless a later anchor lands/);
  assert.doesNotMatch(down.anchor_reason, /covers this|the close/);
  fake.down = false;
  const back = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "c" } }, BASE);
  assert.match(back.anchor_reason, /A later anchor covers this/, "the retry landed");
  await svc.checkpoint(O, { session_id: a.session_id });
  const spent = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "d" } }, BASE);
  await svc.checkpoint(O, { session_id: a.session_id });
  const later = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "e" } }, BASE);
  assert.match(spent.anchor_reason + later.anchor_reason, /anchors for today are used up/);
  assert.equal(deferredReason("turn", { canAnchor: false, closeCanAnchor: false, blocked: null }).includes("no anchors left, so this stays unanchored"), true);
  assert.match(deferredReason("turn", { canAnchor: true, closeCanAnchor: true, blocked: "budget" }), /write budget is used up/);
  assert.match(deferredReason("turn", { canAnchor: true, closeCanAnchor: true, blocked: null }), /the turn's reply, a task, a checkpoint or the close/);
});

test("the close gets its anchor past a backlog", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 1);
  fake.down = true;
  for (let i = 0; i < 22; i++) {
    await svc.logStep(O, { session_id: id, kind: "tool_call", content: { tool: `b${i}` } }, BASE);
    await svc.checkpoint(O, { session_id: id });
  }
  const held = metaOf(svc, id).outbox.length;
  assert.equal(held, 20, "the queue is full");
  const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "pending", "queued, not refused");
  assert.equal(metaOf(svc, id).outbox.length, held + 1);
});

test("a viewer built during a failure doesn't outlive it: the cached page follows the row's state", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 1);
  fake.down = true;
  await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.match(await viewer(svc, id), /still waiting/);
  for (let i = 0; i < 12; i++) await svc.checkpoint(O, { session_id: id });
  assert.match(await viewer(svc, id), /was not anchored/);
});

test("idle close anchors a leveled session, and its steps are covered", async () => {
  let now = Date.parse("2026-11-06T00:00:00Z");
  for (const log_level of ["turn", "milestone"]) {
    const { svc, fake } = service({ now: () => new Date(now), limits: { idleCloseMs: 3_600_000 } });
    const a = await svc.logStep(O, { kind: "prompt", content: "Do it", log_level }, BASE);
    for (const tool of ["a", "b"]) await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool } }, BASE);
    const writes = fake.writes.length;
    now += 2 * 3_600_000;
    assert.equal(await svc.closeIdle(), 1, log_level);
    assert.equal(fake.writes.length, writes + 1, `${log_level}: the final checkpoint is anchored`);
    const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
    assert.equal(got.status, "closed");
    assert.equal(got.log_level, log_level);
    assert.deepEqual({ ...got.anchoring, reason: "" }, { recorded_steps: 3, anchored_steps: 3, unanchored_steps: 0, reason: "" });
  }
});

test("a step's result says log_level had no effect on an open session", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go", log_level: "turn" }, BASE);
  assert.equal("log_level_note" in a, false, "it set this session's level");
  const b = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" }, log_level: "step" }, BASE);
  assert.equal(b.anchor_status, "deferred");
  assert.match(b.log_level_note, /had no effect/);
  const c = await svc.logTurn(O, { session_id: a.session_id, log_level: "milestone", steps: [{ kind: "note", content: "x" }] }, BASE);
  assert.match(c.log_level_note, /had no effect/);
  assert.equal("log_level_note" in await svc.logStep(O, { session_id: a.session_id, kind: "note", content: "y" }, BASE), false);
});

test("footer counts leave out server notes, and the step limit stays exact", async () => {
  const { svc } = service({ limits: { maxStepsPerSession: 3 } });
  svc.setLogLevel(O, "turn");
  const s = await svc.startSession(O, { title: "t", agents: [{ id: "agent", purpose: "p" }] }, BASE);
  const a = await svc.logStep(O, { session_id: s.session_id, kind: "message", content: "one" }, BASE);
  assert.match(a.show_user, /1 step logged so far/, "the start note isn't a step");
  svc.setLogLevel(O, "step");
  const b = await svc.logStep(O, { session_id: s.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  assert.match(b.show_user, /2 steps logged so far/, "nor is a change note");
  svc.setLogLevel(O, "turn");
  await svc.record(O, { session_id: s.session_id, agent: "agent", kind: "note", content: "three" });
  await assert.rejects(svc.record(O, { session_id: s.session_id, agent: "agent", kind: "note", content: "four" }), (e) => e.code === "SHADOW_LIMIT_STEPS");
  await assert.rejects(svc.logStep(O, { session_id: s.session_id, kind: "note", content: "four" }, BASE), (e) => e.code === "SHADOW_LIMIT_STEPS");
  const got = await svc.getSession(O, { session_id: s.session_id }, BASE);
  assert.equal(got.recorded_steps, 3, "exactly the limit, with three server notes on top");
  assert.equal(serverNotes(svc, s.session_id).length, 3);
  const closed = await svc.close(O, { session_id: s.session_id, status: "succeeded", person_messages: 2 }, BASE);
  assert.equal(closed.anchoring.recorded_steps, 3, "nor is the count at close");
  assert.match(closed.summary, /3 steps: /);
  const log = await logJson(svc, s.session_id);
  assert.equal(log.totals.steps, 3);
  assert.equal(log.steps.filter((x) => x.title === "server's note").length, 3, "the list still shows them");
});

test("a rebuilt session counts the same steps", async () => {
  const { svc, fake, stateDir } = service();
  svc.setLogLevel(O, "turn");
  const s = await svc.startSession(O, { title: "t" }, BASE);
  await svc.logStep(O, { session_id: s.session_id, kind: "message", content: "one" }, BASE);
  const meta = metaOf(svc, s.session_id);
  meta.eventsBytes = 0; // As after a crash between an event and its metadata.
  svc.store.writeMeta(meta);
  const { svc: next } = service({ stateDir, ledger: () => fake });
  assert.equal((await next.getSession(O, { session_id: s.session_id }, BASE)).recorded_steps, 1);
});

test("a change note needs room as much as the step does: neither lands if the close would have no room", async () => {
  for (const write of ["logStep", "record"]) {
    const { svc } = service();
    const a = await svc.logStep(O, { kind: "note", content: "go", log_level: "milestone" }, BASE);
    const { seq } = metaOf(svc, a.session_id);
    // One step fits, and the note that is now due would take its place.
    svc.maxEvents = seq + 1 + 4;
    svc.setLogLevel(O, "turn");
    const step = write === "logStep"
      ? svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE)
      : svc.record(O, { session_id: a.session_id, agent: "agent", kind: "tool_call", content: { tool: "x" } });
    await assert.rejects(step, (e) => e.code === "SHADOW_LIMIT_STEPS", write);
    assert.equal(metaOf(svc, a.session_id).seq, seq, `${write}: nothing was written`);
    const closed = await svc.close(O, { session_id: a.session_id, person_messages: 0 }, BASE);
    assert.equal(closed.final_checkpoint.status, "anchored", `${write}: the close still fits`);
  }
});

test("a corrupt settings file: logging off and on doesn't clear the level, and readers keep refusing until one is set", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "level-corrupt-"));
  const { svc } = service({ stateDir });
  svc.setLogLevel(O, "turn");
  const file = findSettings(stateDir);
  rmSync(`${file}.bak`, { force: true });
  writeFileSync(file, "not json");
  assert.doesNotThrow(() => svc.setLogging(O, false));
  assert.doesNotThrow(() => svc.setLogging(O, true));
  assert.equal(svc.loggingEnabled(O), true);
  assert.throws(() => svc.logLevelOf(O), (e) => e.code === "SHADOW_UNAVAILABLE", "unknown, not none");
  await assert.rejects(svc.startSession(O, { title: "t" }, BASE), (e) => e.code === "SHADOW_UNAVAILABLE");
  svc.setLogLevel(O, "milestone");
  assert.equal(svc.logLevelOf(O), "milestone");
  assert.equal((await svc.startSession(O, { title: "t" }, BASE)).log_level, "milestone");
  assert.ok(statSync(file).size > 0);
});

test("a failed anchor older than the latest one is history: it doesn't read as an outage", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do it", log_level: "milestone" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "a" } }, BASE);
  fake.failNextLog = permanent();
  assert.equal((await svc.checkpoint(O, { session_id: a.session_id })).checkpoint.status, "failed");
  const during = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "b" } }, BASE);
  assert.match(during.anchor_reason, /isn't taking anchors right now/, "nothing has landed since");
  assert.equal((await svc.checkpoint(O, { session_id: a.session_id })).checkpoint.status, "anchored");
  const after = await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "c" } }, BASE);
  assert.match(after.anchor_reason, /A later anchor covers this/);
  assert.doesNotMatch(after.anchor_reason, /isn't taking anchors/);
});
