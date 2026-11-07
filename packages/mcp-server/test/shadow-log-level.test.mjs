// How much detail a session anchors, set for the account and by the agent for a session; and the default agent fields. A
// session runs at the finer of the two, budgets move only when an anchor really happens, and nothing a reader sees says a
// step is anchored, or that it will be, unless that is true. Level and agent details come from hashed server notes.
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ownerKeyOf } from "../dist/shadow/store.js";
import { ShadowService } from "../dist/shadow/service.js";
import { anchorsNow, deferredReason, effectiveLevel, finer, levelSetBy, LOG_LEVEL_HELP, LOG_LEVEL_HELP_ASKED } from "../dist/shadow/log-level.js";
import { stepFor } from "../dist/shadow/recorder.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { createLogBudget } from "../dist/budget.js";
import { ApiError, AuthError } from "@clockchain/core";
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
  assert.deepEqual({ ...closed.anchoring, reason: "" }, { recorded_steps: 21, anchored_steps: 1, unanchored_steps: 20, closing_steps: 2, closing_unanchored: 2, reason: "" });
  assert.match(closed.anchoring.reason, /20 of 21 recorded steps have no checkpoint/);
  assert.match(closed.anchoring.reason, /A checkpoint that was not anchored covers 22 of these 22/);
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
  assert.equal(metaOf(svc, id).outbox.filter((r) => r.kind === "checkpoint").length, 1);
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

test("a session's ending needs an anchor too: every step anchored, close pending, it reads indeterminate until the close lands", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go", log_level: "step" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "done" }, BASE);
  fake.confirm = false;
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded", person_messages: 1 }, BASE);
  assert.equal(closed.final_checkpoint.status, "pending");
  assert.deepEqual({ ...closed.anchoring, reason: "" }, { recorded_steps: 2, anchored_steps: 2, unanchored_steps: 0, closing_steps: 2, closing_unanchored: 2, reason: "" }, "the run's ending and session.closed, and not the count");
  assert.match(closed.anchoring.reason, /The session's ending \(2 steps: how runs ended, and the close\) has none\./);
  const v = await svc.verify(O, { session_id: a.session_id }, BASE);
  assert.equal(v.result, "indeterminate", v.summary);
  assert.doesNotMatch(v.summary, /every recorded run has an ending/);
  assert.match(v.summary, /2 of 2 recorded steps have a checkpoint.*how it ended isn't anchored/);
  assert.equal(check(v, "anchoring").status, "indeterminate");
  const html = await viewer(svc, a.session_id);
  assert.equal(viewerResult(html), "indeterminate");
  assert.doesNotMatch(html, /class="result[^<]*every recorded run has an ending/);
  fake.confirm = true;
  fake.confirmPending();
  await svc.checkpoint(O, { session_id: a.session_id });
  const after = await svc.verify(O, { session_id: a.session_id }, BASE);
  assert.equal(after.result, "pass", after.summary);
  assert.equal(after.anchoring.closing_unanchored, 0);
  assert.equal(viewerResult(await viewer(svc, a.session_id)), "pass");
});

test("a gap counts as an ending, and a session with no steps and a failed close doesn't pass", async () => {
  const gap = service();
  const a = await gap.svc.logStep(O, { kind: "task", content: "go" }, BASE);
  await gap.svc.logStep(O, { session_id: a.session_id, kind: "message", content: "done" }, BASE);
  gap.fake.confirm = false;
  const closed = await gap.svc.close(O, { session_id: a.session_id }, BASE);
  assert.equal(closed.anchoring.closing_steps, 2, "the coverage.gap and session.closed");
  assert.equal(closed.anchoring.closing_unanchored, 2);

  const { svc, fake } = service();
  const s = await svc.startSession(O, { title: "empty" }, BASE);
  fake.failNextLog = permanent();
  const empty = await svc.close(O, { session_id: s.session_id }, BASE);
  assert.equal(empty.final_checkpoint.status, "failed");
  assert.deepEqual({ ...empty.anchoring, reason: "" }, { recorded_steps: 0, anchored_steps: 0, unanchored_steps: 0, closing_steps: 1, closing_unanchored: 1, reason: "" });
  const v = await svc.verify(O, { session_id: s.session_id }, BASE);
  assert.equal(v.result, "indeterminate", v.summary);
  assert.equal(viewerResult(await viewer(svc, s.session_id)), "indeterminate");

  const fine = service();
  const t = await fine.svc.startSession(O, { title: "empty" }, BASE);
  const ok = await fine.svc.close(O, { session_id: t.session_id }, BASE);
  assert.match(ok.anchoring.reason, /No steps were recorded, and the session's ending is covered/);
  assert.equal((await fine.svc.verify(O, { session_id: t.session_id }, BASE)).result, "pass");
});

test("server notes aren't recorded steps, so a note after the last anchor can't hold a session back", async () => {
  const { svc } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  svc.setLogLevel(O, "turn");
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "done" }, BASE);
  assert.equal(serverNotes(svc, a.session_id).length, 1);
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.deepEqual({ ...got.anchoring, reason: "" }, { recorded_steps: 2, anchored_steps: 2, unanchored_steps: 0, closing_steps: 0, closing_unanchored: 0, reason: "" });
});

test("listed paths report the counts and keep today's result", async () => {
  const { svc, fake } = service({ autoLog: false });
  const s = await svc.startSession(O, { title: "t", agents: [{ id: "a" }] }, BASE);
  await svc.record(O, { session_id: s.session_id, agent: "a", kind: "task", content: "x" });
  await svc.record(O, { session_id: s.session_id, agent: "a", kind: "message", content: "y" });
  fake.failNextLog = permanent();
  const closed = await svc.close(O, { session_id: s.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.anchoring.unanchored_steps, 2);
  assert.equal(closed.anchoring.closing_unanchored, 2, "reported here too");
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
  fake.down = false;
  fake.failNextLog = permanent();
  await svc.checkpoint(O, { session_id: id });
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
    assert.deepEqual({ ...got.anchoring, reason: "" }, { recorded_steps: 3, anchored_steps: 3, unanchored_steps: 0, closing_steps: 1, closing_unanchored: 0, reason: "" });
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

// ---- second review ---------------------------------------------------------------------------------------------------

class Dead extends Error {}

/** A process that dies right after writing `kind`: nothing later reaches the disk. */
function dieAfter(svc, kind) {
  const append = svc.store.appendLine.bind(svc.store);
  svc.store.appendLine = (meta, line, max) => {
    append(meta, line, max);
    if (JSON.parse(line).body.kind !== kind) return;
    svc.store.appendLine = () => { throw new Dead(); };
    svc.store.writeMeta = () => { throw new Dead(); };
    throw new Dead();
  };
}

/** Holds the heavy gate with its queue full, as a crowd of link readers does. Returns the release. */
async function fillGate(svc) {
  let release;
  svc.heavy.run(() => new Promise((r) => (release = r))).catch(() => {});
  await new Promise((r) => setImmediate(r));
  for (let i = 0; i < 32; i++) svc.heavy.run(() => {}).catch(() => {});
  return release;
}

test("a close under load is refused whole or finishes whole: busy never leaves session.closed with no checkpoint", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 3);
  // Busy before the close starts: nothing is written, and a retry is a fresh close.
  const release = await fillGate(svc);
  const seq = metaOf(svc, id).seq;
  await assert.rejects(svc.close(O, { session_id: id, status: "succeeded" }, BASE), (e) => e.code === "SHADOW_BUSY");
  release();
  await new Promise((r) => setImmediate(r));
  assert.equal(metaOf(svc, id).seq, seq);
  assert.equal(metaOf(svc, id).state, "open");
  // Busy from the moment session.closed lands: the close already holds what it needs.
  const append = svc.store.appendLine.bind(svc.store);
  let free;
  svc.store.appendLine = (meta, line, max) => {
    append(meta, line, max);
    if (JSON.parse(line).body.kind === "session.closed") { svc.store.appendLine = append; for (let i = 0; i < 32; i++) svc.heavy.run(() => {}).catch(() => {}); free = true; }
  };
  const writes = fake.writes.length;
  const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.ok(free);
  assert.equal(closed.final_checkpoint.status, "anchored");
  assert.equal(fake.writes.length, writes + 1);
  assert.equal(closed.anchoring.unanchored_steps, 0);
});

test("a crash between session.closed and the final checkpoint: repair queues it, a retry of close finishes the job", async () => {
  const a = service();
  const id = await deferredSession(a.svc, 3);
  dieAfter(a.svc, "session.closed");
  await assert.rejects(a.svc.close(O, { session_id: id, status: "succeeded", person_messages: 1 }, BASE), (e) => e instanceof Dead);
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  const got = await b.svc.getSession(O, { session_id: id }, BASE);
  assert.equal(got.status, "closed");
  assert.equal(metaOf(b.svc, id).outbox.filter((r) => r.kind === "checkpoint").length, 1, "reconcile queued it");
  assert.equal(metaOf(b.svc, id).capture.person_messages_reported, 1, "and the count at close survives");
  const closed = await b.svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "anchored");
  assert.equal(closed.anchoring.unanchored_steps, 0);
  assert.equal(closed.anchoring.closing_unanchored, 0);
  assert.equal((await b.svc.verify(O, { session_id: id }, BASE)).result, "pass");
  await assert.rejects(b.svc.close(O, { session_id: id, status: "succeeded" }, BASE), (e) => e.code === "SHADOW_SESSION_CLOSED", "after that, a close is refused as before");
});

test("a session left closed with no final checkpoint and tidy metadata gets one from a retry, or from shadow_checkpoint", async () => {
  for (const retry of ["close", "checkpoint"]) {
    const { svc, fake } = service();
    const id = await deferredSession(svc, 3);
    fake.down = true;
    await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
    fake.down = false;
    // As an earlier build left it: closed, nothing queued, nothing to reconcile.
    const meta = metaOf(svc, id);
    meta.outbox = meta.outbox.filter((r) => r.kind !== "checkpoint");
    svc.store.writeMeta(meta);
    if (retry === "close") assert.equal((await svc.close(O, { session_id: id }, BASE)).final_checkpoint.status, "anchored");
    else await svc.checkpoint(O, { session_id: id });
    const got = await svc.getSession(O, { session_id: id }, BASE);
    assert.equal(got.anchoring.unanchored_steps, 0, retry);
    assert.equal(got.anchoring.closing_unanchored, 0, retry);
  }
});

test("a retry of a close that is still waiting tries again and reports, and one that failed for good is refused", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 1);
  fake.down = true;
  assert.equal((await svc.close(O, { session_id: id, status: "succeeded" }, BASE)).final_checkpoint.status, "pending");
  fake.down = false;
  assert.equal((await svc.close(O, { session_id: id, status: "succeeded" }, BASE)).final_checkpoint.status, "anchored");
  const other = service();
  const lost = await deferredSession(other.svc, 1);
  other.fake.failNextLog = permanent();
  assert.equal((await other.svc.close(O, { session_id: lost, status: "succeeded" }, BASE)).final_checkpoint.status, "failed");
  await assert.rejects(other.svc.close(O, { session_id: lost, status: "succeeded" }, BASE), (e) => e.code === "SHADOW_SESSION_CLOSED");
});

test("the packet wrapper and the viewer say what the verify command can't see, and the packet itself is untouched", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 3);
  fake.failNextLog = permanent();
  await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  const cap = metaOf(svc, id).cap;
  const wrapper = JSON.parse(await svc.packetForCap(cap));
  assert.deepEqual(Object.keys(wrapper), ["packet", "pin", "anchoring", "verify"]);
  assert.equal(wrapper.anchoring.anchored_steps, 1);
  assert.equal(wrapper.anchoring.recorded_steps, 4);
  assert.match(wrapper.verify, /shadow-verify packet\.json --pin pin\.json --online/);
  assert.match(wrapper.verify, /doesn't check anchoring/);
  assert.match(wrapper.verify, /1 of 4 recorded steps has a checkpoint with a Clockchain receipt, and 3 do not/);
  assert.match(wrapper.verify, /this server's own count and isn't signed\. It can be recounted from the packet's events/);
  assert.equal("anchoring" in wrapper.packet, false, "nothing new inside the packet");
  const offline = await verifyPacket(wrapper.packet, { pin: wrapper.pin });
  assert.equal(offline.result, "pass", "which is exactly what the caveat is for");
  assert.equal(offline.checks.some((c) => c.name === "anchoring"), false);
  const html = await viewer(svc, id);
  const after = html.slice(html.indexOf("How to verify this yourself"));
  assert.match(after, /shadow-verify packet\.json/);
  assert.match(after, /<p class="meta">This command doesn&#39;t check anchoring.*1 of 4 recorded steps has a checkpoint/);
  const listed = service({ autoLog: false });
  const s = await listed.svc.startSession(O, { title: "t" }, BASE);
  await listed.svc.record(O, { session_id: s.session_id, agent: "agent", kind: "note", content: "x" });
  assert.match(await viewer(listed.svc, s.session_id), /This command doesn&#39;t check anchoring/, "said on listed paths too");
  assert.equal(JSON.parse(await listed.svc.packetForCap(metaOf(listed.svc, s.session_id).cap)).anchoring.recorded_steps, 1);
});

test("the reason says how many steps a waiting checkpoint covers, and how many have nothing coming", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 2);
  fake.down = true;
  await svc.checkpoint(O, { session_id: id });
  for (const tool of ["x", "y", "z"]) await svc.logStep(O, { session_id: id, kind: "tool_call", content: { tool } }, BASE);
  const { reason } = (await svc.getSession(O, { session_id: id }, BASE)).anchoring;
  assert.match(reason, /5 of 6 recorded steps have no checkpoint/);
  assert.match(reason, /A checkpoint still waiting covers 2 of these 5/);
  assert.match(reason, /3 of these 5 have nothing on its way yet\./);
  const all = service();
  const whole = await deferredSession(all.svc, 2);
  all.fake.down = true;
  await all.svc.checkpoint(O, { session_id: whole });
  assert.doesNotMatch((await all.svc.getSession(O, { session_id: whole }, BASE)).anchoring.reason, /nothing on its way/);
});

test("a crash after the start note lands and before the metadata does: the start marker is still owed", async () => {
  const a = service();
  a.svc.store.writeMeta = () => { throw new Dead(); };
  await assert.rejects(a.svc.startSession(O, { title: "t", log_level: "milestone" }, BASE), (e) => e instanceof Dead);
  const id = a.svc.store.sessionIds(ownerKeyOf(O))[0];
  assert.equal(readFileSync(a.svc.store.eventsPath(ownerKeyOf(O), id), "utf8").trim().split("\n").length, 2, "session.opened and the note are on disk");
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  await b.svc.getSession(O, { session_id: id }, BASE);
  const rows = metaOf(b.svc, id).outbox.filter((r) => r.kind === "start");
  assert.equal(rows.length, 1, "seq is 2, and the row is there");
  assert.equal(rows[0].sendStarted, true, "it may have been written, so the ledger is searched first");
  assert.equal(serverNotes(b.svc, id).length, 1, "the note isn't written twice");
  await b.svc.logStep(O, { session_id: id, kind: "task", content: "go" }, BASE);
  await b.svc.logStep(O, { session_id: id, kind: "message", content: "done" }, BASE);
  await b.svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.ok(metaOf(b.svc, id).anchors.some((x) => x.marker === "start"));
  const v = await b.svc.verify(O, { session_id: id }, BASE);
  assert.equal(v.result, "pass", v.summary);
});

test("a crash during the repair of an interrupted start is repaired the same way", async () => {
  const a = service();
  a.svc.appendStep = () => { throw new Dead(); };
  await assert.rejects(a.svc.startSession(O, { title: "t", log_level: "turn" }, BASE), (e) => e instanceof Dead);
  const id = a.svc.store.sessionIds(ownerKeyOf(O))[0];
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  b.svc.store.writeMeta = () => { throw new Dead(); };
  await assert.rejects(b.svc.getSession(O, { session_id: id }, BASE), (e) => e instanceof Dead);
  const c = service({ stateDir: a.stateDir, ledger: () => a.fake });
  await c.svc.getSession(O, { session_id: id }, BASE);
  assert.equal(metaOf(c.svc, id).outbox.filter((r) => r.kind === "start").length, 1);
  assert.equal(serverNotes(c.svc, id).length, 1);
});

test("the server retries what a person-closed session owes, within the same limits", async () => {
  for (const limits of [{}, { idleCloseMs: 3_600_000 }]) {
    let now = Date.parse("2026-11-07T10:00:00Z");
    const { svc, fake } = service({ limits, now: () => new Date(now) });
    const id = await deferredSession(svc, 3);
    fake.down = true;
    assert.equal((await svc.close(O, { session_id: id, status: "succeeded" }, BASE)).final_checkpoint.status, "pending");
    assert.match((await svc.getSession(O, { session_id: id }, BASE)).anchoring.reason, /still waiting/);
    now += 3_600_000;
    await svc.closeIdle();
    assert.equal(metaOf(svc, id).outbox.length, 1, "still down");
    fake.down = false;
    now += 3_600_000;
    await svc.closeIdle();
    assert.equal(metaOf(svc, id).outbox.length, 0);
    const got = await svc.getSession(O, { session_id: id }, BASE);
    assert.equal(got.anchoring.unanchored_steps, 0);
    assert.equal(got.anchoring.closing_unanchored, 0);
    assert.equal((await svc.verify(O, { session_id: id }, BASE)).result, "pass");
  }
  const capped = service({ limits: { maxAnchorsPerOwnerPerDay: 2 } });
  const id = await deferredSession(capped.svc, 1);
  const closed = await capped.svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "pending", "today's anchors are gone");
  const writes = capped.fake.writes.length;
  await capped.svc.closeIdle();
  assert.equal(capped.fake.writes.length, writes, "the pass spends nothing past the day's limit");
  assert.equal(metaOf(capped.svc, id).outbox.length, 1);
});

test("the close's row goes first, and one anchor settles the rows it replaces", async () => {
  let t = new Date("2026-11-07T10:00:00Z");
  const { svc, fake } = service({ now: () => t, limits: { maxAnchorsPerOwnerPerDay: 3 } });
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "last of the day" } }, BASE);
  for (let i = 0; i < 4; i++) assert.equal((await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: `t${i}` } }, BASE)).anchor_status, "over_limit");
  const queued = metaOf(svc, a.session_id).outbox;
  assert.equal(queued.length, 4);
  assert.ok(queued.every((r) => r.attempts === 0), "our own limit: none was written");
  t = new Date("2026-11-08T10:00:00Z"); // A new day's allowance.
  const writes = fake.writes.length;
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "anchored");
  assert.equal(fake.writes.length, writes + 1, "one anchor, not five");
  assert.equal(metaOf(svc, a.session_id).outbox.length, 0, "rows never written are dropped");
  assert.equal(closed.anchoring.unanchored_steps, 0);
  const v = await svc.verify(O, { session_id: a.session_id }, BASE);
  assert.equal(v.result, "pass", v.summary);
});

test("at one anchor left, the close takes it, not the rows behind it", async () => {
  const { svc, fake } = service({ limits: { maxAnchorsPerOwnerPerDay: 3 } });
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  fake.degraded = true; // Refused before any write, and counted as an attempt.
  for (const tool of ["a", "b", "c"]) await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool } }, BASE);
  fake.degraded = false;
  assert.equal(metaOf(svc, a.session_id).outbox.length, 3);
  const closed = await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "anchored");
  assert.equal(closed.anchoring.unanchored_steps, 0);
  assert.equal(closed.anchoring.closing_unanchored, 0);
  const rows = metaOf(svc, a.session_id).outbox;
  assert.equal(rows.length, 0, "the pool refused before any write, so none of them can be on the ledger");
  await svc.closeIdle();
  assert.equal(fake.writes.length, 3, "and they are never paid for");
  assert.equal((await svc.verify(O, { session_id: a.session_id }, BASE)).result, "pass");
});

test("a replaced row whose write did land stays accounted for, so the online check doesn't fail on it", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "done" }, BASE);
  // The write lands, and the answer never comes back.
  const log = fake.log.bind(fake);
  fake.log = async (entry) => { await log(entry); fake.down = true; throw new TypeError("fetch failed"); };
  await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "x" } }, BASE);
  fake.log = log;
  fake.down = false;
  const written = metaOf(svc, a.session_id).outbox[0];
  assert.equal(written.sendStarted, true);
  assert.equal(fake.writes.filter((w) => w.assetHash === written.hash).length, 1);
  await svc.close(O, { session_id: a.session_id, status: "succeeded" }, BASE);
  assert.equal(metaOf(svc, a.session_id).outbox.find((r) => r.hash === written.hash).lastErrorCode, "superseded");
  assert.match(JSON.stringify((await svc.getSession(O, { session_id: a.session_id }, BASE)).pending_anchors), /A later anchor covers these steps/);
  const v = await svc.verify(O, { session_id: a.session_id }, BASE);
  assert.equal(check(v, "witness").status, "pass", check(v, "witness").reason);
  assert.equal(v.result, "pass", v.summary);
});

test("rows on an open session still go oldest first, and each is paid for", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  fake.down = true;
  for (const tool of ["a", "b"]) await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool } }, BASE);
  fake.down = false;
  const writes = fake.writes.length;
  await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool: "c" } }, BASE);
  assert.equal(fake.writes.length, writes + 3, "at the step level each call keeps its anchor");
  const counts = metaOf(svc, a.session_id).anchors.filter((x) => x.marker === "checkpoint").map((x) => x.count);
  assert.deepEqual(counts, [...counts].sort((x, y) => x - y));
});

test("the tag check is linear on content, and refuses exactly what the old expression did", () => {
  const oldTag = /<\/?(think|thinking|reasoning)\b[^>]*>/i;
  const refused = (text) => { try { stepFor("message", text); return false; } catch (e) { assert.equal(e.code, "SHADOW_REASONING_REFUSED"); return true; } };
  for (const text of ["<think>x</think>", "</reasoning>", "<THINK\n>", "a <thinking b='c'> d", "<think<think>", "<reasoning >", "> <think>", "<think", "think>", "<thinker>", "<reasons>", "< think>", "> <think", "<think-x>", "<think.x>", "a<b>c"])
    assert.equal(refused(text), oldTag.test(text), JSON.stringify(text));
  const t = performance.now();
  for (let i = 0; i < 28; i++) stepFor("message", "<think ".repeat(4600));
  const took = performance.now() - t;
  assert.ok(took < 400, `28 steps of 32 KB took ${Math.round(took)} ms`);
});

test("corrupt settings: setting a level is the way back on every path, and no message says more than is true", async () => {
  // Where the person asks: nothing but the level can reach the file.
  const listedDir = mkdtempSync(path.join(tmpdir(), "level-listed-"));
  const listed = service({ stateDir: listedDir, autoLog: false });
  listed.svc.setLogLevel(O, "turn");
  const file = findSettings(listedDir);
  rmSync(`${file}.bak`, { force: true });
  writeFileSync(file, "not json");
  await assert.rejects(listed.svc.startSession(O, { title: "t" }, BASE), (e) => e.code === "SHADOW_UNAVAILABLE" && /ask the person whether to set the account's level/.test(e.message));
  const reset = listed.svc.setLogLevel(O, "milestone", false);
  assert.equal(reset.settings_reset, true);
  assert.match(reset.message, /couldn't be read, so they were reset, and sessions can start again/);
  assert.equal((await listed.svc.startSession(O, { title: "t" }, BASE)).log_level, "milestone");
  assert.equal(listed.svc.setLogLevel(O, "turn", false).settings_reset, undefined, "said once");

  // Where logging is on by default: "off" must not turn back on by itself.
  const autoDir = mkdtempSync(path.join(tmpdir(), "level-auto-"));
  const auto = service({ stateDir: autoDir });
  auto.svc.setLogging(O, false);
  const autoFile = findSettings(autoDir);
  rmSync(`${autoFile}.bak`, { force: true });
  writeFileSync(autoFile, "not json");
  const back = auto.svc.setLogLevel(O, "turn");
  assert.match(back.message, /logging is off until clockchain_logging turns it back on/);
  assert.equal(auto.svc.loggingEnabled(O), false);
  await assert.rejects(auto.svc.logStep(O, { kind: "note", content: "x" }, BASE), (e) => e.code === "LOGGING_OFF");
  assert.equal(auto.svc.setLogging(O, true).logging.enabled, true);
  assert.equal((await auto.svc.logStep(O, { kind: "note", content: "x" }, BASE)).log_level, "turn");

  // Logging turned on while the level is unknown: steps stay refused, and the message says so.
  const onDir = mkdtempSync(path.join(tmpdir(), "level-on-"));
  const on = service({ stateDir: onDir });
  on.svc.setLogLevel(O, "turn");
  const onFile = findSettings(onDir);
  rmSync(`${onFile}.bak`, { force: true });
  writeFileSync(onFile, "not json");
  on.svc.setLogging(O, false);
  const said_ = on.svc.setLogging(O, true);
  assert.deepEqual(said_.logging, { enabled: true, level_readable: false });
  assert.match(said_.message, /steps are still refused\. Ask the person whether to set the account's level/);
  assert.doesNotMatch(said_.message, /logged from now on/);
  await assert.rejects(on.svc.logStep(O, { kind: "note", content: "x" }, BASE), (e) => e.code === "SHADOW_UNAVAILABLE");
  on.svc.setLogLevel(O, "step");
  assert.match(on.svc.setLogging(O, true).message, /logged from now on/);
  assert.equal((await on.svc.logStep(O, { kind: "note", content: "x" }, BASE)).anchor_status, "anchored");
});

test("small truths: the refusal's count, logging off's wording, and shadow_record on a listed endpoint of a server with the preview flag", async () => {
  const { svc } = service({ limits: { maxAnchorsPerSession: 3 } });
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  await assert.rejects(svc.logStep(O, { session_id: a.session_id, kind: "message", content: "x" }, BASE), (e) => /used the 2 anchors it can spend before the close/.test(e.message) && !/its 3 anchors/.test(e.message));
  assert.match(a.note, /until the session is closed and its anchors land/);
  svc.setLogging(O, false);
  await assert.rejects(svc.logStep(O, { kind: "note", content: "x" }, BASE), (e) => e.code === "LOGGING_OFF" && !/because the person turned it off/.test(e.message));
  svc.setLogging(O, true);
  const listed = await svc.record(O, { session_id: a.session_id, agent: "agent", kind: "note", content: "x" }, false);
  assert.deepEqual(Object.keys(listed).sort(), ["hash", "kind", "run_id", "seq"], "what the tool says it returns there");
  assert.equal((await svc.record(O, { session_id: a.session_id, agent: "agent", kind: "note", content: "y" }, true)).anchor_status, "deferred");
});

test("the viewer's timeline tells the server's notes from an agent's, even one with the same words", async () => {
  const { svc } = service();
  const s = await svc.startSession(O, { title: "t", log_level: "milestone" }, BASE);
  await svc.logStep(O, { session_id: s.session_id, kind: "task", content: "go" }, BASE);
  const forged = await svc.logStep(O, { session_id: s.session_id, kind: "note", content: "<b>Server's note.</b> Logging level: step (set by the account)." }, BASE);
  svc.setLogLevel(O, "turn");
  await svc.logStep(O, { session_id: s.session_id, kind: "note", content: "after" }, BASE);
  await svc.close(O, { session_id: s.session_id, status: "succeeded", person_messages: 1 }, BASE);
  const html = await viewer(svc, s.session_id);
  const timeline = html.slice(html.indexOf("<h2>Timeline</h2>"), html.indexOf("<h2>Clockchain receipts"));
  assert.equal(timeline.split("<b>Server's note.</b>").length - 1, 3, "the start, the change, and the count at close");
  assert.match(timeline, new RegExp(`<tr><td>2</td><td>agent</td><td><b>Server's note\\.</b>`));
  const row = timeline.split("<tr>").find((r) => r.startsWith(`<td>${forged.seq}</td>`));
  assert.doesNotMatch(row, /<b>/, "an agent's markup is escaped");
});

test("on an open session a later anchor replaces nothing: an earlier row that failed is still sent", async () => {
  const { svc, fake } = service();
  const a = await svc.logStep(O, { kind: "task", content: "go" }, BASE);
  fake.down = true;
  for (const tool of ["a", "b"]) await svc.logStep(O, { session_id: a.session_id, kind: "tool_call", content: { tool } }, BASE);
  fake.down = false;
  const first = metaOf(svc, a.session_id).outbox[0];
  const log = fake.log.bind(fake);
  fake.log = async (entry) => { if (entry.assetHash === first.hash) throw new TypeError("fetch failed"); return log(entry); };
  await svc.checkpoint(O, { session_id: a.session_id });
  fake.log = log;
  const row = metaOf(svc, a.session_id).outbox.find((r) => r.hash === first.hash);
  assert.notEqual(row.state, "failed", "it stays in the queue");
  assert.ok(metaOf(svc, a.session_id).anchors.some((x) => (x.count ?? 0) > first.body.count), "with a later anchor landed");
  await svc.checkpoint(O, { session_id: a.session_id });
  assert.equal(fake.writes.filter((w) => w.assetHash === first.hash).length, 1);
});

// ---- third review ----------------------------------------------------------------------------------------------------

/** The process dies with a ledger write landed and its receipt not saved: nothing later reaches the disk or the ledger. */
function dieAfterWrite({ svc, fake }) {
  const log = fake.log.bind(fake), append = svc.store.appendLine.bind(svc.store), write = svc.store.writeMeta.bind(svc.store);
  let dead = false;
  fake.log = async (entry) => { await log(entry); dead = true; throw new Dead(); };
  svc.store.appendLine = (...a) => { if (dead) throw new Dead(); return append(...a); };
  svc.store.writeMeta = (...a) => { if (dead) throw new Dead(); return write(...a); };
  return () => { fake.log = log; };
}

const refuseSearch = (fake) => { fake.searchAsset = async () => { throw new AuthError("no", 401); }; };
const allowSearch = (fake) => { delete fake.searchAsset; };

test("a crash after a ledger write, before its receipt, then the close: the row stays accounted for, and verify doesn't fail", async () => {
  for (const how of ["close", "idle"]) {
    let now = Date.parse("2026-11-07T10:00:00Z");
    const o = { now: () => new Date(now), limits: { idleCloseMs: 3_600_000 } };
    const a = service(o);
    const id = await deferredSession(a.svc, 3);
    const restore = dieAfterWrite(a);
    await a.svc.checkpoint(O, { session_id: id }).catch(() => {});
    restore();
    const rowHash = metaOf(a.svc, id).outbox[0].hash;
    assert.equal(metaOf(a.svc, id).outbox[0].sendStarted, true, "saved before the network call");
    assert.equal(metaOf(a.svc, id).outbox[0].attempts, 0, "and nothing else says it was sent");
    const b = service({ ...o, stateDir: a.stateDir, ledger: () => a.fake });
    if (how === "close") await b.svc.close(O, { session_id: id, status: "succeeded" }, BASE);
    else { now += 2 * 3_600_000; await b.svc.closeIdle(); }
    assert.equal(a.fake.writes.filter((w) => w.assetHash === rowHash).length, 1, `${how}: not paid twice`);
    const v = await b.svc.verify(O, { session_id: id }, BASE);
    assert.equal(check(v, "witness").status, "pass", `${how}: ${check(v, "witness").reason}`);
    assert.notEqual(v.result, "fail", v.summary);
    const packet = JSON.parse(await b.svc.packetForCap(metaOf(b.svc, id).cap)).packet;
    assert.ok(packet.pendingCheckpoints.some((p) => p.hash === rowHash), `${how}: the packet accounts for it`);
  }
});

test("the mark is on disk before the network call, and it stops the crash double pay", async () => {
  const a = service();
  const id = await deferredSession(a.svc, 1);
  const log = a.fake.log.bind(a.fake);
  let seen;
  a.fake.log = async (e) => { seen = metaOf(a.svc, id).outbox.find((r) => r.hash === e.assetHash)?.sendStarted; return log(e); };
  await a.svc.checkpoint(O, { session_id: id });
  a.fake.log = log;
  assert.equal(seen, true);
  const restore = dieAfterWrite(a);
  await a.svc.logStep(O, { session_id: id, kind: "task", content: "again" }, BASE).catch(() => {});
  restore();
  const hash = metaOf(a.svc, id).outbox[0].hash;
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  await b.svc.checkpoint(O, { session_id: id });
  assert.equal(a.fake.writes.filter((w) => w.assetHash === hash).length, 1, "the ledger was asked, and the record adopted");
  assert.equal(metaOf(b.svc, id).outbox.length, 0);
  assert.ok(metaOf(b.svc, id).anchors.some((x) => x.hash === hash));
});

test("a start interrupted after its write isn't paid for twice, with or without a note", async () => {
  for (const input of [{ title: "t" }, { title: "t", log_level: "turn" }]) {
    const a = service();
    dieAfterWrite(a);
    await a.svc.startSession(O, input, BASE).catch(() => {});
    a.fake.log = FakeLedger.prototype.log.bind(a.fake);
    const id = a.svc.store.sessionIds(ownerKeyOf(O))[0];
    const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
    await b.svc.logStep(O, { session_id: id, kind: "task", content: "go" }, BASE);
    const { startHash } = metaOf(b.svc, id);
    assert.equal(a.fake.writes.filter((w) => w.assetHash === startHash).length, 1, JSON.stringify(input));
    assert.ok(metaOf(b.svc, id).anchors.some((x) => x.marker === "start"));
  }
});

test("what can't have been written loses its mark, what may have keeps it, through our own limits too", async () => {
  // Refused before any write: no mark, so no search, and a later anchor can drop it.
  const a = service();
  const id = await deferredSession(a.svc, 1);
  a.fake.degraded = true;
  await a.svc.checkpoint(O, { session_id: id });
  a.fake.degraded = false;
  assert.equal(metaOf(a.svc, id).outbox[0].sendStarted, false);
  refuseSearch(a.fake);
  await a.svc.checkpoint(O, { session_id: id });
  assert.equal(metaOf(a.svc, id).outbox.length, 0, "sent with no search needed");

  // Written, then the retry stops at the day's limit: its attempts stay at 0 and it may still be on the ledger.
  const b = service({ limits: { maxAnchorsPerOwnerPerDay: 3 } });
  const sid = await deferredSession(b.svc, 1); // The start and the task spend two.
  const restore = dieAfterWrite(b); // The third.
  await b.svc.checkpoint(O, { session_id: sid }).catch(() => {});
  restore();
  // The dying call's refund ran here, as a real crash's wouldn't, so the limit comes down to what a crash would leave.
  const c = service({ stateDir: b.stateDir, ledger: () => b.fake, limits: { maxAnchorsPerOwnerPerDay: 2 } });
  b.fake.searchAsset = async () => [];
  await c.svc.checkpoint(O, { session_id: sid });
  const [row] = metaOf(c.svc, sid).outbox;
  assert.equal(row.lastErrorCode, "anchor_limit");
  assert.equal(row.attempts, 0);
  assert.equal(row.sendStarted, true);
});

test("a row from before the mark counts as maybe written", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 1);
  fake.down = true;
  await svc.checkpoint(O, { session_id: id });
  fake.down = false;
  const meta = metaOf(svc, id);
  delete meta.outbox[0].sendStarted;
  meta.outbox[0].attempts = 0;
  svc.store.writeMeta(meta);
  const { hash } = meta.outbox[0];
  await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  const row = metaOf(svc, id).outbox.find((r) => r.hash === hash);
  assert.equal(row?.lastErrorCode, "superseded", "kept, and never paid");
  assert.equal(fake.writes.filter((w) => w.assetHash === hash).length, 0);
});

test("a row from before the mark is searched for before it is paid for", async () => {
  const a = service();
  const id = await deferredSession(a.svc, 1);
  const restore = dieAfterWrite(a);
  await a.svc.checkpoint(O, { session_id: id }).catch(() => {});
  restore();
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  const meta = metaOf(b.svc, id);
  const { hash } = meta.outbox[0];
  delete meta.outbox[0].sendStarted;
  b.svc.store.writeMeta(meta);
  await b.svc.checkpoint(O, { session_id: id });
  assert.equal(a.fake.writes.filter((w) => w.assetHash === hash).length, 1);
  assert.ok(metaOf(b.svc, id).anchors.some((x) => x.hash === hash), "adopted");
});

test("a ledger that refuses search: an interrupted row isn't paid blindly, doesn't fail, and blocks nothing", async () => {
  const a = service();
  const id = await deferredSession(a.svc, 2);
  const restore = dieAfterWrite(a);
  await a.svc.checkpoint(O, { session_id: id }).catch(() => {});
  restore();
  const hash = metaOf(a.svc, id).outbox[0].hash;
  let searches = 0;
  a.fake.searchAsset = async () => { searches++; throw new AuthError("no", 401); };
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  const waiting = await b.svc.logStep(O, { session_id: id, kind: "tool_call", content: { tool: "w" } }, BASE);
  assert.match(waiting.anchor_reason, /A later anchor covers this/, "a refused search isn't an outage");
  assert.equal(searches, 1);
  // The next anchor goes straight past it, and the row isn't asked about again until it is due.
  const next = await b.svc.logStep(O, { session_id: id, kind: "task", content: "more" }, BASE);
  assert.equal(next.anchor_status, "anchored");
  assert.equal(searches, 1, "it backs off");
  const parked = metaOf(b.svc, id).outbox.find((r) => r.hash === hash);
  assert.equal(parked.state, "queued");
  assert.equal(parked.lastErrorCode, "search_refused");
  assert.equal(a.fake.writes.filter((w) => w.assetHash === hash).length, 1, "not paid again");
  assert.match(JSON.stringify((await b.svc.getSession(O, { session_id: id }, BASE)).pending_anchors), /refused the search that would show it/);
  await b.svc.logStep(O, { session_id: id, kind: "tool_call", content: { tool: "x" } }, BASE);
  const closed = await b.svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "anchored", "the close isn't held up");
  assert.equal(closed.anchoring.unanchored_steps, 0);
  assert.equal(closed.anchoring.closing_unanchored, 0);
  assert.equal(metaOf(b.svc, id).outbox.find((r) => r.hash === hash).lastErrorCode, "superseded");
  // What the session reads as while search stays refused.
  const v = await b.svc.verify(O, { session_id: id }, BASE);
  assert.equal(v.result, "indeterminate");
  assert.equal(check(v, "witness").status, "indeterminate");
  assert.match(check(v, "witness").reason, /could not be reached for every receipt/);
  assert.deepEqual(v.checks.filter((c) => c.status === "fail"), []);
  assert.equal(check(v, "anchoring"), undefined, "no anchoring gap");
  assert.equal(viewerResult(await viewer(b.svc, id)), "pass", "the viewer checks offline");
  allowSearch(a.fake);
  const healthy = await b.svc.verify(O, { session_id: id }, BASE);
  assert.equal(healthy.result, "pass", "and the kept row accounts for the record the search then finds");
});

test("the close's own row, interrupted with search refused, stays honest and settles when search comes back", async () => {
  const a = service();
  const id = await deferredSession(a.svc, 2);
  const restore = dieAfterWrite(a);
  await a.svc.close(O, { session_id: id, status: "succeeded" }, BASE).catch(() => {});
  restore();
  const hash = metaOf(a.svc, id).outbox.find((r) => r.kind === "checkpoint").hash;
  refuseSearch(a.fake);
  const b = service({ stateDir: a.stateDir, ledger: () => a.fake });
  const retry = await b.svc.close(O, { session_id: id }, BASE);
  assert.equal(retry.final_checkpoint.status, "pending");
  assert.match(retry.final_checkpoint.reason, /refused the search/);
  assert.equal(a.fake.writes.filter((w) => w.assetHash === hash).length, 1);
  const v = await b.svc.verify(O, { session_id: id }, BASE);
  assert.equal(v.result, "indeterminate");
  assert.match(v.anchoring.reason, /A checkpoint still waiting covers 4 of these 4: It may already be on Clockchain/);
  allowSearch(a.fake);
  assert.equal((await b.svc.close(O, { session_id: id }, BASE)).final_checkpoint.status, "anchored", "adopted, not paid again");
  assert.equal(a.fake.writes.filter((w) => w.assetHash === hash).length, 1);
  assert.equal((await b.svc.verify(O, { session_id: id }, BASE)).result, "pass");
});

test("hours of outage don't end a close's row: it backs off, the ledger's return lands it, and a person's retry needn't wait", async () => {
  for (const back of ["pass", "close", "checkpoint"]) {
    let now = Date.parse("2026-11-07T10:00:00Z");
    const { svc, fake } = service({ now: () => new Date(now) });
    const id = await deferredSession(svc, 2);
    fake.down = true;
    await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
    for (let hour = 0; hour < 72; hour++) { now += 3_600_000; await svc.closeIdle(); }
    const [row] = metaOf(svc, id).outbox;
    assert.notEqual(row.state, "failed", "three days on, past the ten passes an open session gets");
    assert.ok(row.attempts > 10 && row.attempts < 20, `it backed off: ${row.attempts} tries in 72 hours`);
    fake.down = false;
    if (back === "pass") { now += 6 * 3_600_000; await svc.closeIdle(); }
    else if (back === "close") assert.equal((await svc.close(O, { session_id: id }, BASE)).final_checkpoint.status, "anchored");
    else await svc.checkpoint(O, { session_id: id });
    assert.equal(metaOf(svc, id).outbox.length, 0, back);
    assert.equal((await svc.verify(O, { session_id: id }, BASE)).result, "pass", back);
  }
});

test("a pool or credit failure backs off the same way, and a row a pass isn't due for is left alone", async () => {
  let now = Date.parse("2026-11-07T10:00:00Z");
  const { svc, fake } = service({ now: () => new Date(now) });
  const id = await deferredSession(svc, 1);
  fake.degraded = true;
  await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  const after = metaOf(svc, id).outbox[0];
  assert.ok(Date.parse(after.nextTryAt) > now);
  await svc.closeIdle();
  assert.equal(metaOf(svc, id).outbox[0].attempts, after.attempts, "not due yet");
  now = Date.parse(after.nextTryAt);
  await svc.closeIdle();
  assert.equal(metaOf(svc, id).outbox[0].attempts, after.attempts + 1, "due");
});

test("a row an earlier build gave up on is brought back by a person's retry, unless the refusal was permanent", async () => {
  for (const [retry, kind, code, lands] of [["close", "Transient", "network", true], ["checkpoint", "Auth", "http_401", true], ["checkpoint", "Permanent", "http_400", false]]) {
    const { svc, fake } = service();
    const id = await deferredSession(svc, 1);
    fake.down = true;
    await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
    fake.down = false;
    const meta = metaOf(svc, id);
    Object.assign(meta.outbox[0], { state: "failed", lastErrorKind: kind, lastErrorCode: code, attempts: 10 });
    svc.store.writeMeta(meta);
    if (retry === "close") assert.equal((await svc.close(O, { session_id: id }, BASE)).final_checkpoint.status, "anchored");
    else await svc.checkpoint(O, { session_id: id });
    assert.equal(metaOf(svc, id).outbox.length === 0, lands, `${kind}`);
    assert.equal((await svc.verify(O, { session_id: id }, BASE)).result, lands ? "pass" : "indeterminate", kind);
  }
});

test("an open session's row still gives up after its passes, as before", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 1);
  fake.down = true;
  for (let i = 0; i < 11; i++) await svc.checkpoint(O, { session_id: id });
  assert.equal(metaOf(svc, id).outbox[0].state, "failed");
});

test("a pin given before the close's anchor lands says it will change, and where the current one is", async () => {
  const { svc, fake } = service();
  const id = await deferredSession(svc, 1);
  fake.confirm = false;
  const closed = await svc.close(O, { session_id: id, status: "succeeded" }, BASE);
  assert.equal(closed.final_checkpoint.status, "pending");
  assert.match(closed.pin_note, /the pin changes when it lands/);
  assert.match(closed.pin_note, /shadow_get_session and the packet link give the current one/);
  assert.match((await svc.getSession(O, { session_id: id }, BASE)).pin_note, /the pin changes when it lands/);
  assert.match(await viewer(svc, id), /the pin changes when it lands/);
  fake.confirm = true;
  fake.confirmPending();
  await svc.closeIdle();
  assert.equal(metaOf(svc, id).outbox.length, 0, "the server lands it unprompted");
  const got = await svc.getSession(O, { session_id: id }, BASE);
  assert.equal("pin_note" in got, false);
  assert.doesNotMatch(await viewer(svc, id), /the pin changes when it lands/);
  assert.notEqual(got.pin.checkpointHash, closed.pin.checkpointHash, "the note was true");
  const { packet } = JSON.parse(await svc.packetForCap(metaOf(svc, id).cap));
  assert.equal((await verifyPacket(packet, { pin: closed.pin })).checks.find((c) => c.name === "trust").status, "fail");
  assert.equal((await verifyPacket(packet, { pin: got.pin })).checks.find((c) => c.name === "trust").status, "pass");
  const plain = service();
  const other = await deferredSession(plain.svc, 1);
  assert.equal("pin_note" in await plain.svc.close(O, { session_id: other, status: "succeeded" }, BASE), false);
});

test("a corrupt main settings file doesn't fall back to an older .bak: logging that was turned off stays off", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "level-bak-"));
  const { svc } = service({ stateDir });
  svc.setLogging(O, true);
  svc.setLogging(O, false); // The .bak now says on.
  const file = findSettings(stateDir);
  assert.match(readFileSync(`${file}.bak`, "utf8"), /"loggingOff":false/);
  writeFileSync(file, "not json");
  assert.throws(() => svc.loggingEnabled(O), (e) => e.code === "SHADOW_UNAVAILABLE");
  await assert.rejects(svc.logStep(O, { kind: "note", content: "x" }, BASE), (e) => e.code === "SHADOW_UNAVAILABLE");
  const reset = svc.setLogLevel(O, "turn");
  assert.equal(reset.settings_reset, true);
  assert.equal(svc.loggingEnabled(O), false, "the level doesn't bring logging back");
  await assert.rejects(svc.logStep(O, { kind: "note", content: "x" }, BASE), (e) => e.code === "LOGGING_OFF");
  // The same tests as the durable file's: a file others can read is refused, not fallen back from.
  svc.setLogging(O, false);
  chmodSync(file, 0o644);
  assert.throws(() => svc.loggingEnabled(O), (e) => e.code === "SHADOW_UNAVAILABLE");
  chmodSync(file, 0o600);
  // A crash in the middle of a save leaves only the .bak, and that still reads.
  svc.setLogging(O, true);
  rmSync(file);
  assert.equal(svc.loggingEnabled(O), false, "the value before the save that never finished");
});

test("a read that merely fails isn't corruption: the healthy file stays as it is", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "level-read-"));
  const { svc } = service({ stateDir });
  svc.setLogLevel(O, "turn");
  const file = findSettings(stateDir);
  const before = readFileSync(file, "utf8");
  chmodSync(file, 0o000);
  try {
    assert.throws(() => svc.setLogLevel(O, "step"), (e) => e.code === "SHADOW_UNAVAILABLE" && /stays as it was/.test(e.message));
    assert.throws(() => svc.setLogging(O, true), (e) => e.code === "SHADOW_UNAVAILABLE" && /stays as it was/.test(e.message));
  } finally {
    chmodSync(file, 0o600);
  }
  assert.equal(readFileSync(file, "utf8"), before);
  assert.equal(svc.logLevelOf(O), "turn");
});

test("the owed list takes turns: one account's stuck sessions can't keep another's off, and every session gets its go", async () => {
  const later = Date.now() + 2 * 86_400_000;
  const limits = { maxSessionStartsPerOwnerPerDay: 100, maxOpenSessionsPerOwner: 100, maxAnchorsPerOwnerPerDay: 1000 };
  const { svc, fake } = service({ limits });
  const [hog, victim] = [O, O2].sort((x, y) => ownerKeyOf(x).localeCompare(ownerKeyOf(y)));
  const close = async (owner) => {
    const s = await svc.startSession(owner, { title: "t" }, BASE);
    fake.down = true;
    await svc.close(owner, { session_id: s.session_id }, BASE);
    fake.down = false;
    return s.session_id;
  };
  const hogs = [];
  for (let i = 0; i < 6; i++) hogs.push(await close(hog));
  const mine = await close(victim);
  const seen = new Set();
  for (let pass = 0; pass < 3; pass++) {
    const { owed } = await svc.store.idleScan(-Infinity, later, 3);
    assert.equal(owed.length, 3);
    assert.ok(owed.some((s) => s.sessionId === mine), `pass ${pass}: the other account is on the list`);
    for (const s of owed) seen.add(s.sessionId);
  }
  assert.equal(hogs.filter((id) => seen.has(id)).length, 6, "and the list moved on through the stuck ones");
  const none = await svc.store.idleScan(-Infinity, Date.now(), 3);
  assert.equal(none.owed.length, 0, "rows backing off aren't due");
});
