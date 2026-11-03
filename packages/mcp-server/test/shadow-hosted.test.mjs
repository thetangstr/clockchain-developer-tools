// Hosted Shadow, service level: the record, its bounds, durability and retention, against a fake ledger. Every
// evidence packet here is checked with the vendored library verifier (src/shadow/lib/verify.ts), strictly parsed
// from its JSON as a relying party would.
import assert from "node:assert/strict";
import { appendFileSync, copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ShadowService, ShadowError } from "../dist/shadow/service.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { SUMMARY_CSP } from "../dist/shadow/lib/summary.js";
import { parseStrict, parseTime } from "../dist/shadow/lib/profile.js";
import { fingerprint } from "../dist/shadow/lib/keys.js";
import { createLogBudget } from "../dist/budget.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const A = "jti:11111111-1111-4111-8111-111111111111";
const B = "jti:22222222-2222-4222-8222-222222222222";
const BASE = "https://mcp.example.test";
const strict = (v) => parseStrict(JSON.stringify(v));
const DAY = 24 * 60 * 60_000;

function setup(o = {}) {
  const dir = o.dir ?? mkdtempSync(path.join(tmpdir(), "shadow-hosted-"));
  const fake = o.fake ?? new FakeLedger();
  const clock = o.clock ?? { t: Date.UTC(2026, 10, 2, 12, 0, 0) };
  const logs = o.logs ?? [];
  const budget = o.budget ?? createLogBudget({});
  const svc = new ShadowService({
    stateDir: dir, ledger: () => fake, budget: () => budget, limits: o.limits, now: () => new Date(clock.t),
    sleep: async () => {}, log: (event, fields) => logs.push({ event, ...fields }),
  });
  svc.sweep();
  return { svc, fake, clock, dir, logs, budget };
}

async function rejects(p, code) {
  await assert.rejects(p, (e) => {
    assert.ok(e instanceof ShadowError, `expected ShadowError ${code}, got ${e?.name}: ${e?.message}`);
    assert.equal(e.code, code, e.message);
    return true;
  });
}

const capOf = (links) => new URL(links.packet).pathname.split("/").pop().replace(/\.json$/, "");

async function packetOf(svc, links) {
  const doc = JSON.parse(await svc.packetForCap(capOf(links)));
  return { packet: strict(doc.packet), pin: strict(doc.pin), doc };
}

async function fullSession(svc, owner = A) {
  const s = await svc.startSession(owner, { title: "Plan a trip to Lisbon", agents: [{ id: "planner", role: "plans the trip" }, { id: "booker" }] }, BASE);
  const id = s.session_id;
  const task = await svc.record(owner, { session_id: id, agent: "planner", kind: "task", content: "Find flights to Lisbon for two" });
  await svc.record(owner, { session_id: id, agent: "planner", kind: "prompt", content: "Find flights to Lisbon for two, 12-19 Dec" });
  await svc.record(owner, { session_id: id, agent: "planner", kind: "tool_call", content: { tool: "search_flights", args: { to: "LIS", adults: 2 } } });
  await svc.record(owner, { session_id: id, agent: "planner", kind: "tool_result", content: { tool: "search_flights", result: { fares: [412.5, 389] }, is_error: false } });
  await svc.record(owner, { session_id: id, agent: "planner", kind: "message", content: "TAP at 389 EUR is the cheapest." });
  await svc.record(owner, { session_id: id, agent: "planner", kind: "file", content: { path: "plan.md", content: "# Lisbon\nTAP, 389 EUR" } });
  await svc.record(owner, { session_id: id, agent: "planner", kind: "note", content: "Chose TAP over easyJet for the bag allowance." });
  const cp = await svc.checkpoint(owner, { session_id: id });
  await svc.record(owner, { session_id: id, agent: "booker", kind: "task", content: { title: "Hold the fare", fare: "389" } });
  await svc.record(owner, { session_id: id, agent: "booker", kind: "message", content: "Held until Friday." });
  const closed = await svc.close(owner, { session_id: id, status: "succeeded" }, BASE);
  return { s, id, task, cp, closed };
}

test("happy path: a hosted packet passes the vendored verifier with its pin, offline and online", async () => {
  const { svc, fake } = setup();
  const { s, id, task, cp, closed } = await fullSession(svc);
  assert.equal(s.start_anchor.status, "anchored");
  assert.match(task.run_id, /^[0-9a-f-]{36}$/);
  assert.equal(cp.checkpoint.status, "anchored");
  assert.equal(cp.checkpoint.covers_steps, 8);
  assert.match(cp.checkpoint.ledger_id, /^[0-9a-f-]{36}$/);
  assert.equal(typeof cp.checkpoint.block, "string");
  assert.equal(typeof cp.checkpoint.block_time, "string");
  assert.equal(closed.final_checkpoint.status, "anchored");

  const { packet, pin, doc } = await packetOf(svc, closed.links);
  assert.deepEqual(doc.pin, closed.pin, "the packet link carries the pin the owner was given");
  assert.equal(packet.format, "shadow-evidence-v2");
  const report = await verifyPacket(packet, { pin: strict(closed.pin) });
  assert.equal(report.result, "pass", JSON.stringify(report.checks, null, 1));
  const status = Object.fromEntries(report.checks.map((c) => [c.name, c.status]));
  for (const name of ["format", "content", "sequence", "membership", "signature", "trust", "coverage", "provenance", "completion", "anchors"]) {
    assert.equal(status[name], "pass", `${name}: ${report.checks.find((c) => c.name === name)?.reason}`);
  }
  assert.ok(report.windows.some((w) => w.lower && w.upper), "steps get Clockchain time bounds");
  // Without the pin it is integrity only (indeterminate on trust), exactly as the library reports.
  const noPin = await verifyPacket(packet);
  assert.deepEqual(noPin.indeterminate, ["trust"]);

  // The library's step kinds and run structure.
  const kinds = packet.events.map((e) => e.body.kind);
  assert.deepEqual(kinds, [
    "session.opened", "task.assigned", "agent.prompt", "agent.tool.call", "agent.tool.result", "agent.message",
    "artifact.created", "agent.message", "clockchain.anchored", "task.assigned", "agent.message",
    "execution.receipt", "execution.receipt", "session.closed", "clockchain.anchored",
  ]);
  const toolCall = packet.events[3].body;
  assert.equal(toolCall.payload.tool, "search_flights");
  assert.equal(toolCall.source.boundary, "transcript");
  assert.equal(toolCall.source.agentRunId, task.run_id);
  assert.equal(packet.events[7].body.payload.note, true);
  assert.equal(packet.events[6].body.payload.path, "plan.md");

  // shadow_verify: the same verifier, online against the (fake) in-process ledger.
  const v = await svc.verify(A, { session_id: id }, BASE);
  assert.equal(v.result, "pass", JSON.stringify(v.checks, null, 1));
  assert.equal(v.checks.find((c) => c.name === "witness").status, "pass", v.checks.find((c) => c.name === "witness").reason);

  // The viewer: the library's static summary.
  const html = await svc.summaryForCap(capOf(closed.links));
  assert.ok(html.includes(`<meta http-equiv="Content-Security-Policy" content="${SUMMARY_CSP.replace(/'/g, "&#39;")}">`), "the library's CSP");
  assert.match(html, /Result: pass/);
  assert.doesNotMatch(html, /<script/i);

  const g = await svc.getSession(A, { session_id: id }, BASE);
  assert.equal(g.status, "closed");
  assert.equal(g.steps, 15);
  assert.equal(g.recorded_steps, 9);
  assert.equal(g.anchors.length, 3);
  assert.deepEqual(g.pin, closed.pin);
  assert.ok(g.time_windows.steps_with_both_bounds > 0);
  assert.ok(g.time_windows.segments.length >= 1);

  // Only hashes, the session reference and fixed labels reached the ledger.
  assert.equal(fake.writes.length, 3);
  for (const w of fake.writes) {
    assert.deepEqual(Object.keys(w).sort(), ["additionalInfo", "assetHash", "assetReferenceId", "hashType"]);
    assert.match(w.assetHash, /^[0-9a-f]{64}$/);
    assert.equal(w.assetReferenceId, `shadow:v1:${id}`);
    assert.ok(["shadow session opened", "shadow checkpoint"].includes(w.additionalInfo));
  }
  assert.doesNotMatch(JSON.stringify(fake.records), /Lisbon|TAP|planner|booker/);
});

test("receipt times are recorded in the canonical UTC form, whatever form the gateway returns, and still bound steps", async () => {
  const fake = new FakeLedger();
  fake.gatewayTimes = true;
  const { svc } = setup({ fake });
  const { id, closed } = await fullSession(svc);
  assert.match(fake.records[0].createdTimestamp, /^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}:\d{3} UTC$/, "the fake speaks the gateway's old form");
  const { packet } = await packetOf(svc, closed.links);
  const receipts = packet.events.flatMap((e) => (e.body.kind === "session.opened" ? [e.body.payload.receipt] : e.body.kind === "clockchain.anchored" ? [e.body.payload] : []));
  assert.equal(receipts.length, 3);
  for (const r of receipts) {
    assert.match(r.submittedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,9}Z$/);
    assert.match(r.blockTime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,9}Z$/);
    assert.ok(parseTime(r.submittedAt) && parseTime(r.blockTime));
  }
  // Same instant as the gateway reported (submission is one second before the block).
  assert.equal(Date.parse(receipts[0].blockTime) - Date.parse(receipts[0].submittedAt), 1000);
  const report = await verifyPacket(packet, { pin: strict(closed.pin) });
  assert.equal(report.result, "pass", JSON.stringify(report.checks, null, 1));
  assert.ok(report.windows.some((w) => w.lower && w.upper), "lower and upper bounds survive the gateway's formats");
  // Online, the witness reads the ledger the same way, so the times match.
  const v = await svc.verify(A, { session_id: id }, BASE);
  assert.equal(v.checks.find((c) => c.name === "witness").status, "pass", v.checks.find((c) => c.name === "witness").reason);
});

test("the pin and fingerprint are the owner's: stable across sessions, distinct per owner", async () => {
  const { svc } = setup();
  const one = await fullSession(svc, A);
  const two = await fullSession(svc, A);
  const other = await fullSession(svc, B);
  assert.equal(one.closed.pin.publicKeyFingerprint, two.closed.pin.publicKeyFingerprint);
  assert.equal(one.closed.pin.operatorId, two.closed.pin.operatorId);
  assert.notEqual(one.closed.pin.publicKeyFingerprint, other.closed.pin.publicKeyFingerprint);
  const { packet } = await packetOf(svc, one.closed.links);
  assert.equal(fingerprint(packet.checkpoint.publicKey), one.closed.pin.publicKeyFingerprint);
});

test("hidden reasoning is refused, with a code, and nothing is recorded", async () => {
  const { svc } = setup();
  const { session_id } = await svc.startSession(A, { title: "reasoning" }, BASE);
  const refusals = [
    { kind: "message", content: { reasoning_content: "secret plan", text: "hi" } },
    { kind: "message", content: [{ type: "thinking", thinking: "secret" }, { type: "text", text: "hi" }] },
    { kind: "message", content: "<think>secret</think>The answer is 4." },
    { kind: "prompt", content: { thinking: "secret" } },
    { kind: "note", content: [{ type: "redacted_thinking", data: "x" }] },
    { kind: "tool_result", content: { tool: "x", result: "<thinking>secret</thinking>done" } },
    { kind: "task", content: { thought: "secret", title: "t" } },
    { kind: "message", content: [{ text: "secret", thought: true }] },
  ];
  for (const r of refusals) {
    await assert.rejects(svc.record(A, { session_id, agent: "agent", ...r }), (e) => {
      assert.equal(e.code, "SHADOW_REASONING_REFUSED", `${r.kind}: ${e.message}`);
      assert.match(e.message, /never recorded/);
      return true;
    });
  }
  assert.equal((await svc.getSession(A, { session_id }, BASE)).steps, 1, "only session.opened");
  // Visible tool arguments may use the word, and counts of reasoning tokens are fine.
  await svc.record(A, { session_id, agent: "agent", kind: "tool_call", content: { tool: "decide", args: { reasoning: "shown to the user" } } });
  await svc.record(A, { session_id, agent: "agent", kind: "message", content: { text: "ok", reasoningTokens: 12 } });
  const closed = await svc.close(A, { session_id }, BASE);
  const { packet } = await packetOf(svc, closed.links);
  assert.doesNotMatch(JSON.stringify(packet), /secret/);
  assert.equal((await verifyPacket(packet, { pin: strict(closed.pin) })).result, "pass");
});

test("owner isolation: another owner can neither read nor write a session, nor reach it by id", async () => {
  const { svc } = setup();
  const { session_id } = await svc.startSession(A, { title: "mine" }, BASE);
  await svc.record(A, { session_id, agent: "agent", kind: "message", content: "hello" });
  await rejects(svc.record(B, { session_id, agent: "agent", kind: "message", content: "intrusion" }), "SHADOW_NOT_FOUND");
  await rejects(svc.getSession(B, { session_id }, BASE), "SHADOW_NOT_FOUND");
  await rejects(svc.checkpoint(B, { session_id }), "SHADOW_NOT_FOUND");
  await rejects(svc.close(B, { session_id }, BASE), "SHADOW_NOT_FOUND");
  await rejects(svc.verify(B, { session_id }, BASE), "SHADOW_NOT_FOUND");
  assert.deepEqual((await svc.listSessions(B)).sessions, []);
  // Path tricks are just unknown ids.
  await rejects(svc.getSession(B, { session_id: `../${ownerKeyOf(A)}/sessions/${session_id}` }, BASE), "SHADOW_NOT_FOUND");
  const mine = await svc.getSession(A, { session_id }, BASE);
  assert.equal(mine.steps, 2, "B's attempts left no trace");
  assert.equal((await svc.listSessions(A)).sessions.length, 1);
});

test("runs: a task starts a run, steps join the agent's open run, and close reports how it ended", async () => {
  const { svc } = setup();
  const { session_id } = await svc.startSession(A, { title: "runs", agents: [{ id: "a" }, { id: "b" }] }, BASE);
  const t = await svc.record(A, { session_id, agent: "a", kind: "task", content: "do it", run_id: "run-1" });
  assert.equal(t.run_id, "run-1");
  assert.equal((await svc.record(A, { session_id, agent: "a", kind: "message", content: "doing" })).run_id, "run-1");
  assert.equal((await svc.record(A, { session_id, agent: "b", kind: "message", content: "idle" })).run_id, null);
  await rejects(svc.record(A, { session_id, agent: "a", kind: "task", content: "again", run_id: "run-1" }), "SHADOW_RUN_EXISTS");
  await rejects(svc.record(A, { session_id, agent: "b", kind: "message", content: "x", run_id: "run-1" }), "SHADOW_RUN_NOT_FOUND");
  await rejects(svc.record(A, { session_id, agent: "c", kind: "message", content: "x" }), "SHADOW_UNKNOWN_AGENT");
  await rejects(svc.record(A, { session_id, agent: "a", kind: "speech", content: "x" }), "SHADOW_BAD_INPUT");
  await rejects(svc.record(A, { session_id, agent: "a", kind: "file", content: "no path" }), "SHADOW_BAD_CONTENT");
  // Without a status, an open run becomes a capture gap: the record is honest, and verification says so.
  const closed = await svc.close(A, { session_id }, BASE);
  const { packet } = await packetOf(svc, closed.links);
  assert.ok(packet.events.some((e) => e.body.kind === "coverage.gap" && e.body.source.agentRunId === "run-1"));
  const report = await verifyPacket(packet, { pin: strict(closed.pin) });
  assert.equal(report.result, "indeterminate");
  assert.deepEqual(report.indeterminate, ["coverage"]);
  await rejects(svc.record(A, { session_id, agent: "a", kind: "message", content: "late" }), "SHADOW_SESSION_CLOSED");
  await rejects(svc.close(A, { session_id }, BASE), "SHADOW_SESSION_CLOSED");
});

test("bounds: open and total sessions per owner", async () => {
  const { svc } = setup({ limits: { maxOpenSessionsPerOwner: 2, maxSessionsPerOwner: 3 } });
  const s1 = await svc.startSession(A, { title: "1" }, BASE);
  await svc.startSession(A, { title: "2" }, BASE);
  await rejects(svc.startSession(A, { title: "3" }, BASE), "SHADOW_LIMIT_OPEN_SESSIONS");
  await svc.startSession(B, { title: "B is counted apart" }, BASE);
  await svc.close(A, { session_id: s1.session_id }, BASE);
  await svc.startSession(A, { title: "3" }, BASE);
  await svc.close(A, { session_id: s1.session_id }, BASE).catch(() => {});
  await rejects(svc.startSession(A, { title: "4" }, BASE), "SHADOW_LIMIT_SESSIONS");
});

test("bounds: steps, content size, agents and open runs", async () => {
  const { svc } = setup({ limits: { maxStepsPerSession: 3, maxAgents: 2, maxOpenRuns: 1 } });
  await rejects(svc.startSession(A, { title: "x", agents: [{ id: "a" }, { id: "b" }, { id: "c" }] }, BASE), "SHADOW_LIMIT_AGENTS");
  await rejects(svc.startSession(A, { title: "x", agents: [{ id: "collector" }] }, BASE), "SHADOW_BAD_INPUT");
  await rejects(svc.startSession(A, { title: "" }, BASE), "SHADOW_BAD_INPUT");
  const { session_id } = await svc.startSession(A, { title: "steps" }, BASE);
  await svc.record(A, { session_id, agent: "agent", kind: "task", content: "t" });
  await rejects(svc.record(A, { session_id, agent: "agent", kind: "task", content: "t2" }), "SHADOW_LIMIT_RUNS");
  await rejects(svc.record(A, { session_id, agent: "agent", kind: "message", content: "x".repeat(32 * 1024 + 1) }), "SHADOW_CONTENT_TOO_LARGE");
  await rejects(svc.record(A, { session_id, agent: "agent", kind: "message", content: { big: "é".repeat(16 * 1024) } }), "SHADOW_CONTENT_TOO_LARGE");
  const full = await svc.record(A, { session_id, agent: "agent", kind: "message", content: "y".repeat(32 * 1024) });
  await svc.record(A, { session_id, agent: "agent", kind: "message", content: "three" });
  await rejects(svc.record(A, { session_id, agent: "agent", kind: "message", content: "four" }), "SHADOW_LIMIT_STEPS");
  // The collector's own steps still fit: the session closes and verifies, with nothing clipped.
  const closed = await svc.close(A, { session_id, status: "succeeded" }, BASE);
  const { packet } = await packetOf(svc, closed.links);
  const kept = packet.events[full.seq - 1].body.payload.content;
  assert.equal(kept.truncated, false);
  assert.equal(kept.chars, 32 * 1024);
  assert.equal((await verifyPacket(packet, { pin: strict(closed.pin) })).result, "pass");
});

test("bounds: bytes per session on disk", async () => {
  const limit = 96 * 1024;
  const { svc, dir } = setup({ limits: { maxSessionBytes: limit } });
  const { session_id } = await svc.startSession(A, { title: "bytes" }, BASE);
  let refused;
  for (let i = 0; i < 40 && !refused; i++) {
    try {
      await svc.record(A, { session_id, agent: "agent", kind: "message", content: `${i} ${"z".repeat(8000)}` });
    } catch (e) {
      refused = e;
    }
  }
  assert.equal(refused?.code, "SHADOW_LIMIT_SESSION_SIZE");
  const closed = await svc.close(A, { session_id }, BASE);
  assert.equal(closed.status, "closed");
  const sdir = path.join(dir, "owners", ownerKeyOf(A), "sessions", session_id);
  const bytes = readdirSync(sdir).reduce((n, f) => n + statSync(path.join(sdir, f)).size, 0);
  assert.ok(bytes <= limit, `session uses ${bytes} bytes on disk (limit ${limit})`);
  const { packet } = await packetOf(svc, closed.links);
  assert.equal((await verifyPacket(packet, { pin: strict(closed.pin) })).failed.length, 0);
});

test("bounds: the whole state directory refuses new sessions past its bound, and new steps past 125% of it", async () => {
  const { svc } = setup({ limits: { maxStateBytes: 64 * 1024 } });
  const { session_id } = await svc.startSession(A, { title: "first" }, BASE);
  for (let i = 0; i < 8; i++) await svc.record(A, { session_id, agent: "agent", kind: "message", content: "w".repeat(8000) });
  svc.sweep();
  await rejects(svc.startSession(B, { title: "second" }, BASE), "SHADOW_STORAGE_FULL");
  await svc.record(A, { session_id, agent: "agent", kind: "message", content: "still recording" });
  let refused;
  for (let i = 0; i < 10 && !refused; i++) {
    try {
      await svc.record(A, { session_id, agent: "agent", kind: "message", content: "w".repeat(8000) });
    } catch (e) {
      refused = e;
    }
  }
  assert.equal(refused?.code, "SHADOW_STORAGE_FULL");
  const closed = await svc.close(A, { session_id }, BASE);
  const { packet } = await packetOf(svc, closed.links);
  assert.equal((await verifyPacket(packet, { pin: strict(closed.pin) })).result, "pass");
});

test("bounds: anchors per owner per day, and MCP_LOG_BUDGET, leave checkpoints signed and pending", async () => {
  const { svc, fake, clock } = setup({ limits: { maxAnchorsPerOwnerPerDay: 2 } });
  const { session_id } = await svc.startSession(A, { title: "limits" }, BASE); // anchor 1
  await svc.record(A, { session_id, agent: "agent", kind: "message", content: "one" });
  assert.equal((await svc.checkpoint(A, { session_id })).checkpoint.status, "anchored"); // anchor 2
  await svc.record(A, { session_id, agent: "agent", kind: "message", content: "two" });
  const limited = await svc.checkpoint(A, { session_id });
  assert.equal(limited.checkpoint.status, "pending");
  assert.match(limited.checkpoint.reason, /anchor limit/);
  assert.equal(limited.anchors_today, 2);
  assert.equal(fake.writes.length, 2, "no write past the limit");
  const before = (await svc.getSession(A, { session_id }, BASE)).steps;
  await svc.checkpoint(A, { session_id });
  assert.equal((await svc.getSession(A, { session_id }, BASE)).steps, before, "our own limit adds no error steps");
  // Another owner has its own allowance.
  assert.equal((await svc.startSession(B, { title: "b" }, BASE)).start_anchor.status, "anchored");
  // Next day the pending checkpoint lands.
  clock.t += DAY;
  const next = await svc.checkpoint(A, { session_id });
  assert.ok(next.pending_anchors.length === 0, JSON.stringify(next.pending_anchors));
  assert.equal(next.checkpoint.status, "anchored");

  const budget = createLogBudget({ MCP_LOG_BUDGET: "2" });
  const b = setup({ budget });
  const s = await b.svc.startSession(A, { title: "budget" }, BASE);
  await b.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "x" });
  assert.equal((await b.svc.checkpoint(A, { session_id: s.session_id })).checkpoint.status, "anchored");
  assert.equal(budget.remaining(), 0, "hosted anchors count against MCP_LOG_BUDGET");
  await b.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "y" });
  const over = await b.svc.checkpoint(A, { session_id: s.session_id });
  assert.equal(over.checkpoint.status, "pending");
  assert.match(over.checkpoint.reason, /write budget/);
  assert.equal(b.fake.writes.length, 2);
});

test("anchor failure: steps are kept, the checkpoint is pending, and it anchors once Clockchain is back", async () => {
  const fake = new FakeLedger();
  fake.down = true;
  const { svc } = setup({ fake });
  const s = await svc.startSession(A, { title: "offline" }, BASE);
  assert.equal(s.start_anchor.status, "pending");
  for (const c of ["one", "two", "three"]) await svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: c });
  const cp = await svc.checkpoint(A, { session_id: s.session_id });
  assert.equal(cp.checkpoint.status, "pending");
  assert.equal(cp.checkpoint.covers_steps, 4);
  let g = await svc.getSession(A, { session_id: s.session_id }, BASE);
  assert.equal(g.recorded_steps, 3, "every record kept");
  assert.equal(g.pending_anchors.length, 2);
  // While pending, the packet still verifies: the queued checkpoint travels as a pending checkpoint.
  const mid = await packetOf(svc, s.links);
  assert.equal(mid.packet.pendingCheckpoints.length, 1);
  const midReport = await verifyPacket(mid.packet, { pin: mid.pin });
  assert.deepEqual(midReport.failed, [], JSON.stringify(midReport.checks, null, 1));
  const errors = mid.packet.events.filter((e) => e.body.kind === "clockchain.error");
  assert.ok(errors.length >= 1);
  for (const e of errors) {
    assert.deepEqual(Object.keys(e.body.payload).sort(), ["errorCode", "errorKind", "hash", "marker", "outcome"]);
    assert.match(e.body.payload.errorCode, /^[a-z0-9_]{1,40}$/);
  }
  fake.down = false;
  const later = await svc.checkpoint(A, { session_id: s.session_id });
  assert.equal(later.checkpoint.status, "anchored");
  assert.deepEqual(later.pending_anchors, []);
  const closed = await svc.close(A, { session_id: s.session_id }, BASE);
  const { packet } = await packetOf(svc, closed.links);
  const report = await verifyPacket(packet, { pin: strict(closed.pin) });
  assert.equal(report.result, "pass", JSON.stringify(report.checks, null, 1));
  assert.ok(packet.events.some((e) => e.body.kind === "clockchain.anchored" && e.body.payload.marker === "start"), "the start marker landed late");
  const v = await svc.verify(A, { session_id: s.session_id }, BASE);
  assert.equal(v.result, "pass", JSON.stringify(v.checks, null, 1));
});

test("anchor pending (written, no block yet) is adopted later without paying twice", async () => {
  const fake = new FakeLedger();
  const { svc } = setup({ fake });
  const s = await svc.startSession(A, { title: "slow" }, BASE);
  await svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "x" });
  fake.confirm = false;
  assert.equal((await svc.checkpoint(A, { session_id: s.session_id })).checkpoint.status, "pending");
  fake.confirmPending();
  fake.confirm = true;
  const again = await svc.checkpoint(A, { session_id: s.session_id });
  assert.equal(again.pending_anchors.length, 0);
  assert.equal(again.checkpoint.status, "anchored", "nothing changed, so the pending checkpoint is the one that lands");
  assert.equal(fake.writes.length, 2, "start and the checkpoint, written once each");
  // A failed write that actually landed is found by searching the session reference first.
  await svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "y" });
  const realLog = fake.log.bind(fake);
  fake.log = async (entry) => {
    await realLog(entry);
    fake.log = realLog;
    throw new TypeError("fetch failed");
  };
  const uncertain = await svc.checkpoint(A, { session_id: s.session_id });
  assert.equal(uncertain.checkpoint.status, "anchored");
  assert.equal(fake.writes.length, 3, "the landed write was adopted, not repeated");
  const closed = await svc.close(A, { session_id: s.session_id }, BASE);
  const v = await svc.verify(A, { session_id: s.session_id }, BASE);
  assert.equal(v.result, "pass", JSON.stringify(v.checks, null, 1));
  assert.equal(closed.status, "closed");
});

test("restart durability: a new service on the same directory continues the session", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-restart-"));
  const fake = new FakeLedger();
  const first = setup({ dir, fake });
  const s = await first.svc.startSession(A, { title: "durable" }, BASE);
  await first.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "task", content: "keep going" });
  await first.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "before restart" });
  await first.svc.checkpoint(A, { session_id: s.session_id });
  first.svc.stop();
  const keyFile = path.join(dir, "owners", ownerKeyOf(A), "key.json");
  const keyBefore = readFileSync(keyFile, "utf8");

  const second = setup({ dir, fake });
  const g = await second.svc.getSession(A, { session_id: s.session_id }, BASE);
  assert.equal(g.steps, 4);
  assert.equal(g.open_runs.length, 1);
  const r = await second.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "after restart" });
  assert.equal(r.seq, 5);
  assert.equal(r.run_id, g.open_runs[0].run_id, "the run continues");
  const closed = await second.svc.close(A, { session_id: s.session_id, status: "succeeded" }, BASE);
  const { packet } = await packetOf(second.svc, closed.links);
  assert.equal((await verifyPacket(packet, { pin: strict(closed.pin) })).result, "pass");
  // The same operator and key before and after the restart; the key file is private.
  assert.equal(readFileSync(keyFile, "utf8"), keyBefore);
  assert.equal(packet.checkpoint.body.operatorId, packet.events[0].body.operatorId);
  assert.equal(statSync(keyFile).mode & 0o777, 0o600);
});

test("crash recovery: an event appended without its metadata is adopted; a torn last line is dropped", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-crash-"));
  const first = setup({ dir });
  const s = await first.svc.startSession(A, { title: "crash" }, BASE);
  await first.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "one" });
  const sdir = path.join(dir, "owners", ownerKeyOf(A), "sessions", s.session_id);
  const metaPath = path.join(sdir, "meta.json");
  copyFileSync(metaPath, path.join(dir, "meta.before"));
  await first.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "two" });
  // Simulate a crash after the event append but before the metadata write.
  copyFileSync(path.join(dir, "meta.before"), metaPath);
  rmSync(`${metaPath}.bak`, { force: true });
  // ...and a torn, half-written line after it.
  appendFileSync(path.join(sdir, "events.jsonl"), '{"body":{"profile":"shadow-json-safeint-v1","seq":4');

  const second = setup({ dir });
  const g = await second.svc.getSession(A, { session_id: s.session_id }, BASE);
  assert.equal(g.steps, 3, "the appended event is adopted");
  assert.equal(g.recorded_steps, 2);
  const r = await second.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "three" });
  assert.equal(r.seq, 4);
  const closed = await second.svc.close(A, { session_id: s.session_id }, BASE);
  const { packet } = await packetOf(second.svc, closed.links);
  const report = await verifyPacket(packet, { pin: strict(closed.pin) });
  assert.equal(report.result, "pass", JSON.stringify(report.checks, null, 1));
  assert.deepEqual(packet.events.filter((e) => e.body.kind === "agent.message").map((e) => e.body.payload.content.text), ["one", "two", "three"]);
});

test("an interrupted start (no session.opened yet) is opened on next use, with its start marker queued", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "shadow-interrupted-"));
  const fake = new FakeLedger();
  const first = setup({ dir, fake });
  const s = await first.svc.startSession(A, { title: "interrupted" }, BASE);
  // Rewind the session to its state just after creation.
  const sdir = path.join(dir, "owners", ownerKeyOf(A), "sessions", s.session_id);
  const meta = JSON.parse(readFileSync(path.join(sdir, "meta.json"), "utf8"));
  Object.assign(meta.value, { seq: 0, head: null, eventsBytes: 0, anchors: [], outbox: [] });
  writeFileSync(path.join(sdir, "meta.json"), JSON.stringify(meta), { mode: 0o600 });
  rmSync(path.join(sdir, "meta.json.bak"), { force: true });
  rmSync(path.join(sdir, "events.jsonl"), { force: true });
  const second = setup({ dir, fake });
  await second.svc.record(A, { session_id: s.session_id, agent: "agent", kind: "message", content: "hi" });
  const closed = await second.svc.close(A, { session_id: s.session_id }, BASE);
  const { packet } = await packetOf(second.svc, closed.links);
  assert.equal(packet.events[0].body.kind, "session.opened");
  assert.equal((await verifyPacket(packet, { pin: strict(closed.pin) })).result, "pass");
});

test("retention: sessions are removed 30 days after they start; their links stop working", async () => {
  const { svc, clock, dir } = setup();
  const s = await svc.startSession(A, { title: "old" }, BASE);
  const cap = capOf(s.links);
  assert.ok(await svc.packetForCap(cap));
  clock.t += 29 * DAY;
  assert.equal(svc.sweep().removed, 0);
  assert.equal((await svc.listSessions(A)).sessions.length, 1);
  clock.t += 2 * DAY;
  // Expired sessions are already invisible before the sweep runs...
  await rejects(svc.getSession(A, { session_id: s.session_id }, BASE), "SHADOW_NOT_FOUND");
  assert.equal(await svc.packetForCap(cap), undefined);
  // ...and the sweep deletes them, their link capability, and the owner once nothing is left.
  assert.equal(svc.sweep().removed, 1);
  assert.equal(existsSync(path.join(dir, "owners", ownerKeyOf(A), "sessions", s.session_id)), false);
  assert.deepEqual(readdirSync(path.join(dir, "caps")).filter((f) => !f.endsWith(".tmp")), []);
  assert.equal(existsSync(path.join(dir, "owners", ownerKeyOf(A))), false);
  assert.deepEqual((await svc.listSessions(A)).sessions, []);
});

test("cap links: unknown and malformed capabilities resolve to nothing", async () => {
  const { svc } = setup();
  const s = await svc.startSession(A, { title: "links" }, BASE);
  assert.match(capOf(s.links), /^[A-Za-z0-9_-]{22}$/);
  assert.equal(await svc.packetForCap("A".repeat(22)), undefined);
  assert.equal(await svc.summaryForCap("A".repeat(22)), undefined);
  assert.equal(await svc.packetForCap("../../owners"), undefined);
  assert.equal(await svc.packetForCap(capOf(s.links).slice(0, 21) + "_"), undefined);
  assert.ok((await svc.summaryForCap(capOf(s.links))).startsWith("<!doctype html>"));
});

test("logs carry counts and session ids only", async () => {
  const logs = [];
  const fake = new FakeLedger();
  const { svc } = setup({ logs, fake });
  const { s, closed } = await fullSession(svc);
  fake.down = true;
  const t = await svc.startSession(A, { title: "Secret title 42" }, BASE);
  await svc.record(A, { session_id: t.session_id, agent: "agent", kind: "message", content: "SECRET-CONTENT-77" });
  await svc.checkpoint(A, { session_id: t.session_id });
  const text = JSON.stringify(logs);
  assert.ok(logs.length > 0);
  for (const secret of ["Lisbon", "SECRET-CONTENT-77", "Secret title", capOf(s.links), capOf(t.links), closed.pin.publicKeyFingerprint, ownerKeyOf(A), A]) {
    assert.equal(text.includes(secret), false, `log contains ${secret}`);
  }
  for (const entry of logs) {
    for (const [k, v] of Object.entries(entry)) {
      if (k === "event" || k === "sessionId" || k === "marker" || k === "outcome" || k === "code" || k === "startAnchor") continue;
      assert.ok(typeof v === "number" || typeof v === "boolean", `${entry.event}.${k} is ${typeof v}`);
    }
  }
});
