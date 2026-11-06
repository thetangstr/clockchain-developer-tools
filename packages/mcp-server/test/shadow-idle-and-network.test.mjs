// Sessions nobody closes close by themselves; and a server that has moved to mainnet keeps its testnet records honest.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { ShadowService, ShadowError, loadShadowConfig } from "../dist/shadow/service.js";
import { createLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const O = "acct_AAAAAAAAAAAAAAAAAAAAAA";
const BASE = "https://mcp.example.test";
const HOUR = 3_600_000;

function service(o = {}) {
  const fake = new FakeLedger();
  const clock = { now: Date.parse("2026-11-06T00:00:00Z") };
  const stateDir = o.stateDir ?? mkdtempSync(path.join(tmpdir(), "idle-"));
  const svc = new ShadowService({ stateDir, ledger: () => fake, budget: () => createLogBudget({}), sleep: async () => {}, log: () => {}, now: () => new Date(clock.now), autoLog: true, ...o, limits: { idleCloseMs: 24 * HOUR, ...o.limits } });
  svc.sweep();
  return { svc, fake, clock, stateDir };
}

test("a session with no new step closes by itself, anchored, and says so; a later step starts a new one", async () => {
  const { svc, fake, clock } = service();
  const a = await svc.logStep(O, { kind: "task", content: "Do the thing" }, BASE);
  clock.now += 23 * HOUR;
  assert.equal(await svc.closeIdle(), 0, "not idle long enough");
  await svc.logStep(O, { session_id: a.session_id, kind: "message", content: "still here" }, BASE);
  clock.now += 23 * HOUR;
  assert.equal(await svc.closeIdle(), 0, "a step restarts the wait");
  clock.now += 2 * HOUR;
  const writes = fake.writes.length;
  assert.equal(await svc.closeIdle(), 1);
  assert.equal(await svc.closeIdle(), 0, "only once");
  assert.ok(fake.writes.length > writes, "the final checkpoint is anchored");
  const got = await svc.getSession(O, { session_id: a.session_id }, BASE);
  assert.equal(got.status, "closed");
  assert.ok(got.pin, "it has its pin, as any closed session does");
  const checked = await svc.verify(O, { session_id: a.session_id }, BASE);
  assert.match(checked.capture_note, /closed by itself/);
  assert.equal(checked.checks.find((c) => c.name === "content")?.status ?? "pass", "pass");
  // The open run became a gap that says why, inside the signed record.
  await assert.rejects(svc.logStep(O, { session_id: a.session_id, kind: "note", content: "x" }, BASE), (e) => e.code === "SHADOW_SESSION_CLOSED" && /without session_id/.test(e.message));
});

test("at the open-session limit, the session idle longest makes room", async () => {
  const { svc, clock } = service({ limits: { maxOpenSessionsPerOwner: 2 } });
  const first = await svc.startSession(O, { title: "first" }, BASE);
  clock.now += 2 * HOUR;
  const second = await svc.startSession(O, { title: "second" }, BASE);
  clock.now += 2 * HOUR;
  const third = await svc.startSession(O, { title: "third" }, BASE);
  assert.equal((await svc.getSession(O, { session_id: first.session_id }, BASE)).status, "closed");
  assert.equal((await svc.getSession(O, { session_id: second.session_id }, BASE)).status, "open");
  assert.equal((await svc.getSession(O, { session_id: third.session_id }, BASE)).status, "open");
});

test("at the limit with every session busy, the person is still told plainly", async () => {
  const { svc, clock } = service({ limits: { maxOpenSessionsPerOwner: 1 } });
  await svc.startSession(O, { title: "busy" }, BASE);
  clock.now += 10 * 60_000;
  await assert.rejects(svc.startSession(O, { title: "next" }, BASE), (e) => e instanceof ShadowError && e.code === "SHADOW_LIMIT_OPEN_SESSIONS");
});

test("without the setting nothing closes by itself, and the setting reads as documented", async () => {
  const { svc, clock } = service({ limits: { idleCloseMs: 0 } });
  const a = await svc.startSession(O, { title: "stays open" }, BASE);
  clock.now += 40 * 24 * HOUR - 11 * 24 * HOUR;
  assert.equal(await svc.closeIdle(), 0);
  assert.equal((await svc.getSession(O, { session_id: a.session_id }, BASE)).status, "open");
  const env = { SHADOW_ENABLED: "1", SHADOW_STATE_DIR: "/tmp/x" };
  assert.equal(loadShadowConfig(env).limits.idleCloseMs, undefined, "off unless logging is on by default");
  assert.equal(loadShadowConfig({ ...env, SHADOW_AUTO_LOG: "1" }).limits.idleCloseMs, 24 * HOUR);
  assert.equal(loadShadowConfig({ ...env, SHADOW_AUTO_LOG: "1", SHADOW_IDLE_CLOSE_HOURS: "6" }).limits.idleCloseMs, 6 * HOUR);
  assert.equal(loadShadowConfig({ ...env, SHADOW_AUTO_LOG: "1", SHADOW_IDLE_CLOSE_HOURS: "off" }).limits.idleCloseMs, undefined);
  assert.match(loadShadowConfig({ ...env, SHADOW_IDLE_CLOSE_HOURS: "soon" }).problem, /SHADOW_IDLE_CLOSE_HOURS/);
});

test("after the switch to mainnet a testnet session keeps its network: no new steps, no anchors, and offline checks still pass", async () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "net-"));
  const before = service({ stateDir });
  const open = await before.svc.logStep(O, { kind: "task", content: "Started on testnet" }, BASE);
  const done = await before.svc.logStep(O, { kind: "task", content: "Finished on testnet" }, BASE);
  const closed = await before.svc.close(O, { session_id: done.session_id, status: "succeeded" }, BASE);
  assert.ok(closed.pin);

  const after = service({ stateDir, network: "clockchain-mainnet" });
  const writes = () => after.fake.writes.length;
  const atStart = writes();
  await assert.rejects(after.svc.logStep(O, { session_id: open.session_id, kind: "note", content: "x" }, BASE), (e) => e.code === "SHADOW_OTHER_NETWORK" && /without session_id/.test(e.message));
  await assert.rejects(after.svc.record(O, { session_id: open.session_id, agent: "assistant", kind: "note", content: "x" }), (e) => e.code === "SHADOW_OTHER_NETWORK");

  const finished = await after.svc.close(O, { session_id: open.session_id }, BASE);
  assert.ok(finished.pin, "it still closes, signed");
  assert.match(JSON.stringify(finished.final_checkpoint), /signed but not anchored/);
  assert.equal(writes(), atStart, "nothing from a testnet session is written to mainnet");

  const v = await after.svc.verify(O, { session_id: done.session_id }, BASE);
  assert.match(v.online, /receipts are on clockchain-testnet/);
  assert.notEqual(v.result, "fail", "its testnet receipts aren't a tamper signal");
  assert.equal(writes(), atStart);

  const fresh = await after.svc.logStep(O, { kind: "task", content: "On mainnet" }, BASE);
  assert.equal(after.svc.store.readMeta(ownerKeyFor(after, fresh.session_id), fresh.session_id).network, "clockchain-mainnet");
});

function ownerKeyFor({ svc }, sessionId) {
  for (const owner of svc.store.idleOpenSessions(Number.MAX_SAFE_INTEGER, 1000)) if (owner.sessionId === sessionId) return owner.ownerKey;
  throw new Error("no such open session");
}

// The pages read the switch when the process starts, so each side runs in its own process.
function pages(env) {
  const dist = (f) => path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", f);
  const script = `
    const land = await import(${JSON.stringify(dist("landing.js"))});
    const disc = await import(${JSON.stringify(dist("shadow/discovery.js"))});
    const mcp = await import(${JSON.stringify(dist("shadow/mcp.js"))});
    console.log(JSON.stringify({ html: land.LANDING_HTML, txt: land.INSTALL_TXT, manifest: land.MCP_MANIFEST, label: land.SUBSTRATE_LABEL, connect: disc.connectInstructions("https://x.test", "/shadow/chat/mcp", false), account: mcp.ACCOUNT_INSTRUCTIONS }));`;
  return JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", script], { env: { ...process.env, SHADOW_NETWORK: "", MCP_MAINNET_FREE_TOKENS: "", ...env }, encoding: "utf8" }));
}

test("one setting moves the pages: mainnet makes no free-testnet promise, and testnet reads as before", () => {
  const t = pages({});
  assert.match(t.html, /Get a testnet token/);
  assert.equal(t.manifest.network, "testnet");
  assert.match(t.connect, /It is free, on testnet/);
  const m = pages({ SHADOW_NETWORK: "mainnet" });
  for (const text of [m.html, m.connect, m.account, m.label]) assert.doesNotMatch(String(text), /testnet/i);
  assert.equal(m.manifest.network, "mainnet");
  assert.doesNotMatch(m.html, /getTokenBtn"/, "no free-key button while free keys are off");
  assert.doesNotMatch(m.connect, /free/i);
  assert.match(m.html, /Mainnet/);
  const free = pages({ SHADOW_NETWORK: "mainnet", MCP_MAINNET_FREE_TOKENS: "1" });
  assert.match(free.html, /Get a trial token/);
});
