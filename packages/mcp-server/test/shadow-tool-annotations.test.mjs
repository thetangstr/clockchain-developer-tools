// Every tool on /shadow/mcp and /shadow/chat/mcp has a human title and all four hints, and the hints say what the tools
// really do. The table is written out here on purpose: changing a hint has to change this file too.
import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { ShadowService } from "../dist/shadow/service.js";
import { createLogBudget, __resetSharedLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const PLAIN = "/shadow/mcp";
const CHAT = "/shadow/chat/mcp";
const PREVIEW = "/shadow/preview/mcp";
const PREVIEW_CHAT = "/shadow/preview/chat/mcp";
const STATIC = "static-annotation-token";
const tmp = (label) => mkdtempSync(path.join(tmpdir(), `shadow-annotations-${label}-`));

//                                              title                            readOnly destructive idempotent openWorld
const EXPECTED = {
  shadow_start_session:      ["Start a Shadow session",        false, true,  false, true],
  shadow_record:             ["Record a step",                 false, false, false, true],
  shadow_checkpoint:         ["Anchor a checkpoint",           false, true,  false, true],
  shadow_close_session:      ["Close the session",             false, true,  true,  true],
  shadow_get_session:        ["Get a session",                 true,  false, true,  false],
  shadow_list_sessions:      ["List sessions",                 true,  false, true,  false],
  shadow_verify:             ["Verify a session",              true,  false, true,  true],
  shadow_log_step:           ["Log one step",                  false, true,  false, true],
  shadow_log_turn:           ["Log a whole reply (fallback)",  false, true,  false, true],
  clockchain_logging:        ["Turn logging on or off",        false, true,  true,  false],
  clockchain_whoami:         ["Which Clockchain account",      true,  false, true,  false],
  clockchain_create_account: ["Create a Clockchain account",   false, true,  true,  false],
  clockchain_signup_help:    ["How Clockchain sign-up works",  true,  false, true,  false],
  shadow_revoke_links:       ["Revoke a session's links",      false, true,  true,  true],
  shadow_delete_session:     ["Delete a session",              false, true,  true,  true],
  clockchain_delete_account: ["Delete the Clockchain account", false, true,  true,  true],
};
const SESSION_TOOLS = ["shadow_start_session", "shadow_record", "shadow_checkpoint", "shadow_close_session", "shadow_get_session", "shadow_list_sessions", "shadow_verify", "shadow_revoke_links", "shadow_delete_session", "clockchain_delete_account"];
const LOG_TOOLS = ["shadow_log_step", "shadow_log_turn", "clockchain_logging", "clockchain_whoami"];
const ACCOUNT_TOOLS = ["clockchain_create_account", "clockchain_whoami", "clockchain_signup_help"];

const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "SHADOW_PREVIEW_AUTO_LOG", "SHADOW_ALLOW_NON_ACCT", "MCP_LOG_BUDGET"];

async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  __setShadowLedgerForTests(new FakeLedger());
  __resetSharedLogBudget();
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  const stateDir = tmp("state");
  Object.assign(process.env, {
    MCP_PORT: String(port), MCP_AUTH_TOKENS: STATIC, MCP_TOKEN_SIGNING_SECRET: "annotation-secret", MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"),
    MCP_OAUTH: "1", MCP_PUBLIC_URL: "https://mcp.example.test", SHADOW_ENABLED: "1", SHADOW_LAZY_AUTH: "1", SHADOW_ALLOW_NON_ACCT: "1",
  }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __setShadowLedgerForTests(undefined);
      __resetSharedLogBudget();
    },
  };
}

async function list(base, p, token) {
  const res = await fetch(`${base}${p}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(res.status, 200, p);
  const text = await res.text();
  const body = res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : JSON.parse(text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop());
  return body.result.tools;
}

function assertPinned(tools, want, where) {
  assert.deepEqual(tools.map((t) => t.name).sort(), [...want].sort(), `${where}: the tools listed`);
  for (const t of tools) {
    const [title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint] = EXPECTED[t.name];
    assert.equal(t.title, title, `${where}: ${t.name} title`);
    assert.deepEqual(t.annotations, { title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint }, `${where}: ${t.name} annotations`);
  }
}

for (const [label, autoLog] of [["automatic logging on", "1"], ["automatic logging off", undefined]]) {
  test(`with ${label}, every tool on both endpoints has its title and all four hints`, async () => {
    const s = await boot(autoLog ? { SHADOW_AUTO_LOG: autoLog } : {});
    try {
      const plain = [...SESSION_TOOLS, ...(autoLog ? LOG_TOOLS : [])];
      const chat = [...new Set([...SESSION_TOOLS, ...ACCOUNT_TOOLS, ...(autoLog ? LOG_TOOLS : [])])];
      assertPinned(await list(s.url, PLAIN, STATIC), plain, PLAIN);
      assertPinned(await list(s.url, CHAT, STATIC), chat, `${CHAT} signed in`);
      assertPinned(await list(s.url, CHAT), chat, `${CHAT} before sign-in`);
    } finally {
      await s.close();
    }
  });
}

test("on the preview endpoints too, every tool has its title and all four hints", async () => {
  const s = await boot({ SHADOW_PREVIEW_AUTO_LOG: "1" });
  try {
    assertPinned(await list(s.url, PREVIEW, STATIC), [...SESSION_TOOLS, ...LOG_TOOLS], PREVIEW);
    const chat = [...new Set([...SESSION_TOOLS, ...ACCOUNT_TOOLS, ...LOG_TOOLS])];
    assertPinned(await list(s.url, PREVIEW_CHAT, STATIC), chat, `${PREVIEW_CHAT} signed in`);
    assertPinned(await list(s.url, PREVIEW_CHAT), chat, `${PREVIEW_CHAT} before sign-in`);
  } finally {
    await s.close();
  }
});

test("a read-only tool is never marked destructive, and a repeat of one is always marked idempotent", () => {
  for (const [name, [, readOnly, destructive, idempotent]] of Object.entries(EXPECTED)) {
    if (readOnly) {
      assert.equal(destructive, false, name);
      assert.equal(idempotent, true, name);
    }
  }
});

// ---- what the hints claim ---------------------------------------------------------------------------------------------

const OWNER = "acct_AAAAAAAAAAAAAAAAAAAAAA";
const BASE = "https://mcp.example.test";

function service(autoLog = false) {
  const fake = new FakeLedger();
  let reads = 0;
  const entry = fake.getLedgerEntry.bind(fake);
  fake.getLedgerEntry = (...a) => { reads++; return entry(...a); };
  const svc = new ShadowService({ stateDir: tmp("svc"), ledger: () => fake, budget: () => createLogBudget({}), sleep: async () => {}, log: () => {}, autoLog });
  svc.sweep();
  return { svc, fake, reads: () => reads };
}

test("destructive: every tool that anchors writes to the ledger, which can't be undone; shadow_record does not", async () => {
  const { svc, fake } = service(true);
  let writes = fake.writes.length;
  const wrote = () => { const n = fake.writes.length - writes; writes = fake.writes.length; return n; };

  const s = await svc.startSession(OWNER, { title: "t" }, BASE);
  assert.equal(wrote(), 1, "start");
  await svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind: "task", content: "x" });
  assert.equal(wrote(), 0, "record");
  await svc.checkpoint(OWNER, { session_id: s.session_id });
  assert.equal(wrote(), 1, "checkpoint");
  await svc.logStep(OWNER, { session_id: s.session_id, kind: "message", content: "y" }, BASE);
  assert.equal(wrote(), 1, "log step");
  await svc.logTurn(OWNER, { session_id: s.session_id, steps: [{ kind: "note", content: "z" }] }, BASE);
  assert.equal(wrote(), 1, "log turn");
  await svc.close(OWNER, { session_id: s.session_id, status: "succeeded" }, BASE);
  assert.equal(wrote(), 1, "close");
});

test("openWorld: a recorded step can be read by anyone holding the session's link, so shadow_record is open-world without touching the ledger", async () => {
  const { svc } = service();
  const s = await svc.startSession(OWNER, { title: "t" }, BASE);
  await svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind: "note", content: "readable through the link" });
  const cap = new URL(s.links.packet).pathname.split("/").pop().replace(/\.json$/, "");
  assert.match(await svc.packetForCap(cap), /readable through the link/);
});

test("readOnly: the read tools write nothing to the ledger; only shadow_verify reads it, so only it is open-world", async () => {
  const { svc, fake, reads } = service();
  const s = await svc.startSession(OWNER, { title: "t" }, BASE);
  await svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind: "task", content: "x" });
  await svc.close(OWNER, { session_id: s.session_id, status: "succeeded" }, BASE);
  const writes = fake.writes.length;
  const before = reads();
  const got = await svc.getSession(OWNER, { session_id: s.session_id }, BASE);
  await svc.listSessions(OWNER);
  assert.equal(reads(), before, "shadow_get_session and shadow_list_sessions stay on this server");
  await svc.verify(OWNER, { session_id: s.session_id }, BASE);
  assert.ok(reads() > before, "shadow_verify reads the ledger");
  assert.equal(fake.writes.length, writes, "no read tool writes to the ledger");
  const again = await svc.getSession(OWNER, { session_id: s.session_id }, BASE);
  assert.deepEqual({ ...again, time_windows: 0 }, { ...got, time_windows: 0 }, "and the record is unchanged");
});

test("idempotent: a repeated close is refused with no effect; a repeated checkpoint anchors again", async () => {
  const { svc, fake } = service();
  const s = await svc.startSession(OWNER, { title: "t" }, BASE);
  await svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind: "task", content: "x" });

  const first = fake.writes.length;
  await svc.checkpoint(OWNER, { session_id: s.session_id });
  await svc.checkpoint(OWNER, { session_id: s.session_id });
  assert.equal(fake.writes.length, first + 2, "the first anchor is itself a new step, so the second checkpoint anchors again");

  await svc.close(OWNER, { session_id: s.session_id, status: "succeeded" }, BASE);
  const closed = await svc.getSession(OWNER, { session_id: s.session_id }, BASE);
  const writes = fake.writes.length;
  await assert.rejects(svc.close(OWNER, { session_id: s.session_id, status: "failed" }, BASE), { code: "SHADOW_SESSION_CLOSED" });
  assert.equal(fake.writes.length, writes);
  assert.equal((await svc.getSession(OWNER, { session_id: s.session_id }, BASE)).steps, closed.steps);
});

test("idempotent: turning logging off twice is the same as once, and it deletes nothing already recorded", async () => {
  const { svc } = service(true);
  const s = await svc.logStep(OWNER, { kind: "task", content: "x" }, BASE);
  const steps = (await svc.getSession(OWNER, { session_id: s.session_id }, BASE)).steps;
  assert.deepEqual(svc.setLogging(OWNER, false), svc.setLogging(OWNER, false));
  assert.equal(svc.loggingEnabled(OWNER), false);
  assert.equal((await svc.getSession(OWNER, { session_id: s.session_id }, BASE)).steps, steps);
  svc.setLogging(OWNER, true);
  assert.equal(svc.loggingEnabled(OWNER), true);
});
