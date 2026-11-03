// Security review follow-up, finding 2 (storage fill through free accounts): every Shadow cap is an env setting with
// safer defaults (10 MB per account, 1 GB in all, never more than half the state filesystem's free space), and an
// operator purge script (scripts/shadow-purge.mjs) removes sessions by owner or age, dry run by default.
import { test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, randomUUID } from "node:crypto";

import { runHttp } from "../dist/http.js";
import { mintToken } from "../dist/token.js";
import { loadShadowConfig, diskBudgetProblem, SHADOW_ENV_DEFAULTS, ShadowService } from "../dist/shadow/service.js";
import { ownerKeyOf as storeOwnerKeyOf } from "../dist/shadow/store.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const PURGE = path.join(here, "..", "..", "..", "scripts", "shadow-purge.mjs");
const purgeLib = await import(PURGE);
const SECRET = "shadow-caps-secret";
const tmp = (label) => mkdtempSync(path.join(tmpdir(), `caps-${label}-`));
const acctToken = () => mintToken(SECRET, 3600, undefined, undefined, randomUUID(), `acct_${randomBytes(16).toString("base64url")}`).token;

const KEYS = ["PORT", "MCP_PORT", "MCP_AUTH_TOKENS", "MCP_TOKEN_SIGNING_SECRET", "MCP_RATE_PER_MIN", "SHADOW_ENABLED", "SHADOW_STATE_DIR",
  "SHADOW_MAX_BYTES", "SHADOW_ACCOUNT_MAX_BYTES", "SHADOW_SESSION_STARTS_PER_DAY", "SHADOW_LINK_CONCURRENCY", "SHADOW_ALLOW_NON_ACCT", "MCP_REQUIRE_AUTH"];
async function boot(env) {
  const saved = {};
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0", MCP_AUTH_TOKENS: "static-caps", MCP_TOKEN_SIGNING_SECRET: SECRET, SHADOW_ENABLED: "1", SHADOW_STATE_DIR: tmp("state") }, env);
  const logs = [];
  const origError = console.error;
  console.error = (...a) => { logs.push(a.join(" ")); };
  let server;
  try {
    server = await runHttp();
    if (!server.listening) await once(server, "listening");
  } finally {
    console.error = origError;
  }
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    logs,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}
const call = async (url, token, name, args) => {
  const r = await fetch(`${url}/shadow/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const text = await r.text();
  if (r.status !== 200) return { status: r.status, text };
  const data = JSON.parse(text.split("\n").find((l) => l.startsWith("data: ")).slice(6));
  return { status: 200, isError: data.result.isError === true, value: JSON.parse(data.result.content[0].text) };
};

test("config: Shadow caps come from the environment, with the follow-up's defaults; malformed values are a problem", () => {
  assert.deepEqual(loadShadowConfig({}), { enabled: false });
  const d = loadShadowConfig({ SHADOW_ENABLED: "1" });
  assert.deepEqual(d.limits, { maxStateBytes: 1024 ** 3, maxBytesPerOwner: 10 * 1024 ** 2, maxSessionStartsPerOwnerPerDay: 30 });
  assert.equal(d.linkConcurrency, 32);
  assert.equal(d.problem, undefined);
  assert.deepEqual(SHADOW_ENV_DEFAULTS, { maxStateBytes: 1024 ** 3, maxBytesPerOwner: 10 * 1024 ** 2, maxSessionStartsPerOwnerPerDay: 30, linkConcurrency: 32 });
  const set = loadShadowConfig({ SHADOW_ENABLED: "1", SHADOW_MAX_BYTES: "5000000", SHADOW_ACCOUNT_MAX_BYTES: "100000", SHADOW_SESSION_STARTS_PER_DAY: "3", SHADOW_LINK_CONCURRENCY: "8" });
  assert.deepEqual(set.limits, { maxStateBytes: 5_000_000, maxBytesPerOwner: 100_000, maxSessionStartsPerOwnerPerDay: 3 });
  assert.equal(set.linkConcurrency, 8);
  for (const bad of ["0", "-1", "1e9", "lots", "1.5"]) {
    assert.match(loadShadowConfig({ SHADOW_ENABLED: "1", SHADOW_ACCOUNT_MAX_BYTES: bad }).problem, /SHADOW_ACCOUNT_MAX_BYTES/, bad);
  }
  assert.equal(loadShadowConfig({ SHADOW_ENABLED: "1", SHADOW_MAX_BYTES: "" }).problem, undefined, "empty = default (compose passes \"\")");
});

test("disk budget: a global cap above half the free space is refused; a missing state dir is measured on its parent", () => {
  const free = (bytes) => () => ({ bavail: bytes / 4096, bsize: 4096 });
  assert.match(diskBudgetProblem("/x", 1024 ** 3, free(1024 ** 3)), /more than half/);
  assert.equal(diskBudgetProblem("/x", 1024 ** 3, free(4 * 1024 ** 3)), undefined);
  const seen = [];
  diskBudgetProblem(path.join(tmp("disk"), "not", "yet", "made"), 1, (p) => { seen.push(p); return { bavail: 1e9, bsize: 4096 }; });
  assert.equal(existsSync(seen[0]), true, "statfs runs on the nearest existing directory");
});

test("boot: a cap beyond half the disk, or a malformed cap, keeps Shadow closed (503) and logs why", async () => {
  for (const [env, reason] of [[{ SHADOW_MAX_BYTES: String(10 ** 15) }, /more than half/], [{ SHADOW_ACCOUNT_MAX_BYTES: "ten" }, /SHADOW_ACCOUNT_MAX_BYTES/]]) {
    const s = await boot(env);
    try {
      const r = await call(s.url, acctToken(), "shadow_list_sessions", {});
      assert.equal(r.status, 503);
      const line = s.logs.find((l) => l.includes("shadow_unavailable"));
      assert.ok(line, "logged");
      assert.match(JSON.parse(line).reason, reason);
    } finally {
      await s.close();
    }
  }
});

test("p11: the per-account and global caps from the environment hold through the real server", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const s = await boot({ SHADOW_ACCOUNT_MAX_BYTES: String(300 * 1024), SHADOW_MAX_BYTES: String(1024 * 1024) });
  try {
    const content = "x".repeat(30 * 1024);
    const fill = async (token) => {
      for (let sessions = 0; sessions < 10; sessions++) {
        const st = await call(s.url, token, "shadow_start_session", { title: "fill" });
        if (st.isError) return st.value.error;
        for (;;) {
          const r = await call(s.url, token, "shadow_record", { session_id: st.value.session_id, agent: "agent", kind: "message", content });
          if (!r.isError) continue;
          if (r.value.error === "SHADOW_LIMIT_SESSION_SIZE") break;
          return r.value.error;
        }
      }
      return "never stopped";
    };
    assert.equal(await fill(acctToken()), "SHADOW_LIMIT_ACCOUNT_STORAGE", "one account stops at its 300 KB");
    // Three more accounts reach the 1 MB global cap; then nobody can start a session.
    const stops = [];
    for (let i = 0; i < 4; i++) stops.push(await fill(acctToken()));
    assert.ok(stops.includes("SHADOW_STORAGE_FULL"), JSON.stringify(stops));
    const honest = await call(s.url, acctToken(), "shadow_start_session", { title: "honest" });
    assert.equal(honest.value.error, "SHADOW_STORAGE_FULL");
  } finally {
    await s.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("purge script: owner keys match the store; dry run by default; --apply deletes by owner and by age, links included", async () => {
  for (const id of ["acct_AAAAAAAAAAAAAAAAAAAAAA", "jti:123", "tok:abc"]) assert.equal(purgeLib.ownerKeyOf(id), storeOwnerKeyOf(id));
  assert.equal(purgeLib.parseDuration("7d"), 7 * 86_400_000);
  assert.equal(purgeLib.parseDuration("12h"), 12 * 3_600_000);
  assert.equal(purgeLib.parseDuration("7 days"), undefined);

  const dir = tmp("purge");
  let clock = Date.UTC(2026, 10, 2, 12, 0, 0);
  const svc = new ShadowService({ stateDir: dir, ledger: () => new FakeLedger(), log: () => {}, sleep: async () => {}, now: () => new Date(clock) });
  svc.sweep();
  const A = "acct_aaaaaaaaaaaaaaaaaaaaaa";
  const B = "acct_bbbbbbbbbbbbbbbbbbbbbb";
  const old = await svc.startSession(A, { title: "old secret title" }, "https://x");
  clock += 10 * 86_400_000;
  const recent = await svc.startSession(A, { title: "recent" }, "https://x");
  const other = await svc.startSession(B, { title: "B's" }, "https://x");
  const capOf = (s) => s.links.packet.split("/p/")[1].replace(".json", "");
  const run = (...args) => spawnSync(process.execPath, [PURGE, "--state-dir", dir, ...args], { encoding: "utf8" });

  const none = run();
  assert.equal(none.status, 2, "a selector is required");
  const dry = run("--owner", A);
  assert.equal(dry.status, 0, dry.stderr);
  assert.match(dry.stdout, /dry run: would delete 2 session\(s\)/);
  assert.equal(dry.stdout.includes("secret title"), false, "titles are never printed");
  assert.ok(await svc.getSession(A, { session_id: old.session_id }, "https://x"), "dry run deleted nothing");

  // Age only: the 10-day-old session (computed with the script's own clock, now).
  const byAge = purgeLib.findSessions(dir, { olderThanMs: 5 * 86_400_000, nowMs: clock });
  assert.deepEqual(byAge.map((x) => x.sessionId), [old.session_id]);
  const capsBefore = readdirSync(path.join(dir, "caps")).length;
  purgeLib.purge(dir, byAge);
  await assert.rejects(svc.getSession(A, { session_id: old.session_id }, "https://x"), (e) => e.code === "SHADOW_NOT_FOUND");
  assert.equal((await fetchLink(svc, capOf(old))), undefined, "its link is gone too");
  assert.equal(readdirSync(path.join(dir, "caps")).length, capsBefore - 1);

  const applied = run("--owner", A, "--apply");
  assert.equal(applied.status, 0, applied.stderr);
  assert.match(applied.stdout, /deleted 1 session\(s\)/);
  await assert.rejects(svc.getSession(A, { session_id: recent.session_id }, "https://x"), (e) => e.code === "SHADOW_NOT_FOUND");
  assert.equal((await svc.getSession(B, { session_id: other.session_id }, "https://x")).title, "B's", "another owner is untouched");
});

async function fetchLink(svc, cap) {
  try {
    return await svc.linkBody(cap, "packet");
  } catch {
    return undefined;
  }
}
