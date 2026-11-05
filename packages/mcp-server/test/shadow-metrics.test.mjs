// /metrics: writes against MCP_LOG_BUDGET, Shadow bytes against its cap, accounts, anchors owed and the retention sweep.
// Totals only. No owner, session, account, key, token or link may appear in the output.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { ShadowService } from "../dist/shadow/service.js";
import { __resetSharedLogBudget, createLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const PUBLIC = "https://mcp.example.test";
const PLAIN = "/shadow/mcp";
const CB = "https://claude.ai/api/mcp/auth_callback";
const METRICS = "metrics-test-token";
const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "SHADOW_PREVIEW_AUTO_LOG", "SHADOW_MAX_BYTES", "MCP_LOG_BUDGET", "MCP_METRICS_TOKEN"];
const tmp = (label) => mkdtempSync(path.join(tmpdir(), `shadow-metrics-${label}-`));

async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  const fake = new FakeLedger();
  __setShadowLedgerForTests(fake);
  __resetSharedLogBudget();
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  const stateDir = tmp("state");
  Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_TOKEN_SIGNING_SECRET: "metrics-secret", MCP_METRICS_TOKEN: METRICS, MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"), MCP_PUBLIC_URL: PUBLIC, ...env });
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`, fake,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __setShadowLedgerForTests(undefined);
      __resetSharedLogBudget();
    },
  };
}

const scrape = async (base) => {
  const res = await fetch(`${base}/metrics`, { headers: { authorization: `Bearer ${METRICS}` } });
  assert.equal(res.status, 200);
  return res.text();
};
/** One series' value, or undefined when it has none. */
const value = (text, series) => {
  const line = text.split("\n").find((l) => l.startsWith(`${series} `));
  return line === undefined ? undefined : Number(line.slice(series.length + 1));
};

async function signUp(base) {
  const resource = `${PUBLIC}${PLAIN}`;
  const client = await (await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [CB], token_endpoint_auth_method: "none" }) })).json();
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", state: "s", resource });
  const html = await (await fetch(`${base}/oauth/authorize?${q}`, { headers: { accept: "text/html" } })).text();
  const request = /name="request" value="([^"]+)"/.exec(html)[1];
  const decide = (fields) => fetch(`${base}/oauth/authorize`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: PUBLIC }, body: new URLSearchParams({ request, ...fields }) });
  const keyHtml = await (await decide({ decision: "create", name: "Secret Company Name" })).text();
  const cont = await decide({ decision: "continue", grant: /name="grant" value="([^"]+)"/.exec(keyHtml)[1] });
  const code = new URL(cont.headers.get("location")).searchParams.get("code");
  const t = await (await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: client.client_id, code_verifier: verifier, resource }) })).json();
  return { token: t.access_token, key: /value="(cck_[A-Za-z0-9_-]{32})"/.exec(keyHtml)[1] };
}

const tool = async (base, token, name, args) => {
  const res = await fetch(`${base}${PLAIN}`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
  const text = await res.text();
  const body = res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : JSON.parse(text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop());
  return JSON.parse(body.result.content[0].text);
};

test("the numbers: budget used and limit, Shadow bytes and cap, accounts and cap, anchors owed, sweep age; and nothing that names anyone", async () => {
  const s = await boot({ MCP_OAUTH: "1", SHADOW_ENABLED: "1", MCP_LOG_BUDGET: "100", SHADOW_MAX_BYTES: "5000000" });
  try {
    const before = await scrape(s.url);
    assert.equal(value(before, "clockchain_log_budget_used"), 0);
    assert.equal(value(before, "clockchain_log_budget_limit"), 100);
    assert.equal(value(before, "clockchain_oauth_accounts"), 0);
    assert.equal(value(before, "clockchain_oauth_accounts_cap"), 50_000);
    assert.equal(value(before, "clockchain_shadow_state_bytes_cap"), 5_000_000);
    assert.equal(value(before, 'clockchain_shadow_anchors_owed{state="queued"}'), 0);
    assert.ok(value(before, "clockchain_shadow_last_sweep_age_seconds") >= 0, "the boot sweep ran");

    const a = await signUp(s.url);
    const started = await tool(s.url, a.token, "shadow_start_session", { title: "A very private title" });
    await tool(s.url, a.token, "shadow_record", { session_id: started.session_id, agent: "agent", kind: "task", content: "very private content" });
    await tool(s.url, a.token, "shadow_checkpoint", { session_id: started.session_id });

    const after = await scrape(s.url);
    assert.equal(value(after, "clockchain_oauth_accounts"), 1);
    assert.equal(value(after, "clockchain_log_budget_used"), s.fake.writes.length, "every ledger write counts");
    assert.ok(s.fake.writes.length >= 2);
    assert.ok(value(after, "clockchain_shadow_state_bytes") > 0);
    assert.equal(value(after, 'clockchain_shadow_anchors_owed{state="pending"}'), 0);

    // A write with no block yet shows as pending, until it lands.
    s.fake.confirm = false;
    await tool(s.url, a.token, "shadow_record", { session_id: started.session_id, agent: "agent", kind: "note", content: "more" });
    await tool(s.url, a.token, "shadow_checkpoint", { session_id: started.session_id });
    const pending = await scrape(s.url);
    assert.equal(value(pending, 'clockchain_shadow_anchors_owed{state="pending"}'), 1);

    // Nothing that names anyone, in any of them.
    for (const text of [before, after, pending]) {
      for (const secret of [a.key, a.token, started.session_id, started.links.viewer, new URL(started.links.viewer).pathname.split("/").pop(), "Secret Company Name", "very private", "A very private title", METRICS, "metrics-secret"]) {
        assert.equal(text.includes(secret), false, secret);
      }
      assert.doesNotMatch(text, /acct_|cck_|cc_[A-Za-z0-9]{8}/);
      for (const line of text.split("\n").filter((l) => l.startsWith("clockchain_shadow_") || l.startsWith("clockchain_oauth_") || l.startsWith("clockchain_log_budget_"))) {
        assert.match(line, /^clockchain_[a-z_]+(\{state="(queued|pending|failed)"\})? [0-9.]+$/, line);
      }
    }
  } finally {
    await s.close();
  }
});

test("with no cap the limit reads 0 and writes are still counted; with Shadow off its series stay empty, so a missing sweep age shows", async () => {
  const s = await boot({});
  try {
    const text = await scrape(s.url);
    assert.equal(value(text, "clockchain_log_budget_limit"), 0);
    assert.equal(value(text, "clockchain_log_budget_used"), 0);
    assert.equal(value(text, "clockchain_shadow_last_sweep_age_seconds"), undefined);
    assert.equal(value(text, "clockchain_shadow_state_bytes"), undefined);
    assert.equal(value(text, "clockchain_oauth_accounts"), undefined);
    assert.match(text, /# HELP clockchain_shadow_last_sweep_age_seconds/);
  } finally {
    await s.close();
  }
  const b = createLogBudget({});
  b.record();
  assert.deepEqual(b.usage(), { used: 1, limit: null });
  assert.equal(b.remaining(), null);
  b.check();
  const capped = createLogBudget({ MCP_LOG_BUDGET: "2" });
  capped.record();
  assert.deepEqual(capped.usage(), { used: 1, limit: 2 });
  assert.equal(capped.remaining(), 1);
});

test("anchors owed: counted across owners from memory, removed when they land or the session expires, and rebuilt by a sweep after a restart", async () => {
  const dir = tmp("backlog");
  const fake = new FakeLedger();
  let nowMs = Date.UTC(2026, 10, 5);
  const options = () => ({ stateDir: dir, ledger: () => fake, budget: () => createLogBudget({}), sleep: async () => {}, log: () => {}, now: () => new Date(nowMs), limits: { anchorWaitMs: 0 } });
  const svc = new ShadowService(options());
  svc.sweep();
  const A = "acct_AAAAAAAAAAAAAAAAAAAAAA", B = "acct_BBBBBBBBBBBBBBBBBBBBBB";
  const a = await svc.startSession(A, { title: "a" }, "https://x.test");
  const b = await svc.startSession(B, { title: "b" }, "https://x.test");
  assert.deepEqual(svc.stats().anchors, { queued: 0, pending: 0, failed: 0 });

  fake.down = true;
  for (const [o, s] of [[A, a], [B, b]]) {
    await svc.record(o, { session_id: s.session_id, agent: "agent", kind: "task", content: "x" });
    await svc.checkpoint(o, { session_id: s.session_id });
  }
  assert.deepEqual(svc.stats().anchors, { queued: 2, pending: 0, failed: 0 });

  // A restart: nothing in memory until the boot sweep reads it back.
  const next = new ShadowService(options());
  assert.deepEqual(next.stats().anchors, { queued: 0, pending: 0, failed: 0 });
  assert.equal(next.stats().lastSweepMs, undefined);
  next.sweep();
  assert.deepEqual(next.stats().anchors, { queued: 2, pending: 0, failed: 0 });
  assert.equal(next.stats().lastSweepMs, nowMs);

  // One lands.
  fake.down = false;
  await next.checkpoint(A, { session_id: a.session_id });
  assert.deepEqual(next.stats().anchors, { queued: 1, pending: 0, failed: 0 });

  // The other expires.
  nowMs += 31 * 86_400_000;
  next.sweep();
  assert.deepEqual(next.stats().anchors, { queued: 0, pending: 0, failed: 0 });
});
