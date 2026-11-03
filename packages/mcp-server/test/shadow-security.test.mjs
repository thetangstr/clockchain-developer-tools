// Regression tests for the hosted Shadow security review (findings 1-7). Each mirrors one of the review's proof
// scripts (secreview/public/*.mjs): heavy-dos and e2e-shadow slowread (1), shadow-proofs poison (2) and fill (3),
// e2e-shadow batch and batch-amp (4), flags-off-diff (5, with shadow-http's off-by-default test), reasoning (6).
import assert from "node:assert/strict";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import net from "node:net";
import { once } from "node:events";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { runHttp, rateLimitCost, createRateLimiter } from "../dist/http.js";
import { refuseReservedReference, guardReservedReferences, ReservedReferenceError } from "../dist/tools.js";
import { mintToken } from "../dist/token.js";
import { ShadowService, ShadowError } from "../dist/shadow/service.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { clientBucket } from "../dist/standalone-handshake/public-server.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const SECRET = "shadow-security-test-secret";
const STATIC = "static-shadow-security";
const ACCEPT = "application/json, text/event-stream";
const ENV_KEYS = [
  "PORT", "MCP_PORT", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "MCP_AUTH_TOKENS", "MCP_TOKEN_SIGNING_SECRET", "MCP_RATE_PER_MIN",
  "SHADOW_ALLOW_NON_ACCT", "MCP_REQUIRE_AUTH", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_TRUSTED_PROXY", "CLOCKCHAIN_ENDPOINT",
  "SHADOW_LINKS_PER_MINUTE", "SHADOW_LINK_CONCURRENCY", "SHADOW_LINK_PER_CLIENT", "SHADOW_LINK_IDLE_MS", "SHADOW_LINK_MAX_MS",
];
const OWNER = "acct_" + "S".repeat(22);

async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, {
    MCP_PORT: "0", MCP_AUTH_TOKENS: STATIC, MCP_TOKEN_SIGNING_SECRET: SECRET, CLOCKCHAIN_ENDPOINT: "http://127.0.0.1:9",
  }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    port: server.address().port,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

const b64 = (s) => Buffer.from(s, "utf8").toString("base64url");
function signedToken(claims) {
  const now = Math.floor(Date.now() / 1000);
  const seg = b64(JSON.stringify({ v: 1, tier: "demo", iat: now, exp: now + 3600, jti: randomUUID(), ...claims }));
  return `cc_${seg}.${createHmac("sha256", SECRET).update(seg).digest("base64url")}`;
}
const acctToken = () => signedToken({ acct: "acct_" + randomBytes(16).toString("base64url") });

async function post(url, body, headers = {}) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: ACCEPT, ...headers }, body: JSON.stringify(body) });
  const text = await res.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  let parsed;
  try { parsed = JSON.parse(data ? data.slice(5) : text); } catch { parsed = text; }
  return { status: res.status, headers: res.headers, body: parsed };
}
const rpcCall = (name, args, id = 1) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
async function tool(app, pathName, token, name, args) {
  const r = await post(`${app.url}${pathName}`, rpcCall(name, args), { authorization: `Bearer ${token}` });
  assert.equal(r.status, 200, JSON.stringify(r.body).slice(0, 300));
  const text = r.body.result.content[0].text;
  let value;
  try { value = JSON.parse(text); } catch { value = text; }
  return { isError: r.body.result.isError === true, value, text };
}

/** A session holding about `mb` MB of steps, written straight to a state directory the server will then serve. */
async function bigSession(dir, mb) {
  const svc = new ShadowService({ stateDir: dir, ledger: () => new FakeLedger(), log: () => {}, sleep: async () => {} });
  svc.sweep();
  const s = await svc.startSession(OWNER, { title: "big" }, "http://x");
  let content = "";
  while (Buffer.byteLength(content) < 32 * 1024 - 64) content += "abcdefghijklmnop";
  for (let i = 0; i * 32 * 1024 < mb * 1024 * 1024; i++) await svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind: "message", content: content + i });
  await svc.close(OWNER, { session_id: s.session_id }, "http://x");
  svc.stop();
  return { cap: s.links.packet.split("/p/")[1].replace(".json", ""), sessionId: s.session_id };
}

/** A client that sends a link request and never reads the response. */
async function stalled(port, pathName, headers = {}) {
  const sock = net.connect(port, "127.0.0.1");
  await once(sock, "connect");
  sock.pause();
  const extra = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join("");
  sock.write(`GET ${pathName} HTTP/1.1\r\nHost: 127.0.0.1\r\n${extra}\r\n`);
  return sock;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- finding 1: link bodies -----------------------------------------------------------------------------------------

test("finding 1 (heavy-dos): a link body is built once per (session, steps) and the same Buffer serves every reader", async () => {
  const fake = new FakeLedger();
  const svc = new ShadowService({ stateDir: mkdtempSync(path.join(tmpdir(), "sec-cache-")), ledger: () => fake, log: () => {}, sleep: async () => {} });
  svc.sweep();
  const s = await svc.startSession(OWNER, { title: "cache" }, "http://x");
  for (let i = 0; i < 20; i++) await svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind: "message", content: `step ${i} ${"x".repeat(4000)}` });
  const cap = s.links.packet.split("/p/")[1].replace(".json", "");
  const before = svc.linkBuildCount;
  // 40 simultaneous readers of a link never built before: one build, one Buffer, no SHADOW_BUSY.
  const bodies = await Promise.all(Array.from({ length: 40 }, () => svc.linkBody(cap, "summary")));
  assert.equal(svc.linkBuildCount - before, 1);
  assert.ok(bodies.every((b) => b === bodies[0]), "every reader shares one Buffer");
  const packets = await Promise.all(Array.from({ length: 40 }, () => svc.linkBody(cap, "packet")));
  assert.equal(svc.linkBuildCount - before, 2);
  assert.ok(packets.every((b) => b === packets[0]));
  for (let i = 0; i < 5; i++) await svc.linkBody(cap, "packet");
  assert.equal(svc.linkBuildCount - before, 2, "served from the cache");
  // A new step changes the record: rebuilt once, then cached again.
  await svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind: "message", content: "one more" });
  const next = await svc.linkBody(cap, "packet");
  assert.notEqual(next, packets[0]);
  await svc.linkBody(cap, "packet");
  assert.equal(svc.linkBuildCount - before, 3);
  assert.equal(JSON.parse(next.toString()).packet.events.length, 22, "session.opened, 20 steps and the new one");
});

test("finding 1 (slowread): stalled link readers are capped per client and globally, dropped when idle, and memory stays flat", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sec-slow-"));
  const { cap } = await bigSession(dir, 4);
  const app = await boot({
    SHADOW_ENABLED: "1", SHADOW_STATE_DIR: dir, MCP_OAUTH_TRUSTED_PROXY: "127.0.0.1",
    SHADOW_LINK_IDLE_MS: "800", SHADOW_LINKS_PER_MINUTE: "1000",
    SHADOW_LINK_CONCURRENCY: "4", // this test exercises the cap itself (production default: 32, follow-up finding 2)
  });
  const socks = [];
  try {
    const link = `/shadow/p/${cap}.json`;
    const size = (await (await fetch(app.url + link)).arrayBuffer()).byteLength;
    assert.ok(size > 4_000_000, `packet is ${size} bytes`);
    global.gc?.();
    const heap0 = process.memoryUsage().heapUsed;
    // Per client: one stalled reader holds the client's only slot; the next request from it is told to retry.
    socks.push(await stalled(app.port, link, { "x-forwarded-for": "203.0.113.7" }));
    await sleep(150);
    const second = await fetch(app.url + link, { headers: { "x-forwarded-for": "203.0.113.7" } });
    assert.equal(second.status, 503);
    assert.equal(second.headers.get("retry-after"), "5");
    assert.deepEqual(await second.json(), { error: "busy" });
    // IPv6 clients share a bucket per /64.
    socks.push(await stalled(app.port, link, { "x-forwarded-for": "2001:db8:1:2::10" }));
    await sleep(150);
    assert.equal((await fetch(app.url + link, { headers: { "x-forwarded-for": "2001:db8:1:2:ffff::99" } })).status, 503, "same /64");
    // Globally: four stalled readers in all, then everyone waits.
    socks.push(await stalled(app.port, link, { "x-forwarded-for": "198.51.100.1" }));
    socks.push(await stalled(app.port, link, { "x-forwarded-for": "198.51.100.2" }));
    await sleep(150);
    for (let i = 3; i < 30; i++) socks.push(await stalled(app.port, link, { "x-forwarded-for": `198.51.100.${i}` }));
    await sleep(300);
    assert.equal((await fetch(app.url + link, { headers: { "x-forwarded-for": "192.0.2.50" } })).status, 503, "global cap");
    global.gc?.();
    const growth = process.memoryUsage().heapUsed - heap0;
    assert.ok(growth < 3 * size, `heap grew ${growth} bytes with ${socks.length} stalled readers of a ${size}-byte link`);
    // Idle readers are dropped, and their slots come back.
    await sleep(1500);
    const after = await fetch(app.url + link, { headers: { "x-forwarded-for": "203.0.113.7" } });
    assert.equal(after.status, 200);
    assert.equal((await after.arrayBuffer()).byteLength, size);
  } finally {
    for (const s of socks) s.destroy();
    await app.close();
  }
});

test("finding 1: IPv6 link clients are bucketed by /64 with OAuth's helper", () => {
  assert.equal(clientBucket("2001:db8:1:2::10"), clientBucket("2001:db8:1:2:ffff::99"));
  assert.notEqual(clientBucket("2001:db8:1:2::10"), clientBucket("2001:db8:1:3::10"));
  assert.equal(clientBucket("203.0.113.7"), "203.0.113.7");
});

// ---- finding 2: reserved references ---------------------------------------------------------------------------------

test("finding 2 (poison): /mcp writes are refused when their final reference starts with shadow:", async () => {
  for (const ref of ["shadow:v1:6f1c0a3e-0000-4000-8000-000000000000", "SHADOW:v1:x", "  shadow:anything", "shadow:"]) {
    assert.throws(() => refuseReservedReference(ref), ReservedReferenceError, ref);
  }
  for (const ref of ["myapp:shadow:v1:x", "did:mint:shadow", "stopwatch:shadow:start", "tsa:shadow", "shadowy:v1:x"]) refuseReservedReference(ref);
  // The client guard backs up every write through the request's client (identities, stopwatch, TSA, handshakes).
  const writes = [];
  const client = guardReservedReferences({ log: async (e) => { writes.push(e.assetReferenceId); return { ledgerId: "l" }; } });
  await client.log({ assetHash: "a".repeat(64), assetReferenceId: "ok:1" });
  await assert.rejects(client.log({ assetHash: "a".repeat(64), assetReferenceId: "shadow:v1:x" }), ReservedReferenceError);
  assert.deepEqual(writes, ["ok:1"]);
});

test("finding 2 (poison over HTTP): log_action and attest_action refuse shadow: references before any network call, and the session still verifies", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "sec-poison-")) });
  try {
    const owner = acctToken();
    const { value: s } = await tool(app, "/shadow/mcp", owner, "shadow_start_session", { title: "honest work" });
    await tool(app, "/shadow/mcp", owner, "shadow_record", { session_id: s.session_id, agent: "agent", kind: "message", content: "step" });
    await tool(app, "/shadow/mcp", owner, "shadow_close_session", { session_id: s.session_id }, "http://x");
    const attacker = mintToken(SECRET).token;
    const hash = randomBytes(32).toString("hex");
    const attempts = [
      ["log_action", { asset_reference_id: `shadow:v1:${s.session_id}`, asset_hash: hash }],
      ["log_action", { did: "shadow", asset_reference_id: `v1:${s.session_id}`, asset_hash: hash }],
      ["log_action", { asset_reference_id: `Shadow:v1:${s.session_id}`, content: "x" }],
      ["attest_action", { agent_id: "shadow", action: "v1" }],
    ];
    for (const [name, args] of attempts) {
      const r = await tool(app, "/mcp", attacker, name, args);
      assert.equal(r.isError, true, name);
      assert.match(r.text, /reserved for hosted Shadow records/, `${name} ${JSON.stringify(args)}`);
    }
    // An ordinary reference is not refused for that reason (it fails later, on the unreachable test gateway).
    const plain = await tool(app, "/mcp", attacker, "log_action", { asset_reference_id: "my-app:1", asset_hash: hash });
    assert.doesNotMatch(plain.text, /reserved/);
    const v = await tool(app, "/shadow/mcp", owner, "shadow_verify", { session_id: s.session_id });
    assert.equal(v.value.result, "pass", JSON.stringify(v.value.checks));
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

// ---- finding 3: accounts only, per-account quotas -------------------------------------------------------------------

test("finding 3: /shadow/mcp needs a signed-in account; POST /token and static tokens get 403 with sign-in instructions", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "sec-acct-")) });
  try {
    const anon = (await (await fetch(`${app.url}/token`, { method: "POST" })).json()).token;
    for (const [label, token] of [["POST /token", anon], ["static MCP token", STATIC]]) {
      for (const body of [rpcCall("shadow_start_session", { title: "x" }), { jsonrpc: "2.0", id: 1, method: "tools/list" }]) {
        const r = await post(`${app.url}/shadow/mcp`, body, { authorization: `Bearer ${token}` });
        assert.equal(r.status, 403, label);
        assert.equal(r.body.error, "account_required");
        assert.match(r.body.message, /signed-in accounts only.*sign-in \(OAuth\)/);
        assert.equal(r.body.instructions, `${app.url}/shadow/connect`);
      }
    }
    const page = await fetch(`${app.url}/shadow/connect`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /connect with sign-in[\s\S]*cannot be revoked/);
    const ok = await post(`${app.url}/shadow/mcp`, rpcCall("shadow_list_sessions", {}), { authorization: `Bearer ${acctToken()}` });
    assert.equal(ok.status, 200);
    // No credential is still /mcp's 401 (that is what starts an OAuth client's sign-in).
    assert.equal((await post(`${app.url}/shadow/mcp`, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 401);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("finding 3: SHADOW_ALLOW_NON_ACCT is ignored when MCP_REQUIRE_AUTH is set, and production compose never passes it", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "sec-prod-")), SHADOW_ALLOW_NON_ACCT: "1", MCP_REQUIRE_AUTH: "1" });
  try {
    const r = await post(`${app.url}/shadow/mcp`, rpcCall("shadow_list_sessions", {}), { authorization: `Bearer ${STATIC}` });
    assert.equal(r.status, 403);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
  const infra = new URL("../../../infra/clockchain-mcp/", import.meta.url);
  for (const f of ["docker-compose.yml", "compose-up.sh"]) assert.doesNotMatch(readFileSync(new URL(f, infra), "utf8"), /SHADOW_ALLOW_NON_ACCT/, f);
  assert.match(readFileSync(new URL("compose-up.sh", infra), "utf8"), /^export MCP_REQUIRE_AUTH=1$/m);
});

test("finding 3 (fill): each account has a byte quota and a daily limit on session starts; the global caps still hold", async () => {
  const clock = { t: Math.floor(Date.now() / 1000) * 1000 }; // real time: the sweep compares with real file mtimes
  const svc = new ShadowService({
    stateDir: mkdtempSync(path.join(tmpdir(), "sec-quota-")), ledger: () => new FakeLedger(), log: () => {}, sleep: async () => {},
    now: () => new Date(clock.t), limits: { maxBytesPerOwner: 200 * 1024, maxSessionStartsPerOwnerPerDay: 3 },
  });
  svc.sweep();
  const a = "acct_" + "a".repeat(22), b = "acct_" + "b".repeat(22);
  const s = await svc.startSession(a, { title: "1" }, "http://x");
  let refused;
  for (let i = 0; i < 20 && !refused; i++) {
    try {
      await svc.record(a, { session_id: s.session_id, agent: "agent", kind: "message", content: "q".repeat(30 * 1024) });
    } catch (e) { refused = e; }
  }
  assert.ok(refused instanceof ShadowError);
  assert.equal(refused.code, "SHADOW_LIMIT_ACCOUNT_STORAGE");
  // Smaller steps still fit until the account is full; then a new session (which needs room too) is refused.
  for (let i = 0; i < 40; i++) {
    try {
      await svc.record(a, { session_id: s.session_id, agent: "agent", kind: "message", content: "q".repeat(1024) });
    } catch (e) {
      assert.equal(e.code, "SHADOW_LIMIT_ACCOUNT_STORAGE");
      refused = e;
      break;
    }
  }
  assert.match(refused.message, /^Your account's Shadow records use [\d.]+ MB of the 0\.2 MB it may keep\./);
  await assert.rejects(svc.startSession(a, { title: "2" }, "http://x"), (e) => e.code === "SHADOW_LIMIT_ACCOUNT_STORAGE");
  // Another account is unaffected; its own starts are limited per day.
  for (const t of ["1", "2", "3"]) await svc.startSession(b, { title: t }, "http://x");
  await assert.rejects(svc.startSession(b, { title: "4" }, "http://x"), (e) => e.code === "SHADOW_LIMIT_SESSION_STARTS");
  clock.t += 24 * 60 * 60_000;
  await svc.startSession(b, { title: "next day" }, "http://x");
  // The quota survives a restart (recomputed from disk).
  const again = new ShadowService({ stateDir: svc.store.root, ledger: () => new FakeLedger(), log: () => {}, sleep: async () => {}, now: () => new Date(clock.t), limits: { maxBytesPerOwner: 200 * 1024 } });
  await assert.rejects(again.record(a, { session_id: s.session_id, agent: "agent", kind: "message", content: "q".repeat(30 * 1024) }), (e) => e.code === "SHADOW_LIMIT_ACCOUNT_STORAGE");
});

// ---- finding 4: batches ------------------------------------------------------------------------------------------

test("finding 4 (batch, batch-amp): /shadow/mcp refuses JSON-RPC batches; nothing in them runs", async () => {
  const ledger = new FakeLedger();
  let reads = 0;
  for (const m of ["getLedgerEntry", "getBlock", "searchAsset", "verifyPackage"]) { const f = ledger[m].bind(ledger); ledger[m] = (...a) => { reads++; return f(...a); }; }
  __setShadowLedgerForTests(ledger);
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "sec-batch-")), MCP_RATE_PER_MIN: "30" });
  try {
    const token = acctToken();
    const { value: s } = await tool(app, "/shadow/mcp", token, "shadow_start_session", { title: "t" });
    reads = 0;
    const batch = Array.from({ length: 50 }, (_, i) => rpcCall("shadow_verify", { session_id: s.session_id }, 100 + i));
    const r = await post(`${app.url}/shadow/mcp`, batch, { authorization: `Bearer ${token}` });
    assert.equal(r.status, 400);
    assert.equal(r.body.error.code, -32600);
    assert.match(r.body.error.message, /batches are not supported/);
    assert.equal(reads, 0, "no shadow_verify ran");
    const recs = await post(`${app.url}/shadow/mcp`, [rpcCall("shadow_record", { session_id: s.session_id, agent: "agent", kind: "message", content: "x" })], { authorization: `Bearer ${token}` });
    assert.equal(recs.status, 400, "even a batch of one");
    assert.equal((await tool(app, "/shadow/mcp", token, "shadow_get_session", { session_id: s.session_id })).value.steps, 1);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("finding 4: on /mcp a batch is charged one rate-limit unit per message (lifecycle included, follow-up finding 1)", async () => {
  assert.equal(rateLimitCost({ jsonrpc: "2.0", id: 1, method: "tools/call" }), 1);
  assert.equal(rateLimitCost({ jsonrpc: "2.0", id: 1, method: "tools/list" }), 0, "a single discovery call stays free");
  assert.equal(rateLimitCost([{ method: "tools/list" }, { method: "tools/call" }, { method: "tools/call" }, { method: "ping" }]), 4);
  assert.equal(rateLimitCost([]), 1);
  const rl = createRateLimiter(3);
  assert.equal(rl.allow("k", 0, 4).allowed, false, "more than the window holds is refused whole");
  assert.equal(rl.allow("k", 0, 2).remaining, 1);
  assert.equal(rl.allow("k", 0, 2).allowed, false);
  assert.equal(rl.allow("k", 0).allowed, true);
  assert.equal(rl.allow("k", 0).allowed, false);

  const app = await boot({ MCP_RATE_PER_MIN: "3" });
  try {
    const auth = { authorization: `Bearer ${STATIC}` };
    const msg = (i) => ({ jsonrpc: "2.0", id: i, method: "resources/read", params: { uri: "x://y" } });
    const big = await post(`${app.url}/mcp`, [msg(1), msg(2), msg(3), msg(4)], auth);
    assert.equal(big.status, 429, "a batch of four does not fit three per minute");
    const discovery = await post(`${app.url}/mcp`, Array.from({ length: 10 }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/list" })), auth);
    assert.equal(discovery.status, 429, "discovery messages in a batch are charged too (follow-up finding 1)");
    assert.equal((await post(`${app.url}/mcp`, { jsonrpc: "2.0", id: 99, method: "tools/list" }, auth)).status, 200, "a single discovery call stays free");
    assert.equal((await post(`${app.url}/mcp`, [msg(5), msg(6)], auth)).status, 200);
    assert.equal((await post(`${app.url}/mcp`, msg(7), auth)).status, 200);
    assert.equal((await post(`${app.url}/mcp`, msg(8), auth)).status, 429, "two + one used the three");
  } finally {
    await app.close();
  }
});

// ---- finding 6: hidden reasoning in every field ------------------------------------------------------------------

test("finding 6 (reasoning): every content field of every kind is checked, tags and reasoning keys alike", async () => {
  const svc = new ShadowService({ stateDir: mkdtempSync(path.join(tmpdir(), "sec-reason-")), ledger: () => new FakeLedger(), log: () => {}, sleep: async () => {} });
  svc.sweep();
  const s = await svc.startSession(OWNER, { title: "t" }, "http://x");
  const tries = [
    ["message", "<think>secret plan</think> done"],
    ["message", { reasoning_content: "secret plan" }],
    ["tool_call", { tool: "search", args: { thinking: "secret plan", q: "x" } }],
    ["tool_call", { tool: "search", args: "<think>secret plan</think>" }],
    ["prompt", "<think>secret plan</think>"],
    ["file", { path: "notes.md", content: { reasoning_content: "secret plan" } }],
    ["file", { path: "notes.md", content: "<reasoning>secret plan</reasoning>" }],
    ["task", "<thinking>secret plan</thinking>"],
    ["tool_result", { tool: "x", result: { thoughts: "secret plan" } }],
    ["note", { thought: "secret plan" }],
  ];
  for (const [kind, content] of tries) {
    await assert.rejects(svc.record(OWNER, { session_id: s.session_id, agent: "agent", kind, content }), (e) => {
      assert.equal(e.code, "SHADOW_REASONING_REFUSED", `${kind} ${JSON.stringify(content)}`);
      assert.match(e.message, /^Nothing was recorded: content\S* looks like hidden model reasoning/);
      assert.match(e.message, /<think>, <thinking> or <reasoning> tag.*reasoning, thinking or thought, in every kind of step/);
      return true;
    });
  }
  const g = await svc.getSession(OWNER, { session_id: s.session_id }, "http://x");
  assert.equal(g.steps, 1, "nothing was recorded");
});
