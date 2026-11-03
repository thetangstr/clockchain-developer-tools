// Hosted Shadow over the real runHttp wiring: the SHADOW_ENABLED gate, /mcp's authentication on /shadow/mcp, owner
// identity (acct, jti, static token; never sub), the tool surface, and the public capability links.
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { mintToken, mintTrialToken, mintHandshakeSessionToken } from "../dist/token.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { SHADOW_INSTRUCTIONS } from "../dist/shadow/mcp.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { SUMMARY_CSP } from "../dist/shadow/lib/summary.js";
import { parseStrict } from "../dist/shadow/lib/profile.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const SECRET = "shadow-http-test-secret";
const STATIC = "static-shadow-token";
const ACCEPT = "application/json, text/event-stream";
const ENV_KEYS = ["PORT", "MCP_PORT", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "MCP_AUTH_TOKENS", "MCP_TOKEN_SIGNING_SECRET", "MCP_RATE_PER_MIN", "MCP_SURFACE", "SHADOW_LINKS_PER_MINUTE"];
const SHADOW_TOOLS = ["shadow_start_session", "shadow_record", "shadow_checkpoint", "shadow_close_session", "shadow_get_session", "shadow_list_sessions", "shadow_verify"];

async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0", MCP_AUTH_TOKENS: STATIC, MCP_TOKEN_SIGNING_SECRET: SECRET }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

function headersFor(cred) {
  if (!cred) return {};
  if (cred.bearer) return { authorization: `Bearer ${cred.bearer}` };
  if (cred.apiKey) return { "x-api-key": cred.apiKey };
  return cred.headers;
}

async function rpc(url, method, params = {}, cred) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT, ...headersFor(cred) },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await res.text();
  const data = text.split("\n").find((l) => l.startsWith("data:"));
  let body;
  try { body = JSON.parse(data ? data.slice(5) : text); } catch { body = text; }
  return { status: res.status, body };
}

async function call(app, name, args, cred) {
  const { status, body } = await rpc(`${app.url}/shadow/mcp`, "tools/call", { name, arguments: args }, cred);
  assert.equal(status, 200, JSON.stringify(body));
  const result = body.result;
  return { isError: result.isError === true, value: JSON.parse(result.content[0].text) };
}

const b64 = (s) => Buffer.from(s, "utf8").toString("base64url");
/** A signed v1 cc_ token with arbitrary claims, as the OAuth token endpoint will mint (with `acct`). */
function signedToken(claims, secret = SECRET) {
  const now = Math.floor(Date.now() / 1000);
  const seg = b64(JSON.stringify({ v: 1, tier: "demo", iat: now, exp: now + 3600, jti: randomUUID(), ...claims }));
  return `cc_${seg}.${createHmac("sha256", secret).update(seg).digest("base64url")}`;
}

test("off by default: every /shadow path is 404, nothing is created, and /mcp keeps its 50 tools", async () => {
  const stateDir = path.join(mkdtempSync(path.join(tmpdir(), "shadow-off-")), "state");
  const app = await boot({ SHADOW_STATE_DIR: stateDir });
  try {
    for (const p of ["/shadow/mcp", "/shadow", "/shadow/s/AAAAAAAAAAAAAAAAAAAAAA", "/shadow/p/AAAAAAAAAAAAAAAAAAAAAA.json"]) {
      const res = await fetch(`${app.url}${p}`, { method: p === "/shadow/mcp" ? "POST" : "GET", headers: { authorization: `Bearer ${STATIC}`, accept: "text/html" } });
      assert.equal(res.status, 404, p);
      assert.deepEqual(await res.json(), { error: "not_found" });
    }
    const list = await rpc(`${app.url}/mcp`, "tools/list", {}, { bearer: STATIC });
    assert.equal(list.body.result.tools.length, 50);
    assert.equal(existsSync(stateDir), false);
  } finally {
    await app.close();
  }
});

test("enabled: /mcp is unchanged, /shadow/mcp has the seven Shadow tools and its instructions", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-on-")) });
  try {
    const list = await rpc(`${app.url}/mcp`, "tools/list", {}, { bearer: STATIC });
    assert.equal(list.body.result.tools.length, 50);
    assert.ok(!list.body.result.tools.some((t) => t.name.startsWith("shadow_")));
    const tools = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: STATIC });
    assert.deepEqual(tools.body.result.tools.map((t) => t.name).sort(), [...SHADOW_TOOLS].sort());
    const init = await rpc(`${app.url}/shadow/mcp`, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } }, { bearer: STATIC });
    assert.equal(init.body.result.instructions, SHADOW_INSTRUCTIONS);
    assert.match(init.body.result.instructions, /shadow_start_session.*\n.*shadow_record/s);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("auth matrix: /mcp's credentials work, everything else gets /mcp's own 401", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-auth-")) });
  try {
    const mcp401 = await rpc(`${app.url}/mcp`, "tools/list", {});
    assert.equal(mcp401.status, 401);
    const demo = mintToken(SECRET).token;
    const trial = mintTrialToken(SECRET, { eph: "did:key:z6Mk-test", ch: "web" }).token;
    const now = Math.floor(Date.now() / 1000);
    const scoped = mintHandshakeSessionToken(SECRET, { invitationId: randomUUID(), statementDigest: "a".repeat(64), iat: now, exp: now + 600, jti: randomUUID() }).token;
    const accepted = [
      ["static token, Bearer", { bearer: STATIC }],
      ["static token, x-api-key", { apiKey: STATIC }],
      ["signed demo token, Bearer", { bearer: demo }],
      ["signed demo token, x-api-key", { apiKey: demo }],
      ["signed trial token", { apiKey: trial }],
      ["signed token with an acct claim", { bearer: signedToken({ acct: "acct_" + "A".repeat(22) }) }],
    ];
    for (const [label, cred] of accepted) {
      const r = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, cred);
      assert.equal(r.status, 200, label);
      assert.equal(r.body.result.tools.length, 7, label);
    }
    const refused = [
      ["no credential", undefined],
      ["an unknown key (on /mcp it would be taken as a Clockchain key)", { apiKey: "not-a-token" }],
      ["a bring-your-own Clockchain key", { headers: { "x-clockchain-api-key": "ck_live_x", "x-clockchain-client-id": "c", "x-clockchain-wallet-id": "w" } }],
      ["an expired signed token", { bearer: mintToken(SECRET, 60, now - 3600).token }],
      ["a signed token with a bad signature", { bearer: demo.slice(0, -3) + "AAA" }],
      ["a token signed with another secret", { bearer: signedToken({}, "other-secret") }],
      ["a handshake session token (scoped to one handshake)", { bearer: scoped }],
      ["a wrong static token", { bearer: "static-shadow-tokeN" }],
    ];
    for (const [label, cred] of refused) {
      const r = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, cred);
      assert.equal(r.status, 401, label);
      assert.deepEqual(r.body, mcp401.body, `${label}: the same JSON 401 as /mcp`);
    }
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("owner identity: acct when present, else the token's jti; a forged or shared sub never grants access", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-owner-")) });
  try {
    // POST /token tokens with the same (unauthenticated) sub are different owners.
    const alice = mintToken(SECRET, 3600, undefined, "alice@example.com").token;
    const forged = mintToken(SECRET, 3600, undefined, "alice@example.com").token;
    const { value: s } = await call(app, "shadow_start_session", { title: "alice's" }, { bearer: alice });
    const steal = await call(app, "shadow_get_session", { session_id: s.session_id }, { bearer: forged });
    assert.equal(steal.isError, true);
    assert.equal(steal.value.error, "SHADOW_NOT_FOUND");
    const write = await call(app, "shadow_record", { session_id: s.session_id, agent: "agent", kind: "message", content: "x" }, { bearer: forged });
    assert.equal(write.value.error, "SHADOW_NOT_FOUND");
    assert.deepEqual((await call(app, "shadow_list_sessions", {}, { bearer: forged })).value.sessions, []);
    // The static token is its own owner too.
    assert.deepEqual((await call(app, "shadow_list_sessions", {}, { bearer: STATIC })).value.sessions, []);

    // Two OAuth tokens for one account share its sessions; another account does not see them.
    const acct = "acct_" + "b".repeat(22);
    const t1 = signedToken({ acct, sub: "anything" });
    const t2 = signedToken({ acct });
    const other = signedToken({ acct: "acct_" + "c".repeat(22), sub: "anything" });
    const { value: shared } = await call(app, "shadow_start_session", { title: "account session" }, { bearer: t1 });
    const seen = await call(app, "shadow_get_session", { session_id: shared.session_id }, { apiKey: t2 });
    assert.equal(seen.isError, false);
    assert.equal(seen.value.title, "account session");
    assert.equal((await call(app, "shadow_get_session", { session_id: shared.session_id }, { bearer: other })).value.error, "SHADOW_NOT_FOUND");
    // A malformed acct is never minted (mintToken refuses one), so verifyToken refuses the whole token:
    // it gets /mcp's 401 and owns nothing, rather than falling back to its jti.
    const odd = signedToken({ acct: "acct_short" });
    const refused = await rpc(`${app.url}/shadow/mcp`, "tools/call", { name: "shadow_get_session", arguments: { session_id: shared.session_id } }, { bearer: odd });
    assert.equal(refused.status, 401);
    assert.equal(refused.body.error, "unauthorized");
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("over HTTP: record, close, and anyone with a link can read the summary and the verifiable packet", async () => {
  const fake = new FakeLedger();
  __setShadowLedgerForTests(fake);
  const captured = [];
  const orig = { error: console.error, warn: console.warn, log: console.log };
  for (const k of Object.keys(orig)) console[k] = (...a) => { captured.push(a.map(String).join(" ")); };
  const token = mintToken(SECRET).token;
  let app;
  try {
    app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-flow-")) });
    const cred = { bearer: token };
    const { value: s } = await call(app, "shadow_start_session", { title: "HTTP flow", agents: [{ id: "assistant" }] }, cred);
    assert.match(s.links.viewer, new RegExp(`^${app.url}/shadow/s/[A-Za-z0-9_-]{22}$`));
    await call(app, "shadow_record", { session_id: s.session_id, agent: "assistant", kind: "task", content: "Summarise SECRET-CONTENT-91" }, cred);
    const r = await call(app, "shadow_record", { session_id: s.session_id, agent: "assistant", kind: "message", content: "Done: SECRET-CONTENT-91" }, cred);
    assert.equal(r.value.seq, 3);
    assert.match(r.value.hash, /^[0-9a-f]{64}$/);
    const refused = await call(app, "shadow_record", { session_id: s.session_id, agent: "assistant", kind: "message", content: { reasoning: "hidden" } }, cred);
    assert.equal(refused.isError, true);
    assert.equal(refused.value.error, "SHADOW_REASONING_REFUSED");
    assert.match(refused.value.message, /never recorded/);
    const cp = await call(app, "shadow_checkpoint", { session_id: s.session_id }, cred);
    assert.equal(cp.value.checkpoint.status, "anchored");
    const closed = await call(app, "shadow_close_session", { session_id: s.session_id, status: "succeeded" }, cred);
    assert.equal(closed.value.status, "closed");
    const verified = await call(app, "shadow_verify", { session_id: s.session_id }, cred);
    assert.equal(verified.value.result, "pass", JSON.stringify(verified.value.checks, null, 1));

    // The links: no auth, no-store, no CORS, CSP on the page.
    const page = await fetch(closed.value.links.viewer);
    assert.equal(page.status, 200);
    assert.equal(page.headers.get("cache-control"), "no-store");
    assert.equal(page.headers.get("access-control-allow-origin"), null);
    assert.equal(page.headers.get("content-security-policy"), `${SUMMARY_CSP}; frame-ancestors 'none'`);
    assert.equal(page.headers.get("referrer-policy"), "no-referrer");
    assert.match(await page.text(), /Result: pass/);
    const pkt = await fetch(closed.value.links.packet);
    assert.equal(pkt.status, 200);
    assert.equal(pkt.headers.get("cache-control"), "no-store");
    assert.equal(pkt.headers.get("access-control-allow-origin"), null);
    const doc = parseStrict(await pkt.text());
    const report = await verifyPacket(doc.packet, { pin: parseStrict(JSON.stringify(closed.value.pin)) });
    assert.equal(report.result, "pass", JSON.stringify(report.checks, null, 1));

    for (const bogus of ["/shadow/s/AAAAAAAAAAAAAAAAAAAAAA", "/shadow/p/AAAAAAAAAAAAAAAAAAAAAA.json", "/shadow/s/short", "/shadow/p/x.json", "/shadow/other"]) {
      const res = await fetch(`${app.url}${bogus}`);
      assert.equal(res.status, 404, bogus);
    }
    assert.equal((await fetch(closed.value.links.viewer, { method: "POST" })).status, 404);

    // Logs never carry content, link capabilities or tokens.
    const cap = new URL(closed.value.links.viewer).pathname.split("/").pop();
    const logText = captured.join("\n");
    for (const secret of ["SECRET-CONTENT-91", cap, token, closed.value.pin.publicKeyFingerprint]) assert.equal(logText.includes(secret), false, `logs contain ${secret.slice(0, 12)}`);
    assert.match(logText, /shadow_session_started/);
  } finally {
    for (const k of Object.keys(orig)) console[k] = orig[k];
    await app?.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("links are rate limited per IP, and /shadow/mcp tool calls share /mcp's per-caller limit", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-rl-")), SHADOW_LINKS_PER_MINUTE: "2", MCP_RATE_PER_MIN: "3" });
  try {
    const token = mintToken(SECRET).token;
    const { value: s } = await call(app, "shadow_start_session", { title: "rl" }, { bearer: token });
    assert.equal((await fetch(s.links.packet)).status, 200);
    assert.equal((await fetch(s.links.viewer)).status, 200);
    const limited = await fetch(s.links.viewer);
    assert.equal(limited.status, 429);
    assert.deepEqual(await limited.json(), { error: "rate_limited" });
    // Discovery is exempt (as on /mcp); the next two tool calls use up the bucket.
    assert.equal((await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: token })).status, 200);
    await call(app, "shadow_list_sessions", {}, { bearer: token });
    await call(app, "shadow_list_sessions", {}, { bearer: token });
    const over = await rpc(`${app.url}/shadow/mcp`, "tools/call", { name: "shadow_list_sessions", arguments: {} }, { bearer: token });
    assert.equal(over.status, 429);
    assert.equal(over.body.error, "rate_limited");
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("open mode (no MCP_AUTH_TOKENS, local use): a presented credential owns its sessions; none, or a forged signed token, is 401", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-open-")), MCP_AUTH_TOKENS: "" });
  try {
    assert.equal((await rpc(`${app.url}/shadow/mcp`, "tools/list", {})).status, 401);
    assert.equal((await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: signedToken({}, "other-secret") })).status, 401);
    const { value: s } = await call(app, "shadow_start_session", { title: "local" }, { apiKey: "local-dev" });
    assert.equal((await call(app, "shadow_get_session", { session_id: s.session_id }, { bearer: "local-dev" })).value.title, "local");
    assert.equal((await call(app, "shadow_get_session", { session_id: s.session_id }, { bearer: "someone-else" })).value.error, "SHADOW_NOT_FOUND");
    const signedOwner = mintToken(SECRET).token;
    assert.deepEqual((await call(app, "shadow_list_sessions", {}, { bearer: signedOwner })).value.sessions, []);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});
