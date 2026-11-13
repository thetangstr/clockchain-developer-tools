// Hosted Shadow over the real runHttp wiring: the SHADOW_ENABLED gate, /mcp's authentication on /shadow/mcp, owner
// identity (acct, jti, static token; never sub), the tool surface, and the public capability links.
import assert from "node:assert/strict";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { mintAgentToken, mintToken, mintTrialToken, mintHandshakeSessionToken } from "../dist/token.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { ASKED_INSTRUCTIONS, shadowOwnerFromClaims } from "../dist/shadow/mcp.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { SUMMARY_CSP } from "../dist/shadow/lib/summary.js";
import { parseStrict } from "../dist/shadow/lib/profile.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const SECRET = "shadow-http-test-secret";
const STATIC = "static-shadow-token";
const ACCEPT = "application/json, text/event-stream";
const ENV_KEYS = [
  "PORT", "MCP_PORT", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "MCP_AUTH_TOKENS", "MCP_TOKEN_SIGNING_SECRET", "MCP_RATE_PER_MIN", "MCP_SURFACE",
  "SHADOW_LINKS_PER_MINUTE", "SHADOW_ALLOW_NON_ACCT", "MCP_REQUIRE_AUTH", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_TRUSTED_PROXY",
  "SHADOW_LINK_CONCURRENCY", "SHADOW_LINK_PER_CLIENT", "SHADOW_LINK_IDLE_MS", "SHADOW_LINK_MAX_MS",
  "MCP_STATE_DIR", "MCP_AGENT_KEYS", "MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR",
];
const SHADOW_TOOLS = ["clockchain_log_level", "shadow_start_session", "shadow_record", "shadow_checkpoint", "shadow_close_session", "shadow_get_session", "shadow_list_sessions", "shadow_verify", "shadow_revoke_links", "shadow_delete_session"];

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
/** A token as the OAuth token endpoint mints it: a signed-in account. */
const acctToken = (acct = "acct_" + randomBytes(16).toString("base64url")) => signedToken({ acct });

test("off by default: /shadow/* falls through to the handling it had before Shadow, nothing is created, /mcp keeps 50 tools", async () => {
  const stateDir = path.join(mkdtempSync(path.join(tmpdir(), "shadow-off-")), "state");
  const app = await boot({ SHADOW_STATE_DIR: stateDir });
  try {
    const page = async (p) => {
      const res = await fetch(`${app.url}${p}`, { headers: { accept: "text/html" } });
      return { status: res.status, type: res.headers.get("content-type"), body: await res.text() };
    };
    const landing = await page("/");
    for (const p of ["/shadow", "/shadow/connect", "/shadow/s/AAAAAAAAAAAAAAAAAAAAAA", "/shadow/p/AAAAAAAAAAAAAAAAAAAAAA.json"]) {
      assert.deepEqual(await page(p), landing, `${p} is the landing page, as before`);
    }
    const mcp401 = await rpc(`${app.url}/mcp`, "tools/list", {});
    const shadow401 = await rpc(`${app.url}/shadow/mcp`, "tools/list", {});
    assert.deepEqual(shadow401, mcp401, "the same 401 as /mcp");
    const list = await rpc(`${app.url}/mcp`, "tools/list", {}, { bearer: STATIC });
    assert.equal(list.body.result.tools.length, 50);
    const fallThrough = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: STATIC });
    assert.equal(fallThrough.body.result.tools.length, 50, "/shadow/mcp is the /mcp surface when Shadow is off, as before");
    assert.equal(existsSync(stateDir), false);
  } finally {
    await app.close();
  }
});

test("enabled: /mcp is unchanged, /shadow/mcp has the Shadow tools and its instructions", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-on-")) });
  try {
    const list = await rpc(`${app.url}/mcp`, "tools/list", {}, { bearer: STATIC });
    assert.equal(list.body.result.tools.length, 50);
    assert.ok(!list.body.result.tools.some((t) => t.name.startsWith("shadow_")));
    const account = { bearer: acctToken() };
    const tools = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, account);
    assert.deepEqual(tools.body.result.tools.map((t) => t.name).sort(), [...SHADOW_TOOLS].sort());
    for (const t of tools.body.result.tools.filter((x) => ["shadow_start_session", "shadow_close_session", "shadow_get_session"].includes(x.name)))
      assert.match(t.description, /kept 30 days.*revokes the link/, t.name);
    const init = await rpc(`${app.url}/shadow/mcp`, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } }, account);
    assert.equal(init.body.result.instructions, ASKED_INSTRUCTIONS);
    assert.match(init.body.result.instructions, /shadow_start_session.*\n.*shadow_record/s);
    assert.match(init.body.result.instructions, /kept on this server for 30\s+days/);
    assert.match(init.body.result.instructions, /unless\s+the person revokes the link/);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("auth matrix (with the test-only SHADOW_ALLOW_NON_ACCT=1): /mcp's credentials work, everything else gets /mcp's own 401", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-auth-")), SHADOW_ALLOW_NON_ACCT: "1" });
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
      assert.equal(r.body.result.tools.length, SHADOW_TOOLS.length, label);
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

test("owner identity (with SHADOW_ALLOW_NON_ACCT=1): acct when present, else the token's jti; a forged or shared sub never grants access", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-owner-")), SHADOW_ALLOW_NON_ACCT: "1" });
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
  const token = acctToken();
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
    assert.match(refused.value.message, /^Nothing was recorded: .* never records/);
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
    const token = acctToken();
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
  const app = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "shadow-open-")), MCP_AUTH_TOKENS: "", SHADOW_ALLOW_NON_ACCT: "1" });
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

// ---- agent keys (MCP_AGENT_KEYS=1): an agent's own key owns its records by its root key, with Starter limits ----

const PUBLIC = "https://mcp.example.test";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const CANCELLED = "This agent key was cancelled or replaced; sign in again with your current key.";

async function freeLoopbackPort() {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

/** runHttp with OAuth, Shadow and (unless overridden) agent keys on; retries when another test takes the probed port. */
async function bootAgentKeys(env = {}) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  const stateDir = mkdtempSync(path.join(tmpdir(), "shadow-ak-state-"));
  const shadowDir = mkdtempSync(path.join(tmpdir(), "shadow-ak-"));
  let server;
  for (let attempt = 1; ; attempt++) {
    Object.assign(process.env, {
      MCP_PORT: String(await freeLoopbackPort()), MCP_AUTH_TOKENS: STATIC, MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_STATE_DIR: stateDir,
      MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "1", SHADOW_ENABLED: "1", SHADOW_STATE_DIR: shadowDir,
    }, env);
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
    try {
      server = await runHttp();
      if (!server.listening) await once(server, "listening");
    } catch (e) {
      if (e?.code !== "EADDRINUSE" || attempt >= 5) throw e;
      continue;
    }
    let reached = false;
    const mark = () => { reached = true; };
    server.prependListener("request", mark);
    await fetch(`http://127.0.0.1:${server.address().port}/health`).then((r) => r.arrayBuffer()).catch(() => {});
    server.removeListener("request", mark);
    if (reached) break;
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
    assert.ok(attempt < 5, "no 127.0.0.1 port reached this server in 5 tries");
  }
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url,
    shadowDir,
    /** The same public book the server reads (one file per key on disk), for replacing and revoking keys. */
    book: new AgentKeyBook({ dir: path.join(stateDir, "agent-keys"), now: () => new Date() }),
    /** A Starter token for `agent` from the real client_credentials grant. */
    async tokenFor(agent) {
      const res = await fetch(`${url}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "client_credentials", client_assertion_type: JWT_BEARER, client_assertion: agent.assertion(`${PUBLIC}/oauth/token`) }),
      });
      const body = await res.json();
      assert.equal(res.status, 200, JSON.stringify(body));
      return body.access_token;
    },
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

const sessionDir = (app, ownerId, sessionId) => path.join(app.shadowDir, "owners", ownerKeyOf(ownerId), "sessions", sessionId);

async function mcpCall(app, name, args, cred) {
  const { status, body } = await rpc(`${app.url}/mcp`, "tools/call", { name, arguments: args }, cred);
  assert.equal(status, 200, JSON.stringify(body));
  return body.result;
}

test("shadowOwnerFromClaims: ak:<root> for an agent key whose root is known; acct keeps precedence; no root, the jti as before", () => {
  const akf = "ab".repeat(32);
  const root = "cd".repeat(32);
  assert.equal(shadowOwnerFromClaims({ jti: "j1", akf }, "raw", root), `ak:${root}`);
  assert.equal(shadowOwnerFromClaims({ jti: "j1", akf, acct: "acct_" + "A".repeat(22) }, "raw", root), "acct_" + "A".repeat(22));
  assert.equal(shadowOwnerFromClaims({ jti: "j1", akf }, "raw"), "jti:j1", "no book: not an agent");
  assert.equal(shadowOwnerFromClaims({ jti: "j1" }, "raw", root), "jti:j1", "no akf: not an agent");
  assert.equal(shadowOwnerFromClaims({ jti: "j1", akf }, "raw", "not-a-fingerprint"), "jti:j1");
});

test("an agent token opens /shadow/mcp and owns by ak:<root>", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await bootAgentKeys();
  try {
    const agent = makeAgentKey();
    const token = await app.tokenFor(agent);
    const tools = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: token });
    assert.equal(tools.status, 200, JSON.stringify(tools.body));
    // With sign-in on, every endpoint lists clockchain_delete_account; for an agent it answers ACCOUNT_REQUIRED. With
    // agent keys on, shadow_sign_checkpoint is listed too.
    assert.deepEqual(tools.body.result.tools.map((t) => t.name).sort(), [...SHADOW_TOOLS, "clockchain_delete_account", "shadow_sign_checkpoint"].sort());
    assert.equal((await call(app, "clockchain_delete_account", { confirm: true }, { bearer: token })).value.error, "ACCOUNT_REQUIRED");
    const { value: s } = await call(app, "shadow_start_session", { title: "agent's" }, { bearer: token });
    assert.ok(existsSync(sessionDir(app, `ak:${agent.fingerprint}`, s.session_id)), "stored under ak:<root>");
    // Another token from the same key is the same owner; another agent and an account are not.
    const again = await app.tokenFor(agent);
    assert.equal((await call(app, "shadow_get_session", { session_id: s.session_id }, { apiKey: again })).value.title, "agent's");
    const stranger = await app.tokenFor(makeAgentKey());
    assert.equal((await call(app, "shadow_get_session", { session_id: s.session_id }, { bearer: stranger })).value.error, "SHADOW_NOT_FOUND");
    assert.equal((await call(app, "shadow_get_session", { session_id: s.session_id }, { bearer: acctToken() })).value.error, "SHADOW_NOT_FOUND");
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("an agent signs its own checkpoint over /shadow/mcp, with the key its token names", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await bootAgentKeys();
  try {
    const agent = makeAgentKey();
    const token = await app.tokenFor(agent);
    const { value: s } = await call(app, "shadow_start_session", { title: "agent's", agents: [{ id: "planner" }] }, { bearer: token });
    await call(app, "shadow_record", { session_id: s.session_id, agent: "planner", kind: "task", content: "Find flights" }, { bearer: token });
    const { value: cp } = await call(app, "shadow_checkpoint", { session_id: s.session_id }, { bearer: token });
    assert.match(cp.sign.hash, /^[0-9a-f]{64}$/);
    // A token of another agent can't see the session; an account isn't an agent owner.
    const stranger = await app.tokenFor(makeAgentKey());
    assert.equal((await call(app, "shadow_sign_checkpoint", { session_id: s.session_id, hash: cp.sign.hash, signature: agent.signHash(cp.sign.hash) }, { bearer: stranger })).value.error, "SHADOW_NOT_FOUND");
    assert.equal((await call(app, "shadow_sign_checkpoint", { session_id: s.session_id, hash: cp.sign.hash, signature: agent.signHash(cp.sign.hash) }, { bearer: acctToken() })).value.error, "not_agent_owner");
    const { value: signed } = await call(app, "shadow_sign_checkpoint", { session_id: s.session_id, hash: cp.sign.hash, signature: agent.signHash(cp.sign.hash) }, { bearer: token });
    assert.equal(signed.checkpoint.status, "anchored", JSON.stringify(signed));
    assert.equal(signed.checkpoint.checkpoint_hash, cp.sign.hash);
    // After replace, the old key's tokens stop, and the new key signs for the same records.
    const next = makeAgentKey();
    app.book.replace(agent.fingerprint, next.publicKeyPem);
    const nextToken = await app.tokenFor(next);
    await call(app, "shadow_record", { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." }, { bearer: nextToken });
    const { value: cp2 } = await call(app, "shadow_checkpoint", { session_id: s.session_id }, { bearer: nextToken });
    assert.equal((await call(app, "shadow_sign_checkpoint", { session_id: s.session_id, hash: cp2.sign.hash, signature: agent.signHash(cp2.sign.hash) }, { bearer: nextToken })).value.error, "bad_signature");
    const { value: signed2 } = await call(app, "shadow_sign_checkpoint", { session_id: s.session_id, hash: cp2.sign.hash, signature: next.signHash(cp2.sign.hash) }, { bearer: nextToken });
    assert.equal(signed2.checkpoint.status, "anchored", JSON.stringify(signed2));
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("after replace, a token from the new key owns the same sessions", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await bootAgentKeys();
  try {
    const first = makeAgentKey();
    const oldToken = await app.tokenFor(first);
    const { value: s } = await call(app, "shadow_start_session", { title: "kept across keys" }, { bearer: oldToken });
    const second = makeAgentKey();
    app.book.replace(first.fingerprint, second.publicKeyPem);
    const newToken = await app.tokenFor(second);
    assert.equal((await call(app, "shadow_get_session", { session_id: s.session_id }, { bearer: newToken })).value.title, "kept across keys");
    const { value: listed } = await call(app, "shadow_list_sessions", {}, { bearer: newToken });
    assert.deepEqual(listed.sessions.map((x) => x.session_id), [s.session_id]);
    const { value: s2 } = await call(app, "shadow_start_session", { title: "new key" }, { bearer: newToken });
    assert.ok(existsSync(sessionDir(app, `ak:${first.fingerprint}`, s2.session_id)), "still owned by the first key, the root");
    // Replacing usually follows a compromise: the old key's tokens stop working at once.
    const refused = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: oldToken });
    assert.equal(refused.status, 401);
    assert.deepEqual(refused.body, { error: "invalid_token", message: CANCELLED });
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("a token minted before revoke is refused after it", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await bootAgentKeys();
  try {
    const agent = makeAgentKey();
    const token = await app.tokenFor(agent);
    assert.equal((await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: token })).status, 200);
    assert.equal((await rpc(`${app.url}/mcp`, "tools/list", {}, { bearer: token })).status, 200);
    app.book.revoke(agent.fingerprint);
    for (const endpoint of ["/shadow/mcp", "/mcp"]) {
      const res = await fetch(`${app.url}${endpoint}`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      });
      assert.equal(res.status, 401, endpoint);
      assert.match(res.headers.get("www-authenticate") ?? "", /error="invalid_token"/, endpoint);
      assert.equal(res.headers.get("cache-control"), "no-store", endpoint);
      assert.deepEqual(await res.json(), { error: "invalid_token", message: CANCELLED }, endpoint);
    }
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("a starter token cannot call timer_set or alarm_set on /mcp", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await bootAgentKeys();
  try {
    const token = await app.tokenFor(makeAgentKey());
    const list = await rpc(`${app.url}/mcp`, "tools/list", {}, { bearer: token });
    assert.equal(list.body.result.tools.length, 50, "the tool list is unchanged");
    const calls = [
      ["timer_set", { delay_ms: 60_000 }],
      ["alarm_set", { fire_at: new Date(Date.now() + 3_600_000).toISOString() }],
      ["timer_list", {}],
    ];
    for (const [name, args] of calls) {
      const result = await mcpCall(app, name, args, { bearer: token });
      assert.equal(result.isError, true, name);
      const body = JSON.parse(result.content[0].text);
      assert.equal(body.error, "not_on_starter", name);
      assert.equal(body.tool, name);
      assert.match(body.message, /Starter/);
    }
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("account tokens are unchanged", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await bootAgentKeys();
  try {
    const account = { bearer: acctToken() };
    const { value: s } = await call(app, "shadow_start_session", { title: "account" }, account);
    assert.equal((await call(app, "shadow_get_session", { session_id: s.session_id }, account)).value.title, "account");
    // A keeper tool on /mcp reaches its handler, as before: no Starter refusal.
    const result = await mcpCall(app, "timer_list", {}, account);
    assert.doesNotMatch(result.content[0].text, /not_on_starter/);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});

test("with MCP_AGENT_KEYS off, an akf token gains nothing: Shadow says account_required and /mcp treats it as a demo token", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const app = await bootAgentKeys({ MCP_AGENT_KEYS: undefined });
  try {
    const agent = makeAgentKey();
    const { token } = mintAgentToken(SECRET, 3600, Math.floor(Date.now() / 1000), randomUUID(), agent.fingerprint);
    const shadow = await rpc(`${app.url}/shadow/mcp`, "tools/list", {}, { bearer: token });
    assert.equal(shadow.status, 403);
    assert.equal(shadow.body.error, "account_required");
    const result = await mcpCall(app, "timer_list", {}, { bearer: token });
    assert.doesNotMatch(result.content[0].text, /not_on_starter/, "today's demo-token rules");
    assert.equal(existsSync(path.join(app.shadowDir, "owners", ownerKeyOf(`ak:${agent.fingerprint}`))), false);
  } finally {
    await app.close();
    __setShadowLedgerForTests(undefined);
  }
});
