// A person can delete a session, revoke its links, or delete their account, through tools. Links stop at once. Hashes stay
// on the ledger, and every result says so. The real HTTP server, a fake ledger, sign-in through the real pages.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { AccountStore } from "../dist/accounts.js";
import { __resetSharedLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const PUBLIC = "https://mcp.example.test";
const PLAIN = "/shadow/mcp";
const CHAT = "/shadow/chat/mcp";
const PREVIEW = "/shadow/preview/mcp";
const CB = "https://claude.ai/api/mcp/auth_callback";
const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "SHADOW_PREVIEW_AUTO_LOG", "MCP_LOG_BUDGET", "MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR", "MCP_OAUTH_APPROVALS_PER_HOUR"];
const tmp = (label) => mkdtempSync(path.join(tmpdir(), `shadow-delete-${label}-`));

async function boot(stateDir = tmp("state"), env = {}, fake = new FakeLedger()) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  __setShadowLedgerForTests(fake);
  __resetSharedLogBudget();
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  Object.assign(process.env, {
    MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_TOKEN_SIGNING_SECRET: "delete-test-secret", MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"),
    MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, SHADOW_ENABLED: "1", SHADOW_LAZY_AUTH: "1", MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR: "1000", MCP_OAUTH_APPROVALS_PER_HOUR: "1000", ...env,
  });
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`, fake, stateDir,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __setShadowLedgerForTests(undefined);
      __resetSharedLogBudget();
    },
  };
}

async function openPage(base, resource, cookie) {
  const client = await (await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [CB], token_endpoint_auth_method: "none" }) })).json();
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", state: "s", resource });
  const html = await (await fetch(`${base}/oauth/authorize?${q}`, { headers: { accept: "text/html", ...(cookie ? { cookie } : {}) } })).text();
  return { client, verifier, html, request: /name="request" value="([^"]+)"/.exec(html)[1] };
}
const decide = (base, fields) => fetch(`${base}/oauth/authorize`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: PUBLIC }, body: new URLSearchParams(fields) });
const exchange = (base, fields) => fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) });

async function signUp(base, name = "Acme") {
  const resource = `${PUBLIC}${PLAIN}`;
  const c = await openPage(base, resource);
  const created = await decide(base, { request: c.request, decision: "create", name });
  const keyHtml = await created.text();
  const cookie = (created.headers.get("set-cookie") ?? "").split(";")[0];
  const cont = await decide(base, { request: c.request, decision: "continue", grant: /name="grant" value="([^"]+)"/.exec(keyHtml)[1] });
  const code = new URL(cont.headers.get("location")).searchParams.get("code");
  const t = await (await exchange(base, { grant_type: "authorization_code", code, redirect_uri: CB, client_id: c.client.client_id, code_verifier: c.verifier, resource })).json();
  assert.ok(t.access_token, JSON.stringify(t));
  return { token: t.access_token, refresh: t.refresh_token, clientId: c.client.client_id, key: /value="(cck_[A-Za-z0-9_-]{32})"/.exec(keyHtml)[1], cookie };
}

const post = (base, p, method, params, token) => fetch(`${base}${p}`, {
  method: "POST",
  headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
});
const tool = async (base, token, name, args = {}, p = PLAIN) => {
  const res = await post(base, p, "tools/call", { name, arguments: args }, token);
  assert.equal(res.status, 200, `${name}: HTTP ${res.status}`);
  const text = await res.text();
  const { result } = res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : JSON.parse(text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop());
  return { isError: result.isError === true, value: JSON.parse(result.content[0].text) };
};

/** One closed session with a viewer page already read, so its body is in the server's link cache. */
async function closedSession(base, token, title = "A record", words = "private words") {
  const started = await tool(base, token, "shadow_start_session", { title });
  const id = started.value.session_id;
  await tool(base, token, "shadow_record", { session_id: id, agent: "agent", kind: "task", content: words });
  await tool(base, token, "shadow_record", { session_id: id, agent: "agent", kind: "message", content: "the answer" });
  await tool(base, token, "shadow_checkpoint", { session_id: id });
  const closed = await tool(base, token, "shadow_close_session", { session_id: id, status: "succeeded" });
  const links = closed.value.links;
  const local = (u) => new URL(u).pathname;
  assert.equal((await fetch(`${base}${local(links.viewer)}`)).status, 200);
  assert.equal((await fetch(`${base}${local(links.packet)}`)).status, 200);
  return { id, viewer: `${base}${local(links.viewer)}`, packet: `${base}${local(links.packet)}` };
}

const statusOf = async (url) => (await fetch(url)).status;

test("shadow_delete_session: the record and links go at once, the hashes stay and the result says so, and only its owner can do it", async () => {
  const s = await boot();
  try {
    const a = await signUp(s.url, "A");
    const b = await signUp(s.url, "B");
    const session = await closedSession(s.url, a.token);
    const other = await closedSession(s.url, a.token, "Another");
    const writes = s.fake.writes.length;
    assert.ok(writes > 0);

    // Not the owner: nothing happens, and the session isn't revealed.
    const refused = await tool(s.url, b.token, "shadow_delete_session", { session_id: session.id });
    assert.equal(refused.value.error, "SHADOW_NOT_FOUND");
    assert.equal(await statusOf(session.viewer), 200);

    const done = await tool(s.url, a.token, "shadow_delete_session", { session_id: session.id });
    assert.equal(done.isError, false);
    assert.equal(done.value.status, "deleted");
    assert.equal(done.value.links, "stopped");
    assert.equal(done.value.ledger.kept, true);
    assert.ok(done.value.ledger.fingerprints >= 2);
    assert.match(done.value.message, /links have stopped working/);
    assert.match(done.value.message, /hashes\) stay on the Clockchain ledger and can't be removed/);

    assert.equal(await statusOf(session.viewer), 404, "viewer, though its page was in the link cache");
    assert.equal(await statusOf(session.packet), 404);
    assert.equal((await tool(s.url, a.token, "shadow_get_session", { session_id: session.id })).value.error, "SHADOW_NOT_FOUND");
    assert.deepEqual((await tool(s.url, a.token, "shadow_list_sessions")).value.sessions.map((x) => x.session_id), [other.id]);
    assert.equal(s.fake.writes.length, writes, "deleting writes nothing to the ledger");

    // A repeat has no further effect.
    assert.equal((await tool(s.url, a.token, "shadow_delete_session", { session_id: session.id })).value.error, "SHADOW_NOT_FOUND");
    // The other session is untouched, and nothing of the deleted one is left on disk.
    assert.equal(await statusOf(other.viewer), 200);
    const shadowDir = path.join(s.stateDir, "shadow");
    assert.equal(findFile(shadowDir, session.id), false);
  } finally {
    await s.close();
  }
});

function findFile(dir, needle) {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    if (name.name.includes(needle)) return true;
    if (name.isDirectory() && findFile(path.join(dir, name.name), needle)) return true;
  }
  return false;
}

test("shadow_revoke_links: the links stop at once and for good, across a restart; the record stays, and the owner can still use it", async () => {
  const stateDir = tmp("state");
  let s = await boot(stateDir);
  try {
    const a = await signUp(s.url);
    const session = await closedSession(s.url, a.token);

    const done = await tool(s.url, a.token, "shadow_revoke_links", { session_id: session.id });
    assert.equal(done.value.status, "revoked");
    assert.equal(done.value.record, "kept");
    assert.match(done.value.message, /stopped working, and they can't be turned back on/);
    assert.equal(await statusOf(session.viewer), 404);
    assert.equal(await statusOf(session.packet), 404);

    const got = await tool(s.url, a.token, "shadow_get_session", { session_id: session.id });
    assert.equal(got.isError, false);
    assert.deepEqual(got.value.links, { viewer: null, packet: null });
    assert.match(got.value.links_note, /revoked/);
    assert.equal((await tool(s.url, a.token, "shadow_verify", { session_id: session.id })).value.result, "pass");
    assert.equal((await tool(s.url, a.token, "shadow_revoke_links", { session_id: session.id })).value.status, "already_revoked");

    await s.close();
    s = await boot(stateDir, {}, s.fake);
    assert.equal(await statusOf(s.url + new URL(session.viewer).pathname), 404);
    assert.deepEqual((await tool(s.url, a.token, "shadow_get_session", { session_id: session.id })).value.links, { viewer: null, packet: null });

    // An open session keeps recording after its links are revoked, and none come back at close.
    const open = (await tool(s.url, a.token, "shadow_start_session", { title: "Open" })).value;
    await tool(s.url, a.token, "shadow_revoke_links", { session_id: open.session_id });
    await tool(s.url, a.token, "shadow_record", { session_id: open.session_id, agent: "agent", kind: "task", content: "x" });
    const closed = await tool(s.url, a.token, "shadow_close_session", { session_id: open.session_id, status: "succeeded" });
    assert.deepEqual(closed.value.links, { viewer: null, packet: null });
    assert.match(closed.value.share, /revoked/);
    assert.equal(await statusOf(s.url + new URL(open.links.viewer).pathname), 404);
  } finally {
    await s.close();
  }
});

test("a revoked session on an endpoint that logs by default says so in its footer, with no dead link", async () => {
  const s = await boot(tmp("state"), { SHADOW_PREVIEW_AUTO_LOG: "1" });
  try {
    const a = await signUp(s.url);
    const first = (await tool(s.url, a.token, "shadow_log_step", { kind: "task", content: "x" }, PREVIEW)).value;
    await tool(s.url, a.token, "shadow_revoke_links", { session_id: first.session_id }, PREVIEW);
    const next = (await tool(s.url, a.token, "shadow_log_step", { session_id: first.session_id, kind: "note", content: "y" }, PREVIEW)).value;
    assert.equal(next.viewer, null);
    assert.match(next.show_user, /Viewer link revoked\./);
    assert.doesNotMatch(next.show_user, /shadow\/s\//);
  } finally {
    await s.close();
  }
});

for (const p of [PLAIN, CHAT, PREVIEW]) {
  test(`clockchain_delete_account on ${p}: asks first, then everything goes at once, and nothing of the account still works`, async () => {
    const stateDir = tmp("state");
    let s = await boot(stateDir, { SHADOW_PREVIEW_AUTO_LOG: "1" });
    try {
      const a = await signUp(s.url, "Secret Name");
      const keeper = await signUp(s.url, "Keeper");
      const session = await closedSession(s.url, a.token);
      const kept = await closedSession(s.url, keeper.token, "Kept", "the other account's words");
      const writes = s.fake.writes.length;

      // Without confirm: nothing changes.
      const asked = await tool(s.url, a.token, "clockchain_delete_account", {}, p);
      assert.equal(asked.value.status, "confirmation_needed");
      assert.deepEqual(asked.value.would_delete, { sessions: 1, steps: asked.value.would_delete.steps, links: "all of them" });
      assert.match(asked.value.message, /^Nothing was deleted\./);
      assert.match(asked.value.message, /fingerprint\(s\) \(hashes\) on the Clockchain ledger would stay/);
      assert.equal(await statusOf(session.viewer), 200);
      assert.equal((await tool(s.url, a.token, "clockchain_delete_account", { confirm: false }, p)).value.status, "confirmation_needed");

      const done = await tool(s.url, a.token, "clockchain_delete_account", { confirm: true }, p);
      assert.equal(done.isError, false);
      assert.equal(done.value.status, "deleted");
      assert.equal(done.value.sessions_deleted, 1);
      assert.equal(done.value.ledger.kept, true);
      assert.match(done.value.message, /stay on the Clockchain ledger, because they can't be removed/);
      assert.match(done.value.message, /account key and this connection's sign-in no longer work/);
      assert.equal(s.fake.writes.length, writes, "deleting writes nothing to the ledger");

      // The links, at once.
      assert.equal(await statusOf(session.viewer), 404);
      assert.equal(await statusOf(session.packet), 404);

      // The token, on every surface, with the sign-in challenge; and it can't be refreshed or the key used.
      for (const path_ of [PLAIN, CHAT, PREVIEW, "/mcp"]) {
        assert.equal((await post(s.url, path_, "tools/call", { name: "shadow_list_sessions", arguments: {} }, a.token)).status, 401, path_);
      }
      assert.equal((await (await exchange(s.url, { grant_type: "refresh_token", refresh_token: a.refresh, client_id: a.clientId })).json()).error, "invalid_grant");
      const page = await openPage(s.url, `${PUBLIC}${PLAIN}`);
      const signin = await decide(s.url, { request: page.request, decision: "signin", key: a.key });
      assert.equal(signin.status, 400);
      assert.match(await signin.text(), /wasn’t recognized/);

      // The cookie no longer selects it: the create page, not "Signed in as".
      const again = await openPage(s.url, `${PUBLIC}${PLAIN}`, a.cookie);
      assert.doesNotMatch(again.html, /Signed in as/);

      // Nothing of it is on disk, past a bare id that stops its tokens; and its name is nowhere.
      assert.equal(findFile(path.join(stateDir, "shadow"), session.id), false);
      assert.equal(readdirSync(path.join(stateDir, "shadow", "owners")).length, 1, "only the other owner is left");
      assert.equal(diskHolds(stateDir, "Secret Name"), false);
      assert.equal(diskHolds(stateDir, "private words"), false);
      assert.equal(readdirSync(path.join(stateDir, "accounts", "a")).filter((n) => n.endsWith(".json")).length, 1, "the other account stays");

      // Others are untouched.
      assert.equal(await statusOf(kept.viewer), 200);
      assert.equal((await tool(s.url, keeper.token, "shadow_list_sessions")).value.sessions.length, 1);

      // And it stays that way after a restart.
      await s.close();
      s = await boot(stateDir, { SHADOW_PREVIEW_AUTO_LOG: "1" }, s.fake);
      assert.equal((await post(s.url, PLAIN, "tools/call", { name: "shadow_list_sessions", arguments: {} }, a.token)).status, 401);
      assert.equal(await statusOf(s.url + new URL(session.viewer).pathname), 404);
      // Connecting again starts afresh.
      const fresh = await signUp(s.url, "New");
      assert.deepEqual((await tool(s.url, fresh.token, "shadow_list_sessions")).value.sessions, []);
    } finally {
      await s.close();
    }
  });
}

function diskHolds(dir, text) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory() ? diskHolds(p, text) : readFileSync(p).includes(text)) return true;
  }
  return false;
}

test("clockchain_delete_account needs a signed-in account, and before sign-in it starts sign-in like any other tool", async () => {
  const s = await boot();
  try {
    assert.equal((await post(s.url, CHAT, "tools/call", { name: "clockchain_delete_account", arguments: { confirm: true } })).status, 401);
    assert.equal((await post(s.url, PLAIN, "tools/call", { name: "clockchain_delete_account", arguments: { confirm: true } })).status, 401);
  } finally {
    await s.close();
  }
});

test("AccountStore: a deleted mark holds no name or key hash, survives a reopen, and goes once its tokens can't still be alive", () => {
  const root = tmp("store");
  let t = Date.UTC(2026, 10, 5);
  const store = new AccountStore(root, 100, () => t);
  const created = store.create("Secret Name");
  const { acct } = created.account;
  assert.equal(store.findByKey(created.key).acct, acct);
  assert.equal(store.isDeleted(acct), false);
  assert.equal(store.delete(acct), true);
  assert.equal(store.delete(acct), false, "a repeat does nothing");
  assert.equal(store.isDeleted(acct), true);
  assert.equal(store.get(acct), undefined);
  assert.equal(store.findByKey(created.key), undefined);
  assert.equal(store.count(), 0);
  const mark = readFileSync(path.join(root, "d", `${acct}.json`), "utf8");
  assert.doesNotMatch(mark, /Secret Name|keyHash/);
  assert.equal(new AccountStore(root, 100, () => t).isDeleted(acct), true);
  assert.equal(new AccountStore(root, 100, () => Date.now() + 91 * 86_400_000).isDeleted(acct), false, "past every token's lifetime");
});
