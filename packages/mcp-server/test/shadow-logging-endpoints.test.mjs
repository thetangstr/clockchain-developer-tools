// Logging is per endpoint. On /shadow/mcp and /shadow/chat/mcp, the paths directories list, the person asks, chat by chat:
// no logging tools, no standing switch, no text telling an agent to record unasked. SHADOW_PREVIEW_AUTO_LOG=1 adds
// /shadow/preview/mcp and /shadow/preview/chat/mcp, added by hand, with logging on by default, and changes nothing on the
// other two. SHADOW_AUTO_LOG=1 keeps its old meaning. The real HTTP server, a fake ledger, sign-in through the real pages.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { loadShadowConfig } from "../dist/shadow/service.js";
import { ASKED_INSTRUCTIONS, AUTO_LOG_INSTRUCTIONS } from "../dist/shadow/mcp.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { __resetSharedLogBudget } from "../dist/budget.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const PUBLIC = "https://mcp.example.test";
const PLAIN = "/shadow/mcp";
const CHAT = "/shadow/chat/mcp";
const PREVIEW = "/shadow/preview/mcp";
const PREVIEW_CHAT = "/shadow/preview/chat/mcp";
const CB = "https://claude.ai/api/mcp/auth_callback";
const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_RATE_PER_MIN", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "SHADOW_PREVIEW_AUTO_LOG", "MCP_LOG_BUDGET", "MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR", "MCP_OAUTH_APPROVALS_PER_HOUR"];
const SESSION_TOOLS = ["clockchain_delete_account", "shadow_checkpoint", "shadow_close_session", "shadow_delete_session", "shadow_get_session", "shadow_list_sessions", "shadow_record", "shadow_revoke_links", "shadow_start_session", "shadow_verify"];
const ACCOUNT_TOOLS = ["clockchain_create_account", "clockchain_signup_help", "clockchain_whoami"];
const LOG_TOOLS = ["clockchain_logging", "clockchain_whoami", "shadow_log_step", "shadow_log_turn"];
/** What a directory's checklist rejects, or what makes a listed tool read as logging by default or across chats. */
const NOT_ON_A_LISTED_ENDPOINT = /without being asked|from any connector|on by default|after every step|every tool call|stop logging|shadow_log_|clockchain_logging|agreed to this|\bfree\b/i;

const tmp = (label) => mkdtempSync(path.join(tmpdir(), `logging-endpoints-${label}-`));
const flat = (s) => s.replace(/\s+/g, " ");
const sorted = (names) => [...new Set(names)].sort();

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
  Object.assign(process.env, {
    MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_TOKEN_SIGNING_SECRET: "endpoints-test-secret", MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"),
    MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, SHADOW_ENABLED: "1", SHADOW_LAZY_AUTH: "1", MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR: "1000", MCP_OAUTH_APPROVALS_PER_HOUR: "1000",
    ...env,
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

const post = (base, p, method, params, token) => fetch(`${base}${p}`, {
  method: "POST",
  headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...(params ? { params } : {}) }),
});
const rpc = async (base, p, method, params, token) => {
  const res = await post(base, p, method, params, token);
  assert.equal(res.status, 200, `${p} ${method}: HTTP ${res.status}`);
  const text = await res.text();
  return res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : JSON.parse(text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop());
};
const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } };
const instructionsOf = async (base, p, token) => (await rpc(base, p, "initialize", INIT, token)).result.instructions;
const toolsOf = async (base, p, token) => (await rpc(base, p, "tools/list", {}, token)).result.tools;
const tool = async (base, p, token, name, args = {}) => {
  const { result } = await rpc(base, p, "tools/call", { name, arguments: args }, token);
  return { isError: result.isError === true, text: result.content[0].text, value: (() => { try { return JSON.parse(result.content[0].text); } catch { return undefined; } })() };
};

async function openPage(base, resource) {
  const client = await (await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [CB], token_endpoint_auth_method: "none" }) })).json();
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", state: "s", ...(resource ? { resource } : {}) });
  const res = await fetch(`${base}/oauth/authorize?${q}`, { headers: { accept: "text/html" } });
  const html = await res.text();
  return { status: res.status, client, verifier, html, request: /name="request" value="([^"]+)"/.exec(html)?.[1] };
}
const decide = (base, fields) => fetch(`${base}/oauth/authorize`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: PUBLIC }, body: new URLSearchParams(fields) });

async function signUp(base, p = PLAIN, name = "Acme") {
  const resource = `${PUBLIC}${p}`;
  const c = await openPage(base, resource);
  const created = await decide(base, { request: c.request, decision: "create", ...(/name="name"/.test(c.html) ? { name } : {}) });
  const keyHtml = await created.text();
  assert.equal(created.status, 200, keyHtml);
  const cont = await decide(base, { request: c.request, decision: "continue", grant: /name="grant" value="([^"]+)"/.exec(keyHtml)[1] });
  const code = new URL(cont.headers.get("location")).searchParams.get("code");
  const t = await (await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: c.client.client_id, code_verifier: c.verifier, resource }) })).json();
  assert.ok(t.access_token, JSON.stringify(t));
  return { token: t.access_token, consentHtml: c.html, keyHtml };
}

const pagesOf = async (base) => ({
  llms: await (await fetch(`${base}/llms.txt`)).text(),
  install: await (await fetch(`${base}/install.txt`)).text(),
  connect: await (await fetch(`${base}/shadow/connect`)).text(),
  manifest: await (await fetch(`${base}/.well-known/mcp.json`)).text(),
});

/** Everything on a listed endpoint that a directory scanner or an agent reads. */
async function assertListed(s, token) {
  for (const [where, p, tok, tools] of [
    ["plain", PLAIN, token, SESSION_TOOLS],
    ["chat", CHAT, token, sorted([...SESSION_TOOLS, ...ACCOUNT_TOOLS])],
    ["chat before sign-in", CHAT, undefined, sorted([...SESSION_TOOLS, ...ACCOUNT_TOOLS])],
  ]) {
    const listed = await toolsOf(s.url, p, tok);
    assert.deepEqual(sorted(listed.map((t) => t.name)), tools, where);
    for (const t of listed) assert.doesNotMatch(t.description, NOT_ON_A_LISTED_ENDPOINT, `${where} ${t.name}`);
    const text = await instructionsOf(s.url, p, tok);
    assert.ok(text.startsWith(ASKED_INSTRUCTIONS), where);
    assert.doesNotMatch(text, NOT_ON_A_LISTED_ENDPOINT, where);
    assert.match(text, /^Shadow records a task only when the person asks for it\. Do not start a session unless they ask in this chat\./);
    assert.match(flat(text), /in a new chat, record nothing unless they ask again/);
    const d = (name) => listed.find((t) => t.name === name).description;
    assert.match(d("shadow_start_session"), /^Use only when the person asks to record/);
    assert.match(d("shadow_record"), /^Use only for a session the person asked to record/);
  }
}

// ---- the settings ------------------------------------------------------------------------------------------------------

test("settings: each flag is its own; only the preview flag leaves the listed paths alone; both raise the limits", () => {
  const env = (x) => ({ SHADOW_ENABLED: "1", ...x });
  const none = loadShadowConfig(env({}));
  assert.equal(none.autoLog, undefined);
  assert.equal(none.autoLogOnMainPaths, undefined);
  assert.equal(none.previewAutoLog, undefined);
  const main = loadShadowConfig(env({ SHADOW_AUTO_LOG: "1" }));
  assert.deepEqual([main.autoLog, main.autoLogOnMainPaths, main.previewAutoLog], [true, true, undefined]);
  const preview = loadShadowConfig(env({ SHADOW_PREVIEW_AUTO_LOG: "1" }));
  assert.deepEqual([preview.autoLog, preview.autoLogOnMainPaths, preview.previewAutoLog], [true, undefined, true]);
  assert.equal(preview.limits.maxAnchorsPerOwnerPerDay, main.limits.maxAnchorsPerOwnerPerDay);
  for (const off of ["0", "true", ""]) assert.equal(loadShadowConfig(env({ SHADOW_PREVIEW_AUTO_LOG: off })).previewAutoLog, undefined, off);
});

// ---- a listed server --------------------------------------------------------------------------------------------------

for (const [label, env] of [["with no logging flag", {}], ["with SHADOW_PREVIEW_AUTO_LOG=1", { SHADOW_PREVIEW_AUTO_LOG: "1" }]]) {
  test(`${label}, the listed endpoints: the person asks, and no text or tool says otherwise`, async () => {
    const s = await boot(env);
    try {
      const a = await signUp(s.url);
      await assertListed(s, a.token);

      // The sign-in pages for a listed endpoint say what happens there.
      for (const p of [PLAIN, CHAT]) {
        const page = await openPage(s.url, `${PUBLIC}${p}`);
        assert.doesNotMatch(page.html, /told to log its chats/, p);
        assert.match(page.html, /Shadow records a task only when you ask for it, in that chat\./, p);
      }
      assert.doesNotMatch(a.keyHtml, /told to log its chats/);

      // Discovery: the same, and it never names a preview endpoint.
      for (const [name, text] of Object.entries(await pagesOf(s.url))) {
        const f = flat(text);
        assert.match(f, /Shadow records a task only when the person asks for it, chat by chat/, name);
        assert.doesNotMatch(f, /on by default|without being asked|stop logging/i, name);
        assert.doesNotMatch(f, /shadow\/preview/, name);
      }

      const help = (await tool(s.url, CHAT, a.token, "clockchain_signup_help")).value.message;
      assert.match(help, /Shadow records a task only when you ask for it, in that chat/);
      assert.doesNotMatch(help, NOT_ON_A_LISTED_ENDPOINT);
    } finally {
      await s.close();
    }
  });

  test(`${label}, on the listed endpoints: recording works when asked, with no switch to turn on and nothing kept across chats`, async () => {
    const s = await boot(env);
    try {
      const a = await signUp(s.url);
      for (const p of [PLAIN, CHAT]) {
        // No log tools, and nothing recorded or anchored until a session is started.
        for (const name of ["shadow_log_step", "shadow_log_turn", "clockchain_logging"]) {
          const r = await tool(s.url, p, a.token, name, name === "shadow_log_step" ? { kind: "task", content: "x" } : {});
          assert.equal(r.isError, true, `${p} ${name}`);
          assert.match(r.text, new RegExp(`Tool ${name} not found`), `${p} ${name}`);
        }
        assert.equal(s.fake.writes.length, 0, p);
      }
      assert.equal((await tool(s.url, CHAT, a.token, "clockchain_whoami")).value.logging, undefined, "no account-level setting to report");

      for (const p of [PLAIN, CHAT]) {
        const started = await tool(s.url, p, a.token, "shadow_start_session", { title: "The person asked" });
        assert.equal(started.isError, false, p);
        const step = await tool(s.url, p, a.token, "shadow_record", { session_id: started.value.session_id, agent: "agent", kind: "task", content: "x" });
        assert.equal(step.isError, false, p);
        assert.equal(step.value.show_user, undefined, "no footer");
        const closed = await tool(s.url, p, a.token, "shadow_close_session", { session_id: started.value.session_id, status: "succeeded" });
        assert.equal(closed.value.status, "closed", p);
        assert.equal(closed.value.show_user, undefined, "no footer");
      }
      // A listed connection stores no logging setting for the account: there is nothing to carry into the next chat.
      const owners = path.join(s.stateDir, "shadow", "owners");
      for (const owner of readdirSync(owners)) assert.equal(existsSync(path.join(owners, owner, "settings.json")), false);
    } finally {
      await s.close();
    }
  });
}

// ---- the preview endpoints ----------------------------------------------------------------------------------------------

test("preview endpoints: logging on by default, said on their own sign-in pages, with the same footer and stop", async () => {
  const s = await boot({ SHADOW_PREVIEW_AUTO_LOG: "1" });
  try {
    const a = await signUp(s.url, PREVIEW);
    assert.match(a.consentHtml, /Once connected, Claude is told to log its chats and tool activity to Clockchain Shadow by default/);
    assert.match(a.keyHtml, /Once connected, Claude is told to log its chats/);
    const chatPage = await openPage(s.url, `${PUBLIC}${PREVIEW_CHAT}`);
    assert.match(chatPage.html, /Once connected, Claude is told to log its chats/);
    assert.doesNotMatch(chatPage.html, /name="name"/, "the chat preview has the one-click create page");

    for (const [p, tok, tools] of [
      [PREVIEW, a.token, sorted([...SESSION_TOOLS, ...LOG_TOOLS])],
      [PREVIEW_CHAT, a.token, sorted([...SESSION_TOOLS, ...ACCOUNT_TOOLS, ...LOG_TOOLS])],
      [PREVIEW_CHAT, undefined, sorted([...SESSION_TOOLS, ...ACCOUNT_TOOLS, ...LOG_TOOLS])],
    ]) {
      assert.deepEqual(sorted((await toolsOf(s.url, p, tok)).map((t) => t.name)), tools, p);
      assert.ok((await instructionsOf(s.url, p, tok)).startsWith(AUTO_LOG_INSTRUCTIONS), p);
    }

    const step = await tool(s.url, PREVIEW, a.token, "shadow_log_step", { kind: "task", content: "hello" });
    assert.equal(step.isError, false);
    assert.equal(step.value.anchor_status, "anchored");
    assert.match(step.value.show_user, /^---\n\n\*\*Clockchain Shadow:\*\* 1 step logged so far\./);
    assert.match(step.value.show_user, /Logging is on\. Saying 'stop logging' turns it off\.$/);

    await tool(s.url, PREVIEW_CHAT, a.token, "clockchain_logging", { enabled: false });
    assert.equal((await tool(s.url, PREVIEW, a.token, "shadow_log_step", { kind: "note", content: "x" })).value.error, "LOGGING_OFF");

    // A "stop" there says nothing about what the person asks for on a listed endpoint, which reads no such setting.
    const asked = await tool(s.url, PLAIN, a.token, "shadow_start_session", { title: "Asked for" });
    assert.equal(asked.isError, false);
    assert.equal((await tool(s.url, PLAIN, a.token, "shadow_record", { session_id: asked.value.session_id, agent: "agent", kind: "task", content: "x" })).isError, false);

    // Before sign-in: the 401 and challenge name the endpoint reached, and only a tools/call gets it on the chat one.
    for (const p of [PREVIEW, PREVIEW_CHAT]) {
      const r = await post(s.url, p, "tools/call", { name: "shadow_log_step", arguments: { kind: "task", content: "x" } });
      assert.equal(r.status, 401, p);
      assert.ok(r.headers.get("www-authenticate").includes(`oauth-protected-resource${p}"`), p);
      const meta = await (await fetch(`${s.url}/.well-known/oauth-protected-resource${p}`)).json();
      assert.equal(meta.resource, `${PUBLIC}${p}`);
    }
    // A free key is refused with a challenge for that same endpoint.
    const free = (await (await fetch(`${s.url}/token`, { method: "POST" })).json()).token;
    const refused = await post(s.url, PREVIEW, "tools/list", {}, free);
    assert.equal(refused.status, 403);
    assert.ok(refused.headers.get("www-authenticate").includes(`oauth-protected-resource${PREVIEW}"`));
    assert.match((await refused.json()).message, /\/shadow\/preview\/mcp/);
  } finally {
    await s.close();
  }
});

test("preview endpoints take a body up to 1 MB for shadow_log_turn; the listed ones stay at 512 KB", async () => {
  const s = await boot({ SHADOW_PREVIEW_AUTO_LOG: "1" });
  try {
    const a = await signUp(s.url);
    const big = { name: "shadow_list_sessions", arguments: {}, _pad: "x".repeat(600 * 1024) };
    assert.equal((await post(s.url, PREVIEW, "tools/call", big, a.token)).status, 200);
    // Over its limit the server stops reading: a 400, or the connection dropped while the client is still sending.
    const listed = await post(s.url, PLAIN, "tools/call", big, a.token).then((r) => r.status, () => "dropped");
    assert.ok(listed === 400 || listed === "dropped", String(listed));
  } finally {
    await s.close();
  }
});

test("a large body pays before it is read on an endpoint that logs by default, and only there", async () => {
  const s = await boot({ SHADOW_PREVIEW_AUTO_LOG: "1", MCP_RATE_PER_MIN: "2" });
  try {
    const a = await signUp(s.url);
    // tools/list is exempt from the rate limit once it has been read, so only the charge before reading can spend it.
    const big = { _pad: "x".repeat(300 * 1024) };
    const statuses = async (p) => { const seen = []; for (let i = 0; i < 4; i++) seen.push((await post(s.url, p, "tools/list", big, a.token)).status); return seen; };
    assert.deepEqual(await statuses(PLAIN), [200, 200, 200, 200], "the listed path is as it was with no flag");
    assert.deepEqual(await statuses(PREVIEW), [200, 200, 429, 429], "the preview path charges first");
  } finally {
    await s.close();
  }
});

test("without the flag the preview paths don't exist: 404, no metadata, and sign-in refuses them as a resource", async () => {
  for (const env of [{}, { SHADOW_AUTO_LOG: "1" }]) {
    const s = await boot(env);
    try {
      for (const p of [PREVIEW, PREVIEW_CHAT]) {
        assert.equal((await post(s.url, p, "tools/list", {}, "static-test-token")).status, 404, p);
        assert.notEqual((await fetch(`${s.url}/.well-known/oauth-protected-resource${p}`)).status, 200, p);
        const page = await openPage(s.url, `${PUBLIC}${p}`);
        assert.equal(page.request, undefined, p);
      }
    } finally {
      await s.close();
    }
  }
});

test("the chat preview needs SHADOW_LAZY_AUTH like the chat endpoint", async () => {
  const s = await boot({ SHADOW_PREVIEW_AUTO_LOG: "1", SHADOW_LAZY_AUTH: "" });
  try {
    assert.equal((await post(s.url, PREVIEW_CHAT, "tools/list", {})).status, 404);
    assert.equal((await post(s.url, PREVIEW, "tools/list", {})).status, 401);
  } finally {
    await s.close();
  }
});

// ---- SHADOW_AUTO_LOG keeps its meaning -----------------------------------------------------------------------------------

test("SHADOW_AUTO_LOG=1: the two main paths log by default as before, and a sign-in with no resource says so", async () => {
  const s = await boot({ SHADOW_AUTO_LOG: "1" });
  try {
    const a = await signUp(s.url);
    assert.match(a.consentHtml, /Once connected, Claude is told to log its chats/);
    assert.doesNotMatch(a.consentHtml, /only when you ask/);
    assert.match((await openPage(s.url)).html, /Once connected, Claude is told to log its chats/);
    for (const p of [PLAIN, CHAT]) {
      assert.ok((await instructionsOf(s.url, p, a.token)).startsWith(AUTO_LOG_INSTRUCTIONS), p);
      assert.ok((await toolsOf(s.url, p, a.token)).some((t) => t.name === "shadow_log_step"), p);
    }
    for (const [name, text] of Object.entries(await pagesOf(s.url))) assert.match(flat(text), /Logging is on by default once connected/, name);
  } finally {
    await s.close();
  }
});

test("the consent line is only on a sign-in for an endpoint that logs by default, says the app may not start unasked, and never says it does log", async () => {
  const LINE = /told to log its chats and tool activity to Clockchain Shadow by default, until you turn it off\. Some apps only start when you ask\./;
  for (const [env, logging, asked] of [
    [{ SHADOW_AUTO_LOG: "1" }, [PLAIN, CHAT], ["/mcp"]],
    [{ SHADOW_PREVIEW_AUTO_LOG: "1" }, [PREVIEW, PREVIEW_CHAT], ["/mcp", PLAIN, CHAT]],
    [{}, [], ["/mcp", PLAIN, CHAT]],
  ]) {
    const s = await boot(env);
    try {
      for (const p of logging) {
        const { html } = await openPage(s.url, `${PUBLIC}${p}`);
        assert.match(html, LINE, p);
        assert.doesNotMatch(html, /Claude logs its/, p);
      }
      for (const p of asked) assert.doesNotMatch((await openPage(s.url, `${PUBLIC}${p}`)).html, /told to log|logs its chats/, `${p} with ${JSON.stringify(env)}`);
    } finally {
      await s.close();
    }
  }
});

test("a sign-in with no resource isn't told logging is on unless every endpoint logs", async () => {
  const s = await boot({ SHADOW_PREVIEW_AUTO_LOG: "1" });
  try {
    assert.doesNotMatch((await openPage(s.url)).html, /told to log its chats/);
  } finally {
    await s.close();
  }
});

test("both flags: all four endpoints log by default", async () => {
  const s = await boot({ SHADOW_AUTO_LOG: "1", SHADOW_PREVIEW_AUTO_LOG: "1" });
  try {
    const a = await signUp(s.url);
    for (const p of [PLAIN, CHAT, PREVIEW, PREVIEW_CHAT]) assert.ok((await toolsOf(s.url, p, a.token)).some((t) => t.name === "shadow_log_step"), p);
  } finally {
    await s.close();
  }
});
