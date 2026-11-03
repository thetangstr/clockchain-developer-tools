// OAuth 2.1 sign-in (src/oauth.ts): flag gating, the ChatGPT / Claude Code flow
// end to end against the real runHttp wiring, every rejection path, the `acct`
// claim, CORS scope, and that no credential ever reaches the logs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomBytes, createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { runHttp, signedTokenSubject } from "../dist/http.js";
import { createOAuthHandler, loadOAuthConfig } from "../dist/oauth.js";
import { durableExpiringSet } from "../dist/oauth-replay.js";
import { ACCT_PATTERN, mintToken, verifyToken } from "../dist/token.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { ownerKeyOf } from "../dist/shadow/store.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const SECRET = "oauth-test-signing-secret";
const PUBLIC = "https://mcp.example.test";
const CHATGPT_CB = "https://chatgpt.com/connector_platform_oauth_redirect";
const STATIC_TOKEN = "static-test-token";

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sha256b64url = (s) => createHash("sha256").update(s).digest("base64url");
const pkce = () => {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: sha256b64url(verifier) };
};

// ---- harnesses ------------------------------------------------------------

const ENV_KEYS = [
  "PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_APPROVALS_PER_HOUR", "MCP_OAUTH_TRUSTED_PROXY",
  "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_RATE_PER_MIN", "MCP_TOKEN_MINT_PER_HOUR",
  "MCP_TOKEN_TTL_DAYS", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "MCP_STATE_DIR",
];
const tempDir = (label) => mkdtempSync(path.join(tmpdir(), `oauth-${label}-`));

/** Hosted Shadow on, in a fresh state directory, so /shadow/mcp exists and answers /mcp's 401. */
const shadowOn = () => ({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "oauth-shadow-")) });

/** The REAL runHttp wiring with the given env (static token set, so auth is not open). */
async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0", MCP_AUTH_TOKENS: STATIC_TOKEN, MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_STATE_DIR: tempDir("state") }, env);
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url,
    async close() {
      accountsByBase.delete(url);
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

/** The handler alone, with a controllable clock and captured log events. */
async function harness(opts = {}) {
  let clock = Date.UTC(2026, 10, 2, 12, 0, 0);
  const logs = [];
  const handler = createOAuthHandler({
    signingSecret: SECRET, publicUrl: PUBLIC, tokenTtlSeconds: 7 * 24 * 3600,
    accountsDir: path.join(tempDir("accounts"), "accounts"),
    now: () => clock, log: (e) => logs.push(e), ...opts,
  });
  const server = createServer(async (req, res) => {
    if (!(await handler.handle(req, res))) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("fell through");
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url,
    handler, logs,
    nowSec: () => Math.floor(clock / 1000),
    advance(ms) { clock += ms; },
    async close() { accountsByBase.delete(url); server.closeAllConnections?.(); await new Promise((r) => server.close(r)); },
  };
}

// ---- flow helpers ---------------------------------------------------------

const postJson = (url, body, headers = {}) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

async function registerClient(base, meta = {}) {
  const res = await postJson(`${base}/oauth/register`, { client_name: "ChatGPT", redirect_uris: [CHATGPT_CB], ...meta });
  assert.equal(res.status, 201, await res.clone().text());
  return res.json();
}

/** Register (unless a client is given), then load the consent page. */
async function openConsent(base, o = {}) {
  const client = o.client ?? (await registerClient(base, o.meta));
  const { verifier, challenge } = pkce();
  const redirectUri = o.redirectUri ?? client.redirect_uris[0];
  const params = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: o.state ?? "state-123",
    resource: o.resource ?? `${PUBLIC}/mcp`,
    ...o.params,
  });
  for (const k of o.drop ?? []) params.delete(k);
  const page = await fetch(`${base}/oauth/authorize?${params}`, { redirect: "manual", headers: { accept: "text/html", ...(o.cookie ? { cookie: o.cookie } : {}) } });
  const html = await page.text();
  const requestToken = /name="request" value="([^"]+)"/.exec(html)?.[1];
  const grant = /name="grant" value="([^"]+)"/.exec(html)?.[1];
  return { client, verifier, challenge, redirectUri, page, html, requestToken, grant };
}

/** POST the approval form: `decision` plus any other form fields (grant, name, key). */
const decide = (base, requestToken, decision = "approve", headers = { origin: PUBLIC }, fields = {}) =>
  fetch(`${base}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams({ request: requestToken, decision, ...fields }),
  });

/** "name=value" of the response's Set-Cookie (empty when none). */
const cookieOf = (res) => (res.headers.get("set-cookie") ?? "").split(";")[0];
/** The acct an account cookie selects (its payload is plain base64url JSON; the MAC is what protects it). */
const acctOfCookie = (cookie) =>
  JSON.parse(Buffer.from(cookie.slice(cookie.indexOf("=") + 1).slice("cc_ac_".length).split(".")[0], "base64url").toString()).acct;

/** Sign up through a consent page's create form, stopping at the key page (no approval is spent). */
async function signUp(base, name = "Test Person", o = {}) {
  const consent = await openConsent(base, o);
  assert.equal(consent.page.status, 200, consent.html);
  const res = await decide(base, consent.requestToken, "create", { origin: PUBLIC }, { name });
  const html = await res.text();
  assert.equal(res.status, 200, html);
  const cookie = cookieOf(res);
  const key = /<code>(cck_[A-Za-z0-9_-]{32})<\/code>/.exec(html)?.[1];
  const grant = /name="grant" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(cookie && key && grant, "the key page sets the cookie and shows the key");
  return { consent, res, html, cookie, key, grant, acct: acctOfCookie(cookie), name };
}

const accountsByBase = new Map();
/** One account per server, made on first use: most tests just need "a signed-in person". */
async function accountFor(base) {
  if (!accountsByBase.has(base)) accountsByBase.set(base, await signUp(base));
  return accountsByBase.get(base);
}

async function tokenCall(base, params, type = "form", headers = {}) {
  const res = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": type === "form" ? "application/x-www-form-urlencoded" : "application/json", ...headers },
    body: type === "form" ? new URLSearchParams(params) : JSON.stringify(params),
  });
  return { status: res.status, headers: res.headers, body: await res.json() };
}

/** Open the signed-in consent page and press Allow, sending `headers` (Origin, X-Forwarded-For...) with the click. */
async function allow(base, o = {}, headers = { origin: PUBLIC }) {
  const account = o.account ?? (await accountFor(base));
  const consent = await openConsent(base, { ...o, cookie: account.cookie });
  assert.ok(consent.grant, consent.html);
  return { consent, res: await decide(base, consent.requestToken, "approve", { ...headers, cookie: account.cookie }, { grant: consent.grant }) };
}

/** Signed-in consent page → Allow → code, returning everything needed to exchange it. */
async function approve(base, o = {}) {
  const account = o.account ?? (await accountFor(base));
  const consent = await openConsent(base, { ...o, cookie: account.cookie });
  assert.equal(consent.page.status, 200, consent.html);
  assert.ok(consent.grant, "the signed-in page carries a grant");
  const res = await decide(base, consent.requestToken, "approve", { origin: PUBLIC, cookie: account.cookie }, { grant: consent.grant });
  assert.equal(res.status, 303, await res.clone().text());
  const location = new URL(res.headers.get("location"));
  return { ...consent, account, location, code: location.searchParams.get("code") };
}

const exchangeCode = (base, a, extra = {}) =>
  tokenCall(base, {
    grant_type: "authorization_code",
    code: a.code,
    redirect_uri: a.redirectUri,
    client_id: a.client.client_id,
    code_verifier: a.verifier,
    resource: `${PUBLIC}/mcp`,
    ...extra,
  });

const mcpPost = (base, body, headers = {}, p = "/mcp") =>
  fetch(`${base}${p}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
  });

const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "oauth-test", version: "1" } } };

async function rpcResult(res) {
  const text = await res.text();
  const json = res.headers.get("content-type")?.includes("json")
    ? JSON.parse(text)
    : JSON.parse(text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop());
  return json;
}

/**
 * An error page, never a redirect: the approval page's strict headers, and nothing
 * that could carry the visitor onward (no link, form, script, refresh).
 */
function assertErrorPage(res, html, { status = 400, code, mustNotMention = [] } = {}) {
  assert.equal(res.status, status);
  assert.equal(res.headers.get("location"), null, "never a redirect");
  assert.equal(res.headers.get("refresh"), null, "never an auto-follow");
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.match(res.headers.get("content-type"), /^text\/html/);
  const csp = res.headers.get("content-security-policy");
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /form-action 'none'/);
  assert.doesNotMatch(csp, /script-src|unsafe-inline/);
  assert.doesNotMatch(html, /<a\b|<form|<script|http-equiv/i);
  assert.match(html, /<h1>/);
  if (code) assert.match(html, new RegExp(`Error code: ${code}<`));
  for (const text of mustNotMention) assert.equal(html.includes(text), false, `the page must not mention ${text}`);
}

/** Re-sign nothing: swap a field inside a sealed artifact but keep its old MAC. */
function tamper(artifact, prefix, mutate) {
  const body = artifact.slice(prefix.length);
  const [seg, mac] = body.split(".");
  const blob = JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
  mutate(blob);
  return `${prefix}${Buffer.from(JSON.stringify(blob)).toString("base64url")}.${mac}`;
}

// ===========================================================================
// Gating
// ===========================================================================

test("config: off unless MCP_OAUTH=1 with a signing secret; bad values are misconfigured, never on", () => {
  assert.deepEqual(loadOAuthConfig({}, SECRET), { kind: "disabled" });
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "0" }, SECRET), { kind: "disabled" });
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "" }, SECRET), { kind: "disabled" });
  assert.equal(loadOAuthConfig({ MCP_OAUTH: "1" }, "").kind, "misconfigured");
  assert.equal(loadOAuthConfig({ MCP_OAUTH: "true" }, SECRET).kind, "misconfigured");
  assert.equal(loadOAuthConfig({ MCP_OAUTH: "1", MCP_PUBLIC_URL: "http://mcp.clockchain.network" }, SECRET).kind, "misconfigured");
  assert.equal(loadOAuthConfig({ MCP_OAUTH: "1", MCP_PUBLIC_URL: "https://mcp.clockchain.network/mcp" }, SECRET).kind, "misconfigured");
  assert.equal(loadOAuthConfig({ MCP_OAUTH: "1", MCP_OAUTH_APPROVALS_PER_HOUR: "lots" }, SECRET).kind, "misconfigured");
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1" }, SECRET), { kind: "ready", publicUrl: "https://mcp.clockchain.network", approvalsPerHour: 10, accountsDir: "/app/state/accounts", replayDir: "/app/state/oauth" });
  assert.deepEqual(
    loadOAuthConfig({ MCP_OAUTH: "1", MCP_PUBLIC_URL: "https://mcp.clockchain.network/", MCP_OAUTH_APPROVALS_PER_HOUR: "40", MCP_OAUTH_TRUSTED_PROXY: "172.30.0.3", MCP_STATE_DIR: "/srv/state" }, SECRET),
    { kind: "ready", publicUrl: "https://mcp.clockchain.network", approvalsPerHour: 40, accountsDir: "/srv/state/accounts", replayDir: "/srv/state/oauth", trustedProxy: "172.30.0.3" },
  );
});

const NEW_ROUTES = [
  ["GET", "/.well-known/oauth-protected-resource"],
  ["GET", "/.well-known/oauth-protected-resource/mcp"],
  ["GET", "/.well-known/oauth-protected-resource/shadow/mcp"],
  ["GET", "/.well-known/oauth-authorization-server"],
  ["GET", "/.well-known/openid-configuration"],
  ["GET", "/oauth/authorize?client_id=x"],
  ["POST", "/oauth/authorize"],
  ["POST", "/oauth/register"],
  ["POST", "/oauth/token"],
  ["OPTIONS", "/oauth/token"],
];

async function snapshot(res) {
  const headers = Object.fromEntries([...res.headers].filter(([k]) => !["date", "connection", "keep-alive", "transfer-encoding", "content-length"].includes(k)));
  return { status: res.status, headers, body: await res.text() };
}

for (const [label, env] of [
  ["flag unset", {}],
  ["MCP_OAUTH=1 without a signing secret", { MCP_OAUTH: "1", MCP_TOKEN_SIGNING_SECRET: undefined }],
  ["MCP_OAUTH=true (not 1)", { MCP_OAUTH: "true" }],
]) {
  test(`off (${label}): every new route answers exactly like an unknown path, and the 401 has no WWW-Authenticate`, async () => {
    const s = await boot({ ...shadowOn(), ...env });
    try {
      for (const [method, p] of NEW_ROUTES) {
        for (const accept of ["application/json", "text/html"]) {
          const init = { method, headers: { accept }, ...(method === "POST" ? { body: "{}" } : {}) };
          const got = await snapshot(await fetch(`${s.url}${p}`, init));
          const baseline = await snapshot(await fetch(`${s.url}/no-such-route${p.includes("?") ? "?client_id=x" : ""}`, init));
          assert.deepEqual(got, baseline, `${method} ${p} (${accept})`);
          assert.equal(got.headers["access-control-allow-origin"], undefined);
        }
      }
      for (const p of ["/mcp", "/shadow/mcp"]) {
        const r = await mcpPost(s.url, INIT, {}, p);
        assert.equal(r.status, 401);
        assert.equal(r.headers.get("www-authenticate"), null);
        assert.deepEqual(Object.keys((await snapshot(r)).headers), ["content-type"]);
      }
    } finally {
      await s.close();
    }
  });
}

test("on: the 401 keeps its status and exact body, and gains WWW-Authenticate only on /mcp and /shadow/mcp", async () => {
  const off = await boot(shadowOn());
  const on = await boot({ ...shadowOn(), MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    for (const p of ["/mcp", "/shadow/mcp", "/"]) {
      const a = await mcpPost(off.url, INIT, {}, p);
      const b = await mcpPost(on.url, INIT, {}, p);
      assert.equal(a.status, 401);
      assert.equal(b.status, 401);
      assert.equal(await b.text(), await a.text(), `${p}: body is byte-for-byte unchanged`);
      assert.equal(b.headers.get("content-type"), "application/json");
    }
    const mcp = await mcpPost(on.url, INIT);
    assert.equal(mcp.headers.get("www-authenticate"), `Bearer resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource/mcp"`);
    const shadow = await mcpPost(on.url, INIT, {}, "/shadow/mcp");
    assert.equal(shadow.headers.get("www-authenticate"), `Bearer resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource/shadow/mcp"`);
    assert.equal((await mcpPost(on.url, INIT, {}, "/")).headers.get("www-authenticate"), null);
    assert.equal((await mcpPost(on.url, INIT, {}, "/mcp")).headers.get("access-control-allow-origin"), null, "/mcp gets no CORS");
    // An expired or forged cc_ token: same 401, plus error="invalid_token" (RFC 6750 §3.1).
    const expired = mintToken(SECRET, 60, Math.floor(Date.now() / 1000) - 3600).token;
    const stale = await mcpPost(on.url, INIT, { authorization: `Bearer ${expired}` });
    assert.equal(stale.status, 401);
    assert.equal(stale.headers.get("www-authenticate"), `Bearer resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource/mcp", error="invalid_token"`);
    // /shadow/mcp: the same shared 401, with its own metadata URL; any refused credential adds error="invalid_token".
    for (const authorization of [`Bearer ${expired}`, "Bearer not-an-mcp-token"]) {
      const refused = await mcpPost(on.url, INIT, { authorization }, "/shadow/mcp");
      assert.equal(refused.status, 401);
      assert.equal(refused.headers.get("www-authenticate"), `Bearer resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource/shadow/mcp", error="invalid_token"`);
      const offRefused = await mcpPost(off.url, INIT, { authorization }, "/shadow/mcp");
      assert.equal(await refused.text(), await offRefused.text());
      assert.equal(offRefused.headers.get("www-authenticate"), null);
    }
  } finally {
    await off.close();
    await on.close();
  }
});

async function shadowCall(base, name, args, accessToken) {
  const res = await mcpPost(base, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, { authorization: `Bearer ${accessToken}` }, "/shadow/mcp");
  assert.equal(res.status, 200);
  const { result } = await rpcResult(res);
  return { isError: result.isError === true, value: JSON.parse(result.content[0].text) };
}

test("OAuth on /shadow/mcp: the session owner is the token's acct, unchanged across a refresh; another account sees nothing", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const env = shadowOn();
  const s = await boot({ ...env, MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    const a = await approve(s.url);
    const issued = await exchangeCode(s.url, a);
    assert.equal(issued.status, 200);
    const first = verifyToken(SECRET, issued.body.access_token).payload;
    assert.match(first.acct, ACCT_PATTERN);
    const ownerDir = path.join(env.SHADOW_STATE_DIR, "owners", ownerKeyOf(first.acct));

    const { value: started } = await shadowCall(s.url, "shadow_start_session", { title: "via OAuth" }, issued.body.access_token);
    assert.ok(existsSync(path.join(ownerDir, "sessions", started.session_id)), "stored under the acct's owner key");

    // Refresh: a new access token (new jti) for the same acct reaches the same session and owner.
    const refreshed = await tokenCall(s.url, { grant_type: "refresh_token", refresh_token: issued.body.refresh_token, client_id: a.client.client_id });
    assert.equal(refreshed.status, 200);
    const second = verifyToken(SECRET, refreshed.body.access_token).payload;
    assert.equal(second.acct, first.acct);
    assert.notEqual(second.jti, first.jti);
    const seen = await shadowCall(s.url, "shadow_get_session", { session_id: started.session_id }, refreshed.body.access_token);
    assert.equal(seen.isError, false);
    assert.equal(seen.value.title, "via OAuth");
    const { value: again } = await shadowCall(s.url, "shadow_start_session", { title: "after refresh" }, refreshed.body.access_token);
    assert.ok(existsSync(path.join(ownerDir, "sessions", again.session_id)));
    assert.deepEqual(readdirSync(path.join(env.SHADOW_STATE_DIR, "owners")), [ownerKeyOf(first.acct)], "one owner: the acct, never a per-jti owner");
    const listed = (await shadowCall(s.url, "shadow_list_sessions", {}, refreshed.body.access_token)).value.sessions.map((x) => x.session_id).sort();
    assert.deepEqual(listed, [started.session_id, again.session_id].sort());

    // A second account: it can neither read nor write the first account's sessions.
    const b = await approve(s.url, { client: a.client, account: await signUp(s.url, "Second Person") });
    const other = await exchangeCode(s.url, b);
    assert.notEqual(verifyToken(SECRET, other.body.access_token).payload.acct, first.acct);
    for (const [name, args] of [
      ["shadow_get_session", { session_id: started.session_id }],
      ["shadow_record", { session_id: started.session_id, agent: "agent", kind: "message", content: "intrusion" }],
      ["shadow_verify", { session_id: started.session_id }],
    ]) {
      const r = await shadowCall(s.url, name, args, other.body.access_token);
      assert.equal(r.isError, true, name);
      assert.equal(r.value.error, "SHADOW_NOT_FOUND", name);
    }
    assert.deepEqual((await shadowCall(s.url, "shadow_list_sessions", {}, other.body.access_token)).value.sessions, []);
  } finally {
    await s.close();
    __setShadowLedgerForTests(undefined);
  }
});

// ===========================================================================
// Discovery
// ===========================================================================

test("discovery: protected-resource metadata per path and the authorization-server metadata (with openid alias)", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    for (const [p, resource] of [["", PUBLIC], ["/mcp", `${PUBLIC}/mcp`], ["/shadow/mcp", `${PUBLIC}/shadow/mcp`]]) {
      const r = await fetch(`${s.url}/.well-known/oauth-protected-resource${p}`, { headers: { host: "evil.example" } });
      assert.equal(r.status, 200);
      const doc = await r.json();
      assert.equal(doc.resource, resource);
      assert.deepEqual(doc.authorization_servers, [PUBLIC], "from MCP_PUBLIC_URL, never the Host header");
    }
    const as = await (await fetch(`${s.url}/.well-known/oauth-authorization-server`)).json();
    assert.equal(as.issuer, PUBLIC);
    assert.equal(as.authorization_endpoint, `${PUBLIC}/oauth/authorize`);
    assert.equal(as.token_endpoint, `${PUBLIC}/oauth/token`);
    assert.equal(as.registration_endpoint, `${PUBLIC}/oauth/register`);
    assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(as.grant_types_supported, ["authorization_code", "refresh_token"]);
    assert.deepEqual(as.response_types_supported, ["code"]);
    assert.deepEqual(as.token_endpoint_auth_methods_supported, ["none"]);
    assert.equal(as.authorization_response_iss_parameter_supported, true);
    assert.deepEqual(await (await fetch(`${s.url}/.well-known/openid-configuration`)).json(), as);
    assert.equal((await fetch(`${s.url}/.well-known/oauth-authorization-server`, { method: "POST" })).status, 405);
  } finally {
    await s.close();
  }
});

test("default public URL is https://mcp.clockchain.network", async () => {
  const s = await boot({ MCP_OAUTH: "1" });
  try {
    const doc = await (await fetch(`${s.url}/.well-known/oauth-protected-resource/mcp`)).json();
    assert.deepEqual(doc, {
      resource: "https://mcp.clockchain.network/mcp",
      authorization_servers: ["https://mcp.clockchain.network"],
      bearer_methods_supported: ["header"],
      resource_name: "Clockchain MCP",
      resource_documentation: "https://mcp.clockchain.network/llms.txt",
    });
  } finally {
    await s.close();
  }
});

// ===========================================================================
// The full happy path, through runHttp
// ===========================================================================

test("happy path: register → create-account page → create → key page → Continue → code → token → /mcp → refresh → old refresh rejected", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    const consent = await openConsent(s.url, { meta: { client_name: "ChatGPT", token_endpoint_auth_method: "client_secret_post" } });
    assert.equal(consent.client.token_endpoint_auth_method, "none", "public clients only");
    assert.equal(consent.page.status, 200);
    const csp = consent.page.headers.get("content-security-policy");
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /form-action 'self' https:\/\/chatgpt\.com(;|$)/);
    assert.doesNotMatch(csp, /script-src|unsafe-inline/);
    assert.equal(consent.page.headers.get("x-frame-options"), "DENY");
    assert.equal(consent.page.headers.get("cache-control"), "no-store");
    assert.equal(consent.page.headers.get("access-control-allow-origin"), null);
    assert.doesNotMatch(consent.html, /<script/i);
    // No account cookie: the page is sign-up.
    assert.match(consent.html, /<h1>Create your Clockchain account<\/h1>/);
    assert.match(consent.html, /allow ChatGPT to record and anchor your agents’ work on Clockchain/);
    assert.match(consent.html, /<input id="name" name="name" type="text" maxlength="40" required/);
    assert.match(consent.html, />Create account and allow ChatGPT<\/button>/);
    assert.match(consent.html, /<summary><span class="when-closed">I have an account key<\/span>/);
    assert.match(consent.html, /name="key" type="password"/);
    assert.match(consent.html, /<code>chatgpt\.com<\/code>/);
    assert.match(consent.html, /testnet credits from a shared pool/);
    assert.match(consent.html, /30 days/);
    assert.match(consent.html, /Only fingerprints go on the Clockchain ledger/);
    assert.match(consent.html, /value="create"/);
    assert.match(consent.html, /value="signin"/);
    assert.match(consent.html, /value="cancel"/);
    assert.doesNotMatch(consent.html, /value="approve"|Signed in as/);
    assert.equal(consent.page.headers.get("set-cookie"), null);
    assert.ok(consent.requestToken.startsWith("cc_req_"));

    // Create: the cookie (right attributes) and the key, shown once, on the key page.
    const created = await decide(s.url, consent.requestToken, "create", { origin: PUBLIC }, { name: "  Ada  Lovelace " });
    assert.equal(created.status, 200);
    const keyHtml = await created.text();
    const setCookie = created.headers.get("set-cookie");
    assert.match(setCookie, /^__Host-cc_acct=cc_ac_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}; Max-Age=31536000; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
    assert.match(created.headers.get("content-security-policy"), /form-action 'self' https:\/\/chatgpt\.com/);
    assert.equal(created.headers.get("cache-control"), "no-store");
    assert.equal(created.headers.get("x-frame-options"), "DENY");
    assert.match(keyHtml, /Signed in as <strong>Ada Lovelace<\/strong>/);
    const key = /<code>(cck_[A-Za-z0-9_-]{32})<\/code>/.exec(keyHtml)[1];
    assert.match(keyHtml, /Save this key to sign in on another device\. We can’t show it again\./);
    assert.match(keyHtml, /value="continue" class="primary">Continue<\/button>/);
    assert.doesNotMatch(keyHtml, /<script/i);
    const cookie = setCookie.split(";")[0];
    // The key is never shown again: not on the signed-in page, not after another create attempt's page loads.
    const again = await openConsent(s.url, { client: consent.client, cookie });
    assert.match(again.html, /Signed in as <strong>Ada Lovelace<\/strong>/);
    assert.equal(again.html.includes(key), false);
    assert.equal(again.html.includes("cck_"), false);

    const decision = await decide(s.url, consent.requestToken, "continue", { origin: PUBLIC }, { grant: /name="grant" value="([^"]+)"/.exec(keyHtml)[1] });
    assert.equal(decision.status, 303);
    const location = new URL(decision.headers.get("location"));
    assert.equal(`${location.origin}${location.pathname}`, CHATGPT_CB);
    assert.equal(location.searchParams.get("state"), "state-123");
    assert.equal(location.searchParams.get("iss"), PUBLIC, "RFC 9207 iss, exact issuer string");
    const code = location.searchParams.get("code");
    assert.ok(code.startsWith("cc_code_"));

    const issued = await exchangeCode(s.url, { ...consent, code });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(issued.headers.get("cache-control"), "no-store");
    assert.equal(issued.headers.get("access-control-allow-origin"), "*");
    assert.equal(issued.body.token_type, "Bearer");
    assert.equal(issued.body.expires_in, 7 * 24 * 3600);
    assert.ok(issued.body.refresh_token.startsWith("cc_rt_"));
    const v = verifyToken(SECRET, issued.body.access_token);
    assert.equal(v.valid, true);
    assert.equal(v.payload.tier, "demo");
    assert.match(v.payload.acct, ACCT_PATTERN);
    assert.equal(v.payload.acct, acctOfCookie(cookie), "the token's acct is the new account's");
    assert.equal(v.payload.sub, undefined);

    // The OAuth token works on /mcp exactly like a /token token.
    const init = await mcpPost(s.url, INIT, { authorization: `Bearer ${issued.body.access_token}` });
    assert.equal(init.status, 200);
    assert.equal((await rpcResult(init)).result.serverInfo !== undefined, true);
    const list = await mcpPost(s.url, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, { authorization: `Bearer ${issued.body.access_token}` });
    assert.equal(list.status, 200);
    assert.ok((await rpcResult(list)).result.tools.length > 0);
    const viaApiKey = await mcpPost(s.url, INIT, { "x-api-key": issued.body.access_token });
    assert.equal(viaApiKey.status, 200);

    // Refresh: a new access token (new jti, same acct) and a new refresh token.
    const refreshed = await tokenCall(s.url, { grant_type: "refresh_token", refresh_token: issued.body.refresh_token, client_id: consent.client.client_id, resource: `${PUBLIC}/mcp` });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    const v2 = verifyToken(SECRET, refreshed.body.access_token);
    assert.equal(v2.payload.acct, v.payload.acct);
    assert.notEqual(v2.payload.jti, v.payload.jti);
    assert.notEqual(refreshed.body.refresh_token, issued.body.refresh_token);
    assert.equal((await mcpPost(s.url, INIT, { authorization: `Bearer ${refreshed.body.access_token}` })).status, 200);

    // The old refresh token is spent; replaying it also revokes its whole family.
    const replay = await tokenCall(s.url, { grant_type: "refresh_token", refresh_token: issued.body.refresh_token, client_id: consent.client.client_id });
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error, "invalid_grant");
    const family = await tokenCall(s.url, { grant_type: "refresh_token", refresh_token: refreshed.body.refresh_token, client_id: consent.client.client_id });
    assert.equal(family.body.error, "invalid_grant", "reuse revokes the newer refresh token too");

    // Codes, refresh tokens and client ids are never accepted as MCP credentials.
    for (const credential of [code, issued.body.refresh_token, consent.client.client_id, consent.requestToken, cookie.slice(cookie.indexOf("=") + 1)]) {
      assert.equal((await mcpPost(s.url, INIT, { authorization: `Bearer ${credential}` })).status, 401);
    }
  } finally {
    await s.close();
  }
});

test("the token endpoint also accepts a JSON body", async () => {
  const h = await harness();
  try {
    const a = await approve(h.url);
    const res = await tokenCall(h.url, { grant_type: "authorization_code", code: a.code, redirect_uri: a.redirectUri, client_id: a.client.client_id, code_verifier: a.verifier }, "json");
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.token_type, "Bearer");
  } finally {
    await h.close();
  }
});

test("Claude Code shape: loopback redirect on a different port per sign-in, resource=/mcp, no client secret", async () => {
  const h = await harness();
  try {
    const client = await registerClient(h.url, { client_name: "Claude Code (clockchain)", redirect_uris: ["http://localhost:53092/callback"], token_endpoint_auth_method: "none" });
    for (const redirectUri of ["http://localhost:53092/callback", "http://localhost:60330/callback"]) {
      const a = await approve(h.url, { client, redirectUri });
      assert.equal(`${a.location.origin}${a.location.pathname}`, redirectUri);
      assert.match(a.page.headers.get("content-security-policy"), new RegExp(`form-action 'self' ${redirectUri.slice(0, redirectUri.lastIndexOf("/"))}`));
      assert.equal((await exchangeCode(h.url, a)).status, 200);
    }
    // Any port, but never a different host or path.
    for (const bad of ["http://127.0.0.1:53092/callback", "http://localhost:53092/other", "http://localhost:53092/callback?x=1"]) {
      const c = await openConsent(h.url, { client, redirectUri: bad });
      assert.equal(c.page.status, 400, bad);
      assert.equal(c.page.headers.get("location"), null);
    }
  } finally {
    await h.close();
  }
});

test("redirect_uri may be omitted at authorize when exactly one is registered (then also at the token endpoint)", async () => {
  const h = await harness();
  try {
    const a = await approve(h.url, { drop: ["redirect_uri"] });
    assert.equal(`${a.location.origin}${a.location.pathname}`, CHATGPT_CB);
    const res = await tokenCall(h.url, { grant_type: "authorization_code", code: a.code, client_id: a.client.client_id, code_verifier: a.verifier });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const two = await registerClient(h.url, { redirect_uris: [CHATGPT_CB, "https://chatgpt.com/connector/oauth/abc123"] });
    const c = await openConsent(h.url, { client: two, drop: ["redirect_uri"] });
    assert.equal(c.page.status, 400);
  } finally {
    await h.close();
  }
});

// ===========================================================================
// Rejections
// ===========================================================================

test("PKCE: S256 is required at authorize, and a wrong or missing verifier fails at the token endpoint", async () => {
  const h = await harness();
  try {
    for (const [params, drop, error] of [
      [{ code_challenge_method: "plain" }, [], "invalid_request"],
      [{}, ["code_challenge_method"], "invalid_request"],
      [{}, ["code_challenge"], "invalid_request"],
      [{ code_challenge: "too-short" }, [], "invalid_request"],
      [{ response_type: "token" }, [], "unsupported_response_type"],
      [{}, ["response_type"], "invalid_request"],
      [{ state: "x".repeat(2049) }, [], "invalid_request"],
      [{ state: "caf\u00e9" }, [], "invalid_request"],
    ]) {
      const c = await openConsent(h.url, { params, drop });
      assertErrorPage(c.page, c.html, { code: error, mustNotMention: ["chatgpt.com"] });
    }
    const a = await approve(h.url);
    for (const verifier of [pkce().verifier, "short", undefined]) {
      const params = { grant_type: "authorization_code", code: a.code, redirect_uri: a.redirectUri, client_id: a.client.client_id };
      if (verifier !== undefined) params.code_verifier = verifier;
      const res = await tokenCall(h.url, params);
      assert.equal(res.status, 400);
      assert.equal(res.body.error, "invalid_grant");
      assert.equal(res.headers.get("cache-control"), "no-store");
    }
    assert.equal((await exchangeCode(h.url, a)).status, 200, "failed attempts do not burn the code");
  } finally {
    await h.close();
  }
});

test("a code is single use; replaying it is refused and revokes the refresh tokens it produced", async () => {
  const h = await harness();
  try {
    const a = await approve(h.url);
    const first = await exchangeCode(h.url, a);
    assert.equal(first.status, 200);
    const again = await exchangeCode(h.url, a);
    assert.equal(again.status, 400);
    assert.equal(again.body.error, "invalid_grant");
    const refresh = await tokenCall(h.url, { grant_type: "refresh_token", refresh_token: first.body.refresh_token, client_id: a.client.client_id });
    assert.equal(refresh.body.error, "invalid_grant");
    assert.ok(h.logs.some((e) => e.event === "oauth_code_reuse"));
  } finally {
    await h.close();
  }
});

test("an expired code (5 minutes), request token (10 minutes) or refresh token (60 days) is refused", async () => {
  const h = await harness();
  try {
    const a = await approve(h.url);
    h.advance(5 * 60_000);
    assert.equal((await exchangeCode(h.url, a)).body.error, "invalid_grant");

    const c = await openConsent(h.url);
    h.advance(10 * 60_000);
    const late = await decide(h.url, c.requestToken);
    assert.equal(late.status, 400);
    assert.equal(late.headers.get("location"), null);

    const b = await approve(h.url);
    const issued = await exchangeCode(h.url, b);
    h.advance(60 * 24 * 3600_000 - 1000);
    const ok = await tokenCall(h.url, { grant_type: "refresh_token", refresh_token: issued.body.refresh_token, client_id: b.client.client_id });
    assert.equal(ok.status, 200, "valid until the last second of its 60 days");
    h.advance(60 * 24 * 3600_000 - 1000);
    const rotated = await tokenCall(h.url, { grant_type: "refresh_token", refresh_token: ok.body.refresh_token, client_id: b.client.client_id });
    assert.equal(rotated.status, 200, "each rotated token has its own 60 days");
    h.advance(60 * 24 * 3600_000);
    const dead = await tokenCall(h.url, { grant_type: "refresh_token", refresh_token: rotated.body.refresh_token, client_id: b.client.client_id });
    assert.equal(dead.body.error, "invalid_grant");
  } finally {
    await h.close();
  }
});

test("redirect_uri mismatch: an error page at authorize (never a redirect), invalid_grant at the token endpoint", async () => {
  const h = await harness();
  try {
    for (const evil of ["https://evil.example/cb", `${CHATGPT_CB}/x`, `${CHATGPT_CB}?a=1`, "https://chatgpt.com.evil.example/connector_platform_oauth_redirect"]) {
      const c = await openConsent(h.url, { redirectUri: evil });
      assert.equal(c.page.status, 400, evil);
      assert.equal(c.page.headers.get("location"), null);
      assert.equal(c.requestToken, undefined);
      assert.equal(c.page.headers.get("x-frame-options"), "DENY");
    }
    const two = await registerClient(h.url, { redirect_uris: [CHATGPT_CB, "https://chatgpt.com/connector/oauth/abc123"] });
    const a = await approve(h.url, { client: two });
    const res = await exchangeCode(h.url, a, { redirect_uri: "https://chatgpt.com/connector/oauth/abc123" });
    assert.equal(res.body.error, "invalid_grant");
  } finally {
    await h.close();
  }
});

test("a tampered client_id, request token or state is refused", async () => {
  const h = await harness();
  try {
    const client = await registerClient(h.url);
    // Swapping the registered redirect URI inside the client_id breaks its MAC.
    const forged = { ...client, client_id: tamper(client.client_id, "cc_client_", (b) => { b.ru = ["https://evil.example/cb"]; }) };
    const page = await openConsent(h.url, { client: forged, redirectUri: "https://evil.example/cb" });
    assert.equal(page.page.status, 400);
    assert.equal(page.page.headers.get("location"), null);
    const flipped = { ...client, client_id: `${client.client_id.slice(0, -1)}${client.client_id.endsWith("A") ? "B" : "A"}` };
    assert.equal((await openConsent(h.url, { client: flipped })).page.status, 400);

    const c = await openConsent(h.url, { client });
    for (const bad of [
      tamper(c.requestToken, "cc_req_", (b) => { b.st = "attacker-state"; }),
      tamper(c.requestToken, "cc_req_", (b) => { b.ru = "https://evil.example/cb"; }),
      `${c.requestToken.slice(0, -1)}${c.requestToken.endsWith("A") ? "B" : "A"}`,
      "",
    ]) {
      const res = await decide(h.url, bad);
      assert.equal(res.status, 400);
      assert.equal(res.headers.get("location"), null);
    }
    // A request token is never accepted as a code, nor a code as a refresh token.
    const a = await approve(h.url, { client });
    assert.equal((await exchangeCode(h.url, { ...a, code: c.requestToken })).body.error, "invalid_grant");
    assert.equal((await tokenCall(h.url, { grant_type: "refresh_token", refresh_token: a.code, client_id: client.client_id })).body.error, "invalid_grant");
    // A forged client_id at the token endpoint is invalid_client (401).
    const res = await exchangeCode(h.url, { ...a, client: forged });
    assert.equal(res.status, 401);
    assert.equal(res.body.error, "invalid_client");
    // A real but different client cannot redeem this client's code.
    const other = await registerClient(h.url, { client_name: "Other" });
    assert.equal((await exchangeCode(h.url, { ...a, client: other })).body.error, "invalid_grant");
    assert.equal((await exchangeCode(h.url, a)).status, 200);
  } finally {
    await h.close();
  }
});

test("open redirect closed: a client registered with https://evil.example/cb gets no redirect without the person's click", async () => {
  const h = await harness();
  const EVIL = "https://evil.example/cb";
  try {
    const client = await registerClient(h.url, { client_name: "Totally ChatGPT", redirect_uris: [EVIL] });
    // Every error a crafted link can trigger before anyone clicks renders a page.
    for (const [params, drop, code] of [
      [{ code_challenge_method: "plain" }, [], "invalid_request"],
      [{}, ["code_challenge_method"], "invalid_request"],
      [{}, ["code_challenge"], "invalid_request"],
      [{ code_challenge: "x" }, [], "invalid_request"],
      [{ response_type: "token" }, [], "unsupported_response_type"],
      [{}, ["response_type"], "invalid_request"],
      [{ resource: "https://evil.example/mcp" }, [], "invalid_target"],
      [{ state: "x".repeat(5000) }, [], "invalid_request"],
      [{ state: "\u0000\n" }, [], "invalid_request"],
    ]) {
      for (const redirectUri of [EVIL, undefined]) {
        const c = await openConsent(h.url, { client, params, drop: redirectUri ? drop : [...drop, "redirect_uri"] });
        assertErrorPage(c.page, c.html, { code, mustNotMention: ["evil.example"] });
      }
    }
    const dup = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: EVIL, code_challenge: pkce().challenge, code_challenge_method: "S256", state: "s" });
    dup.append("code_challenge_method", "S256");
    const dupRes = await fetch(`${h.url}/oauth/authorize?${dup}`, { redirect: "manual" });
    assertErrorPage(dupRes, await dupRes.text(), { code: "invalid_request", mustNotMention: ["evil.example"] });
    for (const method of ["PUT", "DELETE", "HEAD"]) {
      const r = await fetch(`${h.url}/oauth/authorize?${dup}`, { method, redirect: "manual" });
      assert.equal(r.headers.get("location"), null, method);
      assert.ok(r.status >= 400, method);
    }

    // A fully valid link shows the approval page and goes nowhere on its own.
    const ok = await openConsent(h.url, { client });
    assert.equal(ok.page.status, 200);
    assert.equal(ok.page.headers.get("location"), null);
    assert.equal(ok.page.headers.get("refresh"), null);
    assert.doesNotMatch(ok.html, /<a\b|<script|http-equiv/i);
    assert.match(ok.html, /<code>evil\.example<\/code>/, "the destination is shown as plain text, not a link");

    // Failures after a click that did not come from our page are pages too.
    for (const [token, decision, headers, status] of [
      [ok.requestToken, "approve", {}, 403],
      [ok.requestToken, "approve", { origin: "https://evil.example" }, 403],
      [tamper(ok.requestToken, "cc_req_", (b) => { b.st = "x"; }), "approve", { origin: PUBLIC }, 400],
      [ok.requestToken, "redirect", { origin: PUBLIC }, 400],
    ]) {
      const r = await decide(h.url, token, decision, headers);
      assertErrorPage(r, await r.text(), { status, mustNotMention: ["evil.example"] });
    }

    // Only the person's own Cancel or Approve sends them there, with state and iss.
    const cancel = await decide(h.url, ok.requestToken, "cancel");
    assert.equal(cancel.status, 303);
    const cancelled = new URL(cancel.headers.get("location"));
    assert.equal(`${cancelled.origin}${cancelled.pathname}`, EVIL);
    assert.equal(cancelled.searchParams.get("error"), "access_denied");
    assert.equal(cancelled.searchParams.get("state"), "state-123");
    assert.equal(cancelled.searchParams.get("iss"), PUBLIC);
    const { res: approve } = await allow(h.url, { client });
    assert.equal(approve.status, 303);
    const approved = new URL(approve.headers.get("location"));
    assert.equal(`${approved.origin}${approved.pathname}`, EVIL);
    assert.ok(approved.searchParams.get("code").startsWith("cc_code_"));
    assert.equal(approved.searchParams.get("state"), "state-123");
    assert.equal(approved.searchParams.get("iss"), PUBLIC);
  } finally {
    await h.close();
  }
});

test("Cancel redirects with error=access_denied, the original state and iss", async () => {
  const h = await harness();
  try {
    const c = await openConsent(h.url, { state: "keep me" });
    const res = await decide(h.url, c.requestToken, "cancel");
    assert.equal(res.status, 303);
    const loc = new URL(res.headers.get("location"));
    assert.equal(loc.searchParams.get("error"), "access_denied");
    assert.equal(loc.searchParams.get("state"), "keep me");
    assert.equal(loc.searchParams.get("iss"), PUBLIC);
    assert.equal(loc.searchParams.get("code"), null);
    assert.equal((await decide(h.url, c.requestToken, "maybe")).status, 400);
  } finally {
    await h.close();
  }
});

test("resource: must be one of this server's MCP URLs, and must match the approval at the token endpoint", async () => {
  const h = await harness();
  try {
    for (const resource of ["https://evil.example/mcp", `${PUBLIC}/other`, `${PUBLIC}/mcp#frag`]) {
      const c = await openConsent(h.url, { resource });
      assertErrorPage(c.page, c.html, { code: "invalid_target", mustNotMention: ["chatgpt.com"] });
    }
    for (const resource of [PUBLIC, `${PUBLIC}/`, `${PUBLIC}/mcp`, `${PUBLIC}/shadow/mcp`]) {
      assert.equal((await openConsent(h.url, { resource })).page.status, 200, resource);
    }
    const a = await approve(h.url, { resource: `${PUBLIC}/mcp` });
    assert.equal((await exchangeCode(h.url, a, { resource: `${PUBLIC}/shadow/mcp` })).body.error, "invalid_target");
    const ok = await exchangeCode(h.url, a);
    assert.equal(ok.status, 200);
    const r = await tokenCall(h.url, { grant_type: "refresh_token", refresh_token: ok.body.refresh_token, client_id: a.client.client_id, resource: `${PUBLIC}/shadow/mcp` });
    assert.equal(r.body.error, "invalid_target");
  } finally {
    await h.close();
  }
});

test("CSRF: the approval POST must come from our own origin", async () => {
  const h = await harness();
  try {
    const c = await openConsent(h.url);
    for (const headers of [{}, { origin: "https://evil.example" }, { origin: "null" }, { referer: "https://evil.example/page" }, { origin: "https://evil.example", referer: `${PUBLIC}/oauth/authorize` }]) {
      const res = await decide(h.url, c.requestToken, "approve", headers);
      assert.equal(res.status, 403, JSON.stringify(headers));
      assert.equal(res.headers.get("location"), null);
    }
    const { res: viaReferer } = await allow(h.url, {}, { referer: `${PUBLIC}/oauth/authorize?client_id=x` });
    assert.equal(viaReferer.status, 303);
  } finally {
    await h.close();
  }
});

test("rate limits: 10 approvals per IP per hour; registrations and token calls are capped too", async () => {
  const h = await harness();
  try {
    const client = await registerClient(h.url);
    for (let i = 0; i < 10; i++) assert.ok((await approve(h.url, { client })).code, `approval ${i + 1}`);
    const { consent: c, res: blocked } = await allow(h.url, { client });
    assertErrorPage(blocked, await blocked.text(), { status: 429, code: "temporarily_unavailable", mustNotMention: ["chatgpt.com"] });
    assert.equal(blocked.headers.get("retry-after"), "3600");
    assert.equal((await decide(h.url, c.requestToken, "cancel")).status, 303, "cancel is never limited");
    h.advance(60 * 60_000);
    assert.ok((await approve(h.url, { client })).code, "the window resets after an hour");
  } finally {
    await h.close();
  }

  const r = await harness({ registrationsPerMinute: 3, tokenCallsPerMinute: 2 });
  try {
    for (let i = 0; i < 3; i++) assert.equal((await postJson(`${r.url}/oauth/register`, { redirect_uris: [CHATGPT_CB] })).status, 201);
    const limited = await postJson(`${r.url}/oauth/register`, { redirect_uris: [CHATGPT_CB] });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("access-control-allow-origin"), "*");
    for (let i = 0; i < 2; i++) assert.equal((await tokenCall(r.url, { grant_type: "refresh_token" })).status, 401);
    assert.equal((await tokenCall(r.url, { grant_type: "refresh_token" })).status, 429);
  } finally {
    await r.close();
  }
});

test("rate-limit buckets use X-Forwarded-For only from the trusted proxy", async () => {
  const trusted = await harness({ trustedProxy: "127.0.0.1", approvalsPerHour: 1 });
  try {
    const client = await registerClient(trusted.url);
    const send = async (xff) => (await allow(trusted.url, { client }, { origin: PUBLIC, "x-forwarded-for": xff })).res.status;
    assert.equal(await send("198.51.100.1"), 303);
    assert.equal(await send("198.51.100.1"), 429);
    assert.equal(await send("198.51.100.2"), 303, "a different client behind the proxy has its own bucket");
  } finally {
    await trusted.close();
  }
  const untrusted = await harness({ approvalsPerHour: 1 });
  try {
    const client = await registerClient(untrusted.url);
    await allow(untrusted.url, { client }, { origin: PUBLIC, "x-forwarded-for": "198.51.100.1" });
    const { res } = await allow(untrusted.url, { client }, { origin: PUBLIC, "x-forwarded-for": "198.51.100.9" });
    assert.equal(res.status, 429, "a spoofed XFF does not rotate the bucket");
  } finally {
    await untrusted.close();
  }
});

test("registration: redirect URI rules, 16 KB JSON-only bodies, and client_name escaped and cut to 60 characters", async () => {
  const h = await harness();
  try {
    for (const redirect_uris of [
      ["http://chatgpt.com/cb"], ["https://chatgpt.com/cb#frag"], ["javascript:alert(1)"], ["https://user:pw@chatgpt.com/cb"],
      ["https://chat gpt.com/cb"], ["/relative"], [], Array.from({ length: 6 }, (_, i) => `https://a.example/${i}`),
      [`https://a.example/${"x".repeat(600)}`], "https://chatgpt.com/cb", [42], ["https://a;b.example/cb"],
    ]) {
      const res = await postJson(`${h.url}/oauth/register`, { redirect_uris });
      assert.equal(res.status, 400, JSON.stringify(redirect_uris).slice(0, 80));
      assert.equal((await res.json()).error, "invalid_redirect_uri");
    }
    for (const ok of [["http://127.0.0.1:3118/callback"], ["http://[::1]:8080/cb"], ["https://localhost/cb"]]) {
      assert.equal((await postJson(`${h.url}/oauth/register`, { redirect_uris: ok })).status, 201, ok[0]);
    }
    const wrongType = await fetch(`${h.url}/oauth/register`, { method: "POST", headers: { "content-type": "text/plain" }, body: JSON.stringify({ redirect_uris: [CHATGPT_CB] }) });
    assert.equal(wrongType.status, 400);
    const big = await postJson(`${h.url}/oauth/register`, { redirect_uris: [CHATGPT_CB], pad: "x".repeat(17 * 1024) });
    assert.equal(big.status, 413);
    assert.equal((await postJson(`${h.url}/oauth/register`, { redirect_uris: [CHATGPT_CB], grant_types: ["client_credentials"] })).status, 400);

    const name = `<img src=x onerror=alert(1)>‮Evil\u0007 ${"A".repeat(80)}`;
    const client = await registerClient(h.url, { client_name: name });
    assert.equal([...client.client_name].length, 60);
    assert.doesNotMatch(client.client_name, /[‮\u0007]/);
    const c = await openConsent(h.url, { client });
    assert.doesNotMatch(c.html, /<img/);
    assert.match(c.html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    const anon = await openConsent(h.url, { meta: { client_name: undefined } });
    assert.match(anon.html, /An unnamed app/);
  } finally {
    await h.close();
  }
});

test("token endpoint errors use RFC 6749 JSON with no-store", async () => {
  const h = await harness();
  try {
    const client = await registerClient(h.url);
    const cases = [
      [{ grant_type: "client_credentials", client_id: client.client_id }, 400, "unsupported_grant_type"],
      [{ client_id: client.client_id }, 400, "invalid_request"],
      [{ grant_type: "authorization_code", code: "cc_code_x.y", client_id: client.client_id }, 400, "invalid_grant"],
      [{ grant_type: "authorization_code" }, 401, "invalid_client"],
    ];
    for (const [params, status, error] of cases) {
      const res = await tokenCall(h.url, params);
      assert.equal(res.status, status, JSON.stringify(params));
      assert.equal(res.body.error, error);
      assert.equal(typeof res.body.error_description, "string");
      assert.equal(res.headers.get("cache-control"), "no-store");
    }
    const dup = await fetch(`${h.url}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=refresh_token&grant_type=authorization_code" });
    assert.equal((await dup.json()).error, "invalid_request");
    assert.equal((await fetch(`${h.url}/oauth/token`)).status, 405);
  } finally {
    await h.close();
  }
});

test("CORS: * without credentials on metadata, register and token only; never on authorize", async () => {
  const h = await harness();
  try {
    for (const p of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/oauth/register", "/oauth/token"]) {
      const pre = await fetch(`${h.url}${p}`, { method: "OPTIONS", headers: { origin: "https://app.example", "access-control-request-method": "POST" } });
      assert.equal(pre.status, 204, p);
      assert.equal(pre.headers.get("access-control-allow-origin"), "*");
      assert.equal(pre.headers.get("access-control-allow-credentials"), null);
      assert.match(pre.headers.get("access-control-allow-headers"), /content-type/);
    }
    assert.equal((await fetch(`${h.url}/.well-known/oauth-authorization-server`)).headers.get("access-control-allow-origin"), "*");
    const c = await openConsent(h.url);
    assert.equal(c.page.headers.get("access-control-allow-origin"), null);
    const post = await decide(h.url, c.requestToken);
    assert.equal(post.headers.get("access-control-allow-origin"), null);
    const pre = await fetch(`${h.url}/oauth/authorize`, { method: "OPTIONS", headers: { origin: "https://app.example" } });
    assert.notEqual(pre.status, 204);
    assert.equal(pre.headers.get("access-control-allow-origin"), null);
    assert.equal((await fetch(`${h.url}/oauth/other`)).status, 404, "unknown /oauth/* paths fall through");
  } finally {
    await h.close();
  }
});

// ===========================================================================
// Accounts: sign-up / sign-in on the approval page
// ===========================================================================

const SECURE_CLEAR = "__Host-cc_acct=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax";
const keyHashOf = (key) => createHash("sha256").update(key).digest("hex");
const codeOf = (res) => new URL(res.headers.get("location")).searchParams.get("code");
const tokenAcct = (issued) => verifyToken(SECRET, issued.body.access_token).payload.acct;

test("accounts: a second app in the same browser, and a key sign-in from a new browser, get the same acct", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    // App 1 (ChatGPT): a brand-new person creates the account, then Continue.
    const person = await signUp(s.url, "Grace");
    const cont = await decide(s.url, person.consent.requestToken, "continue", { origin: PUBLIC }, { grant: person.grant });
    assert.equal(cont.status, 303);
    const t1 = await exchangeCode(s.url, { ...person.consent, code: codeOf(cont) });
    // App 2 (Claude Code), same browser: the cookie selects the account; the person still clicks Allow.
    const claude = await registerClient(s.url, { client_name: "Claude Code", redirect_uris: ["http://localhost:53111/callback"] });
    const shown = await openConsent(s.url, { client: claude, cookie: person.cookie, redirectUri: "http://localhost:60123/callback" });
    assert.match(shown.html, /Signed in as <strong>Grace<\/strong>/);
    assert.match(shown.html, />Allow Claude Code<\/button>/);
    assert.match(shown.html, /value="cancel">Cancel<\/button>/);
    assert.match(shown.html, />Not you\? Use a different account<\/button>/);
    assert.match(shown.html, /<code>localhost:60123<\/code>/);
    assert.equal(shown.page.headers.get("location"), null, "a valid cookie never approves by itself");
    const a2 = await approve(s.url, { client: claude, account: person, redirectUri: "http://localhost:60123/callback" });
    const t2 = await exchangeCode(s.url, a2);
    // App 3 (another ChatGPT connector), a new browser with no cookie: sign in with the account key.
    const fresh = await openConsent(s.url, { meta: { client_name: "ChatGPT (work)" } });
    assert.match(fresh.html, /Create your Clockchain account/);
    const signin = await decide(s.url, fresh.requestToken, "signin", { origin: PUBLIC }, { key: ` ${person.key} ` });
    assert.equal(signin.status, 303);
    assert.match(signin.headers.get("set-cookie"), /^__Host-cc_acct=cc_ac_[^;]+; Max-Age=31536000; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
    const t3 = await exchangeCode(s.url, { ...fresh, code: codeOf(signin) });
    assert.deepEqual([t1, t2, t3].map(tokenAcct), [person.acct, person.acct, person.acct]);
    // That browser is signed in now too; refresh keeps the acct.
    assert.match((await openConsent(s.url, { client: fresh.client, cookie: cookieOf(signin) })).html, /Signed in as <strong>Grace<\/strong>/);
    const refreshed = await tokenCall(s.url, { grant_type: "refresh_token", refresh_token: t2.body.refresh_token, client_id: claude.client_id });
    assert.equal(tokenAcct(refreshed), person.acct);
  } finally {
    await s.close();
  }
});

test("accounts: bad, tampered, foreign, unknown and expired cookies are signed out (and cleared); other names are ignored", async () => {
  const h = await harness();
  const other = await harness(); // same signing secret, different account store
  const alien = await harness({ signingSecret: "another-secret" });
  try {
    const person = await accountFor(h.url);
    assert.match((await openConsent(h.url, { cookie: person.cookie })).html, /Signed in as/);
    const value = person.cookie.slice(person.cookie.indexOf("=") + 1);
    for (const [label, cookie] of [
      ["garbage", "__Host-cc_acct=nonsense"],
      ["tampered acct", `__Host-cc_acct=${tamper(value, "cc_ac_", (b) => { b.acct = `acct_${"Z".repeat(22)}`; })}`],
      ["tampered iat", `__Host-cc_acct=${tamper(value, "cc_ac_", (b) => { b.iat += 1; })}`],
      ["flipped MAC", `__Host-cc_acct=${value.slice(0, -1)}${value.endsWith("A") ? "B" : "A"}`],
      ["another store's account", (await accountFor(other.url)).cookie],
      ["another secret", (await accountFor(alien.url)).cookie],
    ]) {
      const c = await openConsent(h.url, { cookie });
      assert.equal(c.page.status, 200, label);
      assert.match(c.html, /Create your Clockchain account/, label);
      assert.doesNotMatch(c.html, /Signed in as/, label);
      assert.equal(c.page.headers.get("set-cookie"), SECURE_CLEAR, `${label}: cleared`);
    }
    // Not our cookie name (the non-Secure loopback name, on an https issuer): ignored, not cleared.
    const misnamed = await openConsent(h.url, { cookie: `cc_acct=${value}` });
    assert.match(misnamed.html, /Create your Clockchain account/);
    assert.equal(misnamed.page.headers.get("set-cookie"), null);
    // Approve with a bad cookie: the page again (signed out), never a code.
    const c = await openConsent(h.url, { cookie: person.cookie });
    const bad = await decide(h.url, c.requestToken, "approve", { origin: PUBLIC, cookie: "__Host-cc_acct=nonsense" }, { grant: c.grant });
    assert.equal(bad.status, 409);
    assert.equal(bad.headers.get("location"), null);
    assert.equal(bad.headers.get("set-cookie"), SECURE_CLEAR);
    // A year after it was set, the cookie no longer signs in, whatever the browser does with Max-Age.
    h.advance(365 * 24 * 3600_000 - 60_000);
    assert.match((await openConsent(h.url, { cookie: person.cookie })).html, /Signed in as/);
    h.advance(60_000);
    const expired = await openConsent(h.url, { cookie: person.cookie });
    assert.match(expired.html, /Create your Clockchain account/);
    assert.equal(expired.page.headers.get("set-cookie"), SECURE_CLEAR);
  } finally {
    await h.close();
    await other.close();
    await alien.close();
  }
});

test("accounts: 'Not you? Use a different account' clears the cookie and the same request continues as someone new", async () => {
  const h = await harness();
  try {
    const person = await accountFor(h.url);
    const c = await openConsent(h.url, { cookie: person.cookie });
    assert.equal((await decide(h.url, c.requestToken, "switch", { cookie: person.cookie })).status, 403, "CSRF-checked too");
    const switched = await decide(h.url, c.requestToken, "switch", { origin: PUBLIC, cookie: person.cookie });
    assert.equal(switched.status, 200);
    assert.equal(switched.headers.get("set-cookie"), SECURE_CLEAR);
    const html = await switched.text();
    assert.match(html, /Create your Clockchain account/);
    assert.equal(/name="request" value="([^"]+)"/.exec(html)[1], c.requestToken);
    const created = await decide(h.url, c.requestToken, "create", { origin: PUBLIC }, { name: "Someone New" });
    const grant = /name="grant" value="([^"]+)"/.exec(await created.text())[1];
    const cont = await decide(h.url, c.requestToken, "continue", { origin: PUBLIC }, { grant });
    const issued = await exchangeCode(h.url, { ...c, code: codeOf(cont) });
    assert.notEqual(tokenAcct(issued), person.acct);
    assert.equal(tokenAcct(issued), acctOfCookie(cookieOf(created)));
  } finally {
    await h.close();
  }
});

test("accounts: CSRF — create, sign-in, continue, approve and switch POSTs need our Origin (or Referer)", async () => {
  const accountsDir = path.join(tempDir("csrf"), "accounts");
  const h = await harness({ accountsDir });
  try {
    const person = await accountFor(h.url);
    const before = readdirSync(path.join(accountsDir, "a")).length;
    const c = await openConsent(h.url, { cookie: person.cookie });
    const fresh = await openConsent(h.url);
    for (const [decision, requestToken, fields, cookie] of [
      ["create", fresh.requestToken, { name: "Mallory" }, undefined],
      ["signin", fresh.requestToken, { key: person.key }, undefined],
      ["continue", person.consent.requestToken, { grant: person.grant }, undefined],
      ["approve", c.requestToken, { grant: c.grant }, person.cookie],
      ["switch", c.requestToken, {}, person.cookie],
    ]) {
      for (const headers of [{}, { origin: "https://evil.example" }, { origin: "null" }, { referer: "https://evil.example/x" }, { origin: "https://evil.example", referer: `${PUBLIC}/oauth/authorize` }]) {
        const res = await decide(h.url, requestToken, decision, { ...headers, ...(cookie ? { cookie } : {}) }, fields);
        assert.equal(res.status, 403, `${decision} ${JSON.stringify(headers)}`);
        assert.equal(res.headers.get("location"), null);
        assert.equal(res.headers.get("set-cookie"), null);
        assert.equal((await res.text()).includes("cck_"), false);
      }
    }
    assert.equal(readdirSync(path.join(accountsDir, "a")).length, before, "no account was created");
    assert.equal(h.logs.filter((e) => e.event === "oauth_approved").length, 0, "nothing was approved");
  } finally {
    await h.close();
  }
});

test("accounts: names are cleaned, bounded to 40 characters and always escaped (XSS attempt)", async () => {
  const h = await harness();
  try {
    const xss = `<script>alert(1)</script>"'&`;
    const person = await signUp(h.url, xss);
    assert.doesNotMatch(person.html, /<script>alert/);
    assert.match(person.html, /Signed in as <strong>&lt;script&gt;alert\(1\)&lt;\/script&gt;&quot;&#39;&amp;<\/strong>/);
    const page = await openConsent(h.url, { cookie: person.cookie });
    assert.doesNotMatch(page.html, /<script>alert/);
    assert.match(page.html, /Signed in as <strong>&lt;script&gt;alert\(1\)&lt;\/script&gt;&quot;&#39;&amp;<\/strong>/);
    assert.doesNotMatch(page.page.headers.get("content-security-policy"), /script-src|unsafe-inline/);
    // Control and bidi characters are dropped and whitespace collapsed; 40 characters is the limit.
    assert.match((await signUp(h.url, " a\u0000b‮c  d ")).html, /Signed in as <strong>a b c d<\/strong>/);
    assert.match((await signUp(h.url, "🙂".repeat(40))).html, /Signed in as <strong>(🙂){40}<\/strong>/);
    for (const bad of ["", "   ", "\u0007", "x".repeat(41), "🙂".repeat(41)]) {
      const c = await openConsent(h.url);
      const res = await decide(h.url, c.requestToken, "create", { origin: PUBLIC }, { name: bad });
      assert.equal(res.status, 400, JSON.stringify(bad));
      assert.equal(res.headers.get("set-cookie"), null);
      const html = await res.text();
      assert.match(html, /role="alert">Choose an account name of 1 to 40 characters\./);
      assert.equal(/name="request" value="([^"]+)"/.exec(html)[1], c.requestToken, "the same request, still valid");
      assert.equal(html.includes("cck_"), false);
    }
  } finally {
    await h.close();
  }
});

test("accounts: per-IP limits on creation and key attempts, and the global account cap", async () => {
  const accountsDir = path.join(tempDir("limits"), "accounts");
  const h = await harness({ accountsDir, accountCreationsPerHour: 2, keyAttemptsPerHour: 3 });
  try {
    const first = await signUp(h.url, "One");
    await signUp(h.url, "Two");
    const c = await openConsent(h.url);
    const limited = await decide(h.url, c.requestToken, "create", { origin: PUBLIC }, { name: "Three" });
    assertErrorPage(limited, await limited.text(), { status: 429, code: "temporarily_unavailable" });
    assert.equal(limited.headers.get("set-cookie"), null);
    assert.equal(readdirSync(path.join(accountsDir, "a")).length, 2);

    for (let i = 0; i < 3; i++) {
      const res = await decide(h.url, c.requestToken, "signin", { origin: PUBLIC }, { key: `cck_${String(i).repeat(32)}` });
      assert.equal(res.status, 400);
      assert.match(await res.text(), /role="alert">That account key wasn’t recognized\./);
    }
    const blocked = await decide(h.url, c.requestToken, "signin", { origin: PUBLIC }, { key: first.key });
    assertErrorPage(blocked, await blocked.text(), { status: 429, code: "temporarily_unavailable" });
    assert.equal(blocked.headers.get("set-cookie"), null, "even the right key waits out the limit");
    assert.equal(h.logs.filter((e) => e.event === "oauth_account_key_rejected").length, 3);
    h.advance(60 * 60_000);
    const later = await openConsent(h.url);
    assert.equal((await decide(h.url, later.requestToken, "signin", { origin: PUBLIC }, { key: first.key })).status, 303);
  } finally {
    await h.close();
  }

  const capped = await harness({ maxAccounts: 1 });
  try {
    await signUp(capped.url, "Only");
    const c = await openConsent(capped.url);
    const full = await decide(capped.url, c.requestToken, "create", { origin: PUBLIC }, { name: "One too many" });
    assertErrorPage(full, await full.text(), { status: 503, code: "temporarily_unavailable" });
    assert.ok(capped.logs.some((e) => e.event === "oauth_accounts_full"));
  } finally {
    await capped.close();
  }
});

test("accounts: a click approves only the account its page showed", async () => {
  const h = await harness();
  try {
    const alice = await signUp(h.url, "Alice");
    const bob = await signUp(h.url, "Bob");
    const page = await openConsent(h.url, { cookie: alice.cookie });
    const otherPage = await openConsent(h.url, { client: page.client, cookie: alice.cookie });
    for (const [label, cookie, fields] of [
      ["the cookie switched to Bob after the page loaded", bob.cookie, { grant: page.grant }],
      ["no grant", alice.cookie, {}],
      ["a grant for another request", alice.cookie, { grant: otherPage.grant }],
      ["the key page's grant", alice.cookie, { grant: alice.grant }],
      ["signed out", undefined, { grant: page.grant }],
    ]) {
      const res = await decide(h.url, page.requestToken, "approve", { origin: PUBLIC, ...(cookie ? { cookie } : {}) }, fields);
      assert.equal(res.status, 409, label);
      assert.equal(res.headers.get("location"), null, label);
      assert.match(await res.text(), /Your sign-in changed since this page loaded/, label);
    }
    // Continue only takes the key page's own grant.
    const cont = await decide(h.url, page.requestToken, "continue", { origin: PUBLIC }, { grant: page.grant });
    assertErrorPage(cont, await cont.text(), { status: 400 });
    // The grant expires with the request token (10 minutes).
    h.advance(10 * 60_000);
    assert.equal((await decide(h.url, page.requestToken, "approve", { origin: PUBLIC, cookie: alice.cookie }, { grant: page.grant })).status, 400);
    assert.equal(h.logs.filter((e) => e.event === "oauth_approved").length, 0);
  } finally {
    await h.close();
  }
});

test("accounts: files are private, keep only the key's hash, and an unusable store answers 503 (Cancel still works)", async () => {
  const accountsDir = path.join(tempDir("files"), "accounts");
  const h = await harness({ accountsDir });
  try {
    const person = await signUp(h.url, "Files");
    const accountFile = path.join(accountsDir, "a", `${person.acct}.json`);
    const keyFile = path.join(accountsDir, "k", `${keyHashOf(person.key)}.json`);
    for (const dir of [accountsDir, path.join(accountsDir, "a"), path.join(accountsDir, "k")]) assert.equal(statSync(dir).mode & 0o777, 0o700);
    for (const file of [accountFile, keyFile]) assert.equal(statSync(file).mode & 0o777, 0o600);
    const record = JSON.parse(readFileSync(accountFile, "utf8")).value;
    assert.deepEqual(Object.keys(record).sort(), ["acct", "createdAt", "keyHash", "name"]);
    assert.equal(record.keyHash, keyHashOf(person.key));
    assert.equal(record.name, "Files");
    for (const name of [...readdirSync(path.join(accountsDir, "a")), ...readdirSync(path.join(accountsDir, "k"))]) {
      const dir = name.startsWith("acct_") ? "a" : "k";
      assert.equal(readFileSync(path.join(accountsDir, dir, name), "utf8").includes(person.key), false, "the key itself is never stored");
    }
  } finally {
    await h.close();
  }
  const blocker = path.join(tempDir("blocked"), "not-a-directory");
  writeFileSync(blocker, "x");
  const working = await harness(); // a working page, for a request token valid under the same secret
  try {
    const ok = await openConsent(working.url);
    for (const opts of [{ accountsDir: path.join(blocker, "accounts") }, { accountsDir: undefined }]) {
      const broken = await harness(opts);
      try {
        const c = await openConsent(broken.url);
        assertErrorPage(c.page, c.html, { status: 503, code: "temporarily_unavailable" });
        const res = await decide(broken.url, ok.requestToken, "create", { origin: PUBLIC }, { name: "x" });
        assertErrorPage(res, await res.text(), { status: 503 });
        assert.equal((await decide(broken.url, ok.requestToken, "cancel")).status, 303, "Cancel never needs the store");
        if (opts.accountsDir) assert.ok(broken.logs.some((e) => e.event === "oauth_accounts_unavailable"));
      } finally {
        await broken.close();
      }
    }
  } finally {
    await working.close();
  }
});

test("accounts: survive a restart (same state directory): the cookie still signs in, the key still works, same acct", async () => {
  const stateDir = tempDir("restart");
  const first = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_STATE_DIR: stateDir });
  let person;
  try {
    person = await signUp(first.url, "Durable Dana");
  } finally {
    await first.close();
  }
  const second = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_STATE_DIR: stateDir });
  try {
    const page = await openConsent(second.url, { cookie: person.cookie });
    assert.match(page.html, /Signed in as <strong>Durable Dana<\/strong>/);
    const a = await approve(second.url, { client: page.client, account: person });
    assert.equal(tokenAcct(await exchangeCode(second.url, a)), person.acct);
    const fresh = await openConsent(second.url);
    const signin = await decide(second.url, fresh.requestToken, "signin", { origin: PUBLIC }, { key: person.key });
    assert.equal(signin.status, 303);
    assert.equal(tokenAcct(await exchangeCode(second.url, { ...fresh, code: codeOf(signin) })), person.acct);
  } finally {
    await second.close();
  }
});

// ===========================================================================
// Refresh amplification (security review, MEDIUM)
// ===========================================================================

const refreshOnce = (base, clientId, refreshToken) =>
  tokenCall(base, { grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });

test("refresh: capped per refresh family and per IP; a limited refresh keeps its token for later", async () => {
  const h = await harness({ refreshesPerFamilyPerHour: 3, refreshesPerIpPerHour: 5 });
  try {
    const a = await approve(h.url);
    let rt = (await exchangeCode(h.url, a)).body.refresh_token;
    for (let i = 0; i < 3; i++) {
      const r = await refreshOnce(h.url, a.client.client_id, rt);
      assert.equal(r.status, 200, `refresh ${i + 1}`);
      rt = r.body.refresh_token;
    }
    const limited = await refreshOnce(h.url, a.client.client_id, rt);
    assert.equal(limited.status, 429);
    assert.equal(limited.body.error, "temporarily_unavailable");
    assert.equal(limited.headers.get("retry-after"), "3600");
    assert.equal(limited.headers.get("cache-control"), "no-store");
    // Another family from the same IP still has room until the IP cap (5) is reached.
    const b = await approve(h.url, { client: a.client });
    let rt2 = (await exchangeCode(h.url, b)).body.refresh_token;
    for (let i = 0; i < 1; i++) { const r = await refreshOnce(h.url, a.client.client_id, rt2); assert.equal(r.status, 200); rt2 = r.body.refresh_token; }
    assert.equal((await refreshOnce(h.url, a.client.client_id, rt2)).status, 429, "the IP cap: 3 + 1 + this one");
    // An hour later the limited token (never spent) works, and reuse detection still applies to the spent ones.
    h.advance(60 * 60_000);
    const later = await refreshOnce(h.url, a.client.client_id, rt);
    assert.equal(later.status, 200);
    assert.equal(tokenAcct(later), a.account.acct);
    assert.ok(h.logs.some((e) => e.event === "oauth_rate_limited" && e.surface === "refresh"));
  } finally {
    await h.close();
  }
});

test("refresh: the default cap stops the review's 100-refresh chain at 30 per hour", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    const a = await approve(s.url);
    let rt = (await exchangeCode(s.url, a)).body.refresh_token;
    const statuses = [];
    for (let i = 0; i < 31; i++) {
      const r = await refreshOnce(s.url, a.client.client_id, rt);
      statuses.push(r.status);
      if (r.status === 200) rt = r.body.refresh_token;
    }
    assert.deepEqual(statuses, [...Array(30).fill(200), 429]);
  } finally {
    await s.close();
  }
});

test("per-caller rate limit: all tokens of one account share one bucket on /mcp and /shadow/mcp; /token tokens stay per jti", async () => {
  assert.equal(signedTokenSubject({ jti: "j-1", acct: "acct_AAAAAAAAAAAAAAAAAAAAAA" }), "acct:acct_AAAAAAAAAAAAAAAAAAAAAA");
  assert.equal(signedTokenSubject({ jti: "j-1" }), "j-1");
  __setShadowLedgerForTests(new FakeLedger());
  const s = await boot({ ...shadowOn(), MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_RATE_PER_MIN: "2" });
  try {
    const a = await approve(s.url);
    const issued = await exchangeCode(s.url, a);
    const refreshed = await refreshOnce(s.url, a.client.client_id, issued.body.refresh_token);
    const [t1, t2] = [issued.body.access_token, refreshed.body.access_token];
    assert.notEqual(verifyToken(SECRET, t1).payload.jti, verifyToken(SECRET, t2).payload.jti);
    const call = (token, p = "/mcp", name = "no_such_tool") =>
      mcpPost(s.url, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: {} } }, { authorization: `Bearer ${token}` }, p).then(async (r) => { await r.text(); return r.status; });
    // /mcp: two calls on the first token, then the refreshed token is already out of budget.
    assert.deepEqual([await call(t1), await call(t1), await call(t2), await call(t1)], [200, 200, 429, 429]);
    // Another account has its own bucket; so does each anonymous POST /token token.
    const other = await approve(s.url, { client: a.client, account: await signUp(s.url, "Other Owner") });
    const t3 = (await exchangeCode(s.url, other)).body.access_token;
    assert.equal(await call(t3), 200);
    for (let i = 0; i < 2; i++) {
      const demo = (await (await fetch(`${s.url}/token`, { method: "POST" })).json()).token;
      assert.equal(await call(demo), 200, "a /token token is its own bucket");
    }
    // /shadow/mcp shares the account's bucket too (MCP_RATE_PER_MIN is per caller across both).
    const t4 = (await refreshOnce(s.url, a.client.client_id, refreshed.body.refresh_token)).body.access_token;
    assert.equal(await call(t4, "/shadow/mcp", "shadow_list_sessions"), 429);
    assert.equal(await call(t3, "/shadow/mcp", "shadow_list_sessions"), 200);
  } finally {
    await s.close();
    __setShadowLedgerForTests(undefined);
  }
});

// ===========================================================================
// Replay state survives restarts (security review, LOW)
// ===========================================================================

test("restart: a spent refresh token, its revoked family and a spent code stay refused after a restart", async () => {
  const stateDir = tempDir("replay");
  const env = { MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_STATE_DIR: stateDir };
  let first = await boot(env);
  let person, a, rt0, rt1, rt2, codeA, other;
  try {
    person = await signUp(first.url, "Restart Rita");
    a = await approve(first.url, { account: person });
    codeA = a.code;
    rt0 = (await exchangeCode(first.url, a)).body.refresh_token;
    const r1 = await refreshOnce(first.url, a.client.client_id, rt0);
    rt1 = r1.body.refresh_token;
    // Replaying rt0 revokes the family: rt1 dies too.
    assert.equal((await refreshOnce(first.url, a.client.client_id, rt0)).body.error, "invalid_grant");
    assert.equal((await refreshOnce(first.url, a.client.client_id, rt1)).body.error, "invalid_grant");
    // A second, healthy family: rt2 spent once (its successor stays good).
    const b = await approve(first.url, { client: a.client, account: person });
    const t = await exchangeCode(first.url, b);
    const r2 = await refreshOnce(first.url, a.client.client_id, t.body.refresh_token);
    rt2 = t.body.refresh_token;
    other = { client: a.client, rt: r2.body.refresh_token };
  } finally {
    await first.close();
  }
  for (const name of readdirSync(path.join(stateDir, "oauth"))) assert.equal(statSync(path.join(stateDir, "oauth", name)).mode & 0o777, 0o600, name);

  const second = await boot(env);
  try {
    assert.equal((await refreshOnce(second.url, a.client.client_id, rt0)).body.error, "invalid_grant", "spent + revoked stays spent");
    assert.equal((await refreshOnce(second.url, a.client.client_id, rt1)).body.error, "invalid_grant", "the revoked family stays revoked");
    assert.equal((await exchangeCode(second.url, { ...a, code: codeA })).body.error, "invalid_grant", "a spent code stays spent");
    // The healthy family: its spent token is still refused (and that replay now revokes it); before that, its
    // current token works across the restart.
    const ok = await refreshOnce(second.url, other.client.client_id, other.rt);
    assert.equal(ok.status, 200);
    assert.equal(tokenAcct(ok), person.acct);
    assert.equal((await refreshOnce(second.url, other.client.client_id, rt2)).body.error, "invalid_grant");
    assert.equal((await refreshOnce(second.url, other.client.client_id, ok.body.refresh_token)).body.error, "invalid_grant", "the replay revoked the family");
  } finally {
    await second.close();
  }
  // And once more: the revocation made after the first restart also survives.
  const third = await boot(env);
  try {
    assert.equal((await refreshOnce(third.url, other.client.client_id, other.rt)).body.error, "invalid_grant");
  } finally {
    await third.close();
  }
});

test("replay state files: journal per entry, torn lines skipped, expired entries dropped, compacted at open; corruption fails closed", async () => {
  const dir = path.join(tempDir("replay-unit"), "oauth");
  let t = 1_000;
  const set = durableExpiringSet(dir, "used-refresh", 10, () => t);
  set.add("aaaa-1", 2_000);
  set.add("bbbb-2", 1_500);
  assert.equal(readFileSync(path.join(dir, "used-refresh.jsonl"), "utf8"), '["aaaa-1",2000]\n["bbbb-2",1500]\n');
  writeFileSync(path.join(dir, "used-refresh.jsonl"), '["aaaa-1",2000]\n["bbbb-2",1500]\n["cccc', { flag: "w", mode: 0o600 });
  assert.throws(() => set.add("bad key!", 2_000));
  t = 1_600; // bbbb-2 has expired
  const reopened = durableExpiringSet(dir, "used-refresh", 10, () => t);
  assert.equal(reopened.has("aaaa-1"), true);
  assert.equal(reopened.has("bbbb-2"), false);
  assert.equal(reopened.has("cccc"), false);
  assert.equal(existsSync(path.join(dir, "used-refresh.jsonl")), false, "folded into the snapshot");
  assert.deepEqual(JSON.parse(readFileSync(path.join(dir, "used-refresh.json"), "utf8")).value, [["aaaa-1", 2000]]);
  for (const name of readdirSync(dir)) assert.equal(statSync(path.join(dir, name)).mode & 0o777, 0o600, name);
  assert.equal(statSync(dir).mode & 0o777, 0o700);

  // A corrupt snapshot with no valid backup: the OAuth token endpoint refuses closed.
  const broken = path.join(tempDir("replay-corrupt"), "oauth");
  durableExpiringSet(broken, "used-codes", 10, () => t).add("x-1", 5_000);
  durableExpiringSet(broken, "used-codes", 10, () => t); // compacts: snapshot written, journal gone
  for (const name of readdirSync(broken)) if (name.startsWith("used-codes.json")) writeFileSync(path.join(broken, name), "{not json", { mode: 0o600 });
  const h = await harness({ replayDir: broken });
  try {
    const a = await approve(h.url);
    const res = await exchangeCode(h.url, a);
    assert.equal(res.status, 503);
    assert.equal(res.body.error, "temporarily_unavailable");
    assert.ok(h.logs.some((e) => e.event === "oauth_replay_state_unavailable"));
  } finally {
    await h.close();
  }
});

// ===========================================================================
// acct
// ===========================================================================

test("acct: every OAuth token carries its account's acct; POST /token can never set it", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    const a = await approve(s.url);
    const b = await approve(s.url, { client: a.client });
    const other = await approve(s.url, { client: a.client, account: await signUp(s.url, "Someone Else") });
    const ta = verifyToken(SECRET, (await exchangeCode(s.url, a)).body.access_token).payload;
    const tb = verifyToken(SECRET, (await exchangeCode(s.url, b)).body.access_token).payload;
    const tc = verifyToken(SECRET, (await exchangeCode(s.url, other)).body.access_token).payload;
    assert.match(ta.acct, ACCT_PATTERN);
    assert.equal(ta.acct, a.account.acct);
    assert.equal(tb.acct, ta.acct, "the same account approving again keeps its acct");
    assert.notEqual(tc.acct, ta.acct, "another account has its own acct");

    for (const [query, headers] of [
      ["", {}],
      ["?acct=acct_AAAAAAAAAAAAAAAAAAAAAA", {}],
      ["?sub=acct_AAAAAAAAAAAAAAAAAAAAAA", { "x-clockchain-sub": "acct_AAAAAAAAAAAAAAAAAAAAAA" }],
      ["", { "x-clockchain-acct": "acct_AAAAAAAAAAAAAAAAAAAAAA", acct: "acct_AAAAAAAAAAAAAAAAAAAAAA", authorization: `Bearer ${STATIC_TOKEN}` }],
    ]) {
      const res = await fetch(`${s.url}/token${query}`, { method: "POST", headers });
      assert.equal(res.status, 200);
      const body = await res.json();
      const v = verifyToken(SECRET, body.token);
      assert.equal(v.valid, true);
      assert.equal("acct" in v.payload, false, `${query} ${JSON.stringify(headers)}`);
    }
  } finally {
    await s.close();
  }
});

test("verifier: acct is optional, returned when present, and must be well-formed", () => {
  const now = Math.floor(Date.now() / 1000);
  const legacy = mintToken(SECRET, 3600, now, "someone");
  assert.equal(verifyToken(SECRET, legacy.token).valid, true);
  assert.equal(verifyToken(SECRET, legacy.token).payload.acct, undefined);
  const withAcct = mintToken(SECRET, 3600, now, undefined, undefined, "acct_0123456789abcdefghij_-");
  assert.equal(verifyToken(SECRET, withAcct.token).payload.acct, "acct_0123456789abcdefghij_-");
  assert.throws(() => mintToken(SECRET, 3600, now, undefined, undefined, "acct_short"));
  // A correctly signed token with a malformed acct still fails verification.
  const seg = Buffer.from(JSON.stringify({ v: 1, tier: "demo", iat: now, exp: now + 60, jti: "j", acct: "acct_bad" })).toString("base64url");
  const sig = createHmac("sha256", SECRET).update(seg).digest("base64url");
  assert.deepEqual(verifyToken(SECRET, `cc_${seg}.${sig}`), { valid: false, reason: "bad acct" });
});

// ===========================================================================
// Logs
// ===========================================================================

test("no code, token, refresh token, verifier, request token or client_id reaches stdout/stderr", async () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const proc = spawn(process.execPath, [path.join(here, "..", "dist", "index.js")], {
    env: { ...process.env, MCP_TRANSPORT: "http", PORT: String(port), MCP_AUTH_TOKENS: STATIC_TOKEN, MCP_REQUIRE_AUTH: "1", MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_STATE_DIR: tempDir("logs") },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  proc.stdout.on("data", (d) => { out += d; });
  proc.stderr.on("data", (d) => { out += d; });
  try {
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`server did not start: ${out}`)), 10_000);
      const check = () => { if (out.includes("listening on")) { clearTimeout(t); resolve(); } };
      proc.stderr.on("data", check);
      proc.on("exit", (code) => reject(new Error(`server exited (${code}): ${out}`)));
    });
    const base = `http://127.0.0.1:${port}`;
    const a = await approve(base, { meta: { client_name: "Log Probe" } });
    const issued = await exchangeCode(base, a);
    assert.equal(issued.status, 200);
    const refreshed = await tokenCall(base, { grant_type: "refresh_token", refresh_token: issued.body.refresh_token, client_id: a.client.client_id });
    await tokenCall(base, { grant_type: "refresh_token", refresh_token: issued.body.refresh_token, client_id: a.client.client_id });
    await exchangeCode(base, a);
    await mcpPost(base, INIT, { authorization: `Bearer ${refreshed.body.access_token}` });
    // A key sign-in from a browser with no cookie, and a wrong key.
    const fresh = await openConsent(base, { client: a.client });
    const signedIn = await decide(base, fresh.requestToken, "signin", { origin: PUBLIC }, { key: a.account.key });
    assert.equal(signedIn.status, 303);
    const wrong = await openConsent(base, { client: a.client });
    assert.equal((await decide(base, wrong.requestToken, "signin", { origin: PUBLIC }, { key: `cck_${"x".repeat(32)}` })).status, 400);
    await new Promise((r) => setTimeout(r, 200));

    const secrets = {
      code: a.code, verifier: a.verifier, requestToken: a.requestToken, clientId: a.client.client_id,
      access: issued.body.access_token, refresh: issued.body.refresh_token,
      access2: refreshed.body.access_token, refresh2: refreshed.body.refresh_token,
      signinCookie: cookieOf(signedIn).slice(cookieOf(signedIn).indexOf("=") + 1),
      accountKey: a.account.key, accountCookie: a.account.cookie.slice(a.account.cookie.indexOf("=") + 1),
      grant: a.grant, keyPageGrant: a.account.grant,
    };
    for (const [name, value] of Object.entries(secrets)) {
      assert.equal(out.includes(value), false, `${name} leaked into the logs`);
      // Not even the MAC or payload segment on its own.
      for (const part of value.split(".")) if (part.length > 20) assert.equal(out.includes(part.slice(-24)), false, `${name} fragment leaked`);
    }
    assert.equal(out.includes(SECRET), false);
    const acct = verifyToken(SECRET, issued.body.access_token).payload.acct;
    const events = out.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
    assert.ok(events.some((e) => e.event === "oauth_approved" && e.acct === acct && e.client_name === "Log Probe"));
    assert.ok(events.some((e) => e.event === "oauth_refresh_reuse" && e.acct === acct));
    assert.ok(events.some((e) => e.event === "oauth_code_reuse" && e.acct === acct));
    for (const e of events.filter((x) => String(x.event).startsWith("oauth_"))) {
      assert.deepEqual(Object.keys(e).filter((k) => !["event", "client_name", "acct", "grant", "surface", "accounts"].includes(k)), [], JSON.stringify(e));
    }
  } finally {
    proc.kill();
  }
});
