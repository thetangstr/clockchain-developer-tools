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
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { runHttp } from "../dist/http.js";
import { createOAuthHandler, loadOAuthConfig } from "../dist/oauth.js";
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
  "MCP_TOKEN_TTL_DAYS", "SHADOW_ENABLED", "SHADOW_STATE_DIR",
];

/** Hosted Shadow on, in a fresh state directory, so /shadow/mcp exists and answers /mcp's 401. */
const shadowOn = () => ({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "oauth-shadow-")) });

/** The REAL runHttp wiring with the given env (static token set, so auth is not open). */
async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0", MCP_AUTH_TOKENS: STATIC_TOKEN, MCP_TOKEN_SIGNING_SECRET: SECRET }, env);
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
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
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    handler, logs,
    nowSec: () => Math.floor(clock / 1000),
    advance(ms) { clock += ms; },
    async close() { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); },
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
  const page = await fetch(`${base}/oauth/authorize?${params}`, { redirect: "manual", headers: { accept: "text/html" } });
  const html = await page.text();
  const requestToken = /name="request" value="([^"]+)"/.exec(html)?.[1];
  return { client, verifier, challenge, redirectUri, page, html, requestToken };
}

const decide = (base, requestToken, decision = "approve", headers = { origin: PUBLIC }) =>
  fetch(`${base}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams({ request: requestToken, decision }),
  });

async function tokenCall(base, params, type = "form", headers = {}) {
  const res = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": type === "form" ? "application/x-www-form-urlencoded" : "application/json", ...headers },
    body: type === "form" ? new URLSearchParams(params) : JSON.stringify(params),
  });
  return { status: res.status, headers: res.headers, body: await res.json() };
}

/** Consent → approve → code, returning everything needed to exchange it. */
async function approve(base, o = {}) {
  const consent = await openConsent(base, o);
  assert.equal(consent.page.status, 200, consent.html);
  const res = await decide(base, consent.requestToken);
  assert.equal(res.status, 303);
  const location = new URL(res.headers.get("location"));
  return { ...consent, location, code: location.searchParams.get("code") };
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
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1" }, SECRET), { kind: "ready", publicUrl: "https://mcp.clockchain.network", approvalsPerHour: 10 });
  assert.deepEqual(
    loadOAuthConfig({ MCP_OAUTH: "1", MCP_PUBLIC_URL: "https://mcp.clockchain.network/", MCP_OAUTH_APPROVALS_PER_HOUR: "40", MCP_OAUTH_TRUSTED_PROXY: "172.30.0.3" }, SECRET),
    { kind: "ready", publicUrl: "https://mcp.clockchain.network", approvalsPerHour: 40, trustedProxy: "172.30.0.3" },
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

    // A second approval is a different account: it can neither read nor write the first account's sessions.
    const b = await approve(s.url, { client: a.client });
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

test("happy path: register → consent page → approve → code → token → /mcp → refresh → old refresh rejected", async () => {
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
    assert.match(consent.html, /Allow ChatGPT to record and anchor your agents’ work on Clockchain/);
    assert.match(consent.html, /<code>chatgpt\.com<\/code>/);
    assert.match(consent.html, /testnet credits from a shared pool/);
    assert.match(consent.html, /30 days/);
    assert.match(consent.html, /Only fingerprints go on the Clockchain ledger/);
    assert.match(consent.html, /value="approve"/);
    assert.match(consent.html, /value="cancel"/);
    assert.ok(consent.requestToken.startsWith("cc_req_"));

    const decision = await decide(s.url, consent.requestToken);
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
    for (const credential of [code, issued.body.refresh_token, consent.client.client_id, consent.requestToken]) {
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
    const approve = await decide(h.url, ok.requestToken, "approve");
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
    const viaReferer = await decide(h.url, c.requestToken, "approve", { referer: `${PUBLIC}/oauth/authorize?client_id=x` });
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
    const c = await openConsent(h.url, { client });
    const blocked = await decide(h.url, c.requestToken);
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
    const send = async (xff) => {
      const c = await openConsent(trusted.url, { client });
      const res = await decide(trusted.url, c.requestToken, "approve", { origin: PUBLIC, "x-forwarded-for": xff });
      return res.status;
    };
    assert.equal(await send("198.51.100.1"), 303);
    assert.equal(await send("198.51.100.1"), 429);
    assert.equal(await send("198.51.100.2"), 303, "a different client behind the proxy has its own bucket");
  } finally {
    await trusted.close();
  }
  const untrusted = await harness({ approvalsPerHour: 1 });
  try {
    const client = await registerClient(untrusted.url);
    const c1 = await openConsent(untrusted.url, { client });
    await decide(untrusted.url, c1.requestToken, "approve", { origin: PUBLIC, "x-forwarded-for": "198.51.100.1" });
    const c2 = await openConsent(untrusted.url, { client });
    const res = await decide(untrusted.url, c2.requestToken, "approve", { origin: PUBLIC, "x-forwarded-for": "198.51.100.9" });
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
// acct
// ===========================================================================

test("acct: every OAuth token has one, fixed per approval; POST /token can never set it", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  try {
    const a = await approve(s.url);
    const b = await approve(s.url, { client: a.client });
    const ta = verifyToken(SECRET, (await exchangeCode(s.url, a)).body.access_token).payload;
    const tb = verifyToken(SECRET, (await exchangeCode(s.url, b)).body.access_token).payload;
    assert.match(ta.acct, ACCT_PATTERN);
    assert.match(tb.acct, ACCT_PATTERN);
    assert.notEqual(ta.acct, tb.acct, "each approval is a new account");

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
    env: { ...process.env, MCP_TRANSPORT: "http", PORT: String(port), MCP_AUTH_TOKENS: STATIC_TOKEN, MCP_REQUIRE_AUTH: "1", MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC },
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
    await new Promise((r) => setTimeout(r, 200));

    const secrets = {
      code: a.code, verifier: a.verifier, requestToken: a.requestToken, clientId: a.client.client_id,
      access: issued.body.access_token, refresh: issued.body.refresh_token,
      access2: refreshed.body.access_token, refresh2: refreshed.body.refresh_token,
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
      assert.deepEqual(Object.keys(e).filter((k) => !["event", "client_name", "acct", "grant", "surface"].includes(k)), [], JSON.stringify(e));
    }
  } finally {
    proc.kill();
  }
});
