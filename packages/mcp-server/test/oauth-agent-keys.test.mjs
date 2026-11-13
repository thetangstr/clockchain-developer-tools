// The client_credentials grant (src/oauth.ts): an agent proves it holds its own Ed25519 key with an RFC 7523 client
// assertion and gets a Starter token in one call. Off unless MCP_AGENT_KEYS=1; off, the endpoint and the metadata are
// exactly as before. Covers single use of each assertion, the per-address new-key limit, cancelled keys, and that no
// assertion or token reaches the logs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { runHttp } from "../dist/http.js";
import { createOAuthHandler, loadOAuthConfig } from "../dist/oauth.js";
import { mintAgentToken, verifyToken } from "../dist/token.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { jwtBearerProof } from "../dist/agent-keys/proof.js";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const SECRET = "oauth-agent-keys-test-secret";
const PUBLIC = "https://mcp.example.test";
const TOKEN_ENDPOINT = `${PUBLIC}/oauth/token`;
const STATIC_TOKEN = "static-test-token";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

const ENV_KEYS = [
  "PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_TRUSTED_PROXY", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS",
  "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "MCP_AGENT_KEYS", "MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR", "SHADOW_ENABLED", "SHADOW_STATE_DIR",
];
const tempDir = (label) => mkdtempSync(path.join(tmpdir(), `oauth-ak-${label}-`));

async function freeLoopbackPort() {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

/** The real runHttp wiring with the given env (copied from test/oauth.test.mjs). */
async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  let server;
  const stateDir = tempDir("state");
  for (let attempt = 1; ; attempt++) {
    Object.assign(process.env, { MCP_PORT: String(await freeLoopbackPort()), MCP_AUTH_TOKENS: STATIC_TOKEN, MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_STATE_DIR: stateDir }, env);
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
    server = await runHttp();
    if (!server.listening) await once(server, "listening");
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
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    stateDir,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

/** The handler alone, with a controllable clock, a fresh key book and captured log events. */
async function harness(agentKeys = {}) {
  let clock = Date.UTC(2026, 10, 13, 12, 0, 0);
  const logs = [];
  const book = new AgentKeyBook({ dir: path.join(tempDir("book"), "agent-keys"), now: () => new Date(clock) });
  const handler = createOAuthHandler({
    signingSecret: SECRET, publicUrl: PUBLIC, tokenTtlSeconds: 7 * 24 * 3600,
    now: () => clock, log: (e) => logs.push(e),
    agentKeys: { book, proof: jwtBearerProof(), newPerIpPerHour: 10, tokenTtlSeconds: 3600, ...agentKeys },
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
    book, logs,
    nowSec: () => Math.floor(clock / 1000),
    advance(ms) { clock += ms; },
    async close() { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); },
  };
}

const grant = (base, assertion, extra = {}) =>
  fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials", client_assertion_type: JWT_BEARER, client_assertion: assertion, ...extra }),
  });

// ---- config -----------------------------------------------------------------

test("config: MCP_AGENT_KEYS=1 adds agentKeys; unset leaves the config as it was; bad values are misconfigured", () => {
  const today = loadOAuthConfig({ MCP_OAUTH: "1" }, SECRET);
  assert.equal("agentKeys" in today, false);
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "0" }, SECRET), today);
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "" }, SECRET), today);
  // Off, the per-address limit is not read at all.
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR: "lots" }, SECRET), today);
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "1" }, SECRET), { ...today, agentKeys: { enabled: true, newPerIpPerHour: 10, tokenTtl: 3600 } });
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "1", MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR: "25" }, SECRET).agentKeys, { enabled: true, newPerIpPerHour: 25, tokenTtl: 3600 });
  assert.match(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "yes" }, SECRET).reason, /MCP_AGENT_KEYS/);
  for (const bad of ["0", "lots", "100000"]) {
    assert.match(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "1", MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR: bad }, SECRET).reason, /MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR/, bad);
  }
  assert.deepEqual(loadOAuthConfig({ MCP_AGENT_KEYS: "1" }, SECRET), { kind: "disabled" });
});

test("mintAgentToken carries akf, verifies unchanged, and refuses a malformed fingerprint", () => {
  const fp = "ab".repeat(32);
  const { token, payload } = mintAgentToken(SECRET, 3600, 1_800_000_000, "jti-0001", fp);
  assert.deepEqual(payload, { v: 1, tier: "demo", iat: 1_800_000_000, exp: 1_800_003_600, jti: "jti-0001", akf: fp });
  const verified = verifyToken(SECRET, token, 1_800_000_001);
  assert.equal(verified.valid, true);
  assert.equal(verified.payload.akf, fp);
  for (const bad of ["", "ab".repeat(31), "AB".repeat(32), `${"ab".repeat(32)}0`, "zz".repeat(32)]) {
    assert.throws(() => mintAgentToken(SECRET, 3600, 1_800_000_000, "jti-0001", bad), /akf/, bad);
  }
});

// ---- the grant through the real server ------------------------------------------

test("one call from a fresh key returns a Starter token with akf", async () => {
  const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "1" });
  try {
    const meta = await (await fetch(`${s.url}/.well-known/oauth-authorization-server`)).json();
    assert.equal(meta.token_endpoint, TOKEN_ENDPOINT);
    const agent = makeAgentKey();
    const res = await grant(s.url, agent.assertion(meta.token_endpoint));
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.deepEqual(Object.keys(body).sort(), ["access_token", "agent_id", "expires_in", "key_filed", "token_type"]);
    assert.equal(body.token_type, "Bearer");
    assert.equal(body.expires_in, 3600);
    assert.equal(body.agent_id, agent.fingerprint.slice(0, 16));
    assert.equal(body.key_filed, false);
    const verified = verifyToken(SECRET, body.access_token);
    assert.equal(verified.valid, true);
    assert.equal(verified.payload.akf, agent.fingerprint);
    assert.equal(verified.payload.exp - verified.payload.iat, 3600);
    assert.equal(verified.payload.acct, undefined);
    // The key is in the book on the state volume.
    assert.ok(existsSync(path.join(s.stateDir, "agent-keys", `${agent.fingerprint}.json`)));
  } finally {
    await s.close();
  }
});

test("metadata advertises client_credentials and private_key_jwt only when enabled", async () => {
  const off = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC });
  let offMeta;
  try {
    offMeta = await (await fetch(`${off.url}/.well-known/oauth-authorization-server`)).json();
    assert.deepEqual(offMeta, {
      issuer: PUBLIC,
      authorization_endpoint: `${PUBLIC}/oauth/authorize`,
      token_endpoint: TOKEN_ENDPOINT,
      registration_endpoint: `${PUBLIC}/oauth/register`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      authorization_response_iss_parameter_supported: true,
      service_documentation: `${PUBLIC}/llms.txt`,
    });
  } finally {
    await off.close();
  }
  const on = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "1" });
  try {
    for (const route of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
      const meta = await (await fetch(`${on.url}${route}`)).json();
      assert.deepEqual(meta, {
        ...offMeta,
        grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
        token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
        token_endpoint_auth_signing_alg_values_supported: ["EdDSA"],
      }, route);
    }
  } finally {
    await on.close();
  }
});

test("disabled by default: client_credentials answers exactly as before and keeps no key", async () => {
  const agent = makeAgentKey();
  for (const flag of [undefined, "0"]) {
    const s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: flag });
    try {
      // No client_id: refused as an unknown client, as before.
      const bare = await grant(s.url, agent.assertion(TOKEN_ENDPOINT));
      assert.equal(bare.status, 401);
      assert.deepEqual(await bare.json(), { error: "invalid_client", error_description: "Unknown client_id. Register again." });
      // A registered client: the grant type is unsupported, as before.
      const reg = await fetch(`${s.url}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Agent", redirect_uris: ["https://example.test/cb"] }) });
      const { client_id } = await reg.json();
      const withClient = await grant(s.url, agent.assertion(TOKEN_ENDPOINT), { client_id });
      assert.equal(withClient.status, 400);
      assert.deepEqual(await withClient.json(), { error: "unsupported_grant_type", error_description: "Only authorization_code and refresh_token are supported." });
      assert.equal(existsSync(path.join(s.stateDir, "agent-keys")), false, "no key book is kept");
    } finally {
      await s.close();
    }
  }
});

test("the response and server log never contain the assertion", async () => {
  const captured = [];
  const originals = {};
  for (const name of ["log", "error", "warn", "info", "debug"]) {
    originals[name] = console[name];
    console[name] = (...args) => { captured.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ")); };
  }
  let s;
  try {
    s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "1" });
    const agent = makeAgentKey();
    const assertion = agent.assertion(TOKEN_ENDPOINT);
    const wrongAudience = agent.assertion("https://elsewhere.test/oauth/token");
    const ok = await grant(s.url, assertion);
    const okText = await ok.text();
    assert.equal(ok.status, 200, okText);
    const replayed = await grant(s.url, assertion);
    const replayedText = await replayed.text();
    assert.equal(replayed.status, 401);
    const refused = await grant(s.url, wrongAudience);
    const refusedText = await refused.text();
    assert.equal(refused.status, 401);
    const accessToken = JSON.parse(okText).access_token;
    const log = captured.join("\n");
    assert.ok(log.includes("oauth_token_issued"), "the issue is logged");
    for (const secret of [assertion, wrongAudience]) {
      const signature = secret.split(".")[2];
      for (const [label, text] of [["log", log], ["ok", okText], ["replayed", replayedText], ["refused", refusedText]]) {
        assert.equal(text.includes(secret), false, `${label} carries an assertion`);
        assert.equal(text.includes(signature), false, `${label} carries an assertion signature`);
      }
    }
    assert.equal(log.includes(accessToken), false, "the log carries the access token");
    assert.equal(log.includes(agent.fingerprint), false, "the log carries the full fingerprint");
  } finally {
    await s?.close();
    Object.assign(console, originals);
  }
});

// ---- the grant's rules (handler alone, with a controllable clock) -----------------

test("a replayed assertion is refused", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    const assertion = agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() });
    assert.equal((await grant(h.url, assertion)).status, 200);
    const again = await grant(h.url, assertion);
    assert.equal(again.status, 401);
    assert.equal((await again.json()).error, "invalid_client");
    // The same jti in a freshly signed assertion is a replay too.
    const sameJti = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec(), jti: JSON.parse(Buffer.from(assertion.split(".")[1], "base64url")).jti }));
    assert.equal(sameJti.status, 401);
    // A fresh jti from the same key mints.
    assert.equal((await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
  } finally {
    await h.close();
  }
});

test("a bad proof is invalid_client and never mints", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    for (const assertion of [
      agent.assertion("https://mcp.example.test/staging/oauth/token", { iat: h.nowSec() }),
      agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() - 400, exp: h.nowSec() - 100 }),
      "not.a.jwt",
    ]) {
      const res = await grant(h.url, assertion);
      assert.equal(res.status, 401);
      assert.equal((await res.json()).error, "invalid_client");
    }
    const missing = await fetch(`${h.url}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "client_credentials" }) });
    assert.equal(missing.status, 401);
    assert.equal((await missing.json()).error, "invalid_client");
    const wrongType = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), { client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer" });
    assert.equal(wrongType.status, 401);
    assert.equal(h.book.get(agent.fingerprint), null, "no refused call admits the key");
  } finally {
    await h.close();
  }
});

test("the 11th new key from one address in an hour gets 429, but a known key still mints", async () => {
  const h = await harness();
  try {
    // Refused proofs from fresh keys don't use up the allowance.
    for (let i = 0; i < 12; i++) {
      assert.equal((await grant(h.url, makeAgentKey().assertion("https://elsewhere.test", { iat: h.nowSec() }))).status, 401);
    }
    const agents = Array.from({ length: 11 }, () => makeAgentKey());
    for (const agent of agents.slice(0, 10)) {
      const res = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
      assert.equal(res.status, 200, await res.text());
    }
    const eleventh = await grant(h.url, agents[10].assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
    assert.equal(eleventh.status, 429);
    assert.ok(Number(eleventh.headers.get("retry-after")) > 0, "Retry-After is set");
    assert.equal((await eleventh.json()).error, "temporarily_unavailable");
    assert.equal(h.book.get(agents[10].fingerprint), null, "the limited key is not admitted");
    // Keys already in the book don't count.
    for (const agent of agents.slice(0, 3)) {
      assert.equal((await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
    }
    // Next hour, a new key is welcome again.
    h.advance(60 * 60_000 + 1000);
    assert.equal((await grant(h.url, agents[10].assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
  } finally {
    await h.close();
  }
});

test("a revoked key cannot mint, nor a replaced one", async () => {
  const h = await harness();
  try {
    const revoked = makeAgentKey();
    assert.equal((await grant(h.url, revoked.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
    h.book.revoke(revoked.fingerprint);
    const res = await grant(h.url, revoked.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "invalid_client");

    const old = makeAgentKey();
    const next = makeAgentKey();
    assert.equal((await grant(h.url, old.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
    h.book.replace(old.fingerprint, next.publicKeyPem);
    assert.equal((await grant(h.url, old.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 401);
    // The new key mints, under the agent's first key's id.
    const fresh = await grant(h.url, next.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
    const body = await fresh.json();
    assert.equal(fresh.status, 200);
    assert.equal(body.agent_id, old.fingerprint.slice(0, 16));
    assert.equal(verifyToken(SECRET, body.access_token, h.nowSec()).payload.akf, next.fingerprint);
  } finally {
    await h.close();
  }
});

test("no refresh_token is returned", async () => {
  const h = await harness();
  try {
    const res = await grant(h.url, makeAgentKey().assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.equal("refresh_token" in body, false);
    assert.equal(JSON.stringify(body).includes("cc_rt_"), false);
  } finally {
    await h.close();
  }
});

test("key_filed reports the book's filing state", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    assert.equal((await (await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).json()).key_filed, false);
    h.book.setFiling(agent.fingerprint, { state: "filed", ledgerId: "agent-key:v1:x", block: 7, filedAt: new Date().toISOString() });
    assert.equal((await (await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).json()).key_filed, true);
  } finally {
    await h.close();
  }
});
