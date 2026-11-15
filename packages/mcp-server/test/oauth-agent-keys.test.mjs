// The client_credentials grant (src/oauth.ts): an agent proves it holds its own Ed25519 key with an RFC 7523 client
// assertion and gets a Starter token in one call. Off unless MCP_AGENT_KEYS=1; off, the endpoint and the metadata are
// exactly as before. Covers single use of each assertion, the per-address new-key limit, cancelled keys, and that no
// assertion or token reaches the logs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { runHttp } from "../dist/http.js";
import { createOAuthHandler, loadOAuthConfig } from "../dist/oauth.js";
import { mintAgentToken, verifyToken } from "../dist/token.js";
import { AgentKeyBook } from "../dist/agent-keys/book.js";
import { jwtBearerProof } from "../dist/agent-keys/proof.js";
import { makeAgentKey as makeTestAgentKey } from "./helpers/agent-key.mjs";

const SECRET = "oauth-agent-keys-test-secret";
const PUBLIC = "https://mcp.example.test";
const TOKEN_ENDPOINT = `${PUBLIC}/oauth/token`;
const STATIC_TOKEN = "static-test-token";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

const ENV_KEYS = [
  "PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_TRUSTED_PROXY", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS",
  "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "MCP_AGENT_KEYS", "MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR", "MCP_AGENT_KEYS_NEW_PER_HOUR", "SHADOW_ENABLED", "SHADOW_STATE_DIR",
];
const tempDir = (label) => mkdtempSync(path.join(tmpdir(), `oauth-ak-${label}-`));

async function freeLoopbackPort() {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

/** The real runHttp wiring with the given env (copied from test/oauth.test.mjs, plus a retry when the port is taken). */
async function boot(env) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  let server;
  const stateDir = tempDir("state");
  for (let attempt = 1; ; attempt++) {
    Object.assign(process.env, { MCP_PORT: String(await freeLoopbackPort()), MCP_AUTH_TOKENS: STATIC_TOKEN, MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_STATE_DIR: stateDir }, env);
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k];
    try {
      server = await runHttp();
      if (!server.listening) await once(server, "listening");
    } catch (e) {
      // Another test took the probed port between the probe and this bind (parallel runs): pick again.
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
async function harness(agentKeys = {}, more = {}) {
  let clock = Date.UTC(2026, 10, 13, 12, 0, 0);
  const logs = [];
  const book = new AgentKeyBook({ dir: path.join(tempDir("book"), "agent-keys"), now: () => new Date(clock) });
  const handler = createOAuthHandler({
    signingSecret: SECRET, publicUrl: PUBLIC, tokenTtlSeconds: 7 * 24 * 3600,
    now: () => clock, log: (e) => logs.push(e), ...more,
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

// Each assertion remembers the agent that signed it, so grant() can add that agent's DPoP proof by default.
const signers = new Map();
function makeAgentKey() {
  const agent = makeTestAgentKey();
  const sign = agent.assertion;
  agent.assertion = (aud, opts) => {
    const assertion = sign(aud, opts);
    signers.set(assertion, agent);
    return assertion;
  };
  return agent;
}
const iatOf = (jwt) => {
  try {
    return JSON.parse(Buffer.from(jwt.split(".")[1], "base64url")).iat;
  } catch {
    return undefined;
  }
};

/**
 * The client_credentials grant. Unless `headers` names `dpop` (undefined sends none), it carries a DPoP proof from the
 * assertion's own agent for POST TOKEN_ENDPOINT, issued at the assertion's iat.
 */
const grant = (base, assertion, extra = {}, headers = {}) => {
  const agent = signers.get(assertion);
  const all = { "content-type": "application/x-www-form-urlencoded" };
  if (agent && !("dpop" in headers)) all.dpop = agent.dpop("POST", TOKEN_ENDPOINT, { iat: iatOf(assertion) });
  for (const [k, v] of Object.entries(headers)) if (v !== undefined) all[k] = v;
  return fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: all,
    body: new URLSearchParams({ grant_type: "client_credentials", client_assertion_type: JWT_BEARER, client_assertion: assertion, ...extra }),
  });
};


// ---- config -----------------------------------------------------------------

test("config: MCP_AGENT_KEYS=1 adds agentKeys; unset leaves the config as it was; bad values keep OAuth up without agent keys", () => {
  const today = loadOAuthConfig({ MCP_OAUTH: "1" }, SECRET);
  assert.equal("agentKeys" in today, false);
  assert.equal("agentKeysProblem" in today, false);
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "0" }, SECRET), today);
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "" }, SECRET), today);
  // Off, the limits are not read at all.
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR: "lots", MCP_AGENT_KEYS_NEW_PER_HOUR: "lots" }, SECRET), today);
  assert.deepEqual(loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "1" }, SECRET), { ...today, agentKeys: { enabled: true, newPerIpPerHour: 10, newPerHour: 200, tokenTtl: 3600, dir: "/app/state/agent-keys" } });
  assert.deepEqual(
    loadOAuthConfig({ MCP_OAUTH: "1", MCP_AGENT_KEYS: "1", MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR: "25", MCP_AGENT_KEYS_NEW_PER_HOUR: "500", MCP_STATE_DIR: "/srv/state" }, SECRET).agentKeys,
    { enabled: true, newPerIpPerHour: 25, newPerHour: 500, tokenTtl: 3600, dir: "/srv/state/agent-keys" },
  );
  // A wrong agent-keys value never takes sign-in down: OAuth stays ready exactly as without it, agent keys stay off,
  // and the problem is reported.
  const bad = [
    [{ MCP_AGENT_KEYS: "yes" }, /MCP_AGENT_KEYS must be 1 or 0/],
    [{ MCP_AGENT_KEYS: "true" }, /MCP_AGENT_KEYS must be 1 or 0/],
    ...["0", "lots", "100000"].map((v) => [{ MCP_AGENT_KEYS: "1", MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR: v }, /MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR/]),
    ...["0", "lots", "100000", "-5"].map((v) => [{ MCP_AGENT_KEYS: "1", MCP_AGENT_KEYS_NEW_PER_HOUR: v }, /MCP_AGENT_KEYS_NEW_PER_HOUR must be a whole number from 1 to 99999/]),
  ];
  for (const [env, reason] of bad) {
    const config = loadOAuthConfig({ MCP_OAUTH: "1", ...env }, SECRET);
    const { agentKeysProblem, ...rest } = config;
    assert.equal(config.kind, "ready", JSON.stringify(env));
    assert.equal("agentKeys" in config, false, JSON.stringify(env));
    assert.match(agentKeysProblem, reason, JSON.stringify(env));
    assert.deepEqual(rest, today, JSON.stringify(env));
  }
  assert.deepEqual(loadOAuthConfig({ MCP_AGENT_KEYS: "1" }, SECRET), { kind: "disabled" });
  assert.deepEqual(loadOAuthConfig({ MCP_AGENT_KEYS: "yes" }, SECRET), { kind: "disabled" });
});

test("a wrong MCP_AGENT_KEYS keeps sign-in serving, leaves the grant off, and says so at boot", async () => {
  const captured = [];
  const original = console.error;
  console.error = (...args) => { captured.push(args.join(" ")); };
  let s;
  try {
    s = await boot({ MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "yes" });
    const meta = await fetch(`${s.url}/.well-known/oauth-authorization-server`);
    assert.equal(meta.status, 200, "OAuth is still up");
    assert.deepEqual((await meta.json()).grant_types_supported, ["authorization_code", "refresh_token"]);
    const reg = await fetch(`${s.url}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "App", redirect_uris: ["https://example.test/cb"] }) });
    assert.equal(reg.status, 201, "registration still works");
    const { client_id } = await reg.json();
    const res = await grant(s.url, makeAgentKey().assertion(TOKEN_ENDPOINT), { client_id });
    assert.equal((await res.json()).error, "unsupported_grant_type");
    assert.equal(existsSync(path.join(s.stateDir, "agent-keys")), false);
    assert.ok(captured.some((line) => /agent keys misconfigured \(off\).*MCP_AGENT_KEYS must be 1 or 0/.test(line)), captured.join("\n"));
  } finally {
    console.error = original;
    await s?.close();
  }
});

test("mintAgentToken carries akf and cnf.jkt, verifies unchanged, and refuses a malformed fingerprint or jkt", () => {
  const fp = "ab".repeat(32);
  const jkt = "A".repeat(43);
  const { token, payload } = mintAgentToken(SECRET, 3600, 1_800_000_000, "jti-0001", fp, jkt);
  assert.deepEqual(payload, { v: 1, tier: "demo", iat: 1_800_000_000, exp: 1_800_003_600, jti: "jti-0001", akf: fp, cnf: { jkt } });
  const verified = verifyToken(SECRET, token, 1_800_000_001);
  assert.equal(verified.valid, true);
  assert.equal(verified.payload.akf, fp);
  assert.deepEqual(verified.payload.cnf, { jkt });
  for (const bad of ["", "ab".repeat(31), "AB".repeat(32), `${"ab".repeat(32)}0`, "zz".repeat(32)]) {
    assert.throws(() => mintAgentToken(SECRET, 3600, 1_800_000_000, "jti-0001", bad, jkt), /akf/, bad);
  }
  for (const bad of [undefined, "", "A".repeat(42), "A".repeat(44), `${"A".repeat(42)}=`, `${"A".repeat(42)}+`]) {
    assert.throws(() => mintAgentToken(SECRET, 3600, 1_800_000_000, "jti-0001", fp, bad), /jkt/, String(bad));
  }
});

test("verifyToken refuses a cnf that is not exactly { jkt: <43 base64url> }", () => {
  // A token signed with the real secret but carrying a malformed cnf, built as mintToken builds tokens.
  const signed = (payload) => {
    const seg = Buffer.from(JSON.stringify(payload)).toString("base64url");
    return `cc_${seg}.${createHmac("sha256", SECRET).update(seg).digest("base64url")}`;
  };
  const base = { v: 1, tier: "demo", iat: 1_800_000_000, exp: 1_800_003_600, jti: "jti-0001", akf: "ab".repeat(32) };
  assert.equal(verifyToken(SECRET, signed({ ...base, cnf: { jkt: "A".repeat(43) } }), 1_800_000_001).valid, true);
  for (const cnf of [{}, { jkt: "x" }, { jkt: "A".repeat(43), x5t: "y" }, "A".repeat(43), null, [], { jkt: 1 }]) {
    assert.deepEqual(verifyToken(SECRET, signed({ ...base, cnf }), 1_800_000_001), { valid: false, reason: "bad cnf" }, JSON.stringify(cnf));
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
    assert.equal(body.token_type, "DPoP");
    assert.equal(body.expires_in, 3600);
    assert.equal(body.agent_id, agent.fingerprint.slice(0, 16));
    assert.equal(body.key_filed, false);
    const verified = verifyToken(SECRET, body.access_token);
    assert.equal(verified.valid, true);
    assert.equal(verified.payload.akf, agent.fingerprint);
    assert.deepEqual(verified.payload.cnf, { jkt: agent.thumbprint });
    assert.equal(verified.payload.exp - verified.payload.iat, 3600);
    assert.equal(verified.payload.acct, undefined);
    // The key is in the book on the state volume.
    assert.ok(existsSync(path.join(s.stateDir, "agent-keys", `${agent.fingerprint}.json`)));
  } finally {
    await s.close();
  }
});

test("metadata advertises client_credentials, private_key_jwt and DPoP only when enabled", async () => {
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
        dpop_signing_alg_values_supported: ["EdDSA"],
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
    const proof = agent.dpop("POST", TOKEN_ENDPOINT);
    const badProof = makeAgentKey().dpop("POST", TOKEN_ENDPOINT);
    const ok = await grant(s.url, assertion, {}, { dpop: proof });
    const okText = await ok.text();
    assert.equal(ok.status, 200, okText);
    const replayed = await grant(s.url, assertion);
    const replayedText = await replayed.text();
    assert.equal(replayed.status, 401);
    const refused = await grant(s.url, wrongAudience);
    const refusedText = await refused.text();
    assert.equal(refused.status, 401);
    const badProofRes = await grant(s.url, agent.assertion(TOKEN_ENDPOINT), {}, { dpop: badProof });
    const badProofText = await badProofRes.text();
    assert.equal(badProofRes.status, 400);
    const accessToken = JSON.parse(okText).access_token;
    const log = captured.join("\n");
    assert.ok(log.includes("oauth_token_issued"), "the issue is logged");
    for (const secret of [assertion, wrongAudience, proof, badProof]) {
      const signature = secret.split(".")[2];
      for (const [label, text] of [["log", log], ["ok", okText], ["replayed", replayedText], ["refused", refusedText], ["bad proof", badProofText]]) {
        assert.equal(text.includes(secret), false, `${label} carries an assertion or proof`);
        assert.equal(text.includes(signature), false, `${label} carries an assertion or proof signature`);
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

test("past the spent-assertion cap a new sign-in gets 503, and a spent assertion stays spent", async () => {
  const h = await harness({ spentAssertionsCap: 1 });
  try {
    const first = makeAgentKey();
    const second = makeAgentKey();
    const assertion = first.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() });
    assert.equal((await grant(h.url, assertion)).status, 200);
    const full = await grant(h.url, second.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
    assert.equal(full.status, 503);
    assert.equal(full.headers.get("retry-after"), "60");
    const body = await full.json();
    assert.equal(body.error, "temporarily_unavailable");
    assert.equal(body.error_description, "Clockchain is taking too many agent sign-ins right now. Try again in a minute.");
    assert.equal(body.access_token, undefined);
    assert.ok(h.logs.some((e) => e.event === "oauth_replay_state_full" && e.set === "used-assertions"), JSON.stringify(h.logs));
    // The flood never pushes out the spent assertion.
    const again = await grant(h.url, assertion);
    assert.equal(again.status, 401);
    const refused = await again.json();
    assert.equal(refused.error, "invalid_client");
    assert.match(refused.error_description, /already used/);
    // Once the first assertion has expired, there is room again.
    h.advance(300_000);
    assert.equal((await grant(h.url, second.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
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

test("past the hourly ceiling on new keys from every address, a new key gets 429, but a known key still mints", async () => {
  const h = await harness({ newPerHour: 3 });
  try {
    const agents = Array.from({ length: 4 }, () => makeAgentKey());
    for (const agent of agents.slice(0, 3)) {
      const res = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
      assert.equal(res.status, 200, await res.text());
    }
    const fourth = await grant(h.url, agents[3].assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
    assert.equal(fourth.status, 429, "the address is still well within its own 10");
    assert.equal(fourth.headers.get("retry-after"), "3600");
    assert.deepEqual(await fourth.json(), { error: "temporarily_unavailable", error_description: "Clockchain isn't taking new agent keys right now. Try again later, or reuse a key you already have." });
    assert.equal(h.book.get(agents[3].fingerprint), null, "the limited key is not admitted");
    assert.ok(h.logs.some((e) => e.event === "oauth_rate_limited" && e.surface === "agent_key_global"), JSON.stringify(h.logs));
    // Keys already in the book don't count.
    assert.equal((await grant(h.url, agents[0].assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
    h.advance(60 * 60_000 + 1000);
    assert.equal((await grant(h.url, agents[3].assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
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

test("a new key records a keyed hash of the address it signed in from as its source, never the address", async () => {
  const h = await harness({}, { trustedProxy: "127.0.0.1" });
  try {
    const from = (ip) => ({ "x-forwarded-for": ip });
    const [a, b, c] = [makeAgentKey(), makeAgentKey(), makeAgentKey()];
    assert.equal((await grant(h.url, a.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), {}, from("203.0.113.7"))).status, 200);
    assert.equal((await grant(h.url, b.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), {}, from("203.0.113.7"))).status, 200);
    assert.equal((await grant(h.url, c.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), {}, from("198.51.100.4"))).status, 200);
    const [sa, sb, sc] = [a, b, c].map((k) => h.book.get(k.fingerprint).source);
    assert.match(sa, /^[0-9a-f]{32}$/);
    assert.equal(sb, sa, "two keys from one address share a source");
    assert.match(sc, /^[0-9a-f]{32}$/);
    assert.notEqual(sc, sa, "another address has another source");
    const expected = (ip) => createHmac("sha256", SECRET).update(`agent-key-source:v1\0${ip}`).digest("hex").slice(0, 32);
    assert.equal(sa, expected("203.0.113.7"));
    assert.equal(sc, expected("198.51.100.4"));
    // A known key signing in from elsewhere keeps its first source.
    assert.equal((await grant(h.url, a.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), {}, from("192.0.2.1"))).status, 200);
    assert.equal(h.book.get(a.fingerprint).source, sa);
    // The address and its hash stay out of the logs.
    const logged = JSON.stringify(h.logs);
    for (const secret of ["203.0.113.7", "198.51.100.4", sa, sc]) assert.ok(!logged.includes(secret), "a log line carries an address or its hash");
  } finally {
    await h.close();
  }
});

// ---- DPoP at sign-in (RFC 9449): the token is bound to the agent's key -----------------

test("each bad DPoP proof gets 400 invalid_dpop_proof, mints nothing and admits no key", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    const other = makeAgentKey();
    const now = h.nowSec();
    const cases = [
      ["no proof", undefined],
      ["two proofs", `${agent.dpop("POST", TOKEN_ENDPOINT, { iat: now })}, ${agent.dpop("POST", TOKEN_ENDPOINT, { iat: now })}`],
      ["another key", other.dpop("POST", TOKEN_ENDPOINT, { iat: now })],
      ["another URL", agent.dpop("POST", `${PUBLIC}/shadow/mcp`, { iat: now })],
      ["another method", agent.dpop("GET", TOKEN_ENDPOINT, { iat: now })],
      ["120 s old", agent.dpop("POST", TOKEN_ENDPOINT, { iat: now - 120 })],
    ];
    for (const [label, dpop] of cases) {
      const res = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: now }), {}, { dpop });
      const body = await res.json();
      assert.equal(res.status, 400, label);
      assert.equal(body.error, "invalid_dpop_proof", label);
      assert.ok(typeof body.error_description === "string" && body.error_description.length > 0, label);
      assert.equal(body.access_token, undefined, label);
    }
    assert.equal(h.book.get(agent.fingerprint), null, "no refused call admits the key");
    assert.ok(h.logs.some((e) => e.event === "oauth_agent_token_refused" && e.outcome === "bad_dpop"), JSON.stringify(h.logs));
    const otherKey = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: now }), {}, { dpop: other.dpop("POST", TOKEN_ENDPOINT, { iat: now }) });
    assert.equal((await otherKey.json()).error_description, "Sign the DPoP proof with the same key as the client assertion.");
  } finally {
    await h.close();
  }
});

test("a grant with a valid proof is a DPoP token bound to the agent's key", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    const res = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(body.token_type, "DPoP");
    assert.equal(verifyToken(SECRET, body.access_token, h.nowSec()).payload.cnf.jkt, agent.thumbprint);
  } finally {
    await h.close();
  }
});

test("a refused proof leaves its assertion unspent", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    const assertion = agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() });
    assert.equal((await grant(h.url, assertion, {}, { dpop: agent.dpop("GET", TOKEN_ENDPOINT, { iat: h.nowSec() }) })).status, 400);
    assert.equal((await grant(h.url, assertion)).status, 200);
  } finally {
    await h.close();
  }
});

test("a replayed proof is refused even with a fresh assertion", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    const proof = agent.dpop("POST", TOKEN_ENDPOINT, { iat: h.nowSec() });
    assert.equal((await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), {}, { dpop: proof })).status, 200);
    const again = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), {}, { dpop: proof });
    assert.equal(again.status, 400);
    assert.deepEqual(await again.json(), { error: "invalid_dpop_proof", error_description: "This DPoP proof was already used." });
  } finally {
    await h.close();
  }
});

test("past the spent-proof cap a new sign-in gets 503 naming the proof set, and its assertion stays unspent", async () => {
  const h = await harness({ spentDpopCap: 1 });
  try {
    const first = makeAgentKey();
    const second = makeAgentKey();
    assert.equal((await grant(h.url, first.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
    const assertion = second.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() });
    const full = await grant(h.url, assertion);
    assert.equal(full.status, 503);
    assert.equal(full.headers.get("retry-after"), "60");
    const body = await full.json();
    assert.equal(body.error, "temporarily_unavailable");
    assert.equal(body.error_description, "Clockchain is taking too many agent sign-ins right now. Try again in a minute.");
    assert.equal(body.access_token, undefined);
    assert.ok(h.logs.some((e) => e.event === "oauth_replay_state_full" && e.set === "used-dpop"), JSON.stringify(h.logs));
    // The proof is spent before the assertion, so the refused assertion can sign in once there is room.
    h.advance(61_000);
    assert.equal((await grant(h.url, assertion, {}, { dpop: second.dpop("POST", TOKEN_ENDPOINT, { iat: h.nowSec() }) })).status, 200);
  } finally {
    await h.close();
  }
});

test("a client_id that isn't the assertion's iss is invalid_client; the key's own thumbprint, or none, mints (RFC 7523 §3)", async () => {
  const h = await harness();
  try {
    const agent = makeAgentKey();
    const other = makeAgentKey();
    for (const client_id of [other.thumbprint, "some-registered-client", ""]) {
      const res = await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), { client_id });
      const body = await res.json();
      assert.equal(res.status, 401, client_id);
      assert.equal(body.error, "invalid_client");
      assert.equal(body.error_description, "client_id must be the assertion's iss (your key's thumbprint), or left out.");
    }
    assert.equal(h.book.get(agent.fingerprint), null, "a refused sign-in admits no key");
    assert.ok(h.logs.some((e) => e.event === "oauth_agent_token_refused" && e.outcome === "client_id_mismatch"));
    assert.equal((await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }), { client_id: agent.thumbprint })).status, 200);
    assert.equal((await grant(h.url, agent.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
  } finally {
    await h.close();
  }
});

test("a sign-in refused because a spent set is full admits no key and spends no new-key allowance", async () => {
  for (const [cap, set] of [[{ spentAssertionsCap: 1 }, "used-assertions"], [{ spentDpopCap: 1 }, "used-dpop"]]) {
    const h = await harness({ ...cap, newPerIpPerHour: 2 });
    try {
      assert.equal((await grant(h.url, makeAgentKey().assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200);
      // Three new keys refused: had any been admitted, its allowance spent, the third would get 429.
      for (let i = 0; i < 3; i++) {
        const refused = makeAgentKey();
        const full = await grant(h.url, refused.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }));
        assert.equal(full.status, 503, set);
        assert.equal(h.book.get(refused.fingerprint), null, `${set}: no key admitted`);
      }
      assert.ok(h.logs.some((e) => e.event === "oauth_replay_state_full" && e.set === set), JSON.stringify(h.logs));
      // Room again (both sets' first entries have expired): a new key mints on the address's second allowance.
      const second = makeAgentKey();
      h.advance(301_000);
      assert.equal((await grant(h.url, second.assertion(TOKEN_ENDPOINT, { iat: h.nowSec() }))).status, 200, set);
    } finally {
      await h.close();
    }
  }
});
