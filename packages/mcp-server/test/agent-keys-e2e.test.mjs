// An agent onboards from the server's own instructions, with no person, over the real runHttp wiring: it reads them in
// /llms.txt and /shadow/connect, makes its own Ed25519 key, gets a token with one signed assertion, records and signs its
// checkpoints, and anyone with the links can check the result. Then AT-7: (a) a second token from the same key sees the
// same sessions, (d) no private key is kept on the server but the witness key the operator provides, (e) no tool result
// or log line carries the token, the assertion or a cc_ token.
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { once } from "node:events";
import test from "node:test";
import { format } from "node:util";

import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { verifyPacket } from "../dist/shadow/lib/verify.js";
import { parseStrict } from "../dist/shadow/lib/profile.js";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";
import { makeAgentKey } from "./helpers/agent-key.mjs";

const SECRET = "agent-keys-e2e-secret";
const PUBLIC = "https://mcp.example.test";
const ACCEPT = "application/json, text/event-stream";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ENV_KEYS = [
  "PORT", "MCP_PORT", "MCP_AUTH_TOKENS", "MCP_TOKEN_SIGNING_SECRET", "MCP_STATE_DIR", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_OAUTH_TRUSTED_PROXY",
  "MCP_REQUIRE_AUTH", "MCP_RATE_PER_MIN", "MCP_SURFACE", "MCP_AGENT_KEYS", "MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR",
  "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_WITNESS_KEY_FILE", "SHADOW_STARTER_ANCHORS_PER_DAY", "SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY", "SHADOW_AUTO_LOG",
  "SHADOW_PREVIEW_AUTO_LOG", "SHADOW_LAZY_AUTH", "SHADOW_ALLOW_NON_ACCT",
];
// Loopback ports 19560-19569, which no other test uses; a busy one is skipped, five tries at most.
const PORT_BASE = 19560;
const AGENT_LINE = /^ *Agents that run code /;

/** runHttp with OAuth, Shadow, agent keys and a witness key on, its state and the witness key file under `root`; `env` on top. */
async function boot(root, env = {}) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  const witnessFile = path.join(root, "witness-key.pem");
  writeFileSync(witnessFile, generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const stateDir = path.join(root, "state");
  let server;
  for (let attempt = 1; ; attempt++) {
    Object.assign(process.env, {
      MCP_PORT: String(PORT_BASE + attempt - 1), MCP_AUTH_TOKENS: "static-e2e-token", MCP_TOKEN_SIGNING_SECRET: SECRET,
      MCP_STATE_DIR: stateDir, MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, MCP_AGENT_KEYS: "1",
      SHADOW_ENABLED: "1", SHADOW_STATE_DIR: path.join(stateDir, "shadow"), SHADOW_WITNESS_KEY_FILE: witnessFile, ...env,
    });
    try {
      server = await runHttp();
      if (!server.listening) await once(server, "listening");
    } catch (e) {
      if (e?.code !== "EADDRINUSE" || attempt >= 5) throw e;
      continue;
    }
    // Something else may hold this port on 127.0.0.1 alone: make sure a request reaches this server.
    let reached = false;
    const mark = () => { reached = true; };
    server.prependListener("request", mark);
    await fetch(`http://127.0.0.1:${server.address().port}/health`).then((r) => r.arrayBuffer()).catch(() => {});
    server.removeListener("request", mark);
    if (reached) break;
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
    assert.ok(attempt < 5, `no port in ${PORT_BASE}-${PORT_BASE + 4} reached this server`);
  }
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    witnessFile,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

/** Every file under `dir`, recursively. */
function filesUnder(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? filesUnder(p) : e.isFile() ? [p] : [];
  });
}

/** The agent block of a discovery text: its first line through the line before the next blank one. */
function agentBlock(text) {
  const lines = text.split("\n");
  const at = lines.findIndex((l) => AGENT_LINE.test(l));
  assert.ok(at >= 0, "the text has instructions for agents that run code");
  const end = lines.indexOf("", at);
  return lines.slice(at, end < 0 ? undefined : end);
}

test("an agent onboards from the instructions alone: one token call, signed checkpoints, a record anyone can check (AT-7 a, d, e)", async () => {
  __setShadowLedgerForTests(new FakeLedger());
  const captured = [];
  const orig = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug };
  for (const k of Object.keys(orig)) console[k] = (...a) => { captured.push(format(...a)); };
  const root = mkdtempSync(path.join(tmpdir(), "agent-keys-e2e-"));
  const results = [];
  const secrets = [];
  let app;
  try {
    app = await boot(root);

    // The instructions: in /llms.txt and on /shadow/connect, eight lines at most, with every name the agent needs.
    const llms = await (await fetch(`${app.url}/llms.txt`)).text();
    const connect = await (await fetch(`${app.url}/shadow/connect`)).text();
    for (const [name, text] of [["llms.txt", llms], ["connect", connect]]) {
      const block = agentBlock(text);
      assert.ok(block.length <= 8, `${name}: ${block.length} lines`);
      const joined = block.join("\n");
      for (const fact of ["Ed25519", "private half", "/oauth/token", "grant_type=client_credentials", `client_assertion_type=${JWT_BEARER}`, "client_assertion=",
        "token_endpoint", "/shadow/mcp", "sign.hash", "shadow_checkpoint", "shadow_close_session", "shadow_sign_checkpoint", "/agent-keys/<fingerprint>.json",
        "never sees", "/replace", "new_key_assertion", "new_public_key", "/revoke", "sign.count", "sign.head",
        "standard base64, 88 characters ending ==", "including its final newline", "under the issuer from the OAuth metadata", "8 to 128 characters"]) {
        assert.ok(joined.includes(fact), `${name} names ${fact}`);
      }
      assert.doesNotMatch(joined, /verified|independent|validator/i, name);
    }

    // The token endpoint named in the OAuth metadata, as the instructions say; one signed assertion for a token.
    const meta = await (await fetch(`${app.url}/.well-known/oauth-authorization-server`)).json();
    assert.equal(meta.token_endpoint, `${PUBLIC}/oauth/token`);
    assert.ok(meta.grant_types_supported.includes("client_credentials"));
    const agent = makeAgentKey();
    const tokenCall = async () => {
      const assertion = agent.assertion(meta.token_endpoint);
      secrets.push(assertion);
      const res = await fetch(`${app.url}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "client_credentials", client_assertion_type: JWT_BEARER, client_assertion: assertion }),
      });
      const body = await res.json();
      assert.equal(res.status, 200, JSON.stringify(body));
      secrets.push(body.access_token);
      return body;
    };
    const issued = await tokenCall();
    assert.equal(issued.token_type, "Bearer");
    assert.equal(issued.expires_in, 3600);
    assert.equal(issued.refresh_token, undefined);
    assert.match(issued.agent_id, /^[0-9a-f]{16}$/);
    const cred = `Bearer ${issued.access_token}`;

    const rpc = async (method, params, authorization = cred) => {
      const res = await fetch(`${app.url}/shadow/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const text = await res.text();
      assert.equal(res.status, 200, text);
      const data = text.split("\n").find((l) => l.startsWith("data:"));
      return JSON.parse(data ? data.slice(5) : text).result;
    };
    const call = async (name, args, authorization) => {
      const result = await rpc("tools/call", { name, arguments: args }, authorization);
      const text = result.content[0].text;
      results.push(text);
      const value = JSON.parse(text);
      assert.notEqual(result.isError, true, `${name}: ${text}`);
      return value;
    };

    // The tool list tells the agent it signs, on the two tools that hand it a hash.
    const { tools } = await rpc("tools/list", {});
    const described = Object.fromEntries(tools.map((t) => [t.name, t.description]));
    assert.ok(described.shadow_sign_checkpoint);
    for (const name of ["shadow_checkpoint", "shadow_close_session"]) assert.match(described[name], /shadow_sign_checkpoint/, name);

    const s = await call("shadow_start_session", { title: "Find a flight", agents: [{ id: "planner" }] });
    await call("shadow_record", { session_id: s.session_id, agent: "planner", kind: "task", content: "Find a flight from Lisbon to Paris" });
    await call("shadow_record", { session_id: s.session_id, agent: "planner", kind: "tool_call", content: { tool: "search_flights", args: { from: "LIS", to: "CDG" } } });
    const last = await call("shadow_record", { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
    const cp = await call("shadow_checkpoint", { session_id: s.session_id });
    assert.match(cp.sign.hash, /^[0-9a-f]{64}$/);
    // As the instructions say: before signing, count and head match the agent's own record.
    assert.equal(cp.sign.count, last.seq);
    assert.equal(cp.sign.head, last.hash);
    const signed = await call("shadow_sign_checkpoint", { session_id: s.session_id, hash: cp.sign.hash, signature: agent.signHash(cp.sign.hash) });
    assert.equal(signed.checkpoint.status, "anchored", JSON.stringify(signed));
    const closed = await call("shadow_close_session", { session_id: s.session_id, status: "succeeded" });
    assert.match(closed.sign.hash, /^[0-9a-f]{64}$/);
    const final = await call("shadow_sign_checkpoint", { session_id: s.session_id, hash: closed.sign.hash, signature: agent.signHash(closed.sign.hash) });
    assert.equal(final.status, "closed");
    assert.ok(final.pin, JSON.stringify(final));

    // Anyone with the links: the packet verifies against the pin, and the viewer says the agent made it.
    const doc = parseStrict(await (await fetch(closed.links.packet)).text());
    const report = await verifyPacket(doc.packet, { pin: parseStrict(JSON.stringify(final.pin)) });
    assert.equal(report.result, "pass", JSON.stringify(report.checks, null, 1));
    const verified = await call("shadow_verify", { session_id: s.session_id });
    assert.equal(verified.result, "pass", verified.summary);
    assert.equal(verified.agent_key.verdict, "made_by_agent");
    const page = await (await fetch(closed.links.viewer)).text();
    assert.ok(page.includes(`Made by agent ${issued.agent_id}, unchanged since`), "the viewer reads made_by_agent");

    // The lookup URL from the instructions: the fingerprint as they describe it is the key's, and its entry is public.
    const fp = createHash("sha256").update(`shadow:public-key:v1\0${JSON.stringify(agent.publicKeyPem)}`).digest("hex");
    assert.equal(fp, agent.fingerprint);
    assert.equal(verified.agent_key.lookup, `/agent-keys/${fp}.json`);
    const entry = await fetch(`${app.url}/agent-keys/${fp}.json`);
    assert.equal(entry.status, 200);
    assert.ok(!(await entry.text()).includes("PRIVATE KEY"));

    // AT-7(a): a second token from the same key is the same agent, and sees the session.
    const again = await tokenCall();
    assert.notEqual(again.access_token, issued.access_token);
    assert.equal(again.agent_id, issued.agent_id);
    const listed = await call("shadow_list_sessions", {}, `Bearer ${again.access_token}`);
    assert.deepEqual(listed.sessions.map((x) => x.session_id), [s.session_id]);

    // AT-7(d): no private key on the server's disk, but the witness key file the operator provided (here, this test).
    const holding = filesUnder(root).filter((f) => readFileSync(f).includes("PRIVATE KEY"));
    assert.deepEqual(holding, [app.witnessFile]);

    // AT-7(e): no tool result and no log line carries the token, the assertion, or any cc_ token.
    assert.ok(captured.some((l) => l.includes("oauth_token_issued")), "the server's log lines were captured");
    const ccToken = /(?<![A-Za-z0-9_-])cc_[A-Za-z0-9._-]{20,}/;
    for (const [where, texts] of [["tool result", results], ["log line", captured]]) {
      for (const text of texts) {
        for (const secret of secrets) assert.ok(!text.includes(secret), `a ${where} carries a token or assertion`);
        assert.doesNotMatch(text, ccToken, `a ${where} carries a cc_ token`);
      }
    }
  } finally {
    for (const k of Object.keys(orig)) console[k] = orig[k];
    await app?.close();
    __setShadowLedgerForTests(undefined);
    rmSync(root, { recursive: true, force: true });
  }
});

test("each address has its share of the Starter allowance: two agents from one address stop at the share, another address still anchors", async () => {
  const fake = new FakeLedger();
  __setShadowLedgerForTests(fake);
  const captured = [];
  const orig = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug };
  for (const k of Object.keys(orig)) console[k] = (...a) => { captured.push(format(...a)); };
  const root = mkdtempSync(path.join(tmpdir(), "agent-keys-e2e-source-"));
  const results = [];
  let app;
  try {
    app = await boot(root, { MCP_OAUTH_TRUSTED_PROXY: "127.0.0.1", SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY: "2" });
    const signIn = async (agent, ip) => {
      const res = await fetch(`${app.url}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": ip },
        body: new URLSearchParams({ grant_type: "client_credentials", client_assertion_type: JWT_BEARER, client_assertion: agent.assertion(`${PUBLIC}/oauth/token`) }),
      });
      const body = await res.json();
      assert.equal(res.status, 200, JSON.stringify(body));
      return `Bearer ${body.access_token}`;
    };
    const call = async (authorization, name, args) => {
      const res = await fetch(`${app.url}/shadow/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, authorization },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
      });
      const text = await res.text();
      assert.equal(res.status, 200, text);
      const data = text.split("\n").find((l) => l.startsWith("data:"));
      const result = JSON.parse(data ? data.slice(5) : text).result;
      results.push(result.content[0].text);
      assert.notEqual(result.isError, true, `${name}: ${result.content[0].text}`);
      return JSON.parse(result.content[0].text);
    };
    /** Starts a session (its key's filing and its start marker), then asks for a signed checkpoint. */
    const run = async (agent, ip) => {
      const cred = await signIn(agent, ip);
      const s = await call(cred, "shadow_start_session", { title: "Find a flight", agents: [{ id: "planner" }] });
      await call(cred, "shadow_record", { session_id: s.session_id, agent: "planner", kind: "task", content: "Find a flight" });
      const cp = await call(cred, "shadow_checkpoint", { session_id: s.session_id });
      const signed = await call(cred, "shadow_sign_checkpoint", { session_id: s.session_id, hash: cp.sign.hash, signature: agent.signHash(cp.sign.hash) });
      return { s, signed };
    };
    const SHARE_USED = "Agents from this address have used their share of today's Starter allowance. Try again tomorrow (UTC), or sign in to a Clockchain account.";

    // The first agent's filing and start marker are the address's two.
    const first = await run(makeAgentKey(), "203.0.113.7");
    assert.equal(first.s.start_anchor.status, "anchored");
    assert.equal(fake.writes.length, 2);
    assert.equal(first.signed.checkpoint.status, "over_limit", JSON.stringify(first.signed));
    assert.equal(first.signed.checkpoint.reason, SHARE_USED);
    // A second agent from the same address: its filing is the third anchor in total, and it is refused.
    const second = await run(makeAgentKey(), "203.0.113.7");
    assert.notEqual(second.s.start_anchor.status, "anchored");
    assert.equal(second.signed.checkpoint.status, "over_limit", JSON.stringify(second.signed));
    assert.equal(second.signed.checkpoint.reason, SHARE_USED);
    assert.equal(fake.writes.length, 2, "nothing more was written for that address");
    // An agent from another address still anchors: its filing and start marker are that address's own two.
    const other = makeAgentKey();
    const third = await run(other, "198.51.100.4");
    assert.equal(third.s.start_anchor.status, "anchored");
    assert.equal(fake.writes.length, 4);
    assert.equal(third.signed.checkpoint.reason, SHARE_USED, "and then its share is used too");

    // The source is kept, but nowhere public: not in the lookup, a ledger write, a tool result or a log line.
    const source = createHmac("sha256", SECRET).update("agent-key-source:v1\x00198.51.100.4").digest("hex").slice(0, 32);
    const lookup = await (await fetch(`${app.url}/agent-keys/${other.fingerprint}.json`)).text();
    for (const [where, text] of [["lookup", lookup], ["ledger write", JSON.stringify(fake.writes)], ...results.map((r) => ["tool result", r]), ...captured.map((l) => ["log line", l])]) {
      assert.ok(!text.includes(source), `a ${where} carries the source`);
      assert.ok(!text.includes("203.0.113.7") && !text.includes("198.51.100.4"), `a ${where} carries an address`);
    }
    assert.ok(!/"source"/.test(lookup), "the lookup has no source field");
    assert.ok(!/"source"/.test(JSON.stringify(fake.writes)), "no ledger write has a source field");
  } finally {
    for (const k of Object.keys(orig)) console[k] = orig[k];
    await app?.close();
    __setShadowLedgerForTests(undefined);
    rmSync(root, { recursive: true, force: true });
  }
});
