// An agent onboards from the server's own instructions, with no person, over the real runHttp wiring: it reads them in
// /llms.txt and /shadow/connect, makes its own Ed25519 key, gets a token with one signed assertion, records and signs its
// checkpoints, and anyone with the links can check the result. Then AT-7: (a) a second token from the same key sees the
// same sessions, (d) no private key is kept on the server but the witness key the operator provides, (e) no tool result
// or log line carries the token, the assertion or a cc_ token.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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
  "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_WITNESS_KEY_FILE", "SHADOW_STARTER_ANCHORS_PER_DAY", "SHADOW_AUTO_LOG",
  "SHADOW_PREVIEW_AUTO_LOG", "SHADOW_LAZY_AUTH", "SHADOW_ALLOW_NON_ACCT",
];
// Loopback ports 19560-19569, which no other test uses; a busy one is skipped, five tries at most.
const PORT_BASE = 19560;
const AGENT_LINE = /^ *Agents that run code /;

/** runHttp with OAuth, Shadow, agent keys and a witness key on, its state and the witness key file under `root`. */
async function boot(root) {
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
      SHADOW_ENABLED: "1", SHADOW_STATE_DIR: path.join(stateDir, "shadow"), SHADOW_WITNESS_KEY_FILE: witnessFile,
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
        "never sees", "/replace", "new_key_assertion", "new_public_key", "/revoke"]) {
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
    await call("shadow_record", { session_id: s.session_id, agent: "planner", kind: "message", content: "TAP at 389 EUR." });
    const cp = await call("shadow_checkpoint", { session_id: s.session_id });
    assert.match(cp.sign.hash, /^[0-9a-f]{64}$/);
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
  }
});
