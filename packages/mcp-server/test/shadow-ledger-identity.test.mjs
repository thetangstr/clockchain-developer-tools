// Hosted Shadow anchors under its own client and wallet. Everything here runs against the real anchoring gateway
// (infra/anchoring-gateway/gateway.mjs) as a separate process, with the real client: nothing is faked, because what
// matters is what the gateway stores, and that its client-scoped search still finds sessions anchored under the old client.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runHttp } from "../dist/http.js";
import { loadShadowConfig } from "../dist/shadow/service.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { __resetSharedLogBudget } from "../dist/budget.js";

const GATEWAY = fileURLToPath(new URL("../../../infra/anchoring-gateway/gateway.mjs", import.meta.url));
const PUBLIC = "https://mcp.example.test";
const PLAIN = "/shadow/mcp";
const CB = "https://claude.ai/api/mcp/auth_callback";
const SIGNING = "gateway-test-signing-secret";
const OLD = "founder@example.com";
const CLIENT = "clockchain-shadow";
const WALLET = "clockchain-shadow-wallet";
const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "SHADOW_PREVIEW_AUTO_LOG", "SHADOW_LEDGER_CLIENT_ID", "SHADOW_LEDGER_WALLET_ID", "MCP_LOG_BUDGET", "CLOCKCHAIN_ENDPOINT", "CLOCKCHAIN_API_KEY", "CLOCKCHAIN_CLIENT_ID", "CLOCKCHAIN_WALLET_ID", "CLOCKCHAIN_SIGNING_SECRET", "CLOCKCHAIN_SIGNING_KEY_ID", "CLOCKCHAIN_SUBSTRATE"];
const tmp = (label) => mkdtempSync(path.join(tmpdir(), `shadow-ledger-${label}-`));

async function freePort() {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

async function startGateway() {
  const dataDir = tmp("gateway");
  const port = await freePort();
  const proc = spawn(process.execPath, [GATEWAY], { env: { PATH: process.env.PATH, GATEWAY_PORT: String(port), GATEWAY_HOST: "127.0.0.1", GATEWAY_DATA_DIR: dataDir, GATEWAY_SIGNING_KEYS: `default:${SIGNING}` }, stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((resolve, reject) => {
    proc.stdout.on("data", (d) => { if (String(d).includes("gateway_listening")) resolve(); });
    proc.on("exit", (c) => reject(new Error(`gateway exited (${c})`)));
  });
  return {
    url: `http://127.0.0.1:${port}`,
    stop: () => { proc.kill(); },
    /** Every entry the gateway has stored, from its own durable log. */
    entries: () => readFileSync(path.join(dataDir, "anchor-events.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((e) => e.k === "log").map((e) => e.entry),
  };
}

async function boot(gateway, stateDir, identity) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  __setShadowLedgerForTests(undefined);
  __resetSharedLogBudget();
  Object.assign(process.env, {
    MCP_PORT: String(await freePort()), MCP_AUTH_TOKENS: "static-test-token", MCP_TOKEN_SIGNING_SECRET: "ledger-identity-secret", MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"),
    MCP_OAUTH: "1", MCP_PUBLIC_URL: PUBLIC, SHADOW_ENABLED: "1", MCP_LOG_BUDGET: "1000",
    CLOCKCHAIN_ENDPOINT: gateway.url, CLOCKCHAIN_API_KEY: "delegated", CLOCKCHAIN_CLIENT_ID: OLD, CLOCKCHAIN_WALLET_ID: OLD, CLOCKCHAIN_SIGNING_SECRET: SIGNING, CLOCKCHAIN_SIGNING_KEY_ID: "default",
    ...(identity ? { SHADOW_LEDGER_CLIENT_ID: CLIENT, SHADOW_LEDGER_WALLET_ID: WALLET } : {}),
  });
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __setShadowLedgerForTests(undefined);
      __resetSharedLogBudget();
    },
  };
}

async function signUp(base) {
  const resource = `${PUBLIC}${PLAIN}`;
  const client = await (await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [CB], token_endpoint_auth_method: "none" }) })).json();
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", state: "s", resource });
  const html = await (await fetch(`${base}/oauth/authorize?${q}`, { headers: { accept: "text/html" } })).text();
  const request = /name="request" value="([^"]+)"/.exec(html)[1];
  const decide = (fields) => fetch(`${base}/oauth/authorize`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", origin: PUBLIC }, body: new URLSearchParams({ request, ...fields }) });
  const keyHtml = await (await decide({ decision: "create", name: "Acme" })).text();
  const cont = await decide({ decision: "continue", grant: /name="grant" value="([^"]+)"/.exec(keyHtml)[1] });
  const code = new URL(cont.headers.get("location")).searchParams.get("code");
  const t = await (await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: client.client_id, code_verifier: verifier, resource }) })).json();
  return t.access_token;
}

const rpc = async (base, p, method, params, headers) => {
  const res = await fetch(`${base}${p}`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const text = await res.text();
  if (res.status !== 200) return { status: res.status, body: JSON.parse(text) };
  return { status: 200, body: res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : JSON.parse(text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop()) };
};
const tool = async (base, token, name, args) => {
  const r = await rpc(base, PLAIN, "tools/call", { name, arguments: args }, { authorization: `Bearer ${token}` });
  assert.equal(r.status, 200, name);
  return JSON.parse(r.body.result.content[0].text);
};
/** A task, what was said, and an anchor over them: what it takes for a check to say pass. */
async function steps(base, token, sessionId) {
  await tool(base, token, "shadow_record", { session_id: sessionId, agent: "agent", kind: "task", content: "the task" });
  await tool(base, token, "shadow_record", { session_id: sessionId, agent: "agent", kind: "message", content: "the answer" });
  await tool(base, token, "shadow_checkpoint", { session_id: sessionId });
}
const witness = (report) => report.checks.find((c) => c.name === "witness");

test("settings: both or neither, no email, not the delegated client; anything else stops Shadow", () => {
  const env = (x) => ({ SHADOW_ENABLED: "1", CLOCKCHAIN_CLIENT_ID: OLD, CLOCKCHAIN_WALLET_ID: OLD, ...x });
  assert.equal(loadShadowConfig(env({})).problem, undefined);
  assert.equal(loadShadowConfig(env({ SHADOW_LEDGER_CLIENT_ID: CLIENT, SHADOW_LEDGER_WALLET_ID: WALLET })).problem, undefined);
  assert.match(loadShadowConfig(env({ SHADOW_LEDGER_CLIENT_ID: CLIENT })).problem, /must be set together/);
  assert.match(loadShadowConfig(env({ SHADOW_LEDGER_WALLET_ID: WALLET })).problem, /must be set together/);
  assert.match(loadShadowConfig(env({ SHADOW_LEDGER_CLIENT_ID: "someone@example.com", SHADOW_LEDGER_WALLET_ID: WALLET })).problem, /not an email address/);
  assert.match(loadShadowConfig(env({ SHADOW_LEDGER_CLIENT_ID: OLD.toUpperCase().replace("@", "."), SHADOW_LEDGER_WALLET_ID: WALLET, CLOCKCHAIN_CLIENT_ID: OLD.replace("@", ".") })).problem, /must differ from the delegated/);
});

test("on the real gateway: new anchors show only the neutral id; a session anchored under the old client still passes online, and finishes", async () => {
  const gateway = await startGateway();
  const stateDir = tmp("state");
  let s = await boot(gateway, stateDir, false);
  try {
    // Before the change: a session under the old client, left open, and one closed.
    const token = await signUp(s.url);
    const old = await tool(s.url, token, "shadow_start_session", { title: "Before the change" });
    await steps(s.url, token, old.session_id);
    const closedOld = await tool(s.url, token, "shadow_start_session", { title: "Closed before the change" });
    await steps(s.url, token, closedOld.session_id);
    await tool(s.url, token, "shadow_close_session", { session_id: closedOld.session_id, status: "succeeded" });
    const before = gateway.entries();
    assert.ok(before.length >= 4);
    assert.ok(before.every((e) => e.clientId === OLD && e.walletId === OLD));

    // The change.
    await s.close();
    s = await boot(gateway, stateDir, true);

    // The closed one, wholly under the old client, still passes its online check, search included.
    const verifiedOld = await tool(s.url, token, "shadow_verify", { session_id: closedOld.session_id });
    assert.equal(witness(verifiedOld).status, "pass", JSON.stringify(witness(verifiedOld)));
    assert.equal(verifiedOld.result, "pass", JSON.stringify(verifiedOld.checks.filter((c) => c.status !== "pass" && c.status !== "not-applicable")));

    // The open one carries on under the new client, and its receipts from both clients check out.
    await tool(s.url, token, "shadow_record", { session_id: old.session_id, agent: "agent", kind: "message", content: "more" });
    await tool(s.url, token, "shadow_checkpoint", { session_id: old.session_id });
    await tool(s.url, token, "shadow_close_session", { session_id: old.session_id, status: "succeeded" });
    const verifiedMixed = await tool(s.url, token, "shadow_verify", { session_id: old.session_id });
    assert.equal(witness(verifiedMixed).status, "pass", JSON.stringify(witness(verifiedMixed)));
    assert.equal(verifiedMixed.result, "pass", JSON.stringify(verifiedMixed.checks.filter((c) => c.status !== "pass" && c.status !== "not-applicable")));

    // A new session: only the neutral id, and it passes.
    const fresh = await tool(s.url, token, "shadow_start_session", { title: "After the change" });
    await steps(s.url, token, fresh.session_id);
    await tool(s.url, token, "shadow_close_session", { session_id: fresh.session_id, status: "succeeded" });
    assert.equal((await tool(s.url, token, "shadow_verify", { session_id: fresh.session_id })).result, "pass");

    const after = gateway.entries().slice(before.length);
    assert.ok(after.length >= 3);
    assert.ok(after.every((e) => e.clientId === CLIENT && e.walletId === WALLET), JSON.stringify(after.map((e) => e.clientId)));
    assert.equal(JSON.stringify(after).includes(OLD), false, "the old id is on no new entry");
  } finally {
    await s.close();
    gateway.stop();
  }
});

test("a /mcp caller can't write under Shadow's client or wallet, in any letter case; /mcp's own writes keep the delegated client", async () => {
  const gateway = await startGateway();
  const s = await boot(gateway, tmp("state"), true);
  try {
    const call = { name: "log_action", arguments: { action: "x", agent_id: "a", content_hash: "a".repeat(64) } };
    for (const headers of [
      { "x-clockchain-api-key": "any-key", "x-clockchain-client-id": CLIENT },
      { "x-clockchain-api-key": "any-key", "x-clockchain-wallet-id": WALLET },
      { "x-clockchain-api-key": "any-key", "x-clockchain-client-id": CLIENT.toUpperCase() },
      { "x-api-key": "any-key", "x-clockchain-client-id": ` ${CLIENT} ` },
      { "x-api-key": "static-test-token", "x-clockchain-client-id": CLIENT },
    ]) {
      const r = await rpc(s.url, "/mcp", "tools/call", call, headers);
      assert.equal(r.status, 403, JSON.stringify(headers));
      assert.equal(r.body.error, "reserved_ledger_identity");
    }
    const none = (() => { try { return gateway.entries(); } catch { return []; } })();
    assert.equal(none.some((e) => e.clientId.toLowerCase() === CLIENT || e.walletId.toLowerCase() === WALLET), false);

    // /mcp itself is unchanged: a delegated write keeps the delegated client, never Shadow's.
    const written = await rpc(s.url, "/mcp", "tools/call", { name: "log_action", arguments: { asset_reference_id: "mcp-delegated-check", asset_hash: "b".repeat(64) } }, { "x-api-key": "static-test-token" });
    assert.equal(written.status, 200);
    assert.notEqual(written.body.result.isError, true, JSON.stringify(written.body.result));
    const entry = gateway.entries().find((e) => e.assetReferenceId.includes("mcp-delegated-check"));
    assert.equal(entry.clientId, OLD);
  } finally {
    await s.close();
    gateway.stop();
  }
});

test("with no identity set, nothing changes: anchors stay under the delegated client and no header is refused", async () => {
  const gateway = await startGateway();
  const s = await boot(gateway, tmp("state"), false);
  try {
    const token = await signUp(s.url);
    await tool(s.url, token, "shadow_start_session", { title: "t" });
    assert.ok(gateway.entries().every((e) => e.clientId === OLD));
    const r = await rpc(s.url, "/mcp", "tools/list", {}, { "x-api-key": "static-test-token", "x-clockchain-client-id": CLIENT });
    assert.equal(r.status, 200);
  } finally {
    await s.close();
    gateway.stop();
  }
});
