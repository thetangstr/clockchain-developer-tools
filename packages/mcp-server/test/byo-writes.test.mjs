// On the owned anchoring gateway, which checks only our signature, a caller's own key can read but never write: a key
// we never issued could otherwise write under any client id, outside MCP_LOG_BUDGET. A fake gateway records every
// request. Delegated callers (signed tokens, OAuth tokens, MCP_AUTH_TOKENS) still write, inside the budget.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { ClockchainClient, ReadOnlyClientError, onOwnedGateway, readConfigFromEnv } from "@clockchain/core";
import { runHttp } from "../dist/http.js";
import { BYO_READ_TOOLS } from "../dist/entitlement.js";
import { mintToken } from "../dist/token.js";
import { __resetSharedLogBudget } from "../dist/budget.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const SECRET = "byo-writes-test-signing-secret";
const STATIC = "static-byo-test-token";
const DELEGATED = "delegated@example.test";
const FOUNDER = "founder@example.test";
const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_TOKEN_SIGNING_SECRET", "MCP_STATE_DIR", "MCP_RATE_PER_MIN", "MCP_LOG_BUDGET", "MCP_BYO_WRITES", "MCP_OAUTH", "MCP_PUBLIC_URL",
  "CLOCKCHAIN_ENDPOINT", "CLOCKCHAIN_SUBSTRATE", "CLOCKCHAIN_API_KEY", "CLOCKCHAIN_CLIENT_ID", "CLOCKCHAIN_WALLET_ID", "CLOCKCHAIN_SIGNING_SECRET", "SHADOW_ENABLED", "STANDALONE_CLOCK_RESYNC_MS"];

/** Answers everything; records every request. A POST /log gets a confirmed record, as the real gateway gives. */
async function fakeGateway() {
  const seen = [];
  let height = 100;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const json = (() => { try { return JSON.parse(body); } catch { return undefined; } })();
      seen.push({ method: req.method, path: req.url.split("?")[0], key: req.headers["x-api-key"], json });
      res.writeHead(200, { "content-type": "application/json" });
      if (req.url.startsWith("/log")) {
        height++;
        return res.end(JSON.stringify({ ledgerId: `ledger-${height}`, clientId: json?.clientId, walletId: json?.walletId, assetHash: json?.assetHash, assetReferenceId: json?.assetReferenceId, blockHeight: String(height), createdTimestamp: new Date().toISOString() }));
      }
      if (req.url.startsWith("/getTime")) return res.end(JSON.stringify({ success: true, data: { blockHeight: 100, blockTime: new Date().toISOString() } }));
      res.end("[]");
    });
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`, seen,
    writes: () => seen.filter((r) => r.method !== "GET"),
    close: () => { server.closeAllConnections?.(); return new Promise((r) => server.close(r)); },
  };
}

async function boot(env = {}) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  __resetSharedLogBudget();
  const gateway = await fakeGateway();
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  Object.assign(process.env, {
    MCP_PORT: String(port), MCP_AUTH_TOKENS: STATIC, MCP_REQUIRE_AUTH: "1", MCP_TOKEN_SIGNING_SECRET: SECRET, MCP_STATE_DIR: mkdtempSync(path.join(tmpdir(), "byo-")),
    CLOCKCHAIN_ENDPOINT: gateway.url, CLOCKCHAIN_SUBSTRATE: "anchoring-gateway", CLOCKCHAIN_API_KEY: "delegated-key", CLOCKCHAIN_CLIENT_ID: DELEGATED, CLOCKCHAIN_WALLET_ID: DELEGATED, CLOCKCHAIN_SIGNING_SECRET: "gateway-secret", STANDALONE_CLOCK_RESYNC_MS: "0",
  }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`, gateway,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      await gateway.close();
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __resetSharedLogBudget();
    },
  };
}

async function rpc(base, method, params, headers, p = "/mcp") {
  const r = await fetch(`${base}${p}`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const text = await r.text();
  let body;
  try { body = r.headers.get("content-type")?.includes("json") ? JSON.parse(text) : JSON.parse(text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).pop()); } catch { body = text; }
  return { status: r.status, body, text, session: r.headers.get("mcp-session-id") };
}
const call = (base, name, args, headers, p) => rpc(base, "tools/call", { name, arguments: args }, headers, p);

/** Valid-looking arguments from a tool's own input schema, so the call gets past validation to the gate. */
function argsFor(tool) {
  const fill = (s) => {
    if (s?.enum) return s.enum[0];
    if (s?.pattern === "^0x[0-9a-f]{130}$") return `0x${"a".repeat(130)}`;
    if (s?.anyOf) return fill(s.anyOf[0]);
    switch (s?.type) {
      case "number": case "integer": return Math.max(1, s.minimum ?? 1);
      case "boolean": return true;
      case "array": return Array.from({ length: Math.max(1, s.minItems ?? 1) }, () => fill(s.items));
      case "object": return Object.fromEntries((s.required ?? []).map((k) => [k, fill(s.properties?.[k])]));
      default: return s?.format === "date-time" ? new Date().toISOString() : "x".repeat(Math.max(1, s?.minLength ?? 1));
    }
  };
  return fill(tool.inputSchema);
}

const BYO_HEADERS = [
  { "x-api-key": "made-up-key-never-issued" },
  { "x-api-key": "made-up-key-never-issued", "x-clockchain-client-id": FOUNDER, "x-clockchain-wallet-id": FOUNDER },
  { "x-clockchain-api-key": "made-up-key-never-issued" },
  { "x-clockchain-api-key": "made-up-key-never-issued", "x-clockchain-client-id": FOUNDER, "x-clockchain-wallet-id": FOUNDER },
  // A valid token doesn't lend its standing to a caller's own key: x-clockchain-api-key takes the BYO path.
  { "x-api-key": STATIC, "x-clockchain-api-key": "made-up-key-never-issued", "x-clockchain-client-id": FOUNDER },
];
const REFUSED = /"error":"BYO_WRITE_REFUSED"/;

test("a caller's own key: zero writes from every write tool, via x-api-key and x-clockchain-api-key, with spoofed client ids", async () => {
  const s = await boot();
  try {
    const tools = (await rpc(s.url, "tools/list", {}, BYO_HEADERS[0])).body.result.tools;
    assert.equal(tools.length, 50, "tools/list is unaffected");
    const writeTools = tools.filter((t) => !BYO_READ_TOOLS.has(t.name));
    assert.ok(writeTools.length >= 20);
    for (const name of ["log_action", "attest_action", "complete_attestation", "mint_identity", "revoke_identity", "delegate_authority", "stopwatch_start", "stopwatch_stop", "timer_set", "alarm_set", "timer_cancel", "tsa_issue", "tsa_checkpoint", "tsa_attest", "tsa_settle", "create_schedule", "handshake_join", "handshake_submit", "agent_handshake_invite", "agent_handshake_submit"]) {
      assert.ok(writeTools.some((t) => t.name === name), `${name} is treated as a write`);
    }
    let refused = 0;
    for (const headers of BYO_HEADERS) {
      for (const tool of writeTools) {
        const r = await call(s.url, tool.name, argsFor(tool), headers);
        assert.equal(r.status, 200, tool.name);
        assert.equal(r.body.result?.isError, true, `${tool.name}: ${r.text.slice(0, 200)}`);
        if (REFUSED.test(r.body.result.content[0].text)) {
          refused++;
          assert.match(r.body.result.content[0].text, /can't write on this server, so nothing was written\. Get a free key with POST \/token, or sign in/);
        }
      }
    }
    assert.equal(s.gateway.writes().length, 0, JSON.stringify(s.gateway.writes().slice(0, 3)));
    assert.equal(refused, writeTools.length * BYO_HEADERS.length, "every call was refused at the gate, not by a later failure");
    // Refused before any network call, not just before the write.
    const before = s.gateway.seen.length;
    const log = await call(s.url, "log_action", { content: "x", asset_reference_id: "demo" }, BYO_HEADERS[1]);
    assert.match(log.text, /BYO_WRITE_REFUSED/);
    assert.equal(s.gateway.seen.length, before);
  } finally {
    await s.close();
  }
});

test("a caller's own key still reads, under its own key, and every listed read tool exists", async () => {
  const s = await boot();
  try {
    const tools = (await rpc(s.url, "tools/list", {}, BYO_HEADERS[3])).body.result.tools;
    const names = new Set(tools.map((t) => t.name));
    for (const name of BYO_READ_TOOLS) assert.ok(names.has(name), `${name} is a real tool`);
    for (const tool of tools.filter((t) => BYO_READ_TOOLS.has(t.name))) {
      const r = await call(s.url, tool.name, argsFor(tool), BYO_HEADERS[3]);
      assert.doesNotMatch(r.text, /BYO_WRITE_REFUSED|ReadOnly|can't write on this server/, tool.name);
    }
    assert.equal(s.gateway.writes().filter((w) => w.path !== "/api/contract/estimate" && w.path !== "/verifyAsset").length, 0);
    const time = await call(s.url, "get_time", {}, BYO_HEADERS[3]);
    assert.notEqual(time.body.result?.isError, true, time.text.slice(0, 200));
    assert.ok(s.gateway.seen.some((r) => r.path === "/getTime" && r.key === "made-up-key-never-issued"), "the read used the caller's key");
    await call(s.url, "search_actions", { asset_reference_id: "demo" }, BYO_HEADERS[3]);
    assert.ok(s.gateway.seen.some((r) => r.path === "/searchAsset"));
  } finally {
    await s.close();
  }
});

test("the client itself refuses, as the backstop: a new tool that writes through it can't miss this", async () => {
  const g = await fakeGateway();
  try {
    const client = new ClockchainClient({ apiKey: "k", clientId: FOUNDER, walletId: FOUNDER, endpoint: g.url, readOnly: true });
    const refused = (e) => e instanceof ReadOnlyClientError;
    await assert.rejects(client.log({ assetHash: "a".repeat(64), assetReferenceId: "r" }), refused);
    await assert.rejects(client.attestAction({ action: "x", agent_id: "a" }), refused);
    await assert.rejects(client.mintIdentity({ owner: "o", agent_id: "a" }).then((v) => v), refused);
    await assert.rejects(client.revokeIdentity("did:x"), refused);
    await assert.rejects(client.delegateAuthority({ from: "a", to: "b", scope: "s", delegator: "a", delegate: "b" }), refused);
    await assert.rejects(client.scheduleContract({ contractName: "c" }, { nonce: 1, signature: "s" }), refused);
    assert.equal(g.seen.length, 0);
    await client.searchAsset("r");
    assert.equal(g.seen.length, 1);
    assert.equal(g.seen[0].method, "GET");
    assert.equal(onOwnedGateway({ endpoint: "https://node.clockchain.network" }), false);
    assert.equal(onOwnedGateway({ endpoint: "http://127.0.0.1:1" }), true);
    assert.equal(onOwnedGateway({ endpoint: "http://127.0.0.1:1", substrate: "clockchain-network" }), false);
    assert.equal(onOwnedGateway({ endpoint: "https://node.clockchain.network", substrate: "anchoring-gateway" }), true);
  } finally {
    await g.close();
  }
});

test("signed tokens, OAuth tokens and MCP_AUTH_TOKENS still write, under the delegated client and inside the budget, whatever client id they name", async () => {
  const s = await boot({ MCP_LOG_BUDGET: "3" });
  try {
    const free = (await (await fetch(`${s.url}/token`, { method: "POST" })).json()).token;
    const oauth = mintToken(SECRET, 3600, Math.floor(Date.now() / 1000), undefined, "11111111-1111-4111-8111-111111111111", "acct_AAAAAAAAAAAAAAAAAAAAAA").token;
    const delegated = [{ "x-api-key": free }, { authorization: `Bearer ${oauth}` }, { "x-api-key": STATIC, "x-clockchain-client-id": FOUNDER, "x-clockchain-wallet-id": FOUNDER }];
    for (const [i, headers] of delegated.entries()) {
      const r = await call(s.url, "log_action", { content: `delegated ${i}`, asset_reference_id: `demo-${i}` }, headers);
      assert.notEqual(r.body.result?.isError, true, r.text.slice(0, 300));
    }
    const writes = s.gateway.writes();
    assert.equal(writes.length, 3);
    for (const w of writes) {
      assert.equal(w.key, "delegated-key");
      assert.equal(w.json.clientId, DELEGATED);
    }
    const over = await call(s.url, "log_action", { content: "over", asset_reference_id: "demo-4" }, { "x-api-key": STATIC });
    assert.match(over.text, /budget exhausted/i);
    assert.equal(s.gateway.writes().length, 3, "the budget still holds for them");
  } finally {
    await s.close();
  }
});

test("MCP_BYO_WRITES=allow undoes it, and on a real upstream network a caller's own key writes as it did", async () => {
  for (const env of [{ MCP_BYO_WRITES: "allow" }, { CLOCKCHAIN_SUBSTRATE: "clockchain-network" }]) {
    const s = await boot(env);
    try {
      const r = await call(s.url, "log_action", { content: "mine", asset_reference_id: "demo" }, BYO_HEADERS[3]);
      assert.notEqual(r.body.result?.isError, true, r.text.slice(0, 300));
      const [w] = s.gateway.writes();
      assert.equal(w.key, "made-up-key-never-issued");
      assert.equal(w.json.clientId, FOUNDER);
    } finally {
      await s.close();
    }
  }
  // Any other value of the override refuses.
  const s = await boot({ MCP_BYO_WRITES: "yes" });
  try {
    assert.match((await call(s.url, "log_action", { content: "x", asset_reference_id: "demo" }, BYO_HEADERS[0])).text, /BYO_WRITE_REFUSED/);
    assert.equal(s.gateway.writes().length, 0);
  } finally {
    await s.close();
  }
});

// /next/* reaches this server with the prefix stripped, so /next/handshake/mcp is /handshake/mcp here. /acm4/* is another
// container running a frozen image (Caddyfile), so this build doesn't serve it, and the catch-all below answers as /mcp.
const FROZEN_ROUTES = ["/handshake/mcp", "/connect/mcp", "/contract/mcp"];
const FROZEN_ENV = (dir) => ({
  HANDSHAKE_RELAY: "http://127.0.0.1:9", EVM_RPC_URL: "http://127.0.0.1:9",
  AGENT_HANDSHAKE_RELEASE_PIN: JSON.stringify({ version: "2.1.8", sourceCommit: "a".repeat(40), manifestDigest: "b".repeat(64), allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/", hostRoots: [{ kid: "root-test", fingerprint: "c".repeat(64) }] }),
  AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE: JSON.stringify({ kid: "access-active", secretBase64: Buffer.alloc(32, 1).toString("base64") }),
  AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE: JSON.stringify({ kid: "hmac-active", secretBase64: Buffer.alloc(32, 2).toString("base64") }),
  AGENT_HANDSHAKE_V2_STATE_FILE: path.join(dir, "state.json"), AGENT_HANDSHAKE_V2_INVITATION_FILE: path.join(dir, "invitations.json"), AGENT_HANDSHAKE_INVITES_PER_HOUR: "1000", AGENT_HANDSHAKE_CALLS_PER_MINUTE: "10000",
  CONTRACT_MCP_ENABLED: "1", CONTRACT_AUTH_TOKENS: "tb1:buyer:kb1:9452:initiator,tp1:provider:kp1:9453:responder", CONTRACT_SERVER_ED25519_SEED: Buffer.alloc(32, 7).toString("base64"), CONTRACT_SERVER_KEY_ID: "contract-server-byo", CONTRACT_SERVER_KEY_VALID_FROM: "2020-01-01T00:00:00Z", CONTRACT_POLICY_DIGESTS: `buyer:0x${"a".repeat(64)},provider:0x${"b".repeat(64)}`, CONTRACT_STATE_DIR: path.join(dir, "contract"),
});
ENV_KEYS.push(...Object.keys(FROZEN_ENV("")));

/** What each frozen route answers a caller sending its own key, with this configuration of the refusal. */
async function frozenAnswers(env) {
  const s = await boot({ ...FROZEN_ENV(mkdtempSync(path.join(tmpdir(), "byo-frozen-"))), ...env });
  // Anything that varies by run: ports, ids, times, signatures.
  const scrub = (t) => String(t).replaceAll(s.url, "U").replace(/\b[0-9a-f]{8}-[0-9a-f-]{27}\b|\bcc[a-z]*_[\w-]+|[A-Za-z0-9_-]{32,}|\d{4}-\d\d-\d\dT[\d:.]+Z|\b\d{10,}\b/g, "X");
  const answers = {};
  try {
    const byo = [{}, { "x-clockchain-api-key": "made-up-key-never-issued", "x-clockchain-client-id": FOUNDER, "x-clockchain-wallet-id": FOUNDER }, { "x-api-key": "made-up-key-never-issued" }];
    for (const p of FROZEN_ROUTES) {
      for (const [h, headers] of byo.entries()) {
        for (const auth of p === "/contract/mcp" ? [{}, { authorization: "Bearer tb1" }] : [{}]) {
          const init = await rpc(s.url, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } }, { ...headers, ...auth }, p);
          const session = init.session ? { "mcp-session-id": init.session } : {};
          if (init.session) await fetch(`${s.url}${p}`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers, ...auth, ...session }, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
          const listed = await rpc(s.url, "tools/list", {}, { ...headers, ...auth, ...session }, p);
          answers[`${p} ${h} ${auth.authorization ?? ""} init`] = `${init.status} ${scrub(init.text)}`;
          answers[`${p} ${h} ${auth.authorization ?? ""} list`] = `${listed.status} ${scrub(listed.text)}`;
          for (const tool of listed.body?.result?.tools ?? []) {
            const r = await call(s.url, tool.name, argsFor(tool), { ...headers, ...auth, ...session }, p);
            assert.doesNotMatch(r.text, /BYO_WRITE_REFUSED|ReadOnly|can't write on this server/, `${p} ${tool.name}`);
            answers[`${p} ${h} ${auth.authorization ?? ""} ${tool.name}`] = `${r.status} ${r.body?.result?.isError === true}`;
          }
        }
      }
    }
    const noCreds = await rpc(s.url, "initialize", {}, {});
    answers["POST /mcp with no credentials"] = `${noCreds.status} ${noCreds.text}`;
    assert.equal(noCreds.status, 401);
    const seenKeys = new Set(s.gateway.seen.map((r) => r.key));
    assert.ok(!seenKeys.has("made-up-key-never-issued"), "a frozen route never used the caller's key");
    assert.ok(s.gateway.seen.some((r) => r.key === "delegated-key"), "a frozen route reached the gateway, with the delegated key");
    const routed = await call(s.url, "log_action", { content: "x", asset_reference_id: "demo" }, BYO_HEADERS[1]);
    return { answers, tools: Object.keys(answers).length, refused: /BYO_WRITE_REFUSED/.test(routed.text) };
  } finally {
    await s.close();
  }
}

test("frozen routes and the 401 answer the same with the refusal on or off, and use the delegated key", async () => {
  const on = await frozenAnswers({});
  const off = await frozenAnswers({ MCP_BYO_WRITES: "allow" });
  assert.equal(on.refused, true, "the refusal really was on in the first run");
  assert.equal(off.refused, false, "and really was off in the second");
  assert.ok(on.tools > 100, `${on.tools} answers compared`);
  for (const route of FROZEN_ROUTES) assert.ok(Object.keys(on.answers).some((k) => k.startsWith(route) && !/ (init|list)$/.test(k)), `${route} served tools`);
  assert.deepEqual(on.answers, off.answers);
});

test("only the bring-your-own server is read-only: the frozen routes' clients are built from the environment, which can't set it", () => {
  const src = path.join(here, "..", "src");
  const sets = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const f = path.join(d, e.name);
      if (e.isDirectory()) walk(f);
      else if (f.endsWith(".ts") && /\.\.\.\w+,\s*readOnly\s*:\s*true\b/.test(readFileSync(f, "utf8"))) sets.push(path.relative(src, f));
    }
  };
  walk(src);
  assert.deepEqual(sets, ["server.ts"]);
  for (const f of ["standalone-handshake/coordinator.ts", "agent-handshake/v2/coordinator.ts", "agent-contract/config.ts", "shadow/ledger.ts", "keeper-runtime.ts"]) {
    assert.match(readFileSync(path.join(src, f), "utf8"), /new ClockchainClient\(readConfigFromEnv\(/, f);
  }
  assert.equal(readConfigFromEnv({ CLOCKCHAIN_API_KEY: "k", CLOCKCHAIN_CLIENT_ID: "c", CLOCKCHAIN_WALLET_ID: "w", CLOCKCHAIN_READ_ONLY: "1", MCP_BYO_WRITES: "refuse" }).readOnly, undefined);
});

test("any other path on this server is the same /mcp handler, so it refuses too", async () => {
  const s = await boot();
  try {
    for (const p of ["/acm4/mcp", "/next/mcp", "/anything"]) {
      assert.match((await call(s.url, "log_action", { content: "x", asset_reference_id: "demo" }, BYO_HEADERS[1], p)).text, /BYO_WRITE_REFUSED/, p);
    }
    assert.equal(s.gateway.writes().length, 0);
  } finally {
    await s.close();
  }
});

test("the install text doesn't promise a caller's own key can write here", () => {
  const landing = (env) => {
    const run = spawnSync(process.execPath, ["--input-type=module", "-e", `const l = await import(${JSON.stringify(path.join(here, "..", "dist", "landing.js"))}); console.log(JSON.stringify({ t: l.INSTALL_TXT, m: l.MCP_MANIFEST, h: l.LANDING_HTML }));`], { env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    return JSON.parse(run.stdout);
  };
  const owned = landing({ CLOCKCHAIN_SUBSTRATE: "anchoring-gateway" });
  const all = JSON.stringify(owned);
  assert.doesNotMatch(all, /writes spend your credits|writes spend YOUR/);
  assert.match(owned.t, /reads only here;\s+to write, use a token/);
  assert.match(owned.m.authentication.methods[1].note, /reads only here; to write, use a token from POST \/token/);
  assert.match(owned.h, /reads only here/);
  for (const env of [{ CLOCKCHAIN_SUBSTRATE: "clockchain-network" }, { CLOCKCHAIN_SUBSTRATE: "anchoring-gateway", MCP_BYO_WRITES: "allow" }]) {
    const other = landing(env);
    assert.match(other.t, /writes spend YOUR\s+credits/);
    assert.match(other.m.authentication.methods[1].note, /writes spend your credits/);
  }
});
