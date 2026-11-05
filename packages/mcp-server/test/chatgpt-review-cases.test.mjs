// The ChatGPT plugin package: it meets the limits in OpenAI's docs, and its test cases run against a local server.
import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runHttp } from "../dist/http.js";
import { __setShadowLedgerForTests } from "../dist/shadow/ledger.js";
import { __resetSharedLogBudget } from "../dist/budget.js";
import { PLUGIN, runCases } from "../../../scripts/chatgpt-review-cases.mjs";
import { signIn, toolCaller, topUpSamples, SAMPLES } from "../../../scripts/seed-reviewer-account.mjs";
import { FakeLedger } from "./helpers/shadow-fake-ledger.mjs";

const plugin = JSON.parse(readFileSync(PLUGIN, "utf8"));
const mcp = JSON.parse(readFileSync(fileURLToPath(new URL("../../../infra/chatgpt-plugin/clockchain-shadow/mcp.json", import.meta.url)), "utf8"));
const openai = plugin.extensions["com.openai"];
const ENV_KEYS = ["PORT", "MCP_PORT", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_TOKEN_SIGNING_SECRET", "MCP_AUTH_TOKENS", "MCP_REQUIRE_AUTH", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "SHADOW_LAZY_AUTH", "SHADOW_AUTO_LOG", "SHADOW_PREVIEW_AUTO_LOG", "MCP_LOG_BUDGET", "MCP_OAUTH_APPROVALS_PER_HOUR"];

async function boot(env = {}) {
  const saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  const fake = new FakeLedger();
  __setShadowLedgerForTests(fake);
  __resetSharedLogBudget();
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  const stateDir = mkdtempSync(path.join(tmpdir(), "review-cases-"));
  const url = `http://127.0.0.1:${port}`;
  Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_TOKEN_SIGNING_SECRET: "review-secret", MCP_STATE_DIR: stateDir, SHADOW_STATE_DIR: path.join(stateDir, "shadow"), MCP_OAUTH: "1", MCP_PUBLIC_URL: url, SHADOW_ENABLED: "1", SHADOW_LAZY_AUTH: "1", MCP_OAUTH_APPROVALS_PER_HOUR: "1000" }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url, fake,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      __setShadowLedgerForTests(undefined);
      __resetSharedLogBudget();
    },
  };
}

test("the package: exactly five and three cases, within the limits, on /shadow/mcp, with no credentials or price wording in it", () => {
  assert.equal(openai.review.test_cases.positive.length, 5);
  assert.equal(openai.review.test_cases.negative.length, 3);
  assert.ok(openai.interface.displayName.length <= 30);
  assert.ok(openai.interface.shortDescription.length <= 30);
  assert.ok(plugin.description.length <= 1024);
  assert.ok(openai.interface.longDescription.length <= 4000);
  assert.equal(mcp.mcpServers["clockchain-shadow"].url, "https://mcp.clockchain.network/shadow/mcp");
  assert.equal(mcp.mcpServers["clockchain-shadow"].extensions["com.openai"].auth.type, "oauth");

  const text = JSON.stringify(plugin);
  for (const banned of ["test_credentials", "reviewer_instructions", "cck_"]) assert.equal(text.includes(banned), false, banned);
  assert.doesNotMatch(text, /\bfree\b|free trial|discount|MCP Server/i);
  assert.doesNotMatch(text, /can't be revoked|cannot be revoked/i, "they can be, now");
  assert.doesNotMatch(text, /without being asked|every step|from any connector/i);
  assert.equal(openai.review.commerce, false);
  assert.equal(existsSync(fileURLToPath(new URL("../../../infra/chatgpt-plugin/clockchain-shadow/assets", import.meta.url))), false, "assets are the founder's to add");
});

test("only what code can't fill is left to fill in", () => {
  const holes = [...JSON.stringify(plugin).matchAll(/\[(FILL IN[^\]]*)\]/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(holes)].sort(), ["FILL IN", "FILL IN: legal entity", "FILL IN: uppercase country codes, after counsel review", "FILL IN: website"]);
});

test("each positive case names only tools that exist on the listed endpoint", async () => {
  const s = await boot();
  try {
    const res = await fetch(`${s.url}/shadow/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}" });
    assert.equal(res.status, 401);
    const a = await signIn(s.url, { name: "Lister" });
    const raw = await fetch(`${s.url}/shadow/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${a.token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
    const text = await raw.text();
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    const names = JSON.parse(data ? data.slice(5) : text).result.tools.map((t) => t.name);
    for (const c of openai.review.test_cases.positive) for (const tool of c.tools_triggered.split(", ")) assert.ok(names.includes(tool), `${c.description}: ${tool}`);
  } finally {
    await s.close();
  }
});

test("all eight cases pass on a local server with the reviewer's samples, and the account is left as it was", async () => {
  const s = await boot();
  try {
    const a = await signIn(s.url, { name: "Directory reviewer" });
    const call = toolCaller(s.url, a.token);
    await topUpSamples(call, { refreshDays: 10 });
    const rows = await runCases(s.url, a.key);
    assert.equal(rows.length, 8);
    assert.deepEqual(rows.filter((r) => r.problem), []);
    assert.deepEqual((await call("shadow_list_sessions")).sessions.map((x) => x.title).sort(), SAMPLES.map((x) => x.title).sort());
  } finally {
    await s.close();
  }
});

test("a server logging by default fails the first negative case: this is what a listed server must not be", async () => {
  const s = await boot({ SHADOW_AUTO_LOG: "1" });
  try {
    const a = await signIn(s.url, { name: "Directory reviewer" });
    await topUpSamples(toolCaller(s.url, a.token), { refreshDays: 10 });
    const rows = await runCases(s.url, a.key);
    const row = rows.find((r) => r.description === "No recording unless asked");
    assert.ok(row.problem);
  } finally {
    await s.close();
  }
});
