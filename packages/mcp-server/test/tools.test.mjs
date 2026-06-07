// Offline tests for the MCP tool layer. Drives the real handlers from
// registerTools() via a fake server; global fetch is stubbed (no network).
// Run: node --test (from packages/mcp-server) or npm test (workspace root).
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerTools } from "../dist/tools.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

// Collect the handlers registerTools() registers, keyed by tool name.
function collectTools() {
  const tools = {};
  const fakeServer = {
    registerTool: (name, _cfg, handler) => {
      tools[name] = handler;
    },
  };
  registerTools(fakeServer, cfg);
  return tools;
}

const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");

// Route the stubbed fetch by URL substring -> { status?, body }.
function routeFetch(routes) {
  globalThis.fetch = async (url) => {
    for (const [match, resp] of routes) {
      if (String(url).includes(match)) {
        const raw = typeof resp.body === "string" ? resp.body : JSON.stringify(resp.body);
        const status = resp.status ?? 200;
        return { status, ok: status >= 200 && status < 300, statusText: "stub", text: async () => raw };
      }
    }
    throw new Error("no stubbed route for " + url);
  };
}

test("get_time returns unwrapped data, not an error", async () => {
  routeFetch([["/api/time/time", { body: { success: true, data: { latestBlockTime: "t", latestBlockHeight: "9" } } }]]);
  const res = await collectTools().get_time({});
  assert.ok(!res.isError);
  assert.deepEqual(JSON.parse(textOf(res)), { latestBlockTime: "t", latestBlockHeight: "9" });
});

test("get_time maps 429 to an actionable rate-limit error", async () => {
  routeFetch([["/api/time/time", { status: 429, body: { message: "slow" } }]]);
  const res = await collectTools().get_time({});
  assert.equal(res.isError, true);
  assert.match(textOf(res), /rate limit/i);
});

test("log_action with wait=true polls until blockHeight populates", async () => {
  routeFetch([
    ["/log", { body: { ledgerId: "L1", blockHeight: null, assetHash: "h" } }],
    ["/ledger/", { body: { ledgerId: "L1", blockHeight: "777", assetHash: "h", assetReferenceId: "r" } }],
  ]);
  const res = await collectTools().log_action({ asset_hash: "h", asset_reference_id: "r", wait: true, wait_ms: 5000 });
  assert.ok(!res.isError);
  assert.equal(JSON.parse(textOf(res)).blockHeight, "777");
});

test("log_action without wait returns the pending record (blockHeight null)", async () => {
  routeFetch([["/log", { body: { ledgerId: "L2", blockHeight: null, assetHash: "h" } }]]);
  const res = await collectTools().log_action({ asset_hash: "h", asset_reference_id: "r" });
  const out = JSON.parse(textOf(res));
  assert.equal(out.ledgerId, "L2");
  assert.equal(out.blockHeight, null);
});

test("log_action folds a DID into the reference id", async () => {
  let sentBody = null;
  routeFetch([["/log", { body: { ledgerId: "L4", blockHeight: null } }]]);
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    sentBody = JSON.parse(opts.body);
    return origFetch(url, opts);
  };
  await collectTools().log_action({ asset_hash: "h", asset_reference_id: "r", did: "did:x:1" });
  assert.equal(sentBody.assetReferenceId, "did:x:1:r");
});

test("verify_asset reports match true and false", async () => {
  routeFetch([["/ledger/", { body: { ledgerId: "L3", blockHeight: "5", assetHash: "abc", assetReferenceId: "r" } }]]);
  const tools = collectTools();
  assert.equal(JSON.parse(textOf(await tools.verify_asset({ ledger_id: "L3", current_hash: "abc" }))).match, true);
  assert.equal(JSON.parse(textOf(await tools.verify_asset({ ledger_id: "L3", current_hash: "zzz" }))).match, false);
});

test("insufficient credits surfaces an actionable message", async () => {
  routeFetch([["/log", { status: 400, body: { message: "No enough tokens to facilitate this logging" } }]]);
  const res = await collectTools().log_action({ asset_hash: "h", asset_reference_id: "r" });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /credit/i);
});

test("resolve_agent returns status unknown when ERC-8004 is unconfigured", async () => {
  const res = await collectTools().resolve_agent({ agent_id: "a1" });
  assert.equal(JSON.parse(textOf(res)).status, "unknown");
});

test("get_block returns the block data", async () => {
  routeFetch([["/api/time/block", { body: { success: true, data: { height: "5", proposer: "p" } } }]]);
  const res = await collectTools().get_block({ height: 5 });
  assert.deepEqual(JSON.parse(textOf(res)), { height: "5", proposer: "p" });
});

test("get_validation returns validation data", async () => {
  routeFetch([["/getValidationBlock", { body: { validationBlockData: { height: 5, trust: 0 } } }]]);
  const res = await collectTools().get_validation({ height: 5 });
  assert.deepEqual(JSON.parse(textOf(res)), { height: 5, trust: 0 });
});

test("get_timestamp returns consensus detail", async () => {
  routeFetch([["/api/time/timestamp", { body: { success: true, data: { votes: 0 } } }]]);
  const res = await collectTools().get_timestamp({});
  assert.deepEqual(JSON.parse(textOf(res)), { votes: 0 });
});

test("search_actions returns the array", async () => {
  routeFetch([["/searchAsset", { body: [{ ledgerId: "L" }] }]]);
  const res = await collectTools().search_actions({ asset_reference_id: "r" });
  assert.deepEqual(JSON.parse(textOf(res)), [{ ledgerId: "L" }]);
});

test("get_log_entry returns the record", async () => {
  routeFetch([["/ledger/", { body: { ledgerId: "L9", blockHeight: "5" } }]]);
  const res = await collectTools().get_log_entry({ ledger_id: "L9" });
  assert.equal(JSON.parse(textOf(res)).ledgerId, "L9");
});

test("log_action honors MCP_LOG_BUDGET cap across calls", async () => {
  routeFetch([["/log", { body: { ledgerId: "LB", blockHeight: null } }]]);
  const prev = process.env.MCP_LOG_BUDGET;
  process.env.MCP_LOG_BUDGET = "1";
  try {
    const tools = collectTools(); // budget bound at registration time
    const first = await tools.log_action({ asset_hash: "h", asset_reference_id: "r1" });
    assert.ok(!first.isError, "first write within budget");
    const second = await tools.log_action({ asset_hash: "h", asset_reference_id: "r2" });
    assert.equal(second.isError, true, "second write exceeds budget");
    assert.match(textOf(second), /budget/i);
  } finally {
    if (prev === undefined) delete process.env.MCP_LOG_BUDGET;
    else process.env.MCP_LOG_BUDGET = prev;
  }
});
