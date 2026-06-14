// Offline tests for the MCP tool layer. Drives the real handlers from
// registerTools() via a fake server; global fetch is stubbed (no network).
// Run: node --test (from packages/mcp-server) or npm test (workspace root).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { registerTools } from "../dist/tools.js";
import { __resetSharedLogBudget } from "../dist/budget.js";
import { __resetIdempotency } from "../dist/idempotency.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };
// A valid 64-char hex SHA-256 digest for log_action tests. The value is irrelevant
// to the stubbed gateway; it just has to pass asset_hash format validation.
const HEX = "a".repeat(64);

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
  routeFetch([["/getTime", { body: { success: true, data: { madMarzulloTime: "t", blockHeight: "9" } } }]]);
  const res = await collectTools().get_time({});
  assert.ok(!res.isError);
  assert.deepEqual(JSON.parse(textOf(res)), { latestBlockTime: "t", latestBlockHeight: "9" });
});

test("get_time maps 429 to an actionable rate-limit error", async () => {
  routeFetch([["/getTime", { status: 429, body: { message: "slow" } }]]);
  const res = await collectTools().get_time({});
  assert.equal(res.isError, true);
  assert.match(textOf(res), /rate limit/i);
});

test("log_action with wait=true polls until blockHeight populates", async () => {
  routeFetch([
    ["/log", { body: { ledgerId: "L1", blockHeight: null, assetHash: "h" } }],
    ["/ledger/", { body: { ledgerId: "L1", blockHeight: "777", assetHash: "h", assetReferenceId: "r" } }],
  ]);
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r", wait: true, wait_ms: 5000 });
  assert.ok(!res.isError);
  assert.equal(JSON.parse(textOf(res)).blockHeight, "777");
});

test("log_action without wait returns the pending record (blockHeight null)", async () => {
  routeFetch([["/log", { body: { ledgerId: "L2", blockHeight: null, assetHash: "h" } }]]);
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r" });
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
  await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r", did: "did:x:1" });
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
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r" });
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
  routeFetch([["/getTime", { body: { success: true, data: { votes: 0 } } }]]);
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

test("attest_action returns a receipt; verify_receipt confirms it", async () => {
  // event hash for the payload below (recomputed by verify) is whatever the
  // server anchors; stub /log to echo a fixed assetHash and make /ledger match it.
  let anchored = null;
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    const json = (body, status = 200) => ({ status, ok: status < 400, statusText: "stub", text: async () => JSON.stringify(body) });
    if (u.includes("/log")) {
      anchored = JSON.parse(opts.body).assetHash;
      return json({ ledgerId: "LR", assetReferenceId: JSON.parse(opts.body).assetReferenceId, assetHash: anchored, blockHeight: "500", createdTimestamp: "t" });
    }
    if (u.includes("/ledger/")) return json({ ledgerId: "LR", assetHash: anchored, blockHeight: "500", assetReferenceId: "r", createdTimestamp: "t" });
    if (u.includes("/api/time/block")) return json({ success: true, data: { blockHeight: 500, proposerAddress: "0x", blockTime: "2026-06-07T00:00:00Z" } });
    if (u.includes("/getValidationBlock")) return json({ validationBlockData: { blockHeight: 500, positiveVotes: 1, negativeVotes: 0, "Trust value percentage": 0, "Node participation percentage": 0 } });
    throw new Error("no route " + u);
  };
  const tools = collectTools();
  const res = await tools.attest_action({ agent_id: "agent:bot", action: "execute_trade", inputs: { size: 1 }, outputs: { ok: true } });
  assert.ok(!res.isError, "attest ok");
  const receipt = JSON.parse(textOf(res));
  assert.equal(receipt.schema, "clockchain.receipt/v1");
  assert.equal(receipt.anchor.blockHeight, "500");
  assert.equal(receipt.attestation.status, "single-validator-testnet");

  const vres = await tools.verify_receipt({ receipt });
  assert.ok(!vres.isError, "verify ok");
  assert.equal(JSON.parse(textOf(vres)).match, true);
});

test("log_action honors MCP_LOG_BUDGET cap across calls", async () => {
  routeFetch([["/log", { body: { ledgerId: "LB", blockHeight: null } }]]);
  const prev = process.env.MCP_LOG_BUDGET;
  process.env.MCP_LOG_BUDGET = "1";
  __resetSharedLogBudget(); // process-wide budget: force a re-read of the cap
  try {
    const tools = collectTools(); // budget bound at registration time
    const first = await tools.log_action({ asset_hash: HEX, asset_reference_id: "r1" });
    assert.ok(!first.isError, "first write within budget");
    const second = await tools.log_action({ asset_hash: HEX, asset_reference_id: "r2" });
    assert.equal(second.isError, true, "second write exceeds budget");
    assert.match(textOf(second), /budget/i);
  } finally {
    if (prev === undefined) delete process.env.MCP_LOG_BUDGET;
    else process.env.MCP_LOG_BUDGET = prev;
    __resetSharedLogBudget(); // clean up so later tests get a fresh budget
  }
});

test("log_action hashes raw content server-side (no asset_hash needed)", async () => {
  let sentBody = null;
  routeFetch([["/log", { body: { ledgerId: "LC", blockHeight: null } }]]);
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, opts) => { sentBody = JSON.parse(opts.body); return orig(url, opts); };
  const res = await collectTools().log_action({ content: "hello eval", asset_reference_id: "r" });
  assert.ok(!res.isError);
  assert.equal(sentBody.assetHash, createHash("sha256").update("hello eval").digest("hex"));
  assert.equal(sentBody.hashType, "SHA-256");
});

test("log_action requires content or asset_hash", async () => {
  routeFetch([["/log", { body: { ledgerId: "x" } }]]);
  const res = await collectTools().log_action({ asset_reference_id: "r" });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /content|asset_hash/i);
});

test("log_action with the same idempotency_key hits /log once and replays the result", async () => {
  __resetIdempotency(); // process-wide cache: start clean
  // Count /log hits and return a distinct ledgerId per hit so a replay is detectable.
  let logHits = 0;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes("/log")) {
      logHits++;
      return { status: 200, ok: true, statusText: "stub", text: async () => JSON.stringify({ ledgerId: "L" + logHits, blockHeight: null }) };
    }
    throw new Error("no route " + u);
  };
  const tools = collectTools();

  const a = await tools.log_action({ asset_hash: HEX, asset_reference_id: "r", idempotency_key: "key-1" });
  const b = await tools.log_action({ asset_hash: HEX, asset_reference_id: "r", idempotency_key: "key-1" });
  assert.ok(!a.isError && !b.isError);
  assert.equal(logHits, 1, "same key hits /log only once");
  assert.equal(JSON.parse(textOf(a)).ledgerId, "L1");
  assert.equal(JSON.parse(textOf(b)).ledgerId, "L1", "retry returns the original ledgerId");

  // A different key re-runs the work and hits /log again.
  const c = await tools.log_action({ asset_hash: HEX, asset_reference_id: "r", idempotency_key: "key-2" });
  assert.ok(!c.isError);
  assert.equal(logHits, 2, "a different key hits /log again");
  assert.equal(JSON.parse(textOf(c)).ledgerId, "L2");
});

test("attest_action wait=false submits, complete_attestation polls to confirmed", async () => {
  const tools = collectTools();
  // SUBMIT: wait=false -> only /log is hit, returns a pending receipt.
  routeFetch([["/log", { body: { ledgerId: "LP", assetReferenceId: "ref", blockHeight: null, createdTimestamp: "t" } }]]);
  const subRes = await tools.attest_action({ agent_id: "agent:bot", action: "act", inputs: { a: 1 }, wait: false });
  assert.ok(!subRes.isError, "submit ok");
  const pending = JSON.parse(textOf(subRes));
  assert.equal(pending.anchor.confirmed, false);
  assert.equal(pending.anchor.blockHeight, null);

  // POLL: block has landed -> complete_attestation returns the confirmed receipt.
  routeFetch([
    ["/ledger/", { body: { ledgerId: "LP", assetReferenceId: "ref", blockHeight: "910", createdTimestamp: "t" } }],
    ["/api/time/block", { body: { success: true, data: { blockHeight: 910, proposerAddress: "0x", blockTime: "2026-06-14T00:00:00Z" } } }],
    ["/getValidationBlock", { body: { validationBlockData: { blockHeight: 910, positiveVotes: 1, negativeVotes: 0, "Trust value percentage": 0 } } }],
  ]);
  const compRes = await tools.complete_attestation({ receipt: pending });
  assert.ok(!compRes.isError, "complete ok");
  const done = JSON.parse(textOf(compRes));
  assert.equal(done.anchor.blockHeight, "910");
  assert.equal(done.anchor.confirmed, true);
  assert.equal(done.eventHash, pending.eventHash);
});
