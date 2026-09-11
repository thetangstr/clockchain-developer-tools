// Offline tests for the verified-time stopwatch tools (clock-sdk GATES.md G1,
// re-pointed at the MCP tools). Drives the real handlers via a fake server with
// a routed fetch stub — no network. Mirrors tools.test.mjs conventions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerTools } from "../dist/tools.js";
import { __resetSharedLogBudget } from "../dist/budget.js";
import { __resetIdempotency } from "../dist/idempotency.js";
import { FREE_TOOLS } from "../dist/entitlement.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

function collectTools() {
  const tools = {};
  registerTools({ registerTool: (name, _c, handler) => { tools[name] = handler; } }, cfg);
  return tools;
}
const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");
const json = (res) => JSON.parse(textOf(res));

// The live gateway shape (2026-09): ISO times, string heights, `nodeParticipation`.
const HEALTHY_GETTIME = {
  success: true,
  data: { blockHeight: "147", madMarzulloTime: "2026-09-10T23:32:01.212Z", totalNodes: 1, nodeParticipation: 100, votes: 1 },
};
const START_TS = "2026-09-10T23:32:01.362Z";
const STOP_TS = "2026-09-10T23:32:07.521Z"; // 6159 ms later (the measured G1 figure)

// Route by URL substring; each route may be a function of (url, init) so a
// single path (/ledger/) can answer differently per ledgerId.
function routeFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method ?? "GET", headers: init?.headers ?? {} });
    for (const [match, resp] of routes) {
      if (String(url).includes(match)) {
        const r = typeof resp === "function" ? resp(String(url), init) : resp;
        const raw = typeof r.body === "string" ? r.body : JSON.stringify(r.body);
        const status = r.status ?? 200;
        // request() reads text(); keylessRequest() (chain reads) uses json().
        return { status, ok: status >= 200 && status < 300, statusText: "stub", text: async () => raw, json: async () => JSON.parse(raw) };
      }
    }
    if (String(url).includes("/getTime")) {
      const raw = JSON.stringify(HEALTHY_GETTIME);
      return { status: 200, ok: true, statusText: "stub", text: async () => raw, json: async () => JSON.parse(raw) };
    }
    throw new Error("no stubbed route for " + url);
  };
  return calls;
}

const startRecord = (blockHeight = "148") => ({
  ledgerId: "L_START", blockHeight, createdTimestamp: START_TS, assetHash: "a".repeat(64), assetReferenceId: "stopwatch:build:start",
});
const stopRecord = (blockHeight = "149") => ({
  ledgerId: "L_STOP", blockHeight, createdTimestamp: STOP_TS, assetHash: "b".repeat(64), assetReferenceId: "stopwatch:build:stop",
});

test.beforeEach(() => {
  __resetSharedLogBudget();
  __resetIdempotency();
});

test("stopwatch tools are registered on the full surface and classified free", () => {
  const tools = collectTools();
  for (const n of ["stopwatch_start", "stopwatch_stop", "stopwatch_verify"]) {
    assert.equal(typeof tools[n], "function", `${n} registered`);
    assert.ok(FREE_TOOLS.has(n), `${n} classified in FREE_TOOLS`);
  }
});

test("stopwatch_start anchors stopwatch:<label>:start, waits for the block, returns the marker", async () => {
  const calls = routeFetch([
    ["/log", { body: { ledgerId: "L_START", blockHeight: null, assetHash: "a".repeat(64), assetReferenceId: "stopwatch:build:start" } }],
    ["/ledger/", { body: startRecord() }],
  ]);
  const out = json(await collectTools().stopwatch_start({ label: "build" }));
  assert.equal(out.status, "anchored");
  assert.equal(out.label, "build");
  assert.equal(out.start.ledgerId, "L_START");
  assert.equal(out.start.blockHeight, "148");
  assert.equal(out.start.assetReferenceId, "stopwatch:build:start");
  assert.equal(out.start.epochMs, Date.parse(START_TS), "createdTimestamp parsed to epoch ms");
  assert.match(out.next, /stopwatch_stop/);
  // Exactly one write, with the SDK's reference-id convention.
  const logCall = calls.find((c) => c.url.includes("/log") && c.method === "POST");
  assert.ok(logCall, "one /log write");
});

test("stopwatch_start: a start marker that never lands a block is PENDING, never success", async () => {
  routeFetch([
    ["/log", { body: { ledgerId: "L_START", blockHeight: null } }],
    ["/ledger/", { body: startRecord(null) }],
  ]);
  const out = json(await collectTools().stopwatch_start({ label: "build", wait_ms: 10 }));
  assert.equal(out.status, "pending");
  assert.match(out.warning, /PENDING/);
});

test("stopwatch_start is refused on a degraded pool unless allow_degraded", async () => {
  routeFetch([
    ["/getTime", { body: { success: true, data: { totalNodes: 1, nodeParticipation: 0, blockHeight: "1", madMarzulloTime: "t" } } }],
    ["/log", { body: { ledgerId: "L_START", blockHeight: "1" } }],
    ["/ledger/", { body: startRecord("1") }],
  ]);
  const tools = collectTools();
  const refused = await tools.stopwatch_start({ label: "build" });
  assert.equal(refused.isError, true);
  assert.match(textOf(refused), /degraded/i);
  const allowed = await tools.stopwatch_start({ label: "build", allow_degraded: true });
  assert.ok(!allowed.isError);
});

test("stopwatch_stop re-reads the start marker from the ledger and reports elapsed between consensus timestamps", async () => {
  routeFetch([
    ["/log", { body: { ledgerId: "L_STOP", blockHeight: null, assetHash: "b".repeat(64), assetReferenceId: "stopwatch:build:stop" } }],
    ["/ledger/L_START", { body: startRecord() }],
    ["/ledger/L_STOP", { body: stopRecord() }],
  ]);
  const out = json(await collectTools().stopwatch_stop({ label: "build", start_ledger_id: "L_START" }));
  assert.equal(out.status, "anchored");
  assert.equal(out.elapsedMs, 6159, "G1.3/G1.4: stop.createdTimestamp − start.createdTimestamp");
  assert.equal(out.start.ledgerId, "L_START");
  assert.equal(out.stop.ledgerId, "L_STOP");
  assert.equal(out.stop.assetReferenceId, "stopwatch:build:stop");
  assert.notEqual(out.start.assetHash, out.stop.assetHash, "G1.6 distinct marker hashes");
  assert.deepEqual(out.verify.start, { ledgerId: "L_START", blockHeight: "148" });
  assert.deepEqual(out.verify.stop, { ledgerId: "L_STOP", blockHeight: "149" });
});

test("stopwatch_stop rejects a start_ledger_id that is not this label's start marker", async () => {
  routeFetch([
    ["/ledger/L_OTHER", { body: { ...startRecord(), ledgerId: "L_OTHER", assetReferenceId: "invoice-42" } }],
    ["/log", { body: { ledgerId: "L_STOP", blockHeight: "149" } }],
  ]);
  const res = await collectTools().stopwatch_stop({ label: "build", start_ledger_id: "L_OTHER" });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /not the start marker "stopwatch:build:start"/);
});

test("stopwatch_stop: measurement is not 'anchored' when the start marker is still pending", async () => {
  routeFetch([
    ["/log", { body: { ledgerId: "L_STOP", blockHeight: null } }],
    ["/ledger/L_START", { body: startRecord(null) }],
    ["/ledger/L_STOP", { body: stopRecord("149") }],
  ]);
  const out = json(await collectTools().stopwatch_stop({ label: "build", start_ledger_id: "L_START" }));
  assert.equal(out.status, "pending", "G1.1: a null start height is a failed anchor, not a measurement");
  assert.equal(out.stop.blockHeight, "149");
  assert.equal(out.elapsedMs, 6159, "elapsed is still reported, but not as verified");
});

test("stopwatch_verify recomputes elapsed from the two immutable block times, keylessly", async () => {
  const calls = routeFetch([
    ["/searchAssetFromChain?blockHeight=148", { body: { blockHeight: "148", proposerAddress: "0xp", blockTime: START_TS, transactions: [`ledgerId=L_START,assetHash=${"a".repeat(64)},assetReferenceId=stopwatch:build:start`] } }],
    ["/searchAssetFromChain?blockHeight=149", { body: { blockHeight: "149", proposerAddress: "0xp", blockTime: STOP_TS, transactions: [`ledgerId=L_STOP,assetHash=${"b".repeat(64)},assetReferenceId=stopwatch:build:stop`] } }],
    ["/api/time/block?height=148", { body: { success: true, data: { blockHeight: 148, proposerAddress: "0xp", blockTime: START_TS } } }],
    ["/api/time/block?height=149", { body: { success: true, data: { blockHeight: 149, proposerAddress: "0xp", blockTime: STOP_TS } } }],
    ["/ledger/L_START", { body: startRecord() }],
    ["/ledger/L_STOP", { body: stopRecord() }],
  ]);
  const out = json(await collectTools().stopwatch_verify({
    start_ledger_id: "L_START", stop_ledger_id: "L_STOP", start_block_height: "148", stop_block_height: "149",
  }));
  assert.equal(out.verified, true);
  assert.equal(out.keyless, true);
  assert.equal(out.elapsedOnChainMs, 6159, "difference of the two block times");
  assert.equal(out.elapsedRecordedMs, 6159, "advisory: difference of the cached createdTimestamps");
  assert.equal(out.start.verifiedAgainst, "on-chain block");
  assert.equal(out.stop.verifiedAgainst, "on-chain block");
  assert.equal(out.start.anchoredHash, "a".repeat(64));
  // The chain reads send NO api key (keyless present-and-verify).
  const chainCalls = calls.filter((c) => c.url.includes("/searchAssetFromChain"));
  assert.ok(chainCalls.length >= 2);
  for (const c of chainCalls) {
    const h = Object.fromEntries(Object.entries(c.headers).map(([k, v]) => [k.toLowerCase(), v]));
    assert.equal(h["x-api-key"], undefined, "chain verification must not send the api key");
  }
});

test("stopwatch_verify is NOT verified when a marker is missing from its block or blocks are out of order", async () => {
  // Stop marker absent from block 149 -> verifiedAgainst "none".
  routeFetch([
    ["/searchAssetFromChain?blockHeight=148", { body: { blockHeight: "148", blockTime: START_TS, transactions: [`ledgerId=L_START,assetHash=${"a".repeat(64)},assetReferenceId=stopwatch:build:start`] } }],
    ["/searchAssetFromChain?blockHeight=149", { body: { blockHeight: "149", blockTime: STOP_TS, transactions: [] } }],
    ["/api/time/block", { body: { success: true, data: { blockHeight: 148, proposerAddress: "0xp", blockTime: START_TS } } }],
    ["/ledger/", { body: startRecord() }],
  ]);
  const out = json(await collectTools().stopwatch_verify({
    start_ledger_id: "L_START", stop_ledger_id: "L_STOP", start_block_height: "148", stop_block_height: "149",
  }));
  assert.equal(out.verified, false);
  assert.equal(out.stop.verifiedAgainst, "none");
  assert.match(out.note, /Not verified/);
});
