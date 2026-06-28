// AGE-193 — "never report success on an un-anchored fire" (MCP tool layer).
// Drives the real handlers from registerTools() via a fake server; global fetch
// is stubbed (no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerTools } from "../dist/tools.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };
const HEX = "a".repeat(64);

function collectTools() {
  const tools = {};
  registerTools({ registerTool: (name, _c, handler) => { tools[name] = handler; } }, cfg);
  return tools;
}

const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");

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

const gettime = (participationPct) => [
  "/getTime",
  { body: { success: true, data: { "nodeParticipation%": participationPct, totalNodes: 1, blockHeight: "1", madMarzulloTime: "t" } } },
];

test("pool-health guard REFUSES a write at 0% participation (no allow_degraded)", async () => {
  // Only /getTime is routed — if the guard works, /log is never reached.
  routeFetch([gettime(0)]);
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r" });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /degraded|participation/i);
  assert.match(textOf(res), /allow_degraded/i);
});

test("pool-health guard ALLOWS the write at 0% participation when allow_degraded=true", async () => {
  routeFetch([gettime(0), ["/log", { body: { ledgerId: "LD", blockHeight: null } }]]);
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r", allow_degraded: true });
  assert.ok(!res.isError, "degraded write proceeds when explicitly allowed");
  assert.equal(JSON.parse(textOf(res)).ledgerId, "LD");
});

test("okWrite emits a PENDING note + status when a write is not anchored", async () => {
  routeFetch([gettime(100), ["/log", { body: { ledgerId: "LP", blockHeight: null } }]]);
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r" });
  assert.ok(!res.isError);
  const out = JSON.parse(textOf(res));
  assert.equal(out.status, "pending");
  assert.match(out.warning, /PENDING — not yet anchored/);
  assert.match(out.warning, /get_log_entry|complete_attestation/);
});

test("okWrite reports status=anchored with NO warning once the block lands", async () => {
  routeFetch([
    gettime(100),
    ["/log", { body: { ledgerId: "LA", blockHeight: null } }],
    ["/ledger/", { body: { ledgerId: "LA", blockHeight: "777", assetHash: "h", assetReferenceId: "r" } }],
  ]);
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r", wait: true, wait_ms: 5000 });
  assert.ok(!res.isError);
  const out = JSON.parse(textOf(res));
  assert.equal(out.status, "anchored");
  assert.equal(out.warning, undefined);
});

test("attest_action is refused on a degraded pool unless allow_degraded", async () => {
  routeFetch([gettime(0)]);
  const refused = await collectTools().attest_action({ agent_id: "a", action: "x", inputs: { a: 1 } });
  assert.equal(refused.isError, true);
  assert.match(textOf(refused), /degraded|participation/i);
});

test("identity write surfaces anchorStatus + PENDING warning when not yet anchored", async () => {
  routeFetch([gettime(100), ["/log", { body: { ledgerId: "LM", blockHeight: null } }]]);
  const res = await collectTools().mint_identity({ did: "did:x:1", document: { id: "did:x:1" } });
  assert.ok(!res.isError);
  const out = JSON.parse(textOf(res));
  assert.equal(out.status, "pending"); // anchor status drives the top-level status
  assert.equal(out.anchorStatus, "pending");
  assert.match(out.warning, /PENDING/);
});
