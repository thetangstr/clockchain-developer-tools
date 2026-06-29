// Truthful anchoring — "never report success on an un-anchored fire" (MCP tool layer).
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

test("identity write keeps lifecycle status, surfaces anchorStatus + PENDING warning", async () => {
  routeFetch([gettime(100), ["/log", { body: { ledgerId: "LM", blockHeight: null } }]]);
  const res = await collectTools().mint_identity({ did: "did:x:1", document: { id: "did:x:1" } });
  assert.ok(!res.isError);
  const out = JSON.parse(textOf(res));
  // Lifecycle status is NOT clobbered; anchor honesty is surfaced separately.
  assert.equal(out.status, "active");
  assert.equal(out.anchorStatus, "pending");
  assert.match(out.warning, /PENDING/);
});

test("TSA write verbs surface top-level pending status + warning (not just anchor.status)", async () => {
  // /log returns a createdTimestamp but blockHeight null -> pending anchor.
  routeFetch([
    gettime(100),
    ["/log", { body: { ledgerId: "L_TSA", blockHeight: null, assetHash: "h", assetReferenceId: "tsa:x", createdTimestamp: "2026-06-01T00:00:00Z" } }],
  ]);
  const tools = collectTools();

  const issue = JSON.parse(textOf(await tools.tsa_issue({ agent_id: "a", commitment: "ship", deadline: "2026-06-30T00:00:00Z" })));
  assert.equal(issue.status, "pending", "top-level status lifted from anchor.status");
  assert.equal(issue.anchor.status, "pending");
  assert.match(issue.warning, /PENDING/);

  // Critical case: a "kept"/onTime verdict on a still-pending anchor must NOT
  // read as a silent greenlight.
  const attest = JSON.parse(textOf(await tools.tsa_attest({ commitment_id: "abc123", outcome: "kept", deadline: "2026-06-30T00:00:00Z" })));
  assert.equal(attest.verdict, "kept");
  assert.equal(attest.onTime, true);
  assert.equal(attest.status, "pending", "pending anchor surfaced despite kept verdict");
  assert.match(attest.warning, /PENDING/);
});

test("TSA write verbs report anchored (no warning) once the block is present", async () => {
  routeFetch([
    gettime(100),
    ["/log", { body: { ledgerId: "L_TSA", blockHeight: "1000", assetHash: "h", assetReferenceId: "tsa:x", createdTimestamp: "2026-06-01T00:00:00Z" } }],
  ]);
  const out = JSON.parse(textOf(await collectTools().tsa_settle({ commitment_id: "abc123", outcome: "kept", consequence: "none" })));
  assert.equal(out.status, "anchored");
  assert.equal(out.warning, undefined);
});

test("guard fails OPEN: getPoolHealth error does not block; status still derived honestly", async () => {
  // /getTime errors (400) -> getPoolHealth throws -> guard fails open -> write proceeds.
  routeFetch([
    ["/getTime", { status: 400, body: { message: "time endpoint down" } }],
    ["/log", { body: { ledgerId: "LF", blockHeight: null } }],
  ]);
  const res = await collectTools().log_action({ asset_hash: HEX, asset_reference_id: "r" });
  assert.ok(!res.isError, "write proceeds when pool health is unknown");
  const out = JSON.parse(textOf(res));
  assert.equal(out.status, "pending");
  assert.match(out.warning, /PENDING/);
});

test("allow_degraded bypasses the guard on an identity verb (mint)", async () => {
  routeFetch([gettime(0), ["/log", { body: { ledgerId: "LMD", blockHeight: null } }]]);
  const res = await collectTools().mint_identity({ did: "did:x:1", document: { id: 1 }, allow_degraded: true });
  assert.ok(!res.isError, "degraded mint proceeds when explicitly allowed");
  assert.equal(JSON.parse(textOf(res)).ledgerId, "LMD");
});

test("allow_degraded bypasses the guard on a TSA verb (tsa_issue)", async () => {
  routeFetch([gettime(0), ["/log", { body: { ledgerId: "L_TSA", blockHeight: null, assetReferenceId: "tsa:x", createdTimestamp: "t" } }]]);
  const res = await collectTools().tsa_issue({ agent_id: "a", commitment: "ship", deadline: "2026-06-30T00:00:00Z", allow_degraded: true });
  assert.ok(!res.isError, "degraded tsa_issue proceeds when explicitly allowed");
  assert.equal(JSON.parse(textOf(res)).anchor.ledgerId, "L_TSA");
});
