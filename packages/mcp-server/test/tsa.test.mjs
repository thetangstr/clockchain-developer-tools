// Offline tests for the TSA (commitment) lifecycle tools. Drives the real
// handlers from registerTools() via a fake server; global fetch is stubbed
// (no network). Mirrors test/tools.test.mjs.
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

// A healthy /getTime so the AGE-193 pool-health guard passes by default.
const HEALTHY_GETTIME = {
  success: true,
  data: { "nodeParticipation%": 100, totalNodes: 1, blockHeight: "1", madMarzulloTime: "t" },
};

// Route the stubbed fetch by URL substring -> { status?, body }. Unmatched
// /getTime falls back to a healthy pool so the write guard is a no-op.
function routeFetch(routes) {
  globalThis.fetch = async (url) => {
    for (const [match, resp] of routes) {
      if (String(url).includes(match)) {
        const raw = typeof resp.body === "string" ? resp.body : JSON.stringify(resp.body);
        const status = resp.status ?? 200;
        return { status, ok: status >= 200 && status < 300, statusText: "stub", text: async () => raw };
      }
    }
    if (String(url).includes("/getTime")) {
      return { status: 200, ok: true, statusText: "stub", text: async () => JSON.stringify(HEALTHY_GETTIME) };
    }
    throw new Error("no stubbed route for " + url);
  };
}

// /log echoes a ledgerId + the anchored hash; createdTimestamp is the on-chain
// anchor time the verdict is judged against.
function logRoute(createdTimestamp = "2026-06-01T00:00:00Z") {
  return [
    "/log",
    { body: { ledgerId: "L_TSA", blockHeight: "1000", assetHash: "h", assetReferenceId: "tsa:x", createdTimestamp } },
  ];
}

test("tsa_issue anchors and returns a commitmentId + anchor.ledgerId", async () => {
  let sentBody = null;
  routeFetch([logRoute()]);
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    if (String(url).includes("/log") && opts?.body) sentBody = JSON.parse(opts.body);
    return orig(url, opts);
  };
  const res = await collectTools().tsa_issue({ agent_id: "agent:bot", commitment: "ship it", deadline: "2026-06-30T00:00:00Z" });
  assert.ok(!res.isError, "issue ok");
  const out = JSON.parse(textOf(res));
  assert.ok(out.commitmentId, "has commitmentId");
  assert.equal(out.commitmentId.length, 24, "24-char commitmentId");
  assert.equal(out.anchor.ledgerId, "L_TSA");
  assert.equal(out.eventHash.length, 64, "anchored a SHA-256 hex hash");
  // The anchor goes under the shared tsa:{id} reference, and the hash anchored on
  // /log equals the receipt's eventHash (canonical-payload SHA-256).
  assert.equal(sentBody.assetReferenceId, "tsa:" + out.commitmentId);
  assert.equal(sentBody.assetHash, out.eventHash);
});

test("tsa_checkpoint anchors under the commitment trail", async () => {
  routeFetch([logRoute()]);
  const res = await collectTools().tsa_checkpoint({ commitment_id: "abc123", note: "halfway" });
  assert.ok(!res.isError, "checkpoint ok");
  const out = JSON.parse(textOf(res));
  assert.equal(out.commitmentId, "abc123");
  assert.equal(out.anchor.ledgerId, "L_TSA");
});

test("tsa_settle records the outcome + consequence", async () => {
  routeFetch([logRoute()]);
  const res = await collectTools().tsa_settle({ commitment_id: "abc123", outcome: "kept", consequence: "none" });
  assert.ok(!res.isError, "settle ok");
  const out = JSON.parse(textOf(res));
  assert.equal(out.commitmentId, "abc123");
  assert.equal(out.event.outcome, "kept");
  assert.equal(out.event.consequence, "none");
  assert.equal(out.anchor.ledgerId, "L_TSA");
});

test("tsa_status reads the on-chain trail (sequence, not content)", async () => {
  routeFetch([
    ["/searchAsset", { body: [
      { ledgerId: "L1", blockHeight: "1000", assetHash: "h1", createdTimestamp: "t1" },
      { ledgerId: "L2", blockHeight: "1001", assetHash: "h2", createdTimestamp: "t2" },
    ] }],
  ]);
  const res = await collectTools().tsa_status({ commitment_id: "abc123" });
  assert.ok(!res.isError, "status ok");
  const out = JSON.parse(textOf(res));
  assert.equal(out.commitmentId, "abc123");
  assert.equal(out.assetReferenceId, "tsa:abc123");
  assert.equal(out.count, 2);
  assert.deepEqual(out.events.map((e) => e.ledgerId), ["L1", "L2"]);
});

test("tsa_attest BEFORE the deadline -> verdict 'kept', onTime true", async () => {
  // Anchor (createdTimestamp) is BEFORE the deadline.
  routeFetch([logRoute("2026-06-10T00:00:00Z")]);
  const res = await collectTools().tsa_attest({ commitment_id: "abc123", outcome: "kept", deadline: "2026-06-30T00:00:00Z" });
  assert.ok(!res.isError, "attest ok");
  const out = JSON.parse(textOf(res));
  assert.equal(out.onTime, true);
  assert.equal(out.verdict, "kept");
  assert.equal(out.outcome, "kept");
  assert.equal(out.anchor.ledgerId, "L_TSA");
});

test("tsa_attest AFTER the deadline -> verdict 'broken-late', onTime false", async () => {
  // Anchor (createdTimestamp) is AFTER the deadline.
  routeFetch([logRoute("2026-07-10T00:00:00Z")]);
  const res = await collectTools().tsa_attest({ commitment_id: "abc123", outcome: "kept", deadline: "2026-06-30T00:00:00Z" });
  assert.ok(!res.isError, "attest ok");
  const out = JSON.parse(textOf(res));
  assert.equal(out.onTime, false);
  assert.equal(out.verdict, "broken-late");
});

test("tsa_attest with outcome 'broken' -> verdict 'broken'", async () => {
  routeFetch([logRoute("2026-06-10T00:00:00Z")]);
  const res = await collectTools().tsa_attest({ commitment_id: "abc123", outcome: "broken", deadline: "2026-06-30T00:00:00Z" });
  const out = JSON.parse(textOf(res));
  assert.equal(out.outcome, "broken");
  assert.equal(out.verdict, "broken");
});

test("tsa_attest parses the gateway's DD-MM-YYYY anchor time first", async () => {
  // Gateway createdTimestamp is DD-MM-YYYY: 10-06-2026 = 10 June (not 6 Oct).
  // 10 June is before a 30 June deadline -> kept.
  routeFetch([logRoute("10-06-2026 00:00:00:000 UTC")]);
  const res = await collectTools().tsa_attest({ commitment_id: "abc123", outcome: "kept", deadline: "30-06-2026 00:00:00:000 UTC" });
  const out = JSON.parse(textOf(res));
  assert.equal(out.onTime, true);
  assert.equal(out.verdict, "kept");
});
