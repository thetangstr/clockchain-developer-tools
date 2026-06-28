// AGE-193 — "never report success on an un-anchored fire" (core layer).
// Offline: global fetch is stubbed (no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ClockchainClient,
  buildReceipt,
  eventHashOf,
  deriveAnchorStatus,
} from "../dist/index.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

function stubFetch(status, body) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  globalThis.fetch = async () => ({
    status,
    ok: status >= 200 && status < 300,
    statusText: "stub",
    text: async () => raw,
  });
}

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
    throw new Error("no route for " + url);
  };
}

test("deriveAnchorStatus: null -> pending, set -> anchored, null+degraded -> degraded", () => {
  assert.equal(deriveAnchorStatus(null), "pending");
  assert.equal(deriveAnchorStatus(undefined), "pending");
  assert.equal(deriveAnchorStatus("5"), "anchored");
  assert.equal(deriveAnchorStatus(null, true), "degraded");
  // A confirmed write is anchored even if the pool is degraded.
  assert.equal(deriveAnchorStatus("5", true), "anchored");
});

test("log() stamps status=pending when blockHeight is null", async () => {
  stubFetch(200, { ledgerId: "L", blockHeight: null });
  const res = await new ClockchainClient(cfg).log({ assetHash: "h", assetReferenceId: "r" });
  assert.equal(res.status, "pending");
});

test("log() stamps status=anchored when blockHeight is set", async () => {
  stubFetch(200, { ledgerId: "L", blockHeight: "900" });
  const res = await new ClockchainClient(cfg).log({ assetHash: "h", assetReferenceId: "r" });
  assert.equal(res.status, "anchored");
});

test("waitForConfirmation stamps anchored once blockHeight populates", async () => {
  stubFetch(200, { ledgerId: "L", blockHeight: "100" });
  const rec = await new ClockchainClient(cfg).waitForConfirmation("L", 2000);
  assert.equal(rec.status, "anchored");
});

test("waitForConfirmation stamps pending on timeout (not unqualified success)", async () => {
  stubFetch(200, { ledgerId: "L", blockHeight: null });
  const rec = await new ClockchainClient(cfg).waitForConfirmation("L", 10);
  assert.equal(rec.blockHeight, null);
  assert.equal(rec.status, "pending");
});

test("getPoolHealth: degraded=true at 0% participation, false otherwise", async () => {
  stubFetch(200, { success: true, data: { "nodeParticipation%": 0, totalNodes: 3 } });
  const degraded = await new ClockchainClient(cfg).getPoolHealth();
  assert.equal(degraded.degraded, true);
  assert.equal(degraded.nodeParticipationPct, 0);
  assert.equal(degraded.totalNodes, 3);

  stubFetch(200, { success: true, data: { "nodeParticipation%": 80, totalNodes: 5 } });
  const healthy = await new ClockchainClient(cfg).getPoolHealth();
  assert.equal(healthy.degraded, false);
  assert.equal(healthy.nodeParticipationPct, 80);
});

test("buildReceipt: top-level status anchored when confirmed", () => {
  const input = { agentId: "a", action: "x" };
  const eventHash = eventHashOf(input);
  const r = buildReceipt({
    input, eventHash, network: "testnet",
    log: { ledgerId: "L", assetReferenceId: "a:x:1", assetHash: eventHash, blockHeight: "900", createdTimestamp: "t" },
  });
  assert.equal(r.status, "anchored");
  assert.equal(r.anchor.confirmed, true);
});

test("buildReceipt: status pending when not anchored; degraded when pool degraded", () => {
  const input = { agentId: "a", action: "x" };
  const eventHash = eventHashOf(input);
  const pendingLog = { ledgerId: "L", assetReferenceId: "a:x:1", assetHash: eventHash, blockHeight: null, createdTimestamp: "t" };

  const pending = buildReceipt({ input, eventHash, network: "testnet", log: pendingLog });
  assert.equal(pending.status, "pending");

  const degraded = buildReceipt({
    input, eventHash, network: "testnet", log: pendingLog,
    poolHealth: { totalNodes: 1, nodeParticipationPct: 0, degraded: true },
  });
  assert.equal(degraded.status, "degraded");
  assert.deepEqual(degraded.poolHealth, { totalNodes: 1, nodeParticipationPct: 0, degraded: true });
});

test("attestAction stamps a top-level status and carries poolHealth", async () => {
  routeFetch([
    ["/log", { body: { ledgerId: "LA", assetReferenceId: "ref", blockHeight: null, createdTimestamp: "t" } }],
    ["/getTime", { body: { success: true, data: { "nodeParticipation%": 0, totalNodes: 1, blockHeight: "1" } } }],
  ]);
  const receipt = await new ClockchainClient(cfg).attestAction({ agentId: "a", action: "x", wait: false });
  // Not anchored + degraded pool -> degraded status, with poolHealth attached.
  assert.equal(receipt.anchor.confirmed, false);
  assert.equal(receipt.status, "degraded");
  assert.equal(receipt.poolHealth.degraded, true);
});

test("backfillPending re-polls and returns records with anchor status", async () => {
  stubFetch(200, { ledgerId: "L1", blockHeight: "900" });
  const out = await new ClockchainClient(cfg).backfillPending(["L1"], 2000);
  assert.equal(out.length, 1);
  assert.equal(out[0].status, "anchored");
});

test("identity writes derive anchorStatus from blockHeight", async () => {
  stubFetch(200, { ledgerId: "L", blockHeight: null });
  const pending = await new ClockchainClient(cfg).mintIdentity("did:x:1", { id: 1 });
  assert.equal(pending.status, "active"); // lifecycle preserved
  assert.equal(pending.anchorStatus, "pending"); // anchor honesty

  stubFetch(200, { ledgerId: "L", blockHeight: "900" });
  const anchored = await new ClockchainClient(cfg).revokeIdentity("did:x:1");
  assert.equal(anchored.status, "revoked");
  assert.equal(anchored.anchorStatus, "anchored");
});
