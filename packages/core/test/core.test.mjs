// Offline unit tests for @clockchain/core. No network: global fetch is stubbed.
// Run: node --test  (from packages/core)  or  npm test  (workspace root).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  computeHash,
  hashFile,
  ClockchainClient,
  ApiError,
  RateLimitError,
  InsufficientCreditsError,
  AuthError,
} from "../dist/index.js";
import { writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

let lastRequest = null;
function stubFetch(status, body) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  globalThis.fetch = async (url, opts) => {
    lastRequest = { url, opts };
    return {
      status,
      ok: status >= 200 && status < 300,
      statusText: "stub",
      text: async () => raw,
    };
  };
}

test("computeHash matches known SHA-256 vectors", () => {
  assert.equal(
    computeHash("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assert.equal(
    computeHash(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});

test("typed error hierarchy + default statuses", () => {
  assert.ok(new RateLimitError() instanceof ApiError);
  assert.ok(new InsufficientCreditsError() instanceof ApiError);
  assert.ok(new AuthError() instanceof ApiError);
  assert.equal(new RateLimitError().status, 429);
  assert.equal(new InsufficientCreditsError().status, 402);
  assert.equal(new AuthError().status, 401);
  assert.equal(new RateLimitError().name, "RateLimitError");
});

test("getTime derives latest time/height from /getTime", async () => {
  stubFetch(200, { success: true, data: { madMarzulloTime: "t", blockHeight: "5" } });
  const c = new ClockchainClient(cfg);
  assert.deepEqual(await c.getTime(), { latestBlockTime: "t", latestBlockHeight: "5" });
});

test("getValidationBlock unwraps the bare {validationBlockData} shape", async () => {
  stubFetch(200, { validationBlockData: { height: 5, votes: 0 } });
  const c = new ClockchainClient(cfg);
  assert.deepEqual(await c.getValidationBlock(5), { height: 5, votes: 0 });
});

test("sets x-api-key header on requests", async () => {
  stubFetch(200, { success: true, data: { latestBlockTime: "t", latestBlockHeight: "1" } });
  await new ClockchainClient(cfg).getTime();
  assert.equal(lastRequest.opts.headers["x-api-key"], "k");
});

test("HTTP 429 maps to RateLimitError", async () => {
  stubFetch(429, { message: "slow down" });
  await assert.rejects(() => new ClockchainClient(cfg).getTime(), RateLimitError);
});

test("body 'Rate limit exceeded' maps to RateLimitError even on 200", async () => {
  stubFetch(200, "Rate limit exceeded");
  await assert.rejects(() => new ClockchainClient(cfg).getTime(), RateLimitError);
});

test("'No enough tokens...' maps to InsufficientCreditsError", async () => {
  stubFetch(400, { message: "No enough tokens to facilitate this logging" });
  await assert.rejects(
    () => new ClockchainClient(cfg).log({ assetHash: "h", assetReferenceId: "r" }),
    InsufficientCreditsError,
  );
});

test("HTTP 401 maps to AuthError", async () => {
  stubFetch(401, { message: "nope" });
  await assert.rejects(() => new ClockchainClient(cfg).getTime(), AuthError);
});

test("other non-2xx maps to generic ApiError", async () => {
  stubFetch(500, { message: "boom" });
  await assert.rejects(() => new ClockchainClient(cfg).getTime(), ApiError);
});

test("log() applies SHA-256 default and config ids", async () => {
  stubFetch(200, { ledgerId: "x" });
  await new ClockchainClient(cfg).log({ assetHash: "h", assetReferenceId: "r" });
  const sent = JSON.parse(lastRequest.opts.body);
  assert.equal(sent.hashType, "SHA-256");
  assert.equal(sent.versionNumber, 1);
  assert.equal(sent.clientId, "c");
  assert.equal(sent.walletId, "w");
});

test("hashFile matches computeHash of the same bytes", async () => {
  const path = join(tmpdir(), `clockchain-hashfile-${process.pid}-${Date.now()}.txt`);
  const contents = "clockchain hashFile test contents";
  await writeFile(path, contents);
  try {
    assert.equal(await hashFile(path), computeHash(contents));
  } finally {
    await rm(path, { force: true });
  }
});

// Route the stubbed fetch by URL substring -> { status?, body }.
function routeFetch(routes) {
  globalThis.fetch = async (url, opts) => {
    lastRequest = { url, opts };
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

test("getBlock(number) hits the block endpoint with the height", async () => {
  routeFetch([["/api/time/block", { body: { success: true, data: { height: "5", proposer: "p" } } }]]);
  assert.deepEqual(await new ClockchainClient(cfg).getBlock(5), { height: "5", proposer: "p" });
  assert.match(String(lastRequest.url), /height=5/);
});

test("getBlock('latest') resolves height via getTime first", async () => {
  routeFetch([
    ["/getTime", { body: { success: true, data: { madMarzulloTime: "t", blockHeight: "42" } } }],
    ["/api/time/block", { body: { success: true, data: { height: "42" } } }],
  ]);
  assert.deepEqual(await new ClockchainClient(cfg).getBlock("latest"), { height: "42" });
  assert.match(String(lastRequest.url), /height=42/);
});

test("getTimestamp unwraps {success,data}", async () => {
  stubFetch(200, { success: true, data: { time: "x", votes: 0 } });
  assert.deepEqual(await new ClockchainClient(cfg).getTimestamp(), { time: "x", votes: 0 });
});

test("searchAsset scopes by clientId and returns the array", async () => {
  stubFetch(200, [{ ledgerId: "L" }]);
  const out = await new ClockchainClient(cfg).searchAsset("ref1");
  assert.deepEqual(out, [{ ledgerId: "L" }]);
  assert.match(String(lastRequest.url), /clientId=c/);
  assert.match(String(lastRequest.url), /assetReferenceId=ref1/);
});

test("getLedgerEntry maps an error envelope to ApiError", async () => {
  stubFetch(200, { success: false, error: { message: "not found" } });
  await assert.rejects(() => new ClockchainClient(cfg).getLedgerEntry("missing"), ApiError);
});

test("waitForConfirmation returns the record once blockHeight populates", async () => {
  stubFetch(200, { ledgerId: "L", blockHeight: "100" });
  const rec = await new ClockchainClient(cfg).waitForConfirmation("L", 2000);
  assert.equal(rec.blockHeight, "100");
});

test("waitForConfirmation returns the pending record on timeout (no throw)", async () => {
  stubFetch(200, { ledgerId: "L", blockHeight: null });
  const rec = await new ClockchainClient(cfg).waitForConfirmation("L", 10);
  assert.equal(rec.ledgerId, "L");
  assert.equal(rec.blockHeight, null);
});

test("attestAction({wait:false}) SUBMITS a pending receipt without blocking", async () => {
  // Only /log is hit on submit; enrichment is skipped while blockHeight is null.
  routeFetch([["/log", { body: { ledgerId: "LA", assetReferenceId: "ref", blockHeight: null, createdTimestamp: "t" } }]]);
  const receipt = await new ClockchainClient(cfg).attestAction({
    agentId: "agent:bot", action: "execute_trade", inputs: { size: 1 }, outputs: { ok: true }, wait: false,
  });
  assert.equal(receipt.anchor.ledgerId, "LA");
  assert.equal(receipt.anchor.blockHeight, null);
  assert.equal(receipt.anchor.confirmed, false);
});

test("completeReceipt POLLS: still pending when the block has not landed", async () => {
  routeFetch([["/log", { body: { ledgerId: "LB", assetReferenceId: "ref", blockHeight: null, createdTimestamp: "t" } }]]);
  const c = new ClockchainClient(cfg);
  const pending = await c.attestAction({ agentId: "a", action: "x", wait: false });
  // Ledger still has no blockHeight -> completeReceipt returns a pending receipt.
  routeFetch([["/ledger/", { body: { ledgerId: "LB", assetReferenceId: "ref", blockHeight: null, createdTimestamp: "t" } }]]);
  const polled = await c.completeReceipt(pending);
  assert.equal(polled.anchor.confirmed, false);
  assert.equal(polled.anchor.blockHeight, null);
});

test("completeReceipt POLLS: returns the COMPLETED receipt once the block lands", async () => {
  routeFetch([["/log", { body: { ledgerId: "LC", assetReferenceId: "ref", blockHeight: null, createdTimestamp: "t" } }]]);
  const c = new ClockchainClient(cfg);
  const pending = await c.attestAction({ agentId: "a", action: "x", inputs: { n: 1 }, wait: false });
  const eventHash = pending.eventHash;
  // Block has now landed: ledger reports a height, and enrichment succeeds.
  routeFetch([
    ["/ledger/", { body: { ledgerId: "LC", assetReferenceId: "ref", blockHeight: "900", createdTimestamp: "t" } }],
    ["/api/time/block", { body: { success: true, data: { blockHeight: 900, proposerAddress: "0x", blockTime: "2026-06-14T00:00:00Z" } } }],
    ["/getValidationBlock", { body: { validationBlockData: { blockHeight: 900, positiveVotes: 1, negativeVotes: 0, "Trust value percentage": 0 } } }],
  ]);
  const done = await c.completeReceipt(pending);
  assert.equal(done.anchor.blockHeight, "900");
  assert.equal(done.anchor.confirmed, true);
  assert.equal(done.anchor.consensusTime, "2026-06-14T00:00:00Z");
  // Event hash is preserved across completion -> same receipt identity.
  assert.equal(done.eventHash, eventHash);
});
