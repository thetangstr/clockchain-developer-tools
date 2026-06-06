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

test("getTime unwraps the {success,data} envelope", async () => {
  stubFetch(200, { success: true, data: { latestBlockTime: "t", latestBlockHeight: "5" } });
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
