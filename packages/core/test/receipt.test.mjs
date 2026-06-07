// Unit tests for receipt fingerprinting + assembly (pure, no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, eventHashOf, buildReceipt, computeHash } from "../dist/index.js";

test("canonicalize sorts keys deeply (order-independent)", () => {
  const a = canonicalize({ b: 1, a: { y: 2, x: 3 } });
  const b = canonicalize({ a: { x: 3, y: 2 }, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":{"x":3,"y":2},"b":1}');
});

test("eventHashOf is deterministic and order-independent", () => {
  const h1 = eventHashOf({ agentId: "a", action: "trade", inputs: { x: 1, y: 2 } });
  const h2 = eventHashOf({ agentId: "a", action: "trade", inputs: { y: 2, x: 1 } });
  assert.equal(h1, h2);
  assert.equal(h1, computeHash(canonicalize({ agentId: "a", action: "trade", inputs: { x: 1, y: 2 }, outputs: null })));
});

test("different inputs produce different hashes", () => {
  const h1 = eventHashOf({ agentId: "a", action: "trade", inputs: { size: 100 } });
  const h2 = eventHashOf({ agentId: "a", action: "trade", inputs: { size: 101 } });
  assert.notEqual(h1, h2);
});

test("buildReceipt assembles an honest testnet receipt", () => {
  const input = { agentId: "agent:treasury-bot", action: "execute_trade", inputs: { pair: "USDC/ETH" }, outputs: { ok: true } };
  const eventHash = eventHashOf(input);
  const log = {
    ledgerId: "L1", assetReferenceId: "agent:treasury-bot:execute_trade:1", assetHash: eventHash,
    blockHeight: "900", createdTimestamp: "06-06-2026 20:00:00:000 UTC",
  };
  const r = buildReceipt({
    input, eventHash, network: "testnet", log,
    block: { blockHeight: 900, proposerAddress: "0x", blockTime: "2026-06-06T20:00:00Z" },
    validation: { blockHeight: 900, positiveVotes: 1, negativeVotes: 0, "Trust value percentage": 0, "Node participation percentage": 0 },
    identity: null,
  });
  assert.equal(r.schema, "clockchain.receipt/v1");
  assert.equal(r.eventHash, eventHash);
  assert.equal(r.anchor.blockHeight, "900");
  assert.equal(r.anchor.confirmed, true);
  assert.equal(r.anchor.consensusTime, "2026-06-06T20:00:00Z");
  assert.equal(r.attestation.status, "single-validator-testnet");
  assert.equal(r.identity.resolved, false);
  assert.match(r.disclaimer, /mainnet-gated/i);
  assert.deepEqual(r.payload, { inputs: { pair: "USDC/ETH" }, outputs: { ok: true } });
});

test("buildReceipt marks pending when no blockHeight", () => {
  const input = { agentId: "a", action: "x" };
  const eventHash = eventHashOf(input);
  const r = buildReceipt({
    input, eventHash, network: "testnet",
    log: { ledgerId: "L2", assetReferenceId: "a:x:1", assetHash: eventHash, blockHeight: null, createdTimestamp: "t" },
  });
  assert.equal(r.anchor.confirmed, false);
  assert.equal(r.anchor.blockHeight, null);
  assert.equal(r.anchor.consensusTime, null);
});
