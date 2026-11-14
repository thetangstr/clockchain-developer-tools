// The OAuth replay sets (src/oauth-replay.ts). A set made with "refuse" refuses a new entry while it holds `cap` unexpired
// ones, so a flood can never push out a spent assertion that is still valid. The default ("evict") is unchanged.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { durableExpiringSet, memoryExpiringSet, ReplayStateFullError } from "../dist/oauth-replay.js";

const clock = (t = 1_000_000) => ({ t, now() { return this.t; } });

test("a refusing set at cap throws ReplayStateFullError and keeps what it holds", () => {
  const c = clock();
  const set = memoryExpiringSet(2, () => c.now(), "refuse");
  set.add("a", c.t + 100);
  set.add("b", c.t + 200);
  assert.equal(set.full(), true);
  assert.throws(() => set.add("c", c.t + 300), (e) => e instanceof ReplayStateFullError && e.name === "ReplayStateFullError");
  assert.equal(set.has("a"), true);
  assert.equal(set.has("b"), true);
  assert.equal(set.has("c"), false);
  assert.equal(set.size(), 2);
});

test("a refusing set takes a new entry once an old one expires", () => {
  const c = clock();
  const set = memoryExpiringSet(2, () => c.now(), "refuse");
  set.add("a", c.t + 100);
  set.add("b", c.t + 200);
  c.t += 100;
  assert.equal(set.full(), false);
  set.add("c", c.t + 300);
  assert.equal(set.has("a"), false);
  assert.equal(set.has("b"), true);
  assert.equal(set.has("c"), true);
});

test("the default set still evicts the oldest entry at cap", () => {
  const c = clock();
  const set = memoryExpiringSet(2, () => c.now());
  set.add("a", c.t + 100);
  set.add("b", c.t + 200);
  set.add("c", c.t + 300);
  assert.equal(set.has("a"), false);
  assert.equal(set.has("b"), true);
  assert.equal(set.has("c"), true);
  assert.equal(set.size(), 2);
});

test("a refusing durable set at cap journals nothing for the refused entry, and reopens with the first ones", () => {
  const c = clock();
  const dir = mkdtempSync(path.join(tmpdir(), "oauth-replay-"));
  const set = durableExpiringSet(dir, "used-assertions", 2, () => c.now(), "refuse");
  set.add("a", c.t + 100);
  set.add("b", c.t + 200);
  const journal = path.join(dir, "used-assertions.jsonl");
  const bytes = statSync(journal).size;
  assert.throws(() => set.add("c", c.t + 300), ReplayStateFullError);
  assert.equal(statSync(journal).size, bytes);
  assert.equal(set.has("c"), false);
  const reopened = durableExpiringSet(dir, "used-assertions", 2, () => c.now(), "refuse");
  assert.equal(reopened.has("a"), true);
  assert.equal(reopened.has("b"), true);
  assert.equal(reopened.has("c"), false);
  assert.equal(existsSync(journal), false, "opening folds the journal into the snapshot");
});
