// The OAuth replay sets (src/oauth-replay.ts). A set made with "refuse" refuses a new entry while it holds `cap` unexpired
// ones, so a flood can never push out a spent assertion that is still valid. The default ("evict") is unchanged.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
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

test("a refusing durable set at its cap reopens when its journal repeats keys its snapshot already holds", () => {
  const c = clock();
  const dir = mkdtempSync(path.join(tmpdir(), "oauth-replay-"));
  const entries = [["a", c.t + 100], ["b", c.t + 200]];
  writeFileSync(path.join(dir, "used-assertions.json"), `${JSON.stringify({ schema: "oauth-used-assertions-v1", value: entries })}\n`, { mode: 0o600 });
  writeFileSync(path.join(dir, "used-assertions.jsonl"), entries.map((e) => JSON.stringify(e)).join("\n") + "\n", { mode: 0o600 });
  const set = durableExpiringSet(dir, "used-assertions", 2, () => c.now(), "refuse");
  assert.equal(set.has("a"), true);
  assert.equal(set.has("b"), true);
  assert.equal(set.size(), 2);
  assert.throws(() => set.add("c", c.t + 300), ReplayStateFullError);
});

test("a refusing durable set with more live entries on disk than its cap fails to open", () => {
  const c = clock();
  const dir = mkdtempSync(path.join(tmpdir(), "oauth-replay-"));
  const entries = [["a", c.t + 100], ["b", c.t + 200], ["c", c.t + 300]];
  writeFileSync(path.join(dir, "used-assertions.json"), `${JSON.stringify({ schema: "oauth-used-assertions-v1", value: entries })}\n`, { mode: 0o600 });
  assert.throws(() => durableExpiringSet(dir, "used-assertions", 2, () => c.now(), "refuse"), ReplayStateFullError);
  // The evicting kind opens the same files, keeping the newest.
  assert.equal(durableExpiringSet(dir, "used-assertions", 2, () => c.now()).size(), 2);
});

test("a refusing durable set whose journal holds more live entries than its cap fails to open, and drops none", () => {
  const c = clock();
  const dir = mkdtempSync(path.join(tmpdir(), "oauth-replay-"));
  const entries = [["a", c.t + 100], ["b", c.t + 200], ["c", c.t + 300]];
  const journal = path.join(dir, "used-assertions.jsonl");
  writeFileSync(journal, entries.map((e) => JSON.stringify(e)).join("\n") + "\n", { mode: 0o600 });
  assert.throws(() => durableExpiringSet(dir, "used-assertions", 2, () => c.now(), "refuse"), ReplayStateFullError);
  assert.equal(readFileSync(journal, "utf8").trim().split("\n").length, 3, "the journal is kept as it was");
});

test("addAll records every entry or none: a refusing set without room for all of them takes none", () => {
  const c = clock();
  for (const make of [
    () => memoryExpiringSet(3, () => c.now(), "refuse"),
    () => durableExpiringSet(mkdtempSync(path.join(tmpdir(), "oauth-replay-")), "used-assertions", 3, () => c.now(), "refuse"),
  ]) {
    const set = make();
    set.add("a", c.t + 100);
    set.add("b", c.t + 100);
    assert.equal(set.full(), false);
    assert.throws(() => set.addAll([["c", c.t + 100], ["d", c.t + 100]]), ReplayStateFullError);
    assert.equal(set.has("c"), false);
    assert.equal(set.has("d"), false);
    set.addAll([["c", c.t + 100]]);
    assert.equal(set.has("c"), true);
    assert.equal(set.full(), true);
  }
});

test("a durable addAll is one journal append, and a write that fails remembers neither entry", () => {
  const c = clock();
  const dir = mkdtempSync(path.join(tmpdir(), "oauth-replay-"));
  const set = durableExpiringSet(dir, "used-assertions", 10, () => c.now(), "refuse");
  set.addAll([["a", c.t + 100], ["b", c.t + 200]]);
  const journal = path.join(dir, "used-assertions.jsonl");
  assert.deepEqual(readFileSync(journal, "utf8"), `["a",${c.t + 100}]\n["b",${c.t + 200}]\n`);
  const reopened = durableExpiringSet(dir, "used-assertions", 10, () => c.now(), "refuse");
  assert.equal(reopened.has("a") && reopened.has("b"), true);
  // The journal can't be written (it is a directory now): neither entry is kept.
  mkdirSync(journal);
  assert.throws(() => reopened.addAll([["c", c.t + 100], ["d", c.t + 100]]));
  assert.equal(reopened.has("c"), false);
  assert.equal(reopened.has("d"), false);
});

test("full() says whether a refusing set would refuse a new entry, and is false for an evicting one", () => {
  const c = clock();
  const evicting = memoryExpiringSet(1, () => c.now());
  evicting.add("a", c.t + 100);
  assert.equal(evicting.full(), false);
  const dir = mkdtempSync(path.join(tmpdir(), "oauth-replay-"));
  const durable = durableExpiringSet(dir, "used-codes", 1, () => c.now());
  durable.add("a", c.t + 100);
  assert.equal(durable.full(), false);
  const refusing = durableExpiringSet(dir, "used-assertions", 1, () => c.now(), "refuse");
  refusing.add("a", c.t + 100);
  assert.equal(refusing.full(), true);
});
