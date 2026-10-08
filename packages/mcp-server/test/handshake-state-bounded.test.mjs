// Regression for the 2026-10-08 production OOM: the v2 handshake state store deep-cloned
// EVERY record and rewrote the whole file on EVERY update (including no-op refresh polls),
// and it never dropped a record. These tests pin the bounded behaviour.
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createIsolatedHandshakeStateStore, stateStoreOptionsFromEnv } from "../dist/handshake/state.js";

const DAY = 24 * 60 * 60 * 1000;
const keyOf = (i) => ({ principal: `p${i}`, session: `s${i}`, role: "initiator" });
const recordFor = (key, extra = {}) => ({ ...key, status: "active", data: { stage: "invited", ...extra } });

async function seeded(n, options) {
  const dir = mkdtempSync(join(tmpdir(), "hs-bounded-"));
  const path = join(dir, "state.json");
  const store = createIsolatedHandshakeStateStore(path, options);
  for (let i = 0; i < n; i += 1) await store.put(keyOf(i), recordFor(keyOf(i), { blob: "x".repeat(200) }));
  return { store, path };
}

test("one update does work proportional to the record, not to the whole store", async () => {
  const { store } = await seeded(400);
  const realParse = JSON.parse;
  let parses = 0;
  JSON.parse = (...args) => { parses += 1; return realParse(...args); };
  try {
    await store.update(keyOf(7), (current) => ({ ...current, data: { ...current.data, stage: "party_ready" } }));
  } finally {
    JSON.parse = realParse;
  }
  // The old implementation deep-cloned all 400 records (>= 400 JSON.parse calls) per update.
  assert.ok(parses < 10, `expected O(1) clones per update, saw ${parses} JSON.parse calls`);
  assert.equal((await store.get(keyOf(7))).data.stage, "party_ready");
  assert.equal((await store.get(keyOf(8))).data.stage, "invited");
});

test("a no-op update (refresh poll that observed nothing) does not rewrite the state file", async () => {
  const { store, path } = await seeded(5);
  const before = statSync(path);
  const bytes = readFileSync(path, "utf8");
  for (let i = 0; i < 20; i += 1) await store.update(keyOf(2), (current) => ({ ...current, data: { ...current.data } }));
  const after = statSync(path);
  assert.equal(after.ino, before.ino, "file was replaced (atomic rename) by a no-op update");
  assert.equal(readFileSync(path, "utf8"), bytes);
  // A real change still persists, compactly.
  await store.update(keyOf(2), (current) => ({ ...current, data: { ...current.data, stage: "certificate_available" } }));
  const persisted = readFileSync(path, "utf8");
  assert.notEqual(statSync(path).ino, before.ino);
  assert.ok(!persisted.includes("\n  "), "state file is written compact");
  const reloaded = createIsolatedHandshakeStateStore(path, {});
  assert.equal((await reloaded.get(keyOf(2))).data.stage, "certificate_available");
});

test("retention bounds the store: stale records are pruned on write and on load, live ones kept", async () => {
  let nowMs = Date.UTC(2026, 9, 1);
  const options = { retentionMs: 30 * DAY, now: () => nowMs };
  const dir = mkdtempSync(join(tmpdir(), "hs-retention-"));
  const path = join(dir, "state.json");
  const store = createIsolatedHandshakeStateStore(path, options);
  for (let i = 0; i < 50; i += 1) {
    await store.put(keyOf(i), { ...recordFor(keyOf(i)), createdAt: nowMs - (60 - i) * DAY, updatedAt: nowMs - (60 - i) * DAY });
  }
  // Records 0..29 are 31..60 days old; 30..49 are 11..30 days old (30 is exactly at the cutoff edge).
  await store.update(keyOf(49), (current) => ({ ...current, data: { ...current.data, stage: "party_ready" } }));
  assert.ok(store.size() <= 21, `expected stale records pruned, size=${store.size()}`);
  assert.equal(await store.get(keyOf(0)), null);
  assert.notEqual(await store.get(keyOf(45)), null);
  const onDisk = Object.keys(JSON.parse(readFileSync(path, "utf8")).records).length;
  assert.equal(onDisk, store.size());

  // Boot of a store whose file holds only stale records: they never enter memory.
  nowMs += 365 * DAY;
  const rebooted = createIsolatedHandshakeStateStore(path, options);
  assert.equal(rebooted.size(), 0);

  // Steady state stays bounded however many sessions flow through.
  for (let i = 100; i < 400; i += 1) {
    nowMs += DAY / 4;
    await rebooted.put(keyOf(i), recordFor(keyOf(i)));
  }
  assert.ok(rebooted.size() <= 30 * 4 + 1, `size ${rebooted.size()} exceeds the 30-day window`);
});

test("retention is opt-in and read from AGENT_HANDSHAKE_V2_STATE_RETENTION_DAYS", () => {
  assert.deepEqual(stateStoreOptionsFromEnv({}), {});
  assert.deepEqual(stateStoreOptionsFromEnv({ AGENT_HANDSHAKE_V2_STATE_RETENTION_DAYS: "0" }), {});
  assert.deepEqual(stateStoreOptionsFromEnv({ AGENT_HANDSHAKE_V2_STATE_RETENTION_DAYS: "nope" }), {});
  assert.deepEqual(stateStoreOptionsFromEnv({ AGENT_HANDSHAKE_V2_STATE_RETENTION_DAYS: "30" }), { retentionMs: 30 * DAY });
});

test("legacy pretty-printed state files still load", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hs-legacy-"));
  const path = join(dir, "state.json");
  const first = createIsolatedHandshakeStateStore(join(dir, "seed.json"), {});
  await first.put(keyOf(1), recordFor(keyOf(1)));
  const seededFile = JSON.parse(readFileSync(join(dir, "seed.json"), "utf8"));
  writeFileSync(path, JSON.stringify(seededFile, null, 2));
  const store = createIsolatedHandshakeStateStore(path, {});
  assert.equal((await store.get(keyOf(1))).data.stage, "invited");
});
