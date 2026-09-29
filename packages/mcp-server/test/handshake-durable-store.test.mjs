// handshake-core: the durable JSON file and the sealed handle map (spec B2).
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createDurableJsonFile, DurableStateError, handshakeStateDir } from "../dist/handshake-core/durable-store.js";
import { createHandleMap } from "../dist/handshake-core/handle-map.js";

const scratch = () => mkdtempSync(join(tmpdir(), "handshake-durable-"));

function fileFor(dir, state, extra = {}) {
  return createDurableJsonFile({
    path: join(dir, "nested", "state.json"),
    schema: "test/v1",
    maxBytes: 4096,
    snapshot: () => state.value,
    validate: (value) => {
      if (value === null || typeof value !== "object" || typeof value.n !== "number") throw new Error("bad");
      return value;
    },
    ...extra,
  });
}

function quietly(t) {
  return t.mock.method(console, "error", () => {});
}

test("writes are atomic, private (0700 dir, 0600 file), keep the previous version as .bak, and leave no temp files", () => {
  const dir = scratch();
  const state = { value: { n: 1 } };
  const file = fileFor(dir, state);
  assert.equal(file.load(), undefined);
  file.save("now");
  state.value = { n: 2 };
  file.save("now");
  const path = join(dir, "nested", "state.json");
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), { schema: "test/v1", value: { n: 2 } });
  assert.deepEqual(JSON.parse(readFileSync(`${path}.bak`, "utf8")).value, { n: 1 });
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(join(dir, "nested")).mode & 0o777, 0o700);
  assert.deepEqual(readdirSync(join(dir, "nested")).sort(), ["state.json", "state.json.bak"]);
  assert.deepEqual(fileFor(dir, state).load(), { n: 2 });
});

test("a corrupt file falls back to the last good backup, is quarantined and logged, and never overwrites the backup", (t) => {
  const errors = quietly(t);
  const dir = scratch();
  const state = { value: { n: 1 } };
  const first = fileFor(dir, state);
  first.save("now");
  state.value = { n: 2 };
  first.save("now");
  const path = join(dir, "nested", "state.json");
  writeFileSync(path, "{ not json", { mode: 0o600 });
  const reader = fileFor(dir, state);
  assert.deepEqual(reader.load(), { n: 1 });
  assert.ok(readdirSync(join(dir, "nested")).some((name) => name.startsWith("state.json.corrupt-")));
  assert.ok(errors.mock.calls.some((call) => JSON.parse(call.arguments[0]).event === "handshake_state_corrupt"));
  state.value = { n: 3 };
  reader.save("now");
  assert.deepEqual(JSON.parse(readFileSync(`${path}.bak`, "utf8")).value, { n: 1 }, "the good backup survived the next write");
  assert.deepEqual(fileFor(dir, state).load(), { n: 3 });
});

test("garbage with no valid backup refuses to load (loudly) and is left in place", (t) => {
  quietly(t);
  const dir = scratch();
  const path = join(dir, "nested", "state.json");
  const state = { value: { n: 1 } };
  fileFor(dir, state).save("now");
  writeFileSync(path, JSON.stringify({ schema: "other/v9", value: {} }), { mode: 0o600 });
  assert.throws(() => fileFor(dir, state).load(), DurableStateError);
  assert.match(readFileSync(path, "utf8"), /other\/v9/, "not replaced by an empty state");
  // A file readable by others is treated the same way.
  const loose = scratch();
  fileFor(loose, state).save("now");
  chmodSync(join(loose, "nested", "state.json"), 0o644);
  assert.throws(() => fileFor(loose, state).load(), DurableStateError);
});

test("an oversized snapshot is not written and is logged; the previous file stays", (t) => {
  const errors = quietly(t);
  const dir = scratch();
  const state = { value: { n: 1 } };
  const file = fileFor(dir, state);
  file.save("now");
  state.value = { n: 2, pad: "x".repeat(8192) };
  file.save("now");
  assert.deepEqual(fileFor(dir, { value: undefined }).load(), { n: 1 });
  assert.ok(errors.mock.calls.some((call) => JSON.parse(call.arguments[0]).event === "handshake_state_oversize"));
});

test("'soon' writes coalesce into one delayed write; flush writes immediately", async () => {
  const dir = scratch();
  const state = { value: { n: 1 } };
  const file = fileFor(dir, state, { coalesceMs: 50 });
  const path = join(dir, "nested", "state.json");
  file.save("soon");
  state.value = { n: 2 };
  file.save("soon");
  assert.equal(existsSync(path), false);
  await new Promise((resolve) => setTimeout(resolve, 120));
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8")).value, { n: 2 });
  assert.equal(existsSync(`${path}.bak`), false, "one write, not two");
  state.value = { n: 3 };
  file.save("soon");
  file.flush();
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8")).value, { n: 3 });
  file.close();
});

test("the state root comes from HANDSHAKE_STATE_DIR with one subdirectory per surface, else memory-only", () => {
  assert.equal(handshakeStateDir("standalone-handshake", { HANDSHAKE_STATE_DIR: "/app/state" }), "/app/state/standalone-handshake");
  assert.equal(handshakeStateDir("agent-handshake-v2", { HANDSHAKE_STATE_DIR: "/app/state" }), "/app/state/agent-handshake-v2");
  assert.equal(handshakeStateDir("standalone-handshake", {}), undefined);
});

test("handle map: handles survive a restart, issue stays idempotent per token, and nothing is stored in the clear", () => {
  const dir = scratch();
  let now = 1_000;
  const open = () => createHandleMap({ label: "test/h", prefix: "tsth_", limit: 3, now: () => now, path: join(dir, "handles.json") });
  const first = open();
  const token = `sat_${"t".repeat(40)}`;
  const handle = first.issue(token, now + 60_000);
  assert.match(handle, /^tsth_[A-Za-z0-9_-]{22}$/);
  assert.equal(first.issue(token, now + 60_000), handle, "one handle per token");
  first.close();

  const raw = readFileSync(join(dir, "handles.json"), "utf8");
  assert.equal(raw.includes(handle), false, "no raw handle at rest");
  assert.equal(raw.includes(token), false, "no raw token at rest");

  const second = open();
  assert.equal(second.resolve(handle), token);
  assert.equal(second.issue(token, now + 60_000), handle, "the same handle after a restart");
  assert.equal(second.resolve(`tsth_${"x".repeat(22)}`), undefined);
  // Sliding expiry, then expiry on load.
  now += 50_000;
  assert.equal(second.resolve(handle, now + 60_000), token);
  second.close();
  now += 100_000;
  assert.equal(open().resolve(handle), undefined);
  assert.equal(open().size(), 0);
});

test("handle map: the cap holds, and a tampered record never resolves", () => {
  const dir = scratch();
  const now = 1_000;
  const map = createHandleMap({ label: "test/h", prefix: "tsth_", limit: 2, now: () => now, path: join(dir, "handles.json") });
  const a = map.issue("sat_" + "a".repeat(40), now + 60_000);
  map.issue("sat_" + "b".repeat(40), now + 60_000);
  assert.equal(map.issue("sat_" + "c".repeat(40), now + 60_000), undefined);
  map.close();
  const path = join(dir, "handles.json");
  const file = JSON.parse(readFileSync(path, "utf8"));
  for (const record of Object.values(file.value)) record.tokenSealed = record.tokenSealed.slice(0, -4) + "AAAA";
  writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
  const reopened = createHandleMap({ label: "test/h", prefix: "tsth_", limit: 2, now: () => now, path });
  assert.equal(reopened.resolve(a), undefined);
  // A different surface label cannot open another surface's records either.
  const other = createHandleMap({ label: "other/h", prefix: "tsth_", limit: 2, now: () => now, path });
  assert.equal(other.resolve(a), undefined);
});
