// Durable store: persistence across "restart" + clean first-run behaviour.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileStore, MemoryStore } from "../dist/index.js";

function trigger(id, over = {}) {
  return {
    id,
    sub: "u1",
    fireAtMs: 1000,
    target: "https://x.test/h",
    payload: { n: 1 },
    mode: "once",
    status: "scheduled",
    createdAtMs: 0,
    updatedAtMs: 0,
    attempts: 0,
    nextAttemptAtMs: 0,
    lastError: null,
    fires: [],
    ...over,
  };
}

test("MemoryStore put/get/all/delete + returns copies (no aliasing)", async () => {
  const s = new MemoryStore();
  await s.put(trigger("a"));
  const got = await s.get("a");
  got.status = "mutated";
  const again = await s.get("a");
  assert.equal(again.status, "scheduled", "store must not be mutated via a returned reference");
  assert.equal((await s.all()).length, 1);
  await s.delete("a");
  assert.equal(await s.get("a"), null);
});

test("FileStore: get on a missing file is a clean first run (no throw)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keeper-"));
  try {
    const s = new FileStore(join(dir, "nope", "store.json"));
    assert.deepEqual(await s.all(), []);
    assert.equal(await s.get("x"), null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("FileStore: data survives a fresh instance (simulated restart)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keeper-"));
  const path = join(dir, "store.json");
  try {
    const a = new FileStore(path);
    await a.put(trigger("t1", { status: "scheduled", fireAtMs: 500 }));
    await a.put(trigger("t2", { status: "done" }));

    // New instance reads from disk — this is the re-arm-on-boot path.
    const b = new FileStore(path);
    const all = await b.all();
    assert.equal(all.length, 2);
    const t1 = await b.get("t1");
    assert.equal(t1.fireAtMs, 500);
    assert.equal(t1.status, "scheduled");

    await b.delete("t2");
    const c = new FileStore(path);
    assert.equal((await c.all()).length, 1);
    assert.equal(await c.get("t2"), null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("FileStore: many concurrent writes serialize without corrupting the file", async () => {
  // The tick loop and the HTTP control plane share the process; both put->flush.
  // With a write queue + unique tmp per write, interleaved writes must not corrupt
  // the file or lose entries.
  const dir = await mkdtemp(join(tmpdir(), "keeper-"));
  const path = join(dir, "store.json");
  try {
    const s = new FileStore(path);
    await Promise.all(
      Array.from({ length: 50 }, (_, i) => s.put(trigger("t" + i, { fireAtMs: i }))),
    );
    // A fresh instance must parse the file (valid JSON) and see ALL 50 triggers.
    const reread = new FileStore(path);
    const all = await reread.all();
    assert.equal(all.length, 50);
    const ids = new Set(all.map((t) => t.id));
    for (let i = 0; i < 50; i++) assert.ok(ids.has("t" + i), `missing t${i}`);
    // No leftover temp files from the unique-tmp writes.
    const leftovers = (await readdir(dir)).filter((f) => f.endsWith(".tmp"));
    assert.deepEqual(leftovers, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
