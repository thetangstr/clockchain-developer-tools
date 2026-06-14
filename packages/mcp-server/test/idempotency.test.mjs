// Unit tests for the idempotency helper. Process-local cache; reset between tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { idempotent, __resetIdempotency } from "../dist/idempotency.js";

test("same key returns the cached result and runs work only once", async () => {
  __resetIdempotency();
  let calls = 0;
  const work = async () => {
    calls++;
    return { n: calls };
  };
  const first = await idempotent("k", work);
  const second = await idempotent("k", work);
  assert.equal(calls, 1, "work ran exactly once");
  assert.deepEqual(first, { n: 1 });
  assert.deepEqual(second, { n: 1 }, "second call returns the original result");
});

test("distinct keys each run work", async () => {
  __resetIdempotency();
  let calls = 0;
  const work = async () => ({ n: ++calls });
  const a = await idempotent("a", work);
  const b = await idempotent("b", work);
  assert.equal(calls, 2);
  assert.deepEqual(a, { n: 1 });
  assert.deepEqual(b, { n: 2 });
});

test("no key always runs work (no caching)", async () => {
  __resetIdempotency();
  let calls = 0;
  const work = async () => ({ n: ++calls });
  await idempotent(undefined, work);
  await idempotent(undefined, work);
  assert.equal(calls, 2, "every keyless call runs work");
});

test("a throwing work is NOT cached and re-runs on retry", async () => {
  __resetIdempotency();
  let calls = 0;
  const work = async () => {
    calls++;
    if (calls === 1) throw new Error("boom");
    return { n: calls };
  };
  await assert.rejects(() => idempotent("k", work), /boom/);
  // Same key, but the first attempt threw -> nothing cached -> work runs again.
  const retry = await idempotent("k", work);
  assert.equal(calls, 2, "work re-ran after the failure");
  assert.deepEqual(retry, { n: 2 });
});
