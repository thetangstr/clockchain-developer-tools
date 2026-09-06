// Unit tests for resilientFetch: timeout, bounded retries (GET only),
// circuit-breaker. Fully synchronous — fetchImpl, sleep, and now are injected
// so nothing sleeps or touches the network.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  resilientFetch,
  __resetBreaker,
  TimeoutError,
  CircuitOpenError,
} from "../dist/index.js";

const noopSleep = () => Promise.resolve();
// A minimal Response stand-in: resilientFetch only inspects `.status`.
const resp = (status) => ({ status, ok: status >= 200 && status < 300 });

test("GET that fails once then succeeds is retried and returns success", async () => {
  __resetBreaker();
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) throw new Error("ECONNRESET");
    return resp(200);
  };
  const res = await resilientFetch(
    "https://node.example/read",
    {},
    { method: "GET", fetchImpl, sleep: noopSleep, now: () => 0 },
  );
  assert.equal(res.status, 200);
  assert.equal(calls, 2, "should have retried exactly once");
});

test("GET 5xx always exhausts retries then throws", async () => {
  __resetBreaker();
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return resp(503);
  };
  // maxRetries=2 => 3 total attempts; final 503 is returned (caller maps !ok).
  const res = await resilientFetch(
    "https://node.example/read",
    {},
    { method: "GET", fetchImpl, sleep: noopSleep, now: () => 0 },
  );
  assert.equal(res.status, 503);
  assert.equal(calls, 3, "1 initial + 2 retries");
});

test("network error on GET exhausts retries then rethrows", async () => {
  __resetBreaker();
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new Error("network down");
  };
  await assert.rejects(
    resilientFetch(
      "https://node.example/read",
      {},
      { method: "GET", fetchImpl, sleep: noopSleep, now: () => 0 },
    ),
    /network down/,
  );
  assert.equal(calls, 3, "1 initial + 2 retries");
});

test("non-GET (POST) failure is NOT retried — exactly one attempt", async () => {
  __resetBreaker();
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new Error("write failed");
  };
  await assert.rejects(
    resilientFetch(
      "https://node.example/log",
      { method: "POST" },
      { method: "POST", fetchImpl, sleep: noopSleep, now: () => 0 },
    ),
    /write failed/,
  );
  assert.equal(calls, 1, "writes must not auto-retry (no double-anchor)");
});

test("POST 5xx is NOT retried and the response is returned", async () => {
  __resetBreaker();
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return resp(500);
  };
  const res = await resilientFetch(
    "https://node.example/log",
    { method: "POST" },
    { method: "POST", fetchImpl, sleep: noopSleep, now: () => 0 },
  );
  assert.equal(res.status, 500);
  assert.equal(calls, 1);
});

test("timeout (AbortError-like) is mapped to TimeoutError", async () => {
  __resetBreaker();
  const fetchImpl = async () => {
    const err = new Error("aborted");
    err.name = "AbortError";
    throw err;
  };
  await assert.rejects(
    resilientFetch(
      "https://node.example/log",
      { method: "POST" },
      { method: "POST", fetchImpl, sleep: noopSleep, now: () => 0 },
    ),
    (err) => {
      assert.ok(err instanceof TimeoutError, "should be a TimeoutError");
      assert.match(err.message, /timed out/i);
      return true;
    },
  );
});

test("circuit-breaker opens after the threshold and fails fast without fetching", async () => {
  __resetBreaker();
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new Error("down");
  };
  const opts = {
    method: "POST", // no retries — one failure per call, clean accounting
    fetchImpl,
    sleep: noopSleep,
    now: () => 1000,
    breakerThreshold: 5,
    breakerCooldownMs: 30_000,
  };
  // 5 consecutive failures trip the breaker open.
  for (let i = 0; i < 5; i += 1) {
    await assert.rejects(resilientFetch("https://node.example/log", {}, opts));
  }
  assert.equal(calls, 5, "fetchImpl invoked once per failing call");

  // Next call (still within cooldown) fails fast WITHOUT calling fetchImpl.
  await assert.rejects(
    resilientFetch("https://node.example/log", {}, opts),
    (err) => {
      assert.ok(err instanceof CircuitOpenError, "breaker should be open");
      assert.match(err.message, /circuit open/i);
      return true;
    },
  );
  assert.equal(calls, 5, "breaker-open call must not invoke fetchImpl");
});

test("circuit-breaker goes half-open after cooldown and closes on success", async () => {
  __resetBreaker();
  let calls = 0;
  let succeed = false;
  const fetchImpl = async () => {
    calls += 1;
    if (succeed) return resp(200);
    throw new Error("down");
  };
  let clock = 1000;
  const opts = {
    method: "POST",
    fetchImpl,
    sleep: noopSleep,
    now: () => clock,
    breakerThreshold: 5,
    breakerCooldownMs: 30_000,
  };
  for (let i = 0; i < 5; i += 1) {
    await assert.rejects(resilientFetch("https://node.example/log", {}, opts));
  }
  assert.equal(calls, 5);

  // Still open during cooldown: fails fast.
  await assert.rejects(
    resilientFetch("https://node.example/log", {}, opts),
    CircuitOpenError,
  );
  assert.equal(calls, 5, "no probe during cooldown");

  // Advance past the cooldown -> half-open. Next call probes (fetch is called).
  clock += 30_001;
  succeed = true;
  const res = await resilientFetch("https://node.example/log", {}, opts);
  assert.equal(res.status, 200);
  assert.equal(calls, 6, "half-open probe should reach fetchImpl");

  // Breaker closed: a subsequent call also probes normally.
  const res2 = await resilientFetch("https://node.example/log", {}, opts);
  assert.equal(res2.status, 200);
  assert.equal(calls, 7);
});

// Regression guard (do not delete): the breaker is PER-HOST. A dependency outage on one host must never
// fail-fast calls to a different host. If this ever fails, the per-host bulkhead has silently reverted to a
// single shared breaker — the outage-amplifying behavior the runtime patch was created to fix.
test("circuit-breaker is per-host: one host tripping does NOT block another host", async () => {
  __resetBreaker();
  const calls = { a: 0, b: 0 };
  const fetchImpl = async (url) => {
    if (url.includes("host-a")) { calls.a += 1; throw new Error("host-a down"); }
    calls.b += 1; return resp(200);
  };
  const opts = { method: "POST", fetchImpl, sleep: noopSleep, now: () => 1000, breakerThreshold: 5, breakerCooldownMs: 30_000 };

  // Trip host-a's breaker open (5 consecutive failures) and confirm it now fails fast.
  for (let i = 0; i < 5; i += 1) await assert.rejects(resilientFetch("https://host-a.example/log", {}, opts));
  await assert.rejects(resilientFetch("https://host-a.example/log", {}, opts), CircuitOpenError);
  assert.equal(calls.a, 5, "host-a breaker open: no further fetch");

  // host-b must be completely unaffected — its breaker is closed, the call reaches fetchImpl and succeeds.
  const res = await resilientFetch("https://host-b.example/getTime", {}, opts);
  assert.equal(res.status, 200);
  assert.equal(calls.b, 1, "host-b is isolated from host-a's open breaker");
});

// Regression guard for the signed-retry bug: reSignHeaders must be called PER ATTEMPT so each retry carries a
// fresh nonce. Reusing one nonce across GET retries makes the gateway reject the retry as a replay (401).
test("reSignHeaders is applied per attempt so retries carry a fresh nonce", async () => {
  __resetBreaker();
  const nonces = [];
  const fetchImpl = async (_url, init) => {
    nonces.push(init.headers["x-cc-nonce"]);
    return nonces.length < 3 ? resp(503) : resp(200); // transient 5xx twice, then succeed on the 3rd attempt
  };
  let n = 0;
  const res = await resilientFetch(
    "https://gw.example/getTime",
    { headers: { "x-cc-nonce": "PLACEHOLDER", accept: "application/json" } },
    { method: "GET", fetchImpl, sleep: noopSleep, now: () => 1000, reSignHeaders: () => ({ "x-cc-nonce": `nonce-${n++}` }) },
  );
  assert.equal(res.status, 200);
  assert.deepEqual(nonces, ["nonce-0", "nonce-1", "nonce-2"]); // fresh per attempt; base placeholder overridden
});
