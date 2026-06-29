// Webhook signing + retry/backoff/idempotency/dead-letter. No network, no timers.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  backoffDelayMs,
  buildHeaders,
  decodeSecret,
  deliverWebhook,
  deliverWithRetry,
  signWebhook,
  verifyWebhook,
} from "../dist/index.js";

test("signWebhook is deterministic and verifyWebhook accepts it", () => {
  const args = { id: "msg_1", timestampSec: 1700000000, body: '{"a":1}', secret: "whsec_dGVzdA==" };
  const sig = signWebhook(args);
  assert.match(sig, /^v1,/);
  assert.equal(sig, signWebhook(args)); // deterministic
  assert.ok(verifyWebhook({ ...args, signatureHeader: sig }));
});

test("verifyWebhook rejects a wrong signature / tampered body", () => {
  const base = { id: "msg_1", timestampSec: 1700000000, secret: "sekret" };
  const sig = signWebhook({ ...base, body: '{"a":1}' });
  assert.ok(!verifyWebhook({ ...base, body: '{"a":2}', signatureHeader: sig }));
  assert.ok(!verifyWebhook({ ...base, body: '{"a":1}', signatureHeader: "v1,bogus" }));
});

test("decodeSecret handles whsec_ and raw secrets distinctly", () => {
  assert.deepEqual(decodeSecret("whsec_dGVzdA=="), Buffer.from("test"));
  assert.deepEqual(decodeSecret("raw"), Buffer.from("raw", "utf8"));
});

test("buildHeaders sets webhook-* and mirrors idempotency-key", () => {
  const h = buildHeaders({ id: "fire#1", timestampSec: 5, body: "{}", secret: "s" });
  assert.equal(h["webhook-id"], "fire#1");
  assert.equal(h["idempotency-key"], "fire#1");
  assert.equal(h["webhook-timestamp"], "5");
  assert.match(h["webhook-signature"], /^v1,/);
});

test("backoffDelayMs grows exponentially and is capped", () => {
  assert.equal(backoffDelayMs(1, 500, 30000), 0); // first attempt: no wait
  assert.equal(backoffDelayMs(2, 500, 30000), 500);
  assert.equal(backoffDelayMs(3, 500, 30000), 1000);
  assert.equal(backoffDelayMs(4, 500, 30000), 2000);
  assert.equal(backoffDelayMs(20, 500, 30000), 30000); // capped
});

test("deliverWebhook treats 2xx as ok, non-2xx as failure", async () => {
  const ok = await deliverWebhook({
    target: "https://example.com/hook",
    body: { x: 1 },
    secret: "s",
    idempotencyKey: "k",
    nowSec: 1,
    fetchFn: async () => ({ status: 204 }),
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.status, 204);

  const bad = await deliverWebhook({
    target: "https://example.com/hook",
    body: { x: 1 },
    secret: "s",
    idempotencyKey: "k",
    nowSec: 1,
    fetchFn: async () => ({ status: 500 }),
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.status, 500);
});

test("deliverWebhook captures a thrown transport error without throwing", async () => {
  const res = await deliverWebhook({
    target: "https://example.com/hook",
    body: {},
    secret: "s",
    idempotencyKey: "k",
    nowSec: 1,
    fetchFn: async () => {
      throw new Error("ECONNREFUSED");
    },
  });
  assert.equal(res.ok, false);
  assert.equal(res.status, null);
  assert.match(res.error, /ECONNREFUSED/);
});

test("retry: succeeds after transient failures, no real sleeping", async () => {
  let calls = 0;
  const sleeps = [];
  const res = await deliverWithRetry(
    async () => {
      calls++;
      return calls < 3 ? { ok: false, status: 503, error: "busy" } : { ok: true, status: 200, error: null };
    },
    { maxAttempts: 5, sleep: async (ms) => void sleeps.push(ms) },
  );
  assert.equal(res.ok, true);
  assert.equal(res.attempts, 3);
  assert.equal(res.deadLettered, false);
  assert.deepEqual(sleeps, [500, 1000]); // backoff before attempts 2 and 3
});

test("idempotency: the SAME webhook-id is reused on every retry", async () => {
  const seenIds = [];
  let calls = 0;
  await deliverWithRetry(
    () =>
      deliverWebhook({
        target: "https://example.com/hook",
        body: { n: 1 },
        secret: "s",
        idempotencyKey: "fire#42", // stable key
        nowSec: 1,
        fetchFn: async (_url, init) => {
          seenIds.push(init.headers["webhook-id"]);
          calls++;
          return calls < 3 ? { status: 500 } : { status: 200 };
        },
      }),
    { sleep: async () => {} },
  );
  assert.equal(seenIds.length, 3);
  assert.ok(seenIds.every((id) => id === "fire#42"), "every retry carried the same idempotency key");
});

test("dead-letter: exhausting all attempts flags deadLettered", async () => {
  let calls = 0;
  const res = await deliverWithRetry(
    async () => {
      calls++;
      return { ok: false, status: 500, error: "down" };
    },
    { maxAttempts: 4, sleep: async () => {} },
  );
  assert.equal(res.ok, false);
  assert.equal(res.attempts, 4);
  assert.equal(calls, 4);
  assert.equal(res.deadLettered, true);
  assert.equal(res.lastStatus, 500);
});
