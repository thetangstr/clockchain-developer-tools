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

// ---- DNS-pinned delivery (C6) ----
import { createServer } from "node:http";
import { pinnedFetch, deriveOwnerSecret, resolvePinnedAddress, SsrfError } from "../dist/index.js";

test("resolvePinnedAddress refuses a hostname that resolves to ANY private/metadata address (rebinding)", async () => {
  const resolver = async () => [{ address: "93.184.216.34", family: 4 }, { address: "169.254.169.254", family: 4 }];
  await assert.rejects(() => resolvePinnedAddress("hooks.example.com", { resolver }), SsrfError);
  const loop = async () => [{ address: "127.0.0.1", family: 4 }];
  await assert.rejects(() => resolvePinnedAddress("evil.example.com", { resolver: loop }), /private\/loopback\/metadata/);
  const ok = await resolvePinnedAddress("hooks.example.com", { resolver: async () => [{ address: "93.184.216.34", family: 4 }] });
  assert.deepEqual(ok, { address: "93.184.216.34", family: 4 });
  await assert.rejects(() => resolvePinnedAddress("nowhere.example.com", { resolver: async () => [] }), /did not resolve/);
});

test("pinnedFetch connects to the vetted address only, keeps the Host header, never follows redirects", async () => {
  // A local receiver on 127.0.0.1; the "public" hostname resolves to it via a fake
  // resolver, and the request must reach the server through the pinned lookup.
  const seen = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ host: req.headers.host, id: req.headers["webhook-id"], body });
      if (req.url === "/redirect") { res.writeHead(302, { location: "http://127.0.0.1:1/private" }); res.end(); return; }
      res.writeHead(204); res.end();
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const resolver = async () => [{ address: "127.0.0.1", family: 4 }];
  const fetchFn = pinnedFetch({ allowLoopback: true, resolver });
  const r1 = await fetchFn(`http://hooks.example.test:${port}/fire`, { method: "POST", headers: { "webhook-id": "t#1" }, body: '{"a":1}' });
  assert.equal(r1.status, 204);
  assert.equal(seen[0].host, `hooks.example.test:${port}`, "Host header is the hostname, not the pinned IP");
  assert.equal(seen[0].body, '{"a":1}');
  const r2 = await fetchFn(`http://hooks.example.test:${port}/redirect`, { method: "POST", headers: {}, body: "{}" });
  assert.equal(r2.status, 302, "a redirect is returned as-is (non-2xx), never followed");
  assert.equal(seen.length, 2);
  server.close();
});

test("pinnedFetch refuses to connect when the resolved address is private (no allowLoopback)", async () => {
  const fetchFn = pinnedFetch({ resolver: async () => [{ address: "10.0.0.5", family: 4 }] });
  await assert.rejects(() => fetchFn("https://internal.example.com/x", { method: "POST", headers: {}, body: "{}" }), SsrfError);
});

test("deriveOwnerSecret: per-owner, deterministic, whsec_-formatted, verifies the fire signature", () => {
  const server = "whsec_c2VydmVyLXNlY3JldA=="; // "server-secret"
  const a = deriveOwnerSecret(server, "owner-a");
  const b = deriveOwnerSecret(server, "owner-b");
  assert.match(a, /^whsec_[A-Za-z0-9+/=]+$/);
  assert.notEqual(a, b);
  assert.equal(a, deriveOwnerSecret(server, "owner-a"), "deterministic per owner");
  const sig = signWebhook({ id: "t#1", timestampSec: 1700000000, body: '{"x":1}', secret: a });
  assert.ok(verifyWebhook({ id: "t#1", timestampSec: 1700000000, body: '{"x":1}', secret: a, signatureHeader: sig }), "owner verifies with the derived secret");
  assert.ok(!verifyWebhook({ id: "t#1", timestampSec: 1700000000, body: '{"x":1}', secret: b, signatureHeader: sig }), "another owner's secret does not verify");
});
