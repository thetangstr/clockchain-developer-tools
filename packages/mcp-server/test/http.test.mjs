// Unit tests for HTTP auth (pure, no port binding).
import { test } from "node:test";
import assert from "node:assert/strict";
import { isAuthorized, parseTokens, isHealthCheck, callerKey, createRateLimiter, rateLimitHeaders, sanitizeSub, pathOf, presentedApiKey, clockchainOverridesFromKey, clientIp } from "../dist/http.js";
import { mintToken } from "../dist/token.js";

const tokens = ["tester-a", "tester-b"];

test("parseTokens splits, trims, and drops empties", () => {
  assert.deepEqual(parseTokens("a, b ,,c"), ["a", "b", "c"]);
  assert.deepEqual(parseTokens(""), []);
  assert.deepEqual(parseTokens(undefined), []);
});

test("open auth when no tokens configured", () => {
  assert.equal(isAuthorized({}, []), true);
});

test("accepts a valid Bearer token", () => {
  assert.equal(isAuthorized({ authorization: "Bearer tester-a" }, tokens), true);
});

test("accepts a valid x-api-key token", () => {
  assert.equal(isAuthorized({ "x-api-key": "tester-b" }, tokens), true);
});

test("rejects missing / wrong / malformed tokens", () => {
  assert.equal(isAuthorized({}, tokens), false);
  assert.equal(isAuthorized({ authorization: "Bearer nope" }, tokens), false);
  assert.equal(isAuthorized({ "x-api-key": "nope" }, tokens), false);
  assert.equal(isAuthorized({ authorization: "tester-a" }, tokens), false); // missing Bearer scheme
});

test("handles array-valued headers", () => {
  assert.equal(isAuthorized({ authorization: ["Bearer tester-a"] }, tokens), true);
});

test("isHealthCheck matches GET /health and /healthz only", () => {
  assert.equal(isHealthCheck("GET", "/health"), true);
  assert.equal(isHealthCheck("GET", "/healthz"), true);
  assert.equal(isHealthCheck("POST", "/health"), false);
  assert.equal(isHealthCheck("GET", "/mcp"), false);
  assert.equal(isHealthCheck("GET", "/"), false);
  assert.equal(isHealthCheck(undefined, undefined), false);
});

test("presentedApiKey reads x-api-key, else Bearer, x-api-key wins", () => {
  assert.equal(presentedApiKey({ "x-api-key": "k" }), "k");
  assert.equal(presentedApiKey({ authorization: "Bearer b" }), "b");
  assert.equal(presentedApiKey({ "x-api-key": "k", authorization: "Bearer b" }), "k");
  assert.equal(presentedApiKey({}), "");
  assert.equal(presentedApiKey({ authorization: "k" }), ""); // missing Bearer scheme
});

test("clockchainOverridesFromKey builds a BYO override (forgiving fallback)", () => {
  assert.deepEqual(clockchainOverridesFromKey("ck", {}), { apiKey: "ck" });
  assert.deepEqual(
    clockchainOverridesFromKey("ck", {
      "x-clockchain-client-id": "you@x.com",
      "x-clockchain-wallet-id": "you@x.com",
    }),
    { apiKey: "ck", clientId: "you@x.com", walletId: "you@x.com" },
  );
});

test("pathOf strips the query string (used to match /llms.txt)", () => {
  assert.equal(pathOf("/llms.txt"), "/llms.txt");
  assert.equal(pathOf("/llms.txt?ref=hermes"), "/llms.txt");
  assert.equal(pathOf("/mcp"), "/mcp");
  assert.equal(pathOf(undefined), "");
});

test("callerKey keys on token when present, else IP", () => {
  assert.equal(callerKey({ authorization: "Bearer tester-a" }, "1.2.3.4"), "tok:tester-a");
  assert.equal(callerKey({ "x-api-key": "tester-b" }, "1.2.3.4"), "tok:tester-b");
  assert.equal(callerKey({}, "1.2.3.4"), "ip:1.2.3.4");
  assert.equal(callerKey({}, undefined), "ip:unknown");
});

test("rate limiter disabled when perMin <= 0 (always allows)", () => {
  const rl = createRateLimiter(0);
  assert.equal(rl.enabled, false);
  for (let i = 0; i < 1000; i++) assert.equal(rl.allow("k", 1000).allowed, true);
});

test("clientIp prefers X-Forwarded-For (real client behind the LB), else socket addr", () => {
  // Behind the GCP LB the socket addr is a proxy; XFF carries the real client.
  assert.equal(clientIp({ "x-forwarded-for": "203.0.113.7, 35.191.0.1" }, "10.0.0.1"), "203.0.113.7");
  assert.equal(clientIp({ "x-forwarded-for": " 198.51.100.2 " }, "10.0.0.1"), "198.51.100.2");
  assert.equal(clientIp({}, "10.0.0.1"), "10.0.0.1"); // no XFF → socket addr
  assert.equal(clientIp({}, undefined), "unknown");
  assert.equal(clientIp({ "x-forwarded-for": ["1.1.1.1, 2.2.2.2"] }, "10.0.0.1"), "1.1.1.1");
});

test("rate limiter honors a custom window (e.g. hourly mint limit)", () => {
  const rl = createRateLimiter(2, 60 * 60_000); // 2 per hour
  assert.equal(rl.allow("ip", 0).allowed, true);
  assert.equal(rl.allow("ip", 1000).allowed, true);
  assert.equal(rl.allow("ip", 2000).allowed, false);       // over limit within the hour
  assert.equal(rl.allow("ip", 59 * 60_000).allowed, false); // still within the hour window
  assert.equal(rl.allow("ip", 60 * 60_000 + 1).allowed, true); // window rolled over
});

test("rate limiter enforces per-key fixed window", () => {
  const rl = createRateLimiter(2);
  assert.equal(rl.allow("a", 0).allowed, true);   // 1
  assert.equal(rl.allow("a", 10).allowed, true);  // 2
  assert.equal(rl.allow("a", 20).allowed, false); // over limit in window
  assert.equal(rl.allow("b", 20).allowed, true);  // different key unaffected
  assert.equal(rl.allow("a", 60_001).allowed, true); // window rolled over
});

// --- per-user auth: rate-limit metadata + headers --------------------------------

test("allow() returns {allowed,limit,remaining,resetAt} metadata", () => {
  const rl = createRateLimiter(3, 60_000);
  assert.deepEqual(rl.allow("k", 0), { allowed: true, limit: 3, remaining: 2, resetAt: 60_000 });
  assert.deepEqual(rl.allow("k", 10), { allowed: true, limit: 3, remaining: 1, resetAt: 60_000 });
  assert.deepEqual(rl.allow("k", 20), { allowed: true, limit: 3, remaining: 0, resetAt: 60_000 });
  // over limit: blocked, no remaining, resetAt unchanged
  assert.deepEqual(rl.allow("k", 30), { allowed: false, limit: 3, remaining: 0, resetAt: 60_000 });
});

test("rateLimitHeaders sets X-RateLimit-* always and Retry-After only on 429", () => {
  // allowed → no Retry-After
  const ok = rateLimitHeaders({ allowed: true, limit: 10, remaining: 4, resetAt: 120_000 }, 60_000);
  assert.equal(ok["X-RateLimit-Limit"], "10");
  assert.equal(ok["X-RateLimit-Remaining"], "4");
  assert.equal(ok["X-RateLimit-Reset"], "120"); // unix seconds
  assert.equal("Retry-After" in ok, false);

  // blocked → Retry-After = ceil((resetAt-now)/1000)
  const blocked = rateLimitHeaders({ allowed: false, limit: 10, remaining: 0, resetAt: 120_500 }, 60_000);
  assert.equal(blocked["Retry-After"], "61"); // ceil(60.5s)
  assert.equal(blocked["X-RateLimit-Remaining"], "0");
});

test("callerKey buckets a self-serve request on its (verified) jti, never sub", () => {
  // The handler threads in the ALREADY-VERIFIED jti; callerKey keys on it.
  assert.equal(callerKey({ "x-api-key": "cc_whatever.sig" }, "9.9.9.9", "jti-1"), "jti:jti-1");
  // No jti threaded → key on the raw token value.
  assert.equal(callerKey({ "x-api-key": "team-token" }, "9.9.9.9"), "tok:team-token");
  // Bearer token, no jti → raw token value.
  assert.equal(callerKey({ authorization: "Bearer tok-b" }, "9.9.9.9"), "tok:tok-b");
  // BYO key (no MCP token) → keyed by the authenticated Clockchain key.
  assert.equal(callerKey({ "x-clockchain-api-key": "ck" }, "9.9.9.9"), "cck:ck");
  // Nothing → IP fallback.
  assert.equal(callerKey({}, "9.9.9.9"), "ip:9.9.9.9");
});

test("SECURITY: callerKey never buckets on an attacker-chosen sub (per-user auth)", () => {
  const SECRET = "rk-secret";
  // Two tokens minted with the SAME sub but distinct jti must land in DISTINCT
  // buckets — otherwise an attacker minting sub=victim could burn a victim's
  // bucket. We pass the verified jti (what the handler does); sub is ignored.
  const { payload: a } = mintToken(SECRET, 3600, undefined, "victim@x.com", "jti-A");
  const { payload: b } = mintToken(SECRET, 3600, undefined, "victim@x.com", "jti-B");
  const keyA = callerKey({ "x-api-key": "cc_a.sig" }, "1.1.1.1", a.jti);
  const keyB = callerKey({ "x-api-key": "cc_b.sig" }, "1.1.1.1", b.jti);
  assert.notEqual(keyA, keyB);
  assert.equal(keyA, "jti:jti-A");
  assert.equal(keyB, "jti:jti-B");
});

test("sanitizeSub strips unsafe chars, caps length, drops empties (per-user auth)", () => {
  assert.equal(sanitizeSub("user@example.com"), "user@example.com");
  assert.equal(sanitizeSub("ok.name_123:tag+x-y"), "ok.name_123:tag+x-y");
  // control chars / newlines (log injection) removed
  assert.equal(sanitizeSub("a\nb\r\tc\x00d"), "abcd");
  // disallowed punctuation/spaces removed
  assert.equal(sanitizeSub("a b/c<script>"), "abcscript");
  // capped at 128 chars
  assert.equal(sanitizeSub("x".repeat(500)).length, 128);
  // empty / nothing-left → undefined
  assert.equal(sanitizeSub(""), undefined);
  assert.equal(sanitizeSub("   "), undefined); // spaces all stripped
  assert.equal(sanitizeSub(undefined), undefined);
});

test("rate limiter evicts expired entries to bound memory (per-user auth)", () => {
  const rl = createRateLimiter(5, 1000); // window + prune-interval = 1000ms
  // Fill window 1 with many distinct keys (e.g. attacker rotating jti/IP).
  for (let i = 0; i < 20; i++) rl.allow(`k${i}`, 0);
  assert.equal(rl.size(), 20);
  // A call past the prune interval triggers a full sweep of expired windows.
  rl.allow("fresh", 1001); // now >= resetAt(1000) for all k* → all evicted
  assert.equal(rl.size(), 1); // only "fresh" remains
});
