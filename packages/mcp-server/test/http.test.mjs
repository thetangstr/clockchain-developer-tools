// Unit tests for HTTP auth (pure, no port binding).
import { test } from "node:test";
import assert from "node:assert/strict";
import { isAuthorized, parseTokens, isHealthCheck, callerKey, createRateLimiter, pathOf, presentedApiKey, clockchainOverridesFromKey, clientIp } from "../dist/http.js";

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
  for (let i = 0; i < 1000; i++) assert.equal(rl.allow("k", 1000), true);
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
  assert.equal(rl.allow("ip", 0), true);
  assert.equal(rl.allow("ip", 1000), true);
  assert.equal(rl.allow("ip", 2000), false);       // over limit within the hour
  assert.equal(rl.allow("ip", 59 * 60_000), false); // still within the hour window
  assert.equal(rl.allow("ip", 60 * 60_000 + 1), true); // window rolled over
});

test("rate limiter enforces per-key fixed window", () => {
  const rl = createRateLimiter(2);
  assert.equal(rl.allow("a", 0), true);   // 1
  assert.equal(rl.allow("a", 10), true);  // 2
  assert.equal(rl.allow("a", 20), false); // over limit in window
  assert.equal(rl.allow("b", 20), true);  // different key unaffected
  assert.equal(rl.allow("a", 60_001), true); // window rolled over
});
