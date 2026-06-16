// Unit tests for HTTP auth (pure, no port binding).
import { test } from "node:test";
import assert from "node:assert/strict";
import { isAuthorized, parseTokens, isHealthCheck, callerKey, createRateLimiter, pathOf } from "../dist/http.js";

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

test("rate limiter enforces per-key fixed window", () => {
  const rl = createRateLimiter(2);
  assert.equal(rl.allow("a", 0), true);   // 1
  assert.equal(rl.allow("a", 10), true);  // 2
  assert.equal(rl.allow("a", 20), false); // over limit in window
  assert.equal(rl.allow("b", 20), true);  // different key unaffected
  assert.equal(rl.allow("a", 60_001), true); // window rolled over
});
