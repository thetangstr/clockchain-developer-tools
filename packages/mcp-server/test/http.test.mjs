// Unit tests for HTTP auth (pure, no port binding).
import { test } from "node:test";
import assert from "node:assert/strict";
import { isAuthorized, parseTokens, isHealthCheck } from "../dist/http.js";

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
