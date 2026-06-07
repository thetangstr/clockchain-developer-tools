// Unit tests for feedback validation/shaping (pure, no I/O).
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildFeedbackRecord } from "../dist/feedback.js";

const NOW = 1781000000000; // fixed for deterministic ts

test("accepts a valid rating", () => {
  const { record, error } = buildFeedbackRecord({ rating: 4 }, {}, NOW);
  assert.equal(error, undefined);
  assert.equal(record.rating, 4);
  assert.equal(record.message, "");
  assert.equal(record.ts, new Date(NOW).toISOString());
});

test("accepts a message with no rating", () => {
  const { record, error } = buildFeedbackRecord({ message: "  loved it  " }, {}, NOW);
  assert.equal(error, undefined);
  assert.equal(record.rating, null);
  assert.equal(record.message, "loved it"); // trimmed
});

test("rejects empty submission", () => {
  const { record, error } = buildFeedbackRecord({}, {}, NOW);
  assert.equal(record, undefined);
  assert.match(error, /rating.*or.*message/i);
});

test("rejects out-of-range / non-integer ratings (treated as no rating)", () => {
  assert.ok(buildFeedbackRecord({ rating: 6 }, {}, NOW).error);
  assert.ok(buildFeedbackRecord({ rating: 0 }, {}, NOW).error);
  assert.ok(buildFeedbackRecord({ rating: 3.5 }, {}, NOW).error);
});

test("captures Cloudflare Access email when present", () => {
  const { record } = buildFeedbackRecord(
    { rating: 5 },
    { "cf-access-authenticated-user-email": "exec@company.com" },
    NOW,
  );
  assert.equal(record.email, "exec@company.com");
});

test("caps message and role length", () => {
  const { record } = buildFeedbackRecord(
    { message: "x".repeat(5000), role: "y".repeat(500) },
    {},
    NOW,
  );
  assert.equal(record.message.length, 4000);
  assert.equal(record.role.length, 200);
});
