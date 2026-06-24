// Unit tests for the gateway time parser/formatter. No network, no timers.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseGatewayTime,
  formatGatewayTime,
  isGatewayTime,
} from "../dist/index.js";

test("parses get_timestamp shape DD-MM-YYYY_HH:MM:SS:mmm as UTC", () => {
  // 24-06-2026 22:49:40.092 UTC
  const expected = Date.UTC(2026, 5, 24, 22, 49, 40, 92);
  assert.equal(parseGatewayTime("24-06-2026_22:49:40:092"), expected);
});

test("parses log createdTimestamp shape DD-MM-YYYY HH:MM:SS:mmm UTC as UTC", () => {
  const expected = Date.UTC(2026, 5, 24, 22, 49, 48, 434);
  assert.equal(parseGatewayTime("24-06-2026 22:49:48:434 UTC"), expected);
});

test("does NOT mis-parse DD-MM month-first (the V8 trap)", () => {
  // 11-06-2026 must be 11 June, not 6 November.
  const june11 = parseGatewayTime("11-06-2026_14:41:29:089");
  assert.equal(new Date(june11).getUTCMonth(), 5); // June (0-indexed)
  assert.equal(new Date(june11).getUTCDate(), 11);
});

test("both gateway shapes for the same instant agree", () => {
  const a = parseGatewayTime("24-06-2026_22:49:40:092");
  const b = parseGatewayTime("24-06-2026 22:49:40:092 UTC");
  assert.equal(a, b);
});

test("formatGatewayTime round-trips with parseGatewayTime", () => {
  const epoch = Date.UTC(2026, 5, 24, 22, 49, 48, 434);
  const formatted = formatGatewayTime(epoch);
  assert.equal(formatted, "24-06-2026 22:49:48:434 UTC");
  assert.equal(parseGatewayTime(formatted), epoch);
});

test("formatGatewayTime zero-pads all fields", () => {
  const epoch = Date.UTC(2026, 0, 5, 3, 7, 9, 4); // 05-01-2026 03:07:09:004
  assert.equal(formatGatewayTime(epoch), "05-01-2026 03:07:09:004 UTC");
});

test("ISO and numeric fallbacks still parse", () => {
  assert.equal(parseGatewayTime("2026-06-24T22:49:40.092Z"), Date.UTC(2026, 5, 24, 22, 49, 40, 92));
  assert.equal(parseGatewayTime(1750805380092), 1750805380092); // epoch ms
  assert.equal(parseGatewayTime(1750805380), 1750805380 * 1000); // epoch s
});

test("unparseable input is NaN; isGatewayTime is precise", () => {
  assert.ok(Number.isNaN(parseGatewayTime("not a time")));
  assert.ok(Number.isNaN(parseGatewayTime("")));
  assert.ok(isGatewayTime("24-06-2026_22:49:40:092"));
  assert.ok(isGatewayTime("24-06-2026 22:49:40:092 UTC"));
  assert.ok(!isGatewayTime("2026-06-24T22:49:40Z"));
});

test("formatGatewayTime rejects non-finite input", () => {
  assert.throws(() => formatGatewayTime(NaN), RangeError);
  assert.throws(() => formatGatewayTime(Infinity), RangeError);
});
