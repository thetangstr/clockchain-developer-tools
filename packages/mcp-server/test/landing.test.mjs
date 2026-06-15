// The marketing landing page is a static string served at GET / (browser) on the
// MCP host. Keep a light guard on its key content + the install/endpoint facts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { LANDING_HTML } from "../dist/landing.js";

test("landing page is well-formed HTML with the core message", () => {
  assert.match(LANDING_HTML, /^<!doctype html>/i);
  assert.match(LANDING_HTML, /<\/html>\s*$/i);
  assert.match(LANDING_HTML, /Clockchain/);
  assert.match(LANDING_HTML, /modules/i);
  assert.match(LANDING_HTML, /\b31\b/);
});

test("landing page points agents at the real endpoint + key headers, not a fake", () => {
  assert.match(LANDING_HTML, /https:\/\/mcp\.clockchain\.network\/mcp/);
  assert.match(LANDING_HTML, /x-api-key/);
  // Links humans to the live status dashboard.
  assert.match(LANDING_HTML, /status\.clockchain\.network/);
});
