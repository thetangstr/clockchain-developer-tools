// The marketing landing page is a static string served at GET / (browser) on the
// MCP host. Keep a light guard on its key content + the install/endpoint facts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { LANDING_HTML, INSTALL_TXT, MCP_MANIFEST } from "../dist/landing.js";

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
  // Links humans to the live status dashboard (the working URL until status DNS lands).
  assert.match(LANDING_HTML, /clockchain-research\.vercel\.app\/dashboard/);
});

test("landing page clearly calls out testnet", () => {
  assert.match(LANDING_HTML, /Testnet/);
});

test("INSTALL_TXT (served at /llms.txt) gives agents a header-agnostic connect guide", () => {
  // The exact facts an agent needs to connect, in plain text.
  assert.match(INSTALL_TXT, /https:\/\/mcp\.clockchain\.network\/mcp/);
  assert.match(INSTALL_TXT, /x-api-key/);
  assert.match(INSTALL_TXT, /mcp-remote/); // stdio-only fallback
  assert.match(INSTALL_TXT, /mcpServers/); // the JSON config block
  // Must steer agents away from hunting for a package to install.
  assert.match(INSTALL_TXT, /NO package to install/i);
  assert.doesNotMatch(INSTALL_TXT, /npm install clockchain/i);
  // Both credential types must be documented co-equally (BYO is not "advanced").
  assert.match(INSTALL_TXT, /x-clockchain-api-key/);
  assert.match(INSTALL_TXT, /pick ONE/i);
});

test("MCP_MANIFEST (served at /.well-known/mcp.json) is self-configuring + remote-only", () => {
  assert.equal(MCP_MANIFEST.endpoint, "https://mcp.clockchain.network/mcp");
  assert.equal(MCP_MANIFEST.type, "http");
  assert.equal(MCP_MANIFEST.remote, true);
  assert.equal(MCP_MANIFEST.package, null); // no package to hunt for
  // Two co-equal auth methods: MCP token (x-api-key) and BYO Clockchain key.
  const methodHeaders = MCP_MANIFEST.authentication.methods.flatMap(
    (m) => m.header ?? m.headers,
  );
  assert.ok(methodHeaders.includes("x-api-key"));
  assert.ok(methodHeaders.includes("x-clockchain-api-key"));
  // The embedded MCP config must be valid JSON pointing at the real endpoint.
  assert.equal(
    MCP_MANIFEST.install.mcpConfig.mcpServers.clockchain.url,
    "https://mcp.clockchain.network/mcp",
  );
  // Must round-trip through JSON.stringify (it's served that way).
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(MCP_MANIFEST)));
});
