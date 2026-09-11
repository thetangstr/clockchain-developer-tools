// The marketing landing page is a static string served at GET / (browser) on the
// MCP host. Keep a light guard on its key content + the install/endpoint facts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { LANDING_HTML, INSTALL_TXT, MCP_MANIFEST, TOOL_COUNT, MODULE_COUNT } from "../dist/landing.js";
import { registerTools } from "../dist/tools.js";

// The number of tools actually registered on the full surface — what an agent
// sees in tools/list. The page must never claim a different number.
function registeredToolCount() {
  const names = [];
  registerTools(
    { registerTool: (name) => { names.push(name); } },
    { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" },
    {},
  );
  return names.length;
}

test("landing page is well-formed HTML with the core message", () => {
  assert.match(LANDING_HTML, /^<!doctype html>/i);
  assert.match(LANDING_HTML, /<\/html>\s*$/i);
  assert.match(LANDING_HTML, /Clockchain/);
  assert.match(LANDING_HTML, /modules/i);
});

test("every tool/module count on the page is derived from the registered surface (no drift)", () => {
  const registered = registeredToolCount();
  assert.equal(TOOL_COUNT, registered, "TOOL_COUNT must equal the registered full-surface tool count");
  // Hero, stat strip, install step, meta tags all carry the same number...
  const hits = LANDING_HTML.match(new RegExp(`\\b${registered} tools\\b`, "g")) ?? [];
  assert.ok(hits.length >= 3, `expected the tool count in hero/meta/install, found ${hits.length}`);
  assert.match(LANDING_HTML, new RegExp(`<div class="k">Tools</div><div class="v">${registered}</div>`));
  assert.match(LANDING_HTML, new RegExp(`<div class="k">Modules</div><div class="v">${MODULE_COUNT}</div>`));
  // ...and the stale literals never come back.
  assert.doesNotMatch(LANDING_HTML, /\b31 tools\b|>31<|>6</);
  assert.doesNotMatch(LANDING_HTML, /Six modules|six modules/);
  assert.match(INSTALL_TXT, new RegExp(`\\(${registered} tools\\)`));
});

test("landing page lists the verified time tools module (stopwatch / timer / alarm)", () => {
  assert.match(LANDING_HTML, /Verified time tools/);
  assert.match(LANDING_HTML, /Stopwatch, timer, alarm/);
  // The hosted tools are named, and the claim stays honest about the substrate.
  assert.match(LANDING_HTML, /timer_set \/ alarm_set/);
  // D7: the page names the real substrate (network or owned gateway), never implies more.
  assert.match(LANDING_HTML, /anchoring gateway \(testnet, single operator\)|single-validator Clockchain testnet/);
  assert.match(LANDING_HTML, /not yet attested by an independent validator set/);
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
  assert.match(MCP_MANIFEST.description, new RegExp(`${TOOL_COUNT} tools`));
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
