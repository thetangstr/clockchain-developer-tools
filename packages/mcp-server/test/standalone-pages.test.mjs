import { test } from "node:test";
import assert from "node:assert/strict";

import { INSTALL_TXT, LANDING_HTML } from "../dist/landing.js";
import { buildStandaloneDiscovery } from "../dist/standalone-handshake/public-server.js";

test("the landing page announces Standalone Handshake and stays consistent", () => {
  assert.match(LANDING_HTML, /Standalone Handshake/);
  assert.match(LANDING_HTML, /\/connect\/mcp/);
  // The module badge renders zero-padded ("08"); a bare "8" could match anywhere.
  assert.match(LANDING_HTML, /08/);
});

test("llms.txt carries the agent-readable handshake facts", () => {
  assert.match(INSTALL_TXT, /standalone-handshake/);
  assert.match(INSTALL_TXT, /\/connect\/mcp/);
  assert.match(INSTALL_TXT, /channel_open/);
  assert.match(INSTALL_TXT, /Consent covers communication only/);
});

test("the discovery manifest matches what the page promises", () => {
  const discovery = buildStandaloneDiscovery();
  assert.match(LANDING_HTML, new RegExp(discovery.endpoint.replace(/\//g, "\\/")));
  // A path-prefixed deployment passes its own endpoint through verbatim — the
  // manifest must advertise where this instance actually answers.
  const staged = buildStandaloneDiscovery("https://mcp.clockchain.network/staging/connect/mcp");
  assert.equal(staged.endpoint, "https://mcp.clockchain.network/staging/connect/mcp");
});
