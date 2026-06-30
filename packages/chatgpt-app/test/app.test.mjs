// Scaffold smoke tests for the Clockchain ChatGPT app (Apps SDK = MCP).
//
// Offline. Verifies the time-only curated tool surface (get_time, get_timestamp),
// the Apps SDK read-only annotations/hints, the (orphaned but still-registered)
// widget resource, and the dev-mode x-api-key auth resolution.
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerAppTools } from "../dist/tools.js";
import { buildServer } from "../dist/index.js";
import { resolveOverride } from "../dist/http.js";
import {
  RECEIPT_WIDGET_URI,
  RECEIPT_WIDGET_MIME,
  buildReceiptWidgetHtml,
} from "../dist/widget.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

function collect() {
  const tools = {};
  const resources = {};
  const server = {
    registerTool: (name, config, handler) => {
      tools[name] = { config, handler };
    },
    registerResource: (name, uri, config, read) => {
      resources[name] = { uri, config, read };
    },
  };
  registerAppTools(server, cfg);
  return { tools, server, resources };
}

const CURATED = ["get_time", "get_timestamp"];

test("exposes exactly the curated tool subset", () => {
  const { tools } = collect();
  assert.deepEqual(Object.keys(tools).sort(), [...CURATED].sort());
});

test("read-only tools carry readOnlyHint", () => {
  const { tools } = collect();
  for (const name of ["get_time", "get_timestamp"]) {
    const a = tools[name].config.annotations;
    assert.equal(a.readOnlyHint, true, `${name} readOnlyHint`);
    assert.equal(a.destructiveHint, false, `${name} destructiveHint`);
  }
});

test("widget resource: skybridge mime + self-contained HTML with the bundle inlined", () => {
  assert.equal(RECEIPT_WIDGET_URI, "ui://widget/receipt.html");
  assert.equal(RECEIPT_WIDGET_MIME, "text/html+skybridge");
  const html = buildReceiptWidgetHtml();
  assert.match(html, /id="receipt-root"/, "has the widget root element");
  assert.match(html, /<script type="module">/, "inlines the bundled module");
  assert.match(html, /Content-Security-Policy/, "includes a basic CSP");
});

test("buildServer constructs without throwing (registers tools + widget resource)", () => {
  const server = buildServer({ apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" });
  assert.ok(server, "buildServer returns a server");
});

test("dev-mode auth: allowlisted tester key vs BYO key vs none", () => {
  // Allowlisted tester key -> delegated env key (empty override).
  assert.deepEqual(resolveOverride({ "x-api-key": "tester1" }, ["tester1"]), {});
  // Some other key -> BYO override carrying that key.
  assert.deepEqual(resolveOverride({ "x-api-key": "ck_abc" }, ["tester1"]), { apiKey: "ck_abc" });
  // No key -> null (401).
  assert.equal(resolveOverride({}, ["tester1"]), null);
});
