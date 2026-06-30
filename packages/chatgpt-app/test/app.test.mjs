// Scaffold smoke tests for the Clockchain ChatGPT app (Apps SDK = MCP).
//
// Offline. Verifies the curated tool surface (the anchor→verify loop), the Apps
// SDK annotations/hints, the verify tool's widget output-template linkage, the
// widget resource registration, the dev-mode x-api-key auth resolution, and —
// load-bearing (CLO-84) — the truthful anchoring status: a verify result that is
// not anchored on-chain is reported as PENDING (confirmed:false), never confirmed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { registerAppTools } from "../dist/tools.js";
import { buildServer } from "../dist/index.js";
import { resolveOverride } from "../dist/http.js";
import {
  RECEIPT_WIDGET_URI,
  RECEIPT_WIDGET_MIME,
  RECEIPT_WIDGET_CSP,
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

const CURATED = ["get_time", "log_action", "verify_cross_party"];

test("exposes exactly the curated tool subset", () => {
  const { tools } = collect();
  assert.deepEqual(Object.keys(tools).sort(), [...CURATED].sort());
});

test("read-only tools carry readOnlyHint; writes are destructive + openWorld", () => {
  const { tools } = collect();
  for (const name of ["get_time", "verify_cross_party"]) {
    const a = tools[name].config.annotations;
    assert.equal(a.readOnlyHint, true, `${name} readOnlyHint`);
    assert.equal(a.destructiveHint, false, `${name} destructiveHint`);
  }
  for (const name of ["log_action"]) {
    const a = tools[name].config.annotations;
    assert.equal(a.readOnlyHint, false, `${name} readOnlyHint`);
    assert.equal(a.destructiveHint, true, `${name} destructiveHint`);
    assert.equal(a.openWorldHint, true, `${name} openWorldHint`);
  }
});

test("verify_cross_party links the widget via openai/outputTemplate", () => {
  const { tools } = collect();
  for (const name of ["verify_cross_party"]) {
    assert.equal(
      tools[name].config._meta["openai/outputTemplate"],
      "ui://widget/receipt.html",
      `${name} outputTemplate`,
    );
    assert.ok(tools[name].config.outputSchema, `${name} has an outputSchema`);
  }
});

test("widget resource: skybridge mime + self-contained HTML with the bundle inlined + CSP", () => {
  assert.equal(RECEIPT_WIDGET_URI, "ui://widget/receipt.html");
  assert.equal(RECEIPT_WIDGET_MIME, "text/html+skybridge");
  const html = buildReceiptWidgetHtml();
  assert.match(html, /id="receipt-root"/, "has the widget root element");
  assert.match(html, /<script type="module">/, "inlines the bundled module");
  assert.match(html, /Content-Security-Policy/, "includes an in-document CSP");
  // Host-enforced CSP (openai/widgetCSP): tight connect/resource allowlists.
  assert.ok(Array.isArray(RECEIPT_WIDGET_CSP.connect_domains), "host CSP connect_domains");
  assert.ok(Array.isArray(RECEIPT_WIDGET_CSP.resource_domains), "host CSP resource_domains");
});

test("buildServer constructs without throwing (registers tools + widget resource)", () => {
  const server = buildServer({ apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" });
  assert.ok(server, "buildServer returns a server");
});

test("truthful anchoring: an un-anchored verify result is PENDING, never confirmed", async () => {
  // Fail all upstream calls so nothing resolves to an on-chain block.
  globalThis.fetch = async () => ({
    status: 400,
    ok: false,
    statusText: "bad request",
    text: async () => JSON.stringify({ message: "upstream rejected" }),
  });
  const { tools } = collect();
  const res = await tools.verify_cross_party.handler({ ledger_id: "L1" });
  assert.ok(res.structuredContent, "returns structuredContent for the widget");
  assert.equal(res.structuredContent.confirmed, false, "not confirmed");
  assert.notEqual(res.structuredContent.status, "anchored", "status is not anchored");
});

test("dev-mode auth: allowlisted tester key vs BYO key vs none", () => {
  // Allowlisted tester key -> delegated env key (empty override).
  assert.deepEqual(resolveOverride({ "x-api-key": "tester1" }, ["tester1"]), {});
  // Some other key -> BYO override carrying that key.
  assert.deepEqual(resolveOverride({ "x-api-key": "ck_abc" }, ["tester1"]), { apiKey: "ck_abc" });
  // No key -> null (401).
  assert.equal(resolveOverride({}, ["tester1"]), null);
});
