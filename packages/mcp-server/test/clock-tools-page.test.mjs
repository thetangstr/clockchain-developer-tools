// The clock-tools guide (/clock-tools for people, /clock-tools.txt for agents) must
// name exactly the tools and arguments the server registers, be reachable from the
// landing page, llms.txt and the manifest, and render the same facts both ways.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CLOCK_TOOLS_HTML, CLOCK_TOOLS_TXT } from "../dist/clock-tools-page.js";
import { LANDING_HTML, INSTALL_TXT, MCP_MANIFEST } from "../dist/landing.js";
import { registerTools } from "../dist/tools.js";

const CLOCK_TOOLS = ["stopwatch_start", "stopwatch_stop", "stopwatch_verify", "timer_set", "alarm_set", "timer_status", "timer_cancel", "timer_list"];

function registered() {
  const metas = {};
  registerTools({ registerTool: (name, cfg) => { metas[name] = cfg; } }, { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" }, {});
  return metas;
}

test("both renderings name every clock tool and every argument the server actually registers", () => {
  const metas = registered();
  for (const page of [CLOCK_TOOLS_HTML, CLOCK_TOOLS_TXT]) {
    for (const tool of CLOCK_TOOLS) {
      assert.ok(metas[tool], `${tool} must be registered`);
      assert.ok(page.includes(tool), `guide must mention ${tool}`);
      for (const arg of Object.keys(metas[tool].inputSchema)) {
        assert.ok(page.includes(arg), `guide must name ${tool}'s argument ${arg}`);
      }
    }
    // the keyless verification path the recipe relies on
    assert.ok(page.includes("verify_cross_party") && page.includes("verify_receipt"));
    // no argument the server does not have (the page invents nothing)
    for (const ghost of ["duration_ms", "alarm_cancel", "alarm_status", "timer_get"]) assert.ok(!page.includes(ghost), ghost);
  }
});

test("the bounds on the page are the bounds in the schemas", () => {
  const { timer_set, alarm_set } = registered();
  const delay = timer_set.inputSchema.delay_ms;
  assert.equal(delay.minValue, 1000);
  assert.equal(delay.maxValue, 30 * 24 * 60 * 60 * 1000);
  assert.equal(alarm_set.inputSchema.every_ms._def.innerType.minValue, 60000);
  for (const page of [CLOCK_TOOLS_HTML, CLOCK_TOOLS_TXT]) {
    assert.ok(page.includes("1000") && page.includes("2592000000"), "delay bounds");
    assert.ok(page.includes("60000"), "interval floor");
    assert.ok(page.includes("30 days") || page.includes("30 d"), "horizon");
  }
});

test("the guide is a proper page in the site's chrome and has an agent-readable twin", () => {
  assert.match(CLOCK_TOOLS_HTML, /^<!doctype html>/i);
  assert.match(CLOCK_TOOLS_HTML, /<\/html>\s*$/i);
  assert.ok(CLOCK_TOOLS_HTML.includes('rel="alternate" type="text/plain" href="/clock-tools.txt"'));
  assert.ok(CLOCK_TOOLS_HTML.includes('href="/#install"'), "links back to the install step");
  assert.ok(CLOCK_TOOLS_HTML.includes("/llms.txt"));
  assert.doesNotMatch(CLOCK_TOOLS_TXT, /<\/?(div|p|a|section|html|nav|script)\b/, "the text version carries no markup");
  assert.ok(CLOCK_TOOLS_TXT.includes("AGENT RECIPE"));
  assert.ok(CLOCK_TOOLS_TXT.includes("curl -X POST https://mcp.clockchain.network/token"));
});

test("the landing page, llms.txt and the manifest all link to the guide", () => {
  assert.ok(LANDING_HTML.includes('href="/clock-tools"'), "nav/module/footer link");
  assert.ok((LANDING_HTML.match(/href="\/clock-tools"/g) || []).length >= 3, "linked from nav, the module card and the footer");
  assert.ok(INSTALL_TXT.includes("https://mcp.clockchain.network/clock-tools.txt"));
  assert.equal(MCP_MANIFEST.guides.clockTools, "https://mcp.clockchain.network/clock-tools.txt");
});
