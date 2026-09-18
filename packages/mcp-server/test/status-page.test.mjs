// Unit tests for the public /status HTML renderer: content, freshness labels,
// honest window claims, escaping, and responsive markup.
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderStatusPage } from "../dist/status-page.js";

const T0 = 1_700_000_000_000;

function makeReport(overrides = {}) {
  return {
    schema: "clockchain.status/v1",
    computedAtMs: T0,
    processStartedAtMs: T0 - 300_000,
    overall: "operational",
    components: {
      mcp_host: { state: "ok", detail: "serving", observedAtMs: T0, meta: { uptimeSeconds: 300 } },
      handshake_surface: { state: "ok", detail: "accepting", observedAtMs: T0 },
      relay_supervisor: { state: "ok", detail: "current session fresh", observedAtMs: T0, latencyMs: 42, meta: { sessionAgeSeconds: 60 } },
      anchoring_gateway: { state: "ok", detail: "reachable", observedAtMs: T0, latencyMs: 80 },
      pool_participation: { state: "ok", detail: "pool participating", observedAtMs: T0, latencyMs: 80, meta: { nodeParticipationPct: 100, totalNodes: 12 } },
      evm_rpc: { state: "ok", detail: "eip155:11155111", observedAtMs: T0, latencyMs: 55 },
    },
    build: { service: "0.1.0", helperVersion: "2.1.6", protocolRepositorySha: "abc123def4567890" },
    lastVerifiedHandshake: { evidence: "fresh", outcome: "VERIFIED", observedAtMs: T0 - 30_000, ageSeconds: 30 },
    window: { label: "live dependency probes; counters since process start", sinceProcessStartMs: T0 - 300_000, cacheTtlMs: 15_000 },
    ...overrides,
  };
}

test("operational report renders the green banner and all component rows", () => {
  const html = renderStatusPage(makeReport());
  assert.match(html, /All systems operational/);
  assert.match(html, /b-operational/);
  for (const label of ["MCP host", "Handshake surface", "Relay / session supervisor", "Anchoring gateway", "Clockchain pool participation", "EVM RPC"]) {
    assert.ok(html.includes(label), label);
  }
  assert.match(html, /Operational/g);
});

test("degraded and outage states render distinct banners", () => {
  assert.match(renderStatusPage(makeReport({ overall: "degraded" })), /Partial degradation/);
  assert.match(renderStatusPage(makeReport({ overall: "outage" })), /Outage/);
});

test("down component renders its state and detail", () => {
  const r = makeReport();
  r.components.relay_supervisor = { state: "down", detail: "unreachable", observedAtMs: T0 };
  r.overall = "outage";
  const html = renderStatusPage(r);
  assert.match(html, /st-down/);
  assert.match(html, />Down</);
  assert.ok(html.includes("unreachable"));
});

test("freshness labels: computed ISO time, per-row observed age, cache TTL", () => {
  const html = renderStatusPage(makeReport());
  assert.ok(html.includes(new Date(T0).toISOString()), "computed ISO missing");
  assert.match(html, /observed \d+[smh]/);
  assert.match(html, /cached ≤ 15s/);
});

test("honest window: since-process-start is stated, no fabricated 24h history", () => {
  const html = renderStatusPage(makeReport());
  assert.match(html, /since process start/i);
  assert.ok(!/24[- ]?hour|last 24/i.test(html), "fabricated a 24h claim");
});

test("VERIFIED handshake card shows outcome and age; absent shows 'none observed'", () => {
  const withCert = renderStatusPage(makeReport());
  assert.match(withCert, /VERIFIED/);
  assert.match(withCert, /30s ago/);
  const without = renderStatusPage(makeReport({ lastVerifiedHandshake: { evidence: "none_observed" } }));
  assert.match(without, /None observed/);
  assert.match(without, /not an availability signal/);
});

test("stale and unavailable evidence render their own labels", () => {
  const stale = renderStatusPage(makeReport({
    lastVerifiedHandshake: { evidence: "stale", outcome: "VERIFIED", observedAtMs: T0 - 300_000, ageSeconds: 300 },
  }));
  assert.match(stale, /VERIFIED — stale/);
  assert.match(stale, /older than the evidence window/);
  const unavail = renderStatusPage(makeReport({ lastVerifiedHandshake: { evidence: "unavailable" } }));
  assert.match(unavail, /Evidence unavailable/);
  assert.match(unavail, /does not affect availability/i);
});

test("build card shows service + helper version and truncated repo sha", () => {
  const html = renderStatusPage(makeReport());
  assert.match(html, /mcp-server 0\.1\.0 · helper 2\.1\.6/);
  assert.ok(html.includes("abc123def456…"), "truncated sha missing");
  assert.ok(!html.includes("abc123def4567890"), "full sha leaked");
});

test("component detail is HTML-escaped", () => {
  const r = makeReport();
  r.components.evm_rpc = { state: "down", detail: '<script>alert("x")</script>', observedAtMs: T0 };
  const html = renderStatusPage(r);
  assert.ok(!html.includes('<script>alert("x")</script>'));
  assert.ok(html.includes("&lt;script&gt;"));
});

test("responsive markup: viewport meta and a mobile breakpoint", () => {
  const html = renderStatusPage(makeReport());
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1"/);
  assert.match(html, /@media \(max-width: 760px\)/);
});

test("nav + footer link to status.json, /health liveness, and /readyz is referenced", () => {
  const html = renderStatusPage(makeReport());
  assert.ok(html.includes('href="/status.json"'));
  assert.ok(html.includes('href="/health"'));
  assert.ok(html.includes("/readyz"));
  assert.ok(html.includes("/health"));
});

test("meta refresh keeps the page live without JS", () => {
  assert.match(renderStatusPage(makeReport()), /<meta http-equiv="refresh" content="60"/);
});

test("long latency and meta values render in mono detail lines", () => {
  const html = renderStatusPage(makeReport());
  assert.match(html, /42ms/);
  assert.ok(html.includes("nodeParticipationPct=100"));
});
