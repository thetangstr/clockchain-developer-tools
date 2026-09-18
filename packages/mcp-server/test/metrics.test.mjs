// Unit tests for the in-process Prometheus text-format registry.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MetricsRegistry, bounded, DEFAULT_BUCKETS } from "../dist/metrics.js";

test("counter increments and renders a labelled series", () => {
  const r = new MetricsRegistry();
  const c = r.counter("test_requests_total", "Requests.");
  c.inc({ route: "status", status: "2xx" });
  c.inc({ route: "status", status: "2xx" }, 3);
  c.inc({ route: "health", status: "2xx" });
  const out = r.collect();
  assert.match(out, /# HELP test_requests_total Requests\./);
  assert.match(out, /# TYPE test_requests_total counter/);
  assert.match(out, /test_requests_total\{route="status",status="2xx"\} 4/);
  assert.match(out, /test_requests_total\{route="health",status="2xx"\} 1/);
});

test("gauge sets and renders", () => {
  const r = new MetricsRegistry();
  const g = r.gauge("test_inflight", "Inflight.");
  g.set({ dep: "relay" }, 7);
  assert.equal(g.value({ dep: "relay" }), 7);
  assert.match(r.collect(), /test_inflight\{dep="relay"\} 7/);
});

test("histogram emits cumulative buckets, +Inf, sum, and count", () => {
  const r = new MetricsRegistry();
  const h = r.histogram("test_seconds", "Duration.", [0.1, 1]);
  h.observe({ route: "status" }, 0.05); // lands in both buckets
  h.observe({ route: "status" }, 0.5);  // lands only in le=1
  h.observe({ route: "status" }, 9);    // lands only in +Inf
  const out = r.collect();
  assert.match(out, /test_seconds_bucket\{le="0\.1",route="status"\} 1/);
  assert.match(out, /test_seconds_bucket\{le="1",route="status"\} 2/);
  assert.match(out, /test_seconds_bucket\{le="\+Inf",route="status"\} 3/);
  assert.match(out, /test_seconds_sum\{route="status"\} 9\.55/);
  assert.match(out, /test_seconds_count\{route="status"\} 3/);
  assert.equal(h.count({ route: "status" }), 3);
});

test("default buckets are the shared duration set", () => {
  const r = new MetricsRegistry();
  const h = r.histogram("test_default_seconds", "Duration.");
  h.observe({}, 0.2);
  const out = r.collect();
  for (const le of DEFAULT_BUCKETS) {
    const expected = le >= 0.2 ? " 1" : " 0";
    assert.match(out, new RegExp(`test_default_seconds_bucket\\{le="${String(le).replace(".", "\\.")}"\\}${expected.replace(" ", "\\s")}`));
  }
});

test("label values are escaped (quotes, backslashes, newlines)", () => {
  const r = new MetricsRegistry();
  const c = r.counter("test_esc_total", "Esc.");
  c.inc({ v: 'a"b\\c\nd' });
  const out = r.collect();
  assert.match(out, /test_esc_total\{v="a\\"b\\\\c\\nd"\} 1/);
  assert.ok(!out.includes('a"b'));
});

test("HELP text is escaped", () => {
  const r = new MetricsRegistry();
  r.counter("test_help_total", "line1\nline2\\end");
  assert.match(r.collect(), /# HELP test_help_total line1\\nline2\\\\end/);
});

test("bounded collapses unknown values to the fallback", () => {
  assert.equal(bounded("stage_x", ["a", "b"]), "other");
  assert.equal(bounded("a", ["a", "b"]), "a");
  assert.equal(bounded(undefined, ["a"]), "other");
  assert.equal(bounded(null, ["a"], "unknown"), "unknown");
});

test("redeclaring a series with a different type throws", () => {
  const r = new MetricsRegistry();
  r.counter("test_redeclare_total", "C.");
  assert.throws(() => r.gauge("test_redeclare_total", "G."), /redeclared/);
});

test("invalid metric and label names are rejected", () => {
  const r = new MetricsRegistry();
  assert.throws(() => r.counter("bad-name!", "x"), /bad metric name/);
  const c = r.counter("good_name", "x");
  assert.throws(() => c.inc({ "bad label": "v" }), /bad label name/);
});

test("re-requesting the same series returns the same instance", () => {
  const r = new MetricsRegistry();
  const a = r.counter("test_same_total", "C.");
  const b = r.counter("test_same_total", "C.");
  assert.equal(a, b);
  a.inc({ x: "1" });
  assert.equal(b.value({ x: "1" }), 1);
});

test("names() lists registered series for cardinality audits", () => {
  const r = new MetricsRegistry();
  r.counter("a_total", "a");
  r.gauge("b_gauge", "b");
  r.histogram("c_seconds", "c");
  assert.deepEqual(r.names().sort(), ["a_total", "b_gauge", "c_seconds"]);
});

test("empty registry still emits valid HELP/TYPE scaffolding", () => {
  const r = new MetricsRegistry();
  r.counter("empty_total", "Empty.");
  const out = r.collect();
  assert.ok(out.endsWith("\n"));
  assert.match(out, /# TYPE empty_total counter\n?$/);
});

test("histogram quantile interpolates within the ranked bucket", () => {
  const r = new MetricsRegistry();
  const h = r.histogram("q_seconds", "Q.", [0.1, 0.5, 1, 5]);
  // 10 observations at 0.05 (all in the first bucket): p50 interpolates
  // rank 5/10 across the 0–0.1 bucket → 0.05; p99 → 0.099.
  for (let i = 0; i < 10; i++) h.observe({ route: "x" }, 0.05);
  assert.equal(h.quantile({ route: "x" }, 0.5), 0.05);
  assert.equal(h.quantile({ route: "x" }, 0.99), 0.099);
  // Add 10 more at 2s — now p95 interpolates inside the 1–5s bucket.
  for (let i = 0; i < 10; i++) h.observe({ route: "x" }, 2);
  const p95 = h.quantile({ route: "x" }, 0.95);
  assert.ok(p95 > 1 && p95 <= 5, `p95 ${p95} outside the 1-5 bucket`);
});

test("quantile on an empty series returns undefined; out-of-range q clamps", () => {
  const r = new MetricsRegistry();
  const h = r.histogram("empty_q_seconds", "Q.", [0.1, 1]);
  assert.equal(h.quantile({ route: "x" }, 0.5), undefined);
  h.observe({}, 0.05);
  assert.equal(h.quantile({}, 1.5), h.quantile({}, 1)); // clamped q
});

test("counter and gauge sum() totals across series", () => {
  const r = new MetricsRegistry();
  const c = r.counter("s_total", "S.");
  c.inc({ a: "1" }); c.inc({ a: "2" }, 4);
  assert.equal(c.sum(), 5);
});
