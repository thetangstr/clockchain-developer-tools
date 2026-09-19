// Route-boundary tests for /status, /status.json, /readyz, and /metrics:
// spawn the real server against a stubbed upstream (relay + gateway + EVM
// RPC all on one stub) and verify public/private boundaries end to end.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PORT = 39531;
const BASE = `http://127.0.0.1:${PORT}`;
const METRICS_TOKEN = "metrics-secret-test";
const SESSION_ID = "sess-route-test-001";
const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

let upstream;
let upstreamPort;
let proc;

// Stubs mirror the REAL production v2 payloads:
//   discovery: clockchain.agent-handshake-discovery/v2 — createdAtMs,
//     invitationExpiresAtMs, sessionDeadlineMs, sessionOpenedBlock.
//   result:    certificate envelope {hostSessionKeyCertificate, result, signer}
//     with result = clockchain.agent-handshake-result/v2 (outcome+issuedAtMs).
const DISCOVERY = {
  schema: "clockchain.agent-handshake-discovery/v2",
  protocol: "clockchain.agent-handshake/v2",
  sessionId: SESSION_ID,
  repositorySha: "deadbeefcafe1234deadbeefcafe1234deadbeef",
  kitRepoUrl: "https://example.invalid/kit",
  relayUrl: "",
  invitationExpiresAtMs: String(Date.now() + 120_000),
  sessionDeadlineMs: String(Date.now() + 600_000),
  sessionOpenedBlock: "17100",
  hostSessionKeyCertificate: { certificate: { sessionId: SESSION_ID } },
  externalBusinessActionPerformed: false,
};
const RESULT = {
  hostSessionKeyCertificate: { certificate: { sessionId: SESSION_ID } },
  result: {
    schema: "clockchain.agent-handshake-result/v2",
    outcome: "VERIFIED",
    issuedAtMs: String(Date.now() - 20_000),
    sessionId: SESSION_ID,
    sessionDigest: "f".repeat(64),
    statementDigest: "e".repeat(64),
    externalBusinessActionPerformed: false,
  },
  signer: "0xdeadbeef",
};

before(async () => {
  upstream = createServer((req, res) => {
    const url = (req.url ?? "").split("?")[0];
    if (req.method === "POST") {
      // EVM JSON-RPC stub: answer eth_chainId with Sepolia.
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0xaa36a7" }));
      });
      return;
    }
    if (url === "/v1/discovery/current") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ...DISCOVERY, createdAtMs: String(Date.now()), relayUrl: `http://127.0.0.1:${upstreamPort}` }));
      return;
    }
    if (/^\/v1\/sessions\/[^/]+\/result$/.test(url)) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(RESULT));
      return;
    }
    if (url === "/getTime") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ success: true, data: { nodeParticipation: 100, totalNodes: 12, blockHeight: "1" } }));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  upstreamPort = upstream.address().port;

  proc = spawn("node", [entry], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(PORT),
      MCP_AUTH_TOKENS: "team-tok",
      MCP_REQUIRE_AUTH: "1",
      HANDSHAKE_RELAY: `http://127.0.0.1:${upstreamPort}`,
      CLOCKCHAIN_ENDPOINT: `http://127.0.0.1:${upstreamPort}`,
      EVM_RPC_URL: `http://127.0.0.1:${upstreamPort}`,
      MCP_METRICS_TOKEN: METRICS_TOKEN,
      STATUS_CACHE_MS: "50",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("server did not start in time")), 15_000);
    proc.stderr.on("data", (d) => {
      if (String(d).includes("listening on")) { clearTimeout(t); resolve(); }
    });
    proc.on("exit", (code) => reject(new Error(`server exited early (${code})`)));
  });
});

after(() => {
  if (proc && !proc.killed) proc.kill();
  if (upstream) upstream.close();
});

test("GET /health stays cheap liveness (no auth, instant)", async () => {
  const res = await fetch(`${BASE}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: "ok" });
});

test("GET /status.json returns the sanitized report, unauthenticated", async () => {
  const res = await fetch(`${BASE}/status.json`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("cache-control") ?? "", /no-store/);
  const body = await res.json();
  assert.equal(body.schema, "clockchain.status/v1");
  assert.equal(body.overall, "operational");
  for (const k of ["mcp_host", "handshake_surface", "relay_supervisor", "anchoring_gateway", "pool_participation", "evm_rpc"]) {
    assert.equal(body.components[k].state, "ok", k);
  }
  assert.equal(body.lastVerifiedHandshake.evidence, "fresh");
  assert.equal(body.lastVerifiedHandshake.outcome, "VERIFIED");
  assert.equal(body.build.helperVersion, "2.1.7");
  // Public performance block: real aggregates, labeled since process start.
  assert.equal(body.performance.windowLabel, "since process start");
  assert.equal(typeof body.performance.http.totalRequests, "number");
  assert.equal(typeof body.performance.uptimeSeconds, "number");
  // Non-leakage: no session ids or digests from upstream data.
  const raw = JSON.stringify(body);
  assert.ok(!raw.includes(SESSION_ID), "session id leaked");
  assert.ok(!raw.includes("f".repeat(64)), "session digest leaked");
  assert.ok(!raw.includes("e".repeat(64)), "statement digest leaked");
});

test("GET /status serves HTML to browsers, JSON to agents", async () => {
  const html = await fetch(`${BASE}/status`, { headers: { accept: "text/html" } });
  assert.equal(html.status, 200);
  assert.match(html.headers.get("content-type"), /text\/html/);
  assert.match(await html.text(), /All systems operational/);

  const json = await fetch(`${BASE}/status`, { headers: { accept: "application/json" } });
  assert.equal(json.status, 200);
  assert.match(json.headers.get("content-type"), /application\/json/);
  assert.equal((await json.json()).schema, "clockchain.status/v1");
});

test("GET /readyz is the core MCP-host readiness view", async () => {
  const res = await fetch(`${BASE}/readyz`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("cache-control") ?? "", /no-store/);
  const body = await res.json();
  assert.equal(body.status, "ready");
  assert.equal(body.scope, "mcp_host");
  assert.equal(body.handshakeReady, true);
  assert.equal(body.overall, "operational");
  assert.equal(body.components.relay_supervisor, "ok");
});

test("GET /readyz/handshake → 200 when handshake deps are ok", async () => {
  const res = await fetch(`${BASE}/readyz/handshake`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, "ready");
  assert.equal(body.scope, "handshake");
  assert.equal(body.handshakeReady, true);
});

test("GET /metrics requires the bearer token and serves Prometheus text", async () => {
  const anon = await fetch(`${BASE}/metrics`);
  assert.equal(anon.status, 401);
  const wrong = await fetch(`${BASE}/metrics`, { headers: { authorization: "Bearer nope" } });
  assert.equal(wrong.status, 401);

  const ok = await fetch(`${BASE}/metrics`, { headers: { authorization: `Bearer ${METRICS_TOKEN}` } });
  assert.equal(ok.status, 200);
  assert.match(ok.headers.get("content-type"), /text\/plain/);
  const text = await ok.text();
  assert.match(text, /# HELP clockchain_http_requests_total/);
  assert.match(text, /# TYPE clockchain_http_requests_total counter/);
  assert.match(text, /clockchain_http_requests_total\{route="health",status="2xx"\} \d+/);
  assert.match(text, /clockchain_dependency_up\{dep="relay_discovery"\} 1/);
  assert.match(text, /process_uptime_seconds \d+/);
  // Cardinality + non-leakage: no session ids or raw upstream digests.
  assert.ok(!text.includes(SESSION_ID));
  assert.ok(!text.includes("f".repeat(64)));
});

test("public status contains no protected metrics payload", async () => {
  const body = await (await fetch(`${BASE}/status.json`)).text();
  assert.ok(!body.includes("clockchain_http_requests_total"), "metric series leaked into public status");
});

test("load smoke: 50 concurrent /status.json requests all succeed fast", async () => {
  const started = Date.now();
  const results = await Promise.all(
    Array.from({ length: 50 }, () => fetch(`${BASE}/status.json`)),
  );
  const elapsed = Date.now() - started;
  for (const r of results) assert.equal(r.status, 200);
  assert.ok(elapsed < 10_000, `50 concurrent status requests took ${elapsed}ms`);
});
