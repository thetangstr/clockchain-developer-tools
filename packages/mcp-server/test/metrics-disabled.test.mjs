// When MCP_METRICS_TOKEN is unset, /metrics must not exist (404) — the
// operational surface fails closed rather than serving publicly.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PORT = 39532;
const BASE = `http://127.0.0.1:${PORT}`;
const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

let proc;

before(async () => {
  proc = spawn("node", [entry], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(PORT),
      MCP_AUTH_TOKENS: "team-tok",
      MCP_REQUIRE_AUTH: "1",
      MCP_METRICS_TOKEN: "",
      HANDSHAKE_RELAY: "http://127.0.0.1:1",
      CLOCKCHAIN_ENDPOINT: "http://127.0.0.1:1",
      EVM_RPC_URL: "http://127.0.0.1:1",
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

after(() => { if (proc && !proc.killed) proc.kill(); });

test("GET /metrics → 404 when MCP_METRICS_TOKEN is unset", async () => {
  const res = await fetch(`${BASE}/metrics`);
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error, "not_found");
});

test("GET /metrics → 404 even with a bearer token when unset", async () => {
  const res = await fetch(`${BASE}/metrics`, { headers: { authorization: "Bearer anything" } });
  assert.equal(res.status, 404);
});

test("status still reports degraded/outage when every dependency is down", async () => {
  const res = await fetch(`${BASE}/status.json`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.overall, "outage");
  assert.equal(body.components.relay_supervisor.state, "down");
  assert.equal(body.lastVerifiedHandshake.evidence, "unavailable");
});

test("GET /readyz → 503 not_ready when dependencies are down", async () => {
  const res = await fetch(`${BASE}/readyz`);
  assert.equal(res.status, 503);
  assert.equal((await res.json()).status, "not_ready");
});
