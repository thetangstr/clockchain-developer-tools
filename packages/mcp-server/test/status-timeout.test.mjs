// Route-level timeout regression: when the anchoring gateway (/getTime) hangs
// forever, /status.json must still return inside the probe bound — with
// anchoring_gateway AND pool_participation honestly marked down, not stuck.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PORT = 39551;
const BASE = `http://127.0.0.1:${PORT}`;
const SESSION_ID = "7f3e2d1c-0b9a-4f8e-9d6c-5b4a3f2e1d0c";
const PROBE_TIMEOUT_MS = 400;
// Route ceiling = dependency timeout + a small explicit allowance for
// HTTP handling, the parallel probe set, and report serialization.
const BOUND_MS = PROBE_TIMEOUT_MS + 750;
const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

let upstream;
let upstreamPort;
let proc;

before(async () => {
  upstream = createServer((req, res) => {
    const url = (req.url ?? "").split("?")[0];
    const json = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url === "/getTime") {
      // Hung gateway: never respond. fetchPoolParticipation must bound this
      // with its probeTimeoutMs race rather than blocking status forever.
      return;
    }
    if (req.method === "POST") {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => json(200, { jsonrpc: "2.0", id: 1, result: "0xaa36a7" }));
      return;
    }
    if (url === "/v1/discovery/current") {
      const now = Date.now();
      json(200, {
        schema: "clockchain.agent-handshake-discovery/v2",
        protocol: "clockchain.agent-handshake/v2",
        sessionId: SESSION_ID,
        repositorySha: "deadbeefcafe1234deadbeefcafe1234deadbeef",
        kitRepoUrl: "https://example.invalid/kit",
        relayUrl: `http://127.0.0.1:${upstreamPort}`,
        createdAtMs: String(now),
        invitationExpiresAtMs: String(now + 120_000),
        sessionDeadlineMs: String(now + 600_000),
        sessionOpenedBlock: "17100",
        hostSessionKeyCertificate: { certificate: { sessionId: SESSION_ID } },
        externalBusinessActionPerformed: false,
      });
      return;
    }
    if (/^\/v1\/sessions\/[^/]+\/result$/.test(url)) {
      json(404, { error: "RESULT_PENDING" });
      return;
    }
    json(404, { error: "not_found" });
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  upstreamPort = upstream.address().port;

  proc = spawn("node", [entry], {
    env: {
      ...process.env,
      MCP_TRANSPORT: "http",
      PORT: String(PORT),
      HANDSHAKE_RELAY: `http://127.0.0.1:${upstreamPort}`,
      CLOCKCHAIN_ENDPOINT: `http://127.0.0.1:${upstreamPort}`,
      EVM_RPC_URL: `http://127.0.0.1:${upstreamPort}`,
      STATUS_PROBE_TIMEOUT_MS: String(PROBE_TIMEOUT_MS),
      STATUS_CACHE_MS: "25",
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
  if (upstream) {
    upstream.closeAllConnections(); // release the hung /getTime sockets
    upstream.close();
  }
});

test("/status.json returns inside the probe bound with gateway+pool down when /getTime hangs", async () => {
  const started = Date.now();
  const res = await fetch(`${BASE}/status.json`);
  const elapsed = Date.now() - started;
  assert.equal(res.status, 200);
  assert.ok(
    elapsed < BOUND_MS,
    `/status.json took ${elapsed}ms — exceeds probe timeout ${PROBE_TIMEOUT_MS}ms + overhead allowance (${BOUND_MS}ms)`,
  );

  const body = await res.json();
  assert.equal(body.components.anchoring_gateway.state, "down");
  assert.equal(body.components.pool_participation.state, "down");
  assert.equal(body.components.relay_supervisor.state, "ok");
  assert.equal(body.components.evm_rpc.state, "ok");
  // Both gateway probes carry observation timestamps — honest "down", not missing.
  assert.equal(typeof body.components.anchoring_gateway.observedAtMs, "number");
  assert.equal(typeof body.components.pool_participation.observedAtMs, "number");

  // Second request after the cache TTL must also stay inside the bound —
  // the hung gateway does not wedge later collections either.
  await new Promise((r) => setTimeout(r, 100));
  const second = Date.now();
  const res2 = await fetch(`${BASE}/status.json`);
  const elapsed2 = Date.now() - second;
  assert.equal(res2.status, 200);
  assert.ok(
    elapsed2 < BOUND_MS,
    `second /status.json took ${elapsed2}ms — exceeds probe timeout ${PROBE_TIMEOUT_MS}ms + overhead allowance (${BOUND_MS}ms)`,
  );
  console.log(`hung-gateway probe bound: first=${elapsed}ms second=${elapsed2}ms ceiling=${BOUND_MS}ms (probe ${PROBE_TIMEOUT_MS}ms + overhead)`);
});
