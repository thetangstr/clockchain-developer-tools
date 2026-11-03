// Security review follow-up, finding 1 (batch memory exhaustion), flags-independent: /mcp and /connect/mcp refuse
// JSON-RPC batches of more than 10 messages before running any of them; /mcp charges every message of a batch
// (lifecycle included); /mcp, /connect/mcp and /shadow/mcp drop a connection whose unsent response bytes pile up.
// Mirrors the review's p5 (exempt batch), p6/p6b (non-reading clients) and p7 (which paths accept batches).
import { test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { runHttp, rateLimitCost } from "../dist/http.js";
import { MAX_BATCH_MESSAGES } from "../dist/jsonrpc-limits.js";

const STATIC = "static-batch-token";
const KEYS = ["PORT", "MCP_PORT", "MCP_AUTH_TOKENS", "MCP_TOKEN_SIGNING_SECRET", "MCP_RATE_PER_MIN", "MCP_OAUTH", "MCP_PUBLIC_URL", "MCP_STATE_DIR", "SHADOW_ENABLED", "SHADOW_STATE_DIR", "HANDSHAKE_STATE_DIR"];
async function boot(env = {}) {
  const saved = {};
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, { MCP_PORT: "0", MCP_AUTH_TOKENS: STATIC, MCP_TOKEN_SIGNING_SECRET: "batch-secret", HANDSHAKE_STATE_DIR: mkdtempSync(path.join(tmpdir(), "batch-hs-")) }, env);
  const server = await runHttp();
  if (!server.listening) await once(server, "listening");
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    port: server.address().port,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    },
  };
}

/**
 * The built server in a child process (the handshake routes start long-lived state, so the repo's full-server tests
 * of those routes run out of process, as connect.test.mjs does).
 */
async function spawnServer(env = {}) {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
  const proc = spawn(process.execPath, ["--max-old-space-size=384", entry], {
    env: { PATH: process.env.PATH, MCP_TRANSPORT: "http", PORT: String(port), MCP_AUTH_TOKENS: STATIC, MCP_REQUIRE_AUTH: "1", MCP_TOKEN_SIGNING_SECRET: "batch-secret", HANDSHAKE_STATE_DIR: mkdtempSync(path.join(tmpdir(), "batch-hs-")), ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let err = "";
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`server did not start: ${err}`)), 10_000);
    proc.stderr.on("data", (d) => { err += d; if (err.includes("listening on")) { clearTimeout(t); resolve(); } });
    proc.on("exit", (c) => reject(new Error(`server exited ${c}: ${err}`)));
  });
  return { url: `http://127.0.0.1:${port}`, port, close: () => { proc.kill(); } };
}

const ACCEPT = "application/json, text/event-stream";
const batchOf = (n, method = "tools/list") => Array.from({ length: n }, (_, i) => ({ jsonrpc: "2.0", id: i + 1, method }));
const post = (url, body, headers = {}) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: ACCEPT, ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
const answers = (text) => {
  const data = text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => JSON.parse(l.slice(6)));
  const all = data.length ? data : [JSON.parse(text)];
  return all.flatMap((x) => (Array.isArray(x) ? x : [x]));
};
const TOO_LARGE = { jsonrpc: "2.0", error: { code: -32600, message: `A JSON-RPC batch may hold at most ${MAX_BATCH_MESSAGES} messages; send fewer per request.` }, id: null };

test("rate-limit cost: a single lifecycle message is free; a batch costs one unit per message, lifecycle included", () => {
  assert.equal(rateLimitCost({ jsonrpc: "2.0", id: 1, method: "tools/list" }), 0);
  assert.equal(rateLimitCost({ jsonrpc: "2.0", id: 1, method: "tools/call" }), 1);
  assert.equal(rateLimitCost(batchOf(10, "ping")), 10);
  assert.equal(rateLimitCost([{ method: "tools/list" }, { method: "tools/call" }]), 2);
  assert.equal(rateLimitCost([]), 1);
});

test("/mcp (flags off, p5/p7): batches over 10 are refused before running; up to 10 run and are charged in full", async () => {
  const s = await boot({ MCP_RATE_PER_MIN: "12" });
  try {
    for (const headers of [{ "x-api-key": "junk-byo-key" }, { "x-api-key": STATIC }]) {
      for (const n of [11, 1000, 8000]) {
        const r = await post(`${s.url}/mcp`, batchOf(n, "ping"), headers);
        assert.equal(r.status, 400, `batch of ${n}`);
        assert.deepEqual(await r.json(), TOO_LARGE);
      }
    }
    // Ten fit, and cost ten units of the twelve: the next batch of three no longer fits.
    const ten = await post(`${s.url}/mcp`, batchOf(10, "tools/list"), { "x-api-key": STATIC });
    assert.equal(ten.status, 200);
    assert.equal(answers(await ten.text()).length, 10);
    assert.equal(ten.headers.get("x-ratelimit-remaining"), "2");
    const three = await post(`${s.url}/mcp`, batchOf(3, "ping"), { "x-api-key": STATIC });
    assert.equal(three.status, 429, "lifecycle messages in a batch are charged");
    // A single discovery call stays free.
    assert.equal((await post(`${s.url}/mcp`, { jsonrpc: "2.0", id: 1, method: "tools/list" }, { "x-api-key": STATIC })).status, 200);
  } finally {
    await s.close();
  }
});

test("/connect/mcp: batches over 10 are refused; everything else is answered exactly as the transport answers it", async () => {
  const s = await spawnServer();
  try {
    const big = await post(`${s.url}/connect/mcp`, batchOf(200));
    assert.equal(big.status, 400);
    assert.deepEqual(await big.json(), TOO_LARGE);
    const ten = await post(`${s.url}/connect/mcp`, batchOf(10));
    assert.equal(ten.status, 200);
    assert.equal(answers(await ten.text()).length, 10);
    const one = await post(`${s.url}/connect/mcp`, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(one.status, 200);
    assert.ok(answers(await one.text())[0].result.tools.length > 0);
    // The transport's own refusals, unchanged: bad JSON, wrong Accept, wrong Content-Type, a non-JSON-RPC body.
    const bad = await post(`${s.url}/connect/mcp`, "{not json");
    assert.equal(bad.status, 400);
    assert.deepEqual(await bad.json(), { jsonrpc: "2.0", error: { code: -32700, message: "Parse error: Invalid JSON" }, id: null });
    const accept = await post(`${s.url}/connect/mcp`, batchOf(200), { accept: "application/json" });
    assert.equal(accept.status, 406, "Accept is checked first, as before (the oversized batch is never read)");
    const type = await post(`${s.url}/connect/mcp`, batchOf(200), { "content-type": "text/plain" });
    assert.equal(type.status, 415);
    const notRpc = await post(`${s.url}/connect/mcp`, { hello: "world" });
    assert.equal(notRpc.status, 400);
    assert.equal((await notRpc.json()).error.code, -32700);
  } finally {
    await s.close();
  }
});

test("/shadow/mcp still refuses every batch (Shadow's own rule), and /handshake/mcp and /contract/mcp are untouched", async () => {
  const s = await boot({ SHADOW_ENABLED: "1", SHADOW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "batch-shadow-")) });
  try {
    const shadow = await post(`${s.url}/shadow/mcp`, batchOf(11), { "x-api-key": STATIC });
    assert.notEqual(shadow.status, 200);
    // /contract/mcp is off here (404) whatever the body; /handshake/mcp keeps its own handling (no -32600 cap).
    assert.equal((await post(`${s.url}/contract/mcp`, batchOf(11))).status, 404);
    const hs = await post(`${s.url}/handshake/mcp`, batchOf(11));
    assert.notDeepEqual(await hs.json().catch(() => ({})), TOO_LARGE);
  } finally {
    await s.close();
  }
});

test("p6/p6b: non-reading clients sending huge batches get a small 400 and the server stays healthy", async () => {
  const s = await spawnServer({ MCP_RATE_PER_MIN: "30" });
  try {
    const batch = JSON.stringify(batchOf(3000));
    const sockets = [];
    const statuses = [];
    for (const p of ["/mcp", "/mcp", "/connect/mcp", "/connect/mcp"]) {
      const sock = net.connect(s.port, "127.0.0.1");
      sock.on("error", () => {});
      let head = "";
      sock.on("data", (d) => { if (!head) { head = d.toString().split("\r\n")[0]; statuses.push(head); } sock.pause(); });
      sock.write(`POST ${p} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAccept: ${ACCEPT}\r\nx-api-key: junk\r\nContent-Length: ${Buffer.byteLength(batch)}\r\n\r\n${batch}`);
      sockets.push(sock);
    }
    for (let i = 0; i < 50 && statuses.length < 4; i++) await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(statuses, Array(4).fill("HTTP/1.1 400 Bad Request"));
    assert.equal((await fetch(`${s.url}/health`)).status, 200);
    sockets.forEach((x) => x.destroy());
  } finally {
    await s.close();
  }
});
