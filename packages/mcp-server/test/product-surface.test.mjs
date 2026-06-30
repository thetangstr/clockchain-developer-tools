// CLO-99: product surface ("safe slice") tests.
//
// Asserts that MCP_SURFACE=product → only get_time is registered, and that the
// full surface (default / MCP_SURFACE=full) still exposes all 31 tools.
//
// Two harnesses are used, mirroring the existing test suite:
//   1. Fake-server (offline) — same pattern as tools.test.mjs — fast, no ports.
//   2. Real HTTP server — same pattern as conformance.test.mjs — verifies the
//      env-var→buildServer→tools/list path end-to-end.
//
// Run: node --test (from packages/mcp-server) or npm test (workspace root).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { registerTools } from "../dist/tools.js";
import { buildServer } from "../dist/server.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

// ---------------------------------------------------------------------------
// Harness 1: fake-server (offline), same pattern as tools.test.mjs
// ---------------------------------------------------------------------------

/** Collect the tool names registerTools() registers with a given opts object. */
function collectToolNames(opts) {
  const names = [];
  const fakeServer = {
    registerTool: (name) => { names.push(name); },
  };
  registerTools(fakeServer, cfg, opts);
  return names;
}

test('surface="product" registers exactly ["get_time"] (offline fake-server)', () => {
  const names = collectToolNames({ surface: "product" });
  assert.deepEqual(names, ["get_time"], `Expected only ["get_time"], got: ${JSON.stringify(names)}`);
});

test('surface="full" (explicit) registers all 31 tools including get_time (offline fake-server)', () => {
  const names = collectToolNames({ surface: "full" });
  assert.ok(names.includes("get_time"), "full surface must include get_time");
  assert.ok(names.includes("attest_action"), "full surface must include attest_action");
  assert.ok(names.includes("tsa_status"), "full surface must include tsa_status");
  assert.equal(names.length, 31, `Expected 31 tools, got ${names.length}: ${JSON.stringify(names)}`);
});

test("surface omitted (default) is identical to full — 31 tools (offline fake-server)", () => {
  const names = collectToolNames({});
  assert.equal(names.length, 31, `Expected 31 tools (default), got ${names.length}`);
  assert.ok(names.includes("get_time"));
});

// ---------------------------------------------------------------------------
// Harness 2: real HTTP server, same pattern as conformance.test.mjs
// Tests that MCP_SURFACE env var is picked up by buildServer() → tools/list.
// ---------------------------------------------------------------------------

let httpServerProduct;
let baseUrlProduct;

before(async () => {
  // Start an HTTP server that builds with MCP_SURFACE=product for each request.
  httpServerProduct = createServer(async (req, res) => {
    const prev = process.env.MCP_SURFACE;
    try {
      process.env.MCP_SURFACE = "product";
      const server = buildServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    } finally {
      if (prev === undefined) delete process.env.MCP_SURFACE;
      else process.env.MCP_SURFACE = prev;
    }
  });
  await new Promise((resolve) => httpServerProduct.listen(0, "127.0.0.1", resolve));
  const { port } = httpServerProduct.address();
  baseUrlProduct = `http://127.0.0.1:${port}/`;
});

after(async () => {
  await new Promise((resolve) => httpServerProduct.close(resolve));
});

const ACCEPT = "application/json, text/event-stream";

async function rpc(baseUrl, message) {
  const res = await fetch(baseUrl, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT },
    body: JSON.stringify(message),
  });
  const text = await res.text();
  let body;
  if (text) {
    const dataLine = text.split("\n").find((l) => l.startsWith("data:"));
    const jsonStr = dataLine ? dataLine.slice(5).trim() : text.trim();
    try { body = JSON.parse(jsonStr); } catch { body = undefined; }
  }
  return { status: res.status, body };
}

test('MCP_SURFACE=product → tools/list is exactly ["get_time"] (HTTP server)', async () => {
  const { status, body } = await rpc(baseUrlProduct, {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {},
  });
  assert.equal(status, 200, "tools/list should return 200");
  const names = (body.result.tools ?? []).map((t) => t.name);
  assert.deepEqual(
    names,
    ["get_time"],
    `Expected exactly ["get_time"] for product surface, got: ${JSON.stringify(names)}`,
  );
});

test("MCP_SURFACE unset (default full) → tools/list has 31 tools (HTTP server)", async () => {
  // Build a separate ephemeral server without setting MCP_SURFACE (default=full).
  const fullServer = createServer(async (req, res) => {
    const prev = process.env.MCP_SURFACE;
    try {
      delete process.env.MCP_SURFACE; // ensure default path
      const server = buildServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => { void transport.close(); void server.close(); });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    } finally {
      if (prev !== undefined) process.env.MCP_SURFACE = prev;
    }
  });
  await new Promise((resolve) => fullServer.listen(0, "127.0.0.1", resolve));
  const { port } = fullServer.address();
  const baseUrl = `http://127.0.0.1:${port}/`;

  try {
    const { status, body } = await rpc(baseUrl, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });
    assert.equal(status, 200);
    const names = (body.result.tools ?? []).map((t) => t.name);
    assert.ok(names.includes("get_time"), "full surface must include get_time");
    assert.ok(names.length >= 31, `Expected >= 31 tools on full surface, got ${names.length}`);
  } finally {
    await new Promise((resolve) => fullServer.close(resolve));
  }
});
