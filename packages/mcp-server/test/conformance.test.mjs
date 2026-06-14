// MCP protocol conformance tests (AGE-182).
//
// These exercise the REAL StreamableHTTPServerTransport — the same transport
// the deployed server binds in http.ts — over actual HTTP on an ephemeral port.
// They lock in the latest-protocol behaviors we depend on: the initialize /
// capabilities handshake, tools/list, JSON-RPC error semantics (-32601 unknown
// method, invalid tool call), the Accept-header requirement, and stateless
// StreamableHTTP (each request independent, no session id). No gateway is hit:
// the asserted paths are protocol-level and never call fetch.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildServer } from "../dist/server.js";

// Stand up the transport exactly as http.ts does: a fresh stateless transport +
// server per request, cleaned up on close. This is the production wiring minus
// the auth/health/rate-limit shell (those are unit-tested in http.test.mjs).
let httpServer;
let baseUrl;

before(async () => {
  httpServer = createServer(async (req, res) => {
    try {
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
    }
  });
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const { port } = httpServer.address();
  baseUrl = `http://127.0.0.1:${port}/`;
});

after(async () => {
  await new Promise((resolve) => httpServer.close(resolve));
});

const ACCEPT = "application/json, text/event-stream";

// POST a JSON-RPC message. Returns { status, headers, body } where body is the
// parsed JSON-RPC object (StreamableHTTP replies as SSE; we take the data frame).
async function rpc(message, { accept = ACCEPT } = {}) {
  const headers = { "content-type": "application/json" };
  if (accept !== null) headers["accept"] = accept;
  const res = await fetch(baseUrl, { method: "POST", headers, body: JSON.stringify(message) });
  const text = await res.text();
  let body;
  if (text) {
    // SSE frames look like "event: message\ndata: {json}\n\n"; plain JSON also OK.
    const dataLine = text.split("\n").find((l) => l.startsWith("data:"));
    const jsonStr = dataLine ? dataLine.slice(5).trim() : text.trim();
    try {
      body = JSON.parse(jsonStr);
    } catch {
      body = undefined;
    }
  }
  return { status: res.status, headers: res.headers, body };
}

const INIT = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "conformance", version: "1" },
  },
};

test("initialize returns protocolVersion, capabilities, and serverInfo", async () => {
  const { status, body } = await rpc(INIT);
  assert.equal(status, 200);
  assert.equal(body.jsonrpc, "2.0");
  assert.ok(body.result, "has result");
  assert.ok(body.result.protocolVersion, "advertises a protocolVersion");
  assert.ok(body.result.capabilities, "advertises capabilities");
  assert.ok(body.result.capabilities.tools, "advertises tools capability");
  assert.equal(body.result.serverInfo.name, "clockchain-mcp");
});

test("tools/list returns the full tool surface (stateless, no prior initialize)", async () => {
  const { status, body } = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  assert.equal(status, 200);
  const names = (body.result.tools || []).map((t) => t.name);
  // Stateless: this is a brand-new transport with no initialize in THIS request,
  // yet tools/list still resolves — exactly how the deployed server behaves.
  assert.ok(names.includes("get_time"), "lists get_time");
  assert.ok(names.includes("attest_action"), "lists attest_action");
  assert.ok(names.includes("complete_attestation"), "lists complete_attestation");
  assert.ok(names.length >= 31, `lists >= 31 tools (got ${names.length})`);
});

test("unknown method maps to JSON-RPC -32601 (method not found)", async () => {
  const { body } = await rpc({ jsonrpc: "2.0", id: 3, method: "no/such/method", params: {} });
  assert.ok(body.error, "returns an error object");
  assert.equal(body.error.code, -32601);
});

test("tools/call on an unknown tool is rejected (isError result, not a silent ok)", async () => {
  const { status, body } = await rpc({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "does_not_exist", arguments: {} },
  });
  // Per MCP, a tool-execution failure (here: unknown tool) is reported as a tool
  // RESULT with isError=true — NOT a top-level JSON-RPC error. The SDK surfaces
  // the -32602 "not found" in the error text. Lock that contract in.
  assert.equal(status, 200);
  assert.ok(!body.error, "not a protocol-level error");
  assert.equal(body.result.isError, true, "tool result flagged isError");
  assert.match(body.result.content[0].text, /not found|-32602/i);
});

test("missing Accept header is rejected (406 Not Acceptable)", async () => {
  // The StreamableHTTP spec requires the client accept both application/json and
  // text/event-stream. Omitting Accept must not be silently served.
  const res = await fetch(baseUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(INIT),
  });
  await res.text();
  assert.equal(res.status, 406);
});

test("Accept without text/event-stream is rejected (406)", async () => {
  const { status } = await rpc(INIT, { accept: "application/json" });
  assert.equal(status, 406);
});

test("each request is independent — a second tools/list needs no session id", async () => {
  const a = await rpc({ jsonrpc: "2.0", id: 5, method: "tools/list", params: {} });
  const b = await rpc({ jsonrpc: "2.0", id: 6, method: "tools/list", params: {} });
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  // No Mcp-Session-Id is required or carried between requests (stateless).
  assert.equal(a.headers.get("mcp-session-id"), null);
  assert.equal(b.headers.get("mcp-session-id"), null);
});
