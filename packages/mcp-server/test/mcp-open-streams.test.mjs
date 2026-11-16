// Held-open GETs on /mcp are capped, because each one holds memory until it closes. Tool calls aren't affected.
import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtempSync } from "node:fs";
import { createServer, request } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { runHttp } from "../dist/http.js";

function openGet(port) {
  return new Promise((resolve, reject) => {
    const req = request({ port, host: "127.0.0.1", path: "/mcp", method: "GET", headers: { accept: "text/event-stream", authorization: "Bearer static-test-token" } }, (res) => resolve({ status: res.statusCode, req, res }));
    req.on("error", reject);
    req.end();
  });
}

test("past the cap a stream gets 503, a tool call still works, and closing one frees a place", async () => {
  const probe = createServer().listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  Object.assign(process.env, { MCP_PORT: String(port), MCP_AUTH_TOKENS: "static-test-token", MCP_REQUIRE_AUTH: "1", MCP_MAX_OPEN_STREAMS: "2", MCP_STATE_DIR: mkdtempSync(path.join(tmpdir(), "streams-")) });
  const server = await runHttp();
  try {
    const [a, b] = [await openGet(port), await openGet(port)];
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    const over = await openGet(port);
    assert.equal(over.status, 503);
    over.res.resume();
    const call = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer static-test-token" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) });
    assert.equal(call.status, 200);
    await call.text();
    a.req.destroy();
    await new Promise((r) => setTimeout(r, 100));
    const again = await openGet(port);
    assert.equal(again.status, 200);
    again.req.destroy();
    b.req.destroy();
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
});
