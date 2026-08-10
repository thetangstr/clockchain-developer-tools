import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import test from "node:test";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { buildServer } from "../dist/server.js";

const NAMES = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_status",
  "agent_handshake_join",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

async function listTools() {
  const httpServer = createServer(async (request, response) => {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    response.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(request, response);
  });
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = httpServer.address();
    const response = await fetch(`http://127.0.0.1:${port}/`, {
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      headers: {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      method: "POST",
    });
    assert.equal(response.status, 200);
    const raw = await response.text();
    const dataLine = raw.split("\n").find((line) => line.startsWith("data:"));
    const body = JSON.parse(dataLine ? dataLine.slice(5).trim() : raw);
    return body.result.tools.filter((tool) => NAMES.includes(tool.name));
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
  }
}

test("generic agent-handshake v1 MCP names and JSON Schemas remain byte-for-byte compatible", async () => {
  const captured = JSON.parse(await readFile(
    new URL("fixtures/agent-handshake-v1-tool-contract.json", import.meta.url),
    "utf8",
  ));
  assert.equal(captured.schema, "clockchain.agent-handshake-v1-tool-contract/v1");
  assert.deepEqual(captured.tools.map(({ name }) => name), NAMES);
  assert.deepEqual(await listTools(), captured.tools);
});
