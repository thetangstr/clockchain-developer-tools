// Spec B2 / plan step 3, v2 side: only the ccra_ handle map becomes durable. Everything a
// v2 client sees (tool names, arguments, fields, bytes) is unchanged.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createV2PublicHttpHandler } from "../dist/agent-handshake/v2/public-server.js";
import { AGENT_HANDSHAKE_ROLE_TOOLS, mintV2RoleAccess } from "../dist/agent-handshake/v2/access.js";

const pin = {
  version: "2.1.8",
  sourceCommit: "d".repeat(40),
  manifestDigest: "a".repeat(64),
  allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.8/",
  hostRoots: [{ kid: "root-2026-08", fingerprint: "b".repeat(64) }],
};
const ACCEPT = "application/json, text/event-stream";
const initiatorAccess = mintV2RoleAccess({
  key: { kid: "role-test", secret: Buffer.alloc(32, "r") },
  jti: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  sessionId: "11111111-2222-4333-8444-555555555555",
  role: "initiator",
  statementDigest: "f".repeat(64),
  allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
  nbfMs: 0,
  expMs: 60 * 60_000,
});

async function serve(stateDir, seen) {
  const handler = createV2PublicHttpHandler({
    pin,
    now: () => 1_000,
    stateDir,
    invoke: async (name, args) => {
      seen.push({ name, access: args.access });
      if (name === "agent_handshake_invite") return { sessionId: "s", initiatorAccess };
      return { role: "initiator", sessionId: "s", stage: "invited", externalBusinessActionPerformed: false };
    },
  });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/handshake/mcp`;
  return {
    async call(name, args) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name, arguments: args } }),
      });
      return response.text();
    },
    async raw(method) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params: {} }),
      });
      return response.text();
    },
    async stop() {
      const closed = new Promise((resolve) => server.close(resolve));
      server.closeAllConnections();
      await closed;
    },
  };
}

const payload = (text) => JSON.parse(JSON.parse(text.split("\n").find((line) => line.startsWith("data:")).slice(5)).result.content[0].text);

test("a ccra_ handle survives a restart and v2 responses through it are byte-identical", async () => {
  const dir = mkdtempSync(join(tmpdir(), "v2-handles-"));
  const seen = [];
  const before = await serve(dir, seen);
  const invited = payload(await before.call("agent_handshake_invite", { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } }));
  const handle = invited.roleAccess;
  assert.match(handle, /^ccra_[A-Za-z0-9_-]{22}$/);
  const statusBefore = await before.call("agent_handshake_status", { access: handle });
  await before.stop();

  const after = await serve(dir, seen);
  const statusAfter = await after.call("agent_handshake_status", { access: handle });
  await after.stop();
  assert.equal(statusAfter, statusBefore, "byte-identical response through the same handle");
  assert.equal(payload(statusAfter).roleAccess, handle);
  // The coordinator always receives the underlying signed token, never the handle.
  assert.deepEqual(seen.filter((call) => call.name === "agent_handshake_status").map((call) => call.access), [initiatorAccess, initiatorAccess]);

  const stored = readFileSync(join(dir, "role-handles.json"), "utf8");
  assert.equal(stored.includes(handle), false, "no raw handle at rest");
  assert.equal(stored.includes(initiatorAccess), false, "no raw role token at rest");
});

test("without a state directory v2 handles stay memory-only, exactly as before", async () => {
  const seen = [];
  const first = await serve(undefined, seen);
  const handle = payload(await first.call("agent_handshake_invite", { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } })).roleAccess;
  await first.stop();
  const second = await serve(undefined, seen);
  const refused = JSON.parse(JSON.parse((await second.call("agent_handshake_status", { access: handle })).split("\n").find((line) => line.startsWith("data:")).slice(5)).result.content[0].text);
  await second.stop();
  assert.equal(typeof refused.error, "string");
});

test("tools/list on /handshake/mcp is byte-identical with and without durable handles", async () => {
  const list = async (stateDir) => {
    const server = await serve(stateDir, []);
    try {
      return await server.raw("tools/list");
    } finally {
      await server.stop();
    }
  };
  const durable = await list(mkdtempSync(join(tmpdir(), "v2-list-")));
  const memory = await list(undefined);
  assert.equal(durable, memory);
  assert.ok(JSON.parse(durable.split("\n").find((line) => line.startsWith("data:")).slice(5)).result.tools.length > 0);
});

test("a corrupt ccra_ handle map never takes /handshake/mcp down: non-handle calls and new handles work", async (t) => {
  const errors = t.mock.method(console, "error", () => {});
  const dir = mkdtempSync(join(tmpdir(), "v2-corrupt-"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, "role-handles.json"), "garbage", { mode: 0o600 });
  const seen = [];
  const server = await serve(dir, seen);
  try {
    const listed = await server.raw("tools/list");
    assert.ok(JSON.parse(listed.split("\n").find((line) => line.startsWith("data:")).slice(5)).result.tools.length > 0);
    // A raw role token (no handle involved) still works.
    assert.equal(payload(await server.call("agent_handshake_status", { access: initiatorAccess })).stage, "invited");
    // New handles are issued and resolve from memory.
    const handle = payload(await server.call("agent_handshake_invite", { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } })).roleAccess;
    assert.equal(payload(await server.call("agent_handshake_status", { access: handle })).roleAccess, handle);
    // Only a handle lost with the file is refused.
    assert.equal(typeof payload(await server.call("agent_handshake_status", { access: `ccra_${"z".repeat(22)}` })).error, "string");
  } finally {
    await server.stop();
  }
  assert.equal(readFileSync(join(dir, "role-handles.json"), "utf8"), "garbage", "the corrupt file is left for an operator");
  assert.ok(errors.mock.calls.some((call) => { try { return JSON.parse(call.arguments[0]).event === "handshake_handles_memory_only"; } catch { return false; } }));
});
