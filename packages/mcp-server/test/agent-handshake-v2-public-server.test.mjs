import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import {
  V2_PUBLIC_TOOL_NAMES,
  buildV2PublicServer,
} from "../dist/agent-handshake/v2/public-server.js";
import {
  createV2PublicHttpHandler,
  v2PublicClientIp,
} from "../dist/agent-handshake/v2/public-server.js";
import { V2_VERIFIED_HELPER_BOOTSTRAP, buildV2Instructions, buildV2Manifest } from "../dist/agent-handshake/v2/instructions.js";

const pin = {
  version: "2.1.2",
  sourceCommit: "d".repeat(40),
  manifestDigest: "a".repeat(64),
  allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/",
  hostRoots: [
    { kid: "root-2026-08", fingerprint: "b".repeat(64) },
    { kid: "root-2026-07", fingerprint: "c".repeat(64) },
  ],
};

const ACCEPT = "application/json, text/event-stream";
async function rpc(url, method, params = {}, headers = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: ACCEPT, ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await response.text();
  const data = text.split("\n").find((line) => line.startsWith("data:"));
  return { status: response.status, body: JSON.parse(data ? data.slice(5) : text) };
}

test("public initialization leads with the immutable local-authority boundary", async () => {
  const instructions = buildV2Instructions(pin);
  const first = instructions.slice(0, 512);
  assert.match(first, /local signing/i);
  assert.match(first, /2\.1\.2/);
  assert.equal(first.includes(pin.manifestDigest), false);
  assert.match(first, /digest is encoded only in the exact verified command below/i);
  assert.equal(instructions.split(pin.manifestDigest).length - 1, 1);
  assert.ok(first.includes(pin.allowedAssetPrefix));
  assert.ok(first.includes(pin.hostRoots[0].kid));
  assert.ok(first.includes(pin.hostRoots[0].fingerprint));
  assert.match(first, /stop/i);
  assert.equal(instructions.includes("native signature"), false);
  assert.equal(instructions.includes("node ./clockchain-agent-handshake.cjs"), false);
  assert.match(instructions, /Node 24/);
  assert.ok(instructions.includes(V2_VERIFIED_HELPER_BOOTSTRAP));
  assert.match(instructions, /compile only those verified bytes in memory/i);
  assert.match(instructions, /short opaque local handle/i);
  assert.match(instructions, /do not send it to the other stakeholder or echo it into chat or logs/i);
  assert.match(instructions, /inspect the downloaded manifest and helper source before execution/i);
  assert.ok(instructions.includes("curl --fail --location --proto '=https' --proto-redir '=https' --output ./manifest.json 'https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/manifest.json'"));
  assert.ok(instructions.includes("curl --fail --location --proto '=https' --proto-redir '=https' --output ./clockchain-agent-handshake.cjs 'https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/clockchain-agent-handshake.cjs'"));
  assert.match(instructions, /each command as its own separate Bash tool call.*never prefix, wrap, or combine/is);
  assert.match(instructions, /every Bash action.*one standalone Bash tool call.*never combine.*do not run.*stateDirectoryCommand.*until after.*downloaded.*inspected/is);
  assert.equal(instructions.includes(" ; then "), false);
  assert.match(instructions, /describes mechanics, not stakeholder authorization/i);
  assert.match(instructions, /local stakeholder's own prompt explicitly confirms/i);
  assert.match(instructions, /needed.*erc8004_registration.*pinned helper.*register.*same absolute state directory.*agent_handshake_next/is);
  assert.match(instructions, /session-scoped \$TMPDIR path.*every local helper operation.*do not assign.*shell variable.*replace.*\$HOME.*\$PWD/is);
  assert.match(instructions, /agent_handshake_accept_invitation exactly once.*first successful result.*never retry/is);
  assert.match(instructions, /Every needed or stage response is nonterminal.*retryAfterMs.*agent_handshake_next.*final certificate.*unrecoverable error/is);
  assert.match(instructions, /every successful role-scoped response echoes roleAccess.*use it byte-for-byte.*immediately following.*access argument/is);
  assert.match(instructions, /exact localPolicy object returned by Clockchain.*do not construct, infer, or alter.*helper policy operation/is);
  assert.match(instructions, /statementDigest.*sha-256.*canonical.*terms object.*not.*raw statement text/is);
  assert.match(instructions, /already.*fresh.*disposable.*working directory.*do not create or switch to another working directory/is);
  assert.match(instructions, /never.*shared.*temp.*directory/is);
  assert.match(instructions, /manifest digest.*applies only.*manifest\.json.*helper.*separate.*sha-256.*verified manifest/is);
  assert.match(instructions, /after.*init.*policy.*inspect.*call agent_handshake_join.*do not.*register.*before.*join.*fund.*agent_handshake_next.*erc8004_registration/is);
  assert.match(instructions, /stateDirectoryCommand.*session-scoped.*client.*isolated \$TMPDIR.*helperStep\.shellCommand.*verbatim.*never.*concatenate.*re-encode.*payload/is);
  assert.match(instructions, /operation.*does not include.*--payload-base64url.*do not add/is);
  assert.match(instructions, /Never infer that the other stakeholder stopped from a waiting response/is);
  assert.match(instructions, /HANDSHAKE_TEMPORARILY_UNAVAILABLE.*retryable: true.*retryAfterMs.*retry the same tool.*terminal protocol rejection/is);
  assert.match(instructions, /role-scoped.*access argument.*same Clockchain MCP.*required credential use.*not.*disclosure/is);
  assert.match(instructions, /access.*byte-for-byte.*never.*decode.*re-encode.*shorten.*reconstruct/is);
  assert.match(instructions, /roleAccess.*short opaque local handle.*signed bearer capability.*behind.*handle/is);
  assert.match(instructions, /agent_handshake_invite.*only.*roleAccess.*Initiator.*responderInvitation.*copy.*never substitute/is);
  assert.match(instructions, /invitation acceptance.*only.*roleAccess.*Responder.*original invitation.*never.*access argument/is);
  assert.doesNotMatch(instructions, /keep each returned role access value private/i);
  const manifest = buildV2Manifest(pin);
  assert.equal(manifest.endpoint, "https://mcp.clockchain.network/handshake/mcp");
  assert.equal(manifest.helper.filename, "clockchain-agent-handshake.cjs");
  assert.equal(manifest.helper.nodeRuntimeMajor, "24");
  assert.ok(manifest.helper.verifiedBootstrapPrefix.includes(pin.manifestDigest));
  assert.ok(manifest.helper.verifiedBootstrapPrefix.includes(V2_VERIFIED_HELPER_BOOTSTRAP));
  assert.equal(V2_VERIFIED_HELPER_BOOTSTRAP.includes(","), false);
  assert.equal(V2_VERIFIED_HELPER_BOOTSTRAP.includes("'"), false);
});

test("the dedicated MCP server exposes exactly seven tools and no prompts or resources", async () => {
  const httpServer = createServer(async (req, res) => {
    const server = buildV2PublicServer({ pin, invoke: async (name) => ({
      ok: true,
      name,
      ...(name === "agent_handshake_invite" ? { initiatorAccess: "i".repeat(80) } : {}),
      ...(name === "agent_handshake_accept_invitation" ? { responderAccess: "r".repeat(80) } : {}),
    }) });
    const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { void transport.close(); void server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res);
  });
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${httpServer.address().port}/handshake/mcp`;
  try {
    const initialized = await rpc(url, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "fresh-client", version: "1" },
    });
    assert.equal(initialized.body.result.serverInfo.name, "clockchain-agent-handshake");
    assert.equal(initialized.body.result.instructions, buildV2Instructions(pin));
    assert.equal("resources" in initialized.body.result.capabilities, false);
    assert.equal("prompts" in initialized.body.result.capabilities, false);
    const listed = await rpc(url, "tools/list");
    assert.deepEqual(listed.body.result.tools.map((tool) => tool.name), V2_PUBLIC_TOOL_NAMES);
    const invite = listed.body.result.tools.find((tool) => tool.name === "agent_handshake_invite");
    const inviteSchema = JSON.stringify(invite.inputSchema);
    assert.match(inviteSchema, /eip155:11155111/);
    assert.match(inviteSchema, /0x8004a818bfb912233c491871b3d84c89a494bd9e/);
    assert.match(inviteSchema, /required_fresh/);
    assert.equal(listed.body.result.tools.some((tool) => tool.annotations?.requiresUserInteraction === true), false);
    const invited = await rpc(url, "tools/call", { name: "agent_handshake_invite", arguments: { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } } });
    assert.equal(invited.body.result.structuredContent.roleAccess, "i".repeat(80));
    assert.equal("initiatorAccess" in invited.body.result.structuredContent, false);
    const roleAccess = "r".repeat(80);
    const status = await rpc(url, "tools/call", { name: "agent_handshake_status", arguments: { access: roleAccess } });
    assert.equal(status.body.result.structuredContent.roleAccess, roleAccess);
    assert.equal((await rpc(url, "resources/list")).body.error.code, -32601);
    assert.equal((await rpc(url, "prompts/list")).body.error.code, -32601);
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
  }
});

test("public HTTP routing ignores full-surface credentials, trusts only configured proxies, and rate limits", async () => {
  assert.equal(v2PublicClientIp({ "x-forwarded-for": "203.0.113.9" }, "198.51.100.2", "198.51.100.1"), "198.51.100.2");
  assert.equal(v2PublicClientIp({ "x-forwarded-for": "203.0.113.9, 198.51.100.1" }, "198.51.100.1", "198.51.100.1"), "203.0.113.9");
  let now = 1000;
  const handler = createV2PublicHttpHandler({
    pin,
    now: () => now,
    invitePerHour: 5,
    callsPerMinute: 120,
    invoke: async (name) => ({
      ok: true,
      name,
      ...(name === "agent_handshake_invite" ? { initiatorAccess: `${"a".repeat(160)}.${"b".repeat(43)}` } : {}),
    }),
  });
  const httpServer = createServer((req, res) => handler(req, res));
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${httpServer.address().port}/handshake/mcp`;
  try {
    const listed = await rpc(url, "tools/list", {}, { "x-clockchain-api-key": "must-be-ignored" });
    assert.deepEqual(listed.body.result.tools.map((tool) => tool.name), V2_PUBLIC_TOOL_NAMES);
    for (let index = 0; index < 5; index += 1) {
      const result = await rpc(url, "tools/call", { name: "agent_handshake_invite", arguments: { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } } });
      assert.equal(result.body.result.isError, undefined);
    }
    const limited = await rpc(url, "tools/call", { name: "agent_handshake_invite", arguments: { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } } });
    assert.equal(limited.body.result.isError, true);
    now += 60 * 60_000 + 1;
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
  }
});

test("public HTTP keeps signed role capabilities behind short opaque handles", async () => {
  const initiatorCapability = `${"a".repeat(160)}.${"b".repeat(43)}`;
  const responderCapability = `${"c".repeat(160)}.${"d".repeat(43)}`;
  const observed = [];
  const handler = createV2PublicHttpHandler({
    pin,
    invoke: async (name, args) => {
      observed.push({ name, args });
      if (name === "agent_handshake_invite") {
        return { initiatorAccess: initiatorCapability, responderInvitation: "v".repeat(80) };
      }
      if (name === "agent_handshake_accept_invitation") {
        return { responderAccess: responderCapability, sessionId: "session" };
      }
      return { ok: true, name };
    },
  });
  const httpServer = createServer((req, res) => handler(req, res));
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${httpServer.address().port}/handshake/mcp`;
  try {
    const invited = await rpc(url, "tools/call", {
      name: "agent_handshake_invite",
      arguments: { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } },
    });
    const initiatorHandle = invited.body.result.structuredContent.roleAccess;
    assert.match(initiatorHandle, /^ccra_[A-Za-z0-9_-]{22}$/);
    assert.equal("initiatorAccess" in invited.body.result.structuredContent, false);
    assert.equal(JSON.stringify(invited.body).includes(initiatorCapability), false);

    const status = await rpc(url, "tools/call", {
      name: "agent_handshake_status",
      arguments: { access: initiatorHandle },
    });
    assert.equal(status.body.result.structuredContent.roleAccess, initiatorHandle);
    assert.equal(observed.at(-1).args.access, initiatorCapability);
    assert.equal(JSON.stringify(status.body).includes(initiatorCapability), false);

    const accepted = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80) },
    });
    const responderHandle = accepted.body.result.structuredContent.roleAccess;
    assert.match(responderHandle, /^ccra_[A-Za-z0-9_-]{22}$/);
    assert.notEqual(responderHandle, initiatorHandle);
    assert.equal("responderAccess" in accepted.body.result.structuredContent, false);
    assert.equal(JSON.stringify(accepted.body).includes(responderCapability), false);

    await rpc(url, "tools/call", {
      name: "agent_handshake_next",
      arguments: { access: responderHandle },
    });
    assert.equal(observed.at(-1).args.access, responderCapability);

    const invalid = await rpc(url, "tools/call", {
      name: "agent_handshake_next",
      arguments: { access: `${responderHandle.slice(0, -1)}x` },
    });
    assert.equal(invalid.body.result.isError, true);
    assert.equal(observed.at(-1).args.access, responderCapability);
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
  }
});

test("public tools distinguish retryable infrastructure failures from terminal protocol rejection", async () => {
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (value) => warnings.push(value);
  try {
    for (const candidate of [
      { error: Object.assign(new Error("rpc unavailable"), { name: "RpcRequestError" }), retryable: true },
      { error: Object.assign(new Error("ledger is not durable yet"), { name: "V2TransientCoordinatorError" }), retryable: true },
      { error: Object.assign(new Error("secret invalid role state"), { name: "V2CoordinatorError" }), retryable: false },
      { error: new Error("unexpected internal state"), retryable: false },
    ]) {
      const handler = createV2PublicHttpHandler({ pin, invoke: async () => { throw candidate.error; } });
      const httpServer = createServer((req, res) => handler(req, res));
      await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
      const url = `http://127.0.0.1:${httpServer.address().port}/handshake/mcp`;
      try {
        const result = await rpc(url, "tools/call", { name: "agent_handshake_status", arguments: { access: "a".repeat(80) } });
        const body = JSON.parse(result.body.result.content[0].text);
        assert.equal(body.retryable, candidate.retryable);
        assert.equal(result.body.result.isError === true, !candidate.retryable);
        if (candidate.retryable) {
          assert.equal(body.error, "HANDSHAKE_TEMPORARILY_UNAVAILABLE");
          assert.equal(body.retryAfterMs, 5000);
        }
      } finally {
        await new Promise((resolve) => httpServer.close(resolve));
      }
    }
  } finally {
    console.warn = originalWarn;
  }
  assert.deepEqual(warnings.map((entry) => JSON.parse(entry)), [
    { event: "agent_handshake_tool_failure", tool: "agent_handshake_status", errorName: "RpcRequestError" },
    { event: "agent_handshake_tool_failure", tool: "agent_handshake_status", errorName: "V2TransientCoordinatorError" },
    { event: "agent_handshake_tool_failure", tool: "agent_handshake_status", errorName: "V2CoordinatorError" },
    { event: "agent_handshake_tool_failure", tool: "agent_handshake_status", errorName: "Error" },
  ]);
  assert.equal(warnings.join("\n").includes("secret invalid role state"), false);
  assert.equal(warnings.join("\n").includes("unexpected internal state"), false);
});
