import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
import { AGENT_HANDSHAKE_ROLE_TOOLS, mintV2RoleAccess } from "../dist/agent-handshake/v2/access.js";

const pin = {
  version: "2.1.5",
  sourceCommit: "d".repeat(40),
  manifestDigest: "a".repeat(64),
  allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.5/",
  hostRoots: [
    { kid: "root-2026-08", fingerprint: "b".repeat(64) },
    { kid: "root-2026-07", fingerprint: "c".repeat(64) },
  ],
};

const ACCEPT = "application/json, text/event-stream";
const roleKey = { kid: "role-test", secret: Buffer.alloc(32, "r") };
const roleSessionId = "11111111-2222-4333-8444-555555555555";
const roleStatementDigest = "f".repeat(64);

function roleAccess(overrides = {}) {
  return mintV2RoleAccess({
    key: roleKey,
    jti: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    sessionId: roleSessionId,
    role: "initiator",
    statementDigest: roleStatementDigest,
    allowedTools: AGENT_HANDSHAKE_ROLE_TOOLS,
    nbfMs: 0,
    expMs: 60_000,
    ...overrides,
  });
}

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
  assert.match(first, /2\.1\.5/);
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
  assert.match(instructions, /adapter asset path.*mandatory.*approvalCommand.*already preloaded.*do not download or overwrite.*inspect.*manifest.*helper source/is);
  assert.match(instructions, /portable fallback.*only when.*approvalCommand.*not available.*files are absent.*download/is);
  assert.ok(instructions.includes("curl --fail --location --proto '=https' --proto-redir '=https' --output ./manifest.json 'https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.5/manifest.json'"));
  assert.ok(instructions.includes("curl --fail --location --proto '=https' --proto-redir '=https' --output ./clockchain-agent-handshake.cjs 'https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.5/clockchain-agent-handshake.cjs'"));
  assert.match(instructions, /portable fallback.*each file as its own separate Bash tool call.*never prefix, wrap, combine/is);
  assert.match(instructions, /every Bash action.*one standalone Bash tool call.*never combine.*do not run.*stateDirectoryCommand.*until after.*assets.*inspected/is);
  assert.equal(instructions.includes(" ; then "), false);
  assert.match(instructions, /describes mechanics, not stakeholder authorization/i);
  assert.match(instructions, /local stakeholder's own prompt explicitly confirms/i);
  assert.match(instructions, /needed.*erc8004_registration.*pinned helper.*register.*same absolute state directory.*agent_handshake_next/is);
  assert.match(instructions, /session-scoped \$TMPDIR path.*every local helper operation.*do not assign.*shell variable.*replace.*\$HOME.*\$PWD/is);
  assert.match(instructions, /generate one fresh high-entropy acceptanceIdempotencyKey.*client-native secure randomness.*before.*first.*agent_handshake_accept_invitation/is);
  assert.match(instructions, /retain.*acceptanceIdempotencyKey locally.*never share.*return.*log/is);
  assert.match(instructions, /retry.*same invitation.*same acceptanceIdempotencyKey.*retryable.*transport uncertainty/is);
  assert.match(instructions, /after.*success.*retain.*roleAccess.*stop accepting/is);
  assert.match(instructions, /missing acceptanceIdempotencyKey.*transitional one-shot compatibility/is);
  assert.doesNotMatch(instructions, /agent_handshake_accept_invitation exactly once.*first successful result.*never retry/is);
  assert.match(instructions, /Every needed or stage response is nonterminal.*retryAfterMs.*agent_handshake_next.*final certificate.*unrecoverable error/is);
  assert.match(instructions, /every successful role-scoped response echoes roleAccess.*use it byte-for-byte.*immediately following.*access argument/is);
  assert.match(instructions, /exact localPolicy object returned by Clockchain.*do not construct, infer, or alter.*helper policy operation/is);
  assert.match(instructions, /statementDigest.*sha-256.*canonical.*terms object.*not.*raw statement text/is);
  assert.match(instructions, /already.*fresh.*disposable.*working directory.*do not create or switch to another working directory/is);
  assert.match(instructions, /never.*shared.*temp.*directory/is);
  assert.match(instructions, /manifest digest.*applies only.*manifest\.json.*helper.*separate.*sha-256.*verified manifest/is);
  assert.match(instructions, /trust root separation.*manifest digest.*independent pin.*manifest bytes.*asset hash.*helper bytes.*host-root fingerprint.*separate.*session-key certificate.*closing certificate.*not expected.*asset bootstrap/is);
  assert.match(instructions, /after.*init.*policy.*inspect.*call agent_handshake_join.*do not.*register.*before.*join.*fund.*agent_handshake_next.*erc8004_registration/is);
  assert.match(instructions, /approvalCommand.*exact digest-bound local action.*adapter executes.*structured arguments.*Never run helperStep\.shellCommand.*approvalCommand is available/is);
  assert.match(instructions, /Compatibility clients.*stateDirectoryCommand.*helperStep\.shellCommand verbatim.*never.*concatenate.*re-encode.*payload/is);
  assert.match(instructions, /operation.*does not include.*--payload-base64url.*do not add/is);
  assert.match(instructions, /signing and certificate response.*authoritative payload-bearing.*helperStep\.shellCommand.*short digest-bound approvalCommand.*Prefer approvalCommand through the adapter/is);
  assert.match(instructions, /summary fields.*confirmation only.*never.*reconstruct.*payload/is);
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
  assert.ok(V2_VERIFIED_HELPER_BOOTSTRAP.includes('!/^24\\./.test(manifest.nodeRuntime)'));
  assert.ok(V2_VERIFIED_HELPER_BOOTSTRAP.includes('!/^24\\./.test(process.versions.node)'));
  assert.equal(V2_VERIFIED_HELPER_BOOTSTRAP.includes(","), false);
  assert.equal(V2_VERIFIED_HELPER_BOOTSTRAP.includes("'"), false);
});

test("the dedicated MCP server exposes exactly eight tools and no prompts or resources", async () => {
  const signingPayload = Buffer.from(JSON.stringify({ operation: "identity_claim", role: "initiator" }), "utf8").toString("base64url");
  const signingCommand = `verified-helper sign --payload-base64url ${signingPayload}`;
  const setupCommands = ["init", "policy", "inspect"].map((operation) => `verified-helper ${operation}`);
  const httpServer = createServer(async (req, res) => {
    const server = buildV2PublicServer({ pin, invoke: async (name) => ({
      ok: true,
      name,
      ...(name === "agent_handshake_invite" ? {
        initiatorAccess: "i".repeat(80),
        localAction: {
          helperSteps: setupCommands.map((shellCommand, index) => ({
            operation: ["init", "policy", "inspect"][index],
            role: "initiator",
            sessionId: "11111111-2222-4333-8444-555555555555",
            approvalCommand: `clockchain-agent-authorize ${createHash("sha256").update(shellCommand).digest("hex")}`,
            commandLength: Buffer.byteLength(shellCommand),
            commandSha256: createHash("sha256").update(shellCommand).digest("hex"),
            shellCommand,
          })),
        },
      } : {}),
      ...(name === "agent_handshake_accept_invitation" ? {
        responderAccess: "r".repeat(80),
        localAction: {
          helperSteps: setupCommands.map((shellCommand, index) => ({
            operation: ["init", "policy", "inspect"][index],
            role: "responder",
            sessionId: "11111111-2222-4333-8444-555555555555",
            approvalCommand: `clockchain-agent-authorize ${createHash("sha256").update(shellCommand).digest("hex")}`,
            commandLength: Buffer.byteLength(shellCommand),
            commandSha256: createHash("sha256").update(shellCommand).digest("hex"),
            shellCommand,
          })),
        },
      } : {}),
      ...(name === "agent_handshake_join" ? {
        signingSummary: { schema: "clockchain.agent-handshake-signing-summary/v1", operation: "identity_claim" },
        localAction: { helperStep: {
          operation: "sign",
          role: "initiator",
          sessionId: "11111111-2222-4333-8444-555555555555",
          approvalCommand: `clockchain-agent-authorize ${createHash("sha256").update(signingCommand).digest("hex")}`,
          commandLength: Buffer.byteLength(signingCommand),
          commandSha256: createHash("sha256").update(signingCommand).digest("hex"),
          shellCommand: signingCommand,
        } },
      } : {}),
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
    assert.ok(listed.body.result.tools.some((tool) => tool.name === "agent_handshake_submit_checkpoint"));
    const accept = listed.body.result.tools.find((tool) => tool.name === "agent_handshake_accept_invitation");
    assert.equal(accept.inputSchema.required.includes("acceptanceIdempotencyKey"), false);
    assert.equal(accept.inputSchema.properties.acceptanceIdempotencyKey.type, "string");
    assert.doesNotMatch(accept.description, /\bonce\b/i);
    assert.match(accept.description, /optional.*acceptanceIdempotencyKey.*retry-safe/is);
    const invite = listed.body.result.tools.find((tool) => tool.name === "agent_handshake_invite");
    const inviteSchema = JSON.stringify(invite.inputSchema);
    assert.match(inviteSchema, /eip155:11155111/);
    assert.match(inviteSchema, /0x8004a818bfb912233c491871b3d84c89a494bd9e/);
    assert.match(inviteSchema, /required_fresh/);
    assert.equal(listed.body.result.tools.some((tool) => tool.annotations?.requiresUserInteraction === true), false);
    const invited = await rpc(url, "tools/call", { name: "agent_handshake_invite", arguments: { reference: "NS-1847", statement: "test", validForSeconds: "90", identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } } });
    const invitedText = JSON.parse(invited.body.result.content[0].text);
    assert.equal(invited.body.result.structuredContent, undefined);
    assert.equal(invitedText.roleAccess, "i".repeat(80));
    assert.equal("initiatorAccess" in invitedText, false);
    for (const [index, command] of setupCommands.entries()) {
      assert.equal(invitedText.localAction.helperSteps[index].shellCommand, command);
      assert.equal(invitedText.localAction.helperSteps[index].approvalCommand, `clockchain-agent-authorize ${invitedText.localAction.helperSteps[index].commandSha256}`);
      assert.equal(JSON.stringify(invited.body.result).split(command).length - 1, 1);
    }
    const accepted = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80) },
    });
    const acceptedText = JSON.parse(accepted.body.result.content[0].text);
    assert.equal(accepted.body.result.structuredContent, undefined);
    assert.equal(acceptedText.roleAccess, "r".repeat(80));
    assert.equal("responderAccess" in acceptedText, false);
    for (const [index, command] of setupCommands.entries()) {
      assert.equal(acceptedText.localAction.helperSteps[index].shellCommand, command);
      assert.equal(acceptedText.localAction.helperSteps[index].approvalCommand, `clockchain-agent-authorize ${acceptedText.localAction.helperSteps[index].commandSha256}`);
      assert.equal(JSON.stringify(accepted.body.result).split(command).length - 1, 1);
    }
    const roleAccess = "r".repeat(80);
    const status = await rpc(url, "tools/call", { name: "agent_handshake_status", arguments: { access: roleAccess } });
    assert.equal(status.body.result.structuredContent.roleAccess, roleAccess);
    const staleJoined = await rpc(url, "tools/call", { name: "agent_handshake_join", arguments: {
      access: roleAccess,
      helperVersion: "2.1.3",
      sessionKeyAddress: `0x${"1".repeat(40)}`,
      policyDigest: "2".repeat(64),
    } });
    assert.equal(staleJoined.body.result.isError, true, "stale helperVersion is a schema rejection");
    assert.equal(staleJoined.body.result.structuredContent, undefined, "stale helperVersion yields no structured payload");
    const joined = await rpc(url, "tools/call", { name: "agent_handshake_join", arguments: {
      access: roleAccess,
      helperVersion: "2.1.5",
      sessionKeyAddress: `0x${"1".repeat(40)}`,
      policyDigest: "2".repeat(64),
    } });
    const serializedJoin = JSON.stringify(joined.body.result);
    assert.equal(serializedJoin.split(signingPayload).length - 1, 1);
    const joinedText = JSON.parse(joined.body.result.content[0].text);
    assert.equal(joined.body.result.structuredContent, undefined);
    assert.equal(joinedText.localAction.helperStep.shellCommand, signingCommand);
    assert.equal(joinedText.localAction.helperStep.commandLength, Buffer.byteLength(signingCommand));
    assert.equal(joinedText.localAction.helperStep.commandSha256, createHash("sha256").update(signingCommand).digest("hex"));
    assert.equal(joinedText.localAction.helperStep.approvalCommand, `clockchain-agent-authorize ${joinedText.localAction.helperStep.commandSha256}`);
    assert.equal((await rpc(url, "resources/list")).body.error.code, -32601);
    assert.equal((await rpc(url, "prompts/list")).body.error.code, -32601);
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
  }
});

test("accept invitation validates optional acceptance idempotency key and passes it through unchanged", async () => {
  const observed = [];
  const handler = createV2PublicHttpHandler({
    pin,
    now: () => 1_000,
    invoke: async (name, args) => {
      observed.push({ name, args });
      if (name === "agent_handshake_accept_invitation") return { responderAccess: roleAccess({ role: "responder" }), sessionId: "session" };
      return { ok: true, name };
    },
  });
  const httpServer = createServer((req, res) => handler(req, res));
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${httpServer.address().port}/handshake/mcp`;
  try {
    const uuidKey = "11111111-2222-4333-8444-555555555555";
    const accepted = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: uuidKey },
    });
    assert.equal(accepted.body.result.isError, undefined);
    assert.equal(observed.at(-1).args.acceptanceIdempotencyKey, uuidKey);

    const uppercaseUuidKey = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";
    const beforeUppercase = observed.length;
    const uppercaseUuid = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: uppercaseUuidKey },
    });
    assert.equal(observed.length, beforeUppercase);
    assert.ok(uppercaseUuid.body.error || uppercaseUuid.body.result?.isError);

    const base64urlKey = Buffer.from("0123456789abcdef", "utf8").toString("base64url");
    const acceptedWithBase64url = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: base64urlKey },
    });
    assert.equal(acceptedWithBase64url.body.result.isError, undefined);
    assert.equal(observed.at(-1).args.acceptanceIdempotencyKey, base64urlKey);

    const absentKey = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80) },
    });
    assert.equal(absentKey.body.result.isError, undefined);
    assert.equal("acceptanceIdempotencyKey" in observed.at(-1).args, false);

    const beforeMalformed = observed.length;
    const malformed = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: "not-a-valid-key" },
    });
    assert.equal(observed.length, beforeMalformed);
    assert.ok(malformed.body.error || malformed.body.result?.isError);
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
  }
});

test("public HTTP routing ignores full-surface credentials, trusts only configured proxies, and rate limits", async () => {
  assert.equal(v2PublicClientIp({ "x-forwarded-for": "203.0.113.9" }, "198.51.100.2", "198.51.100.1"), "198.51.100.2");
  assert.equal(v2PublicClientIp({ "x-forwarded-for": "203.0.113.9, 198.51.100.1" }, "198.51.100.1", "198.51.100.1"), "203.0.113.9");
  let now = 1000;
  const validInitiatorAccess = roleAccess({ jti: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", expMs: 60 * 60_000 + 10_000 });
  const handler = createV2PublicHttpHandler({
    pin,
    now: () => now,
    invitePerHour: 5,
    callsPerMinute: 120,
    invoke: async (name) => ({
      ok: true,
      name,
      ...(name === "agent_handshake_invite" ? { initiatorAccess: validInitiatorAccess } : {}),
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
  const initiatorCapability = roleAccess({ jti: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", role: "initiator" });
  const responderCapability = roleAccess({ jti: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", role: "responder" });
  const observed = [];
  let now = 1_000;
  const handler = createV2PublicHttpHandler({
    pin,
    now: () => now,
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

test("public HTTP reuses role-access handles by signed access digest until expiry", async () => {
  let now = 1000;
  const firstCapability = roleAccess({ jti: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", role: "responder", expMs: 5_000 });
  const secondCapability = roleAccess({ jti: "ffffffff-ffff-4fff-8fff-ffffffffffff", role: "responder", expMs: 6_000 });
  const freshCapability = roleAccess({ jti: "11111111-2222-4333-8444-555555555555", role: "responder", expMs: 10_000 });
  const expiredCapability = roleAccess({ jti: "22222222-3333-4444-8555-666666666666", role: "responder", expMs: 999 });
  let nextCapability = firstCapability;
  const handler = createV2PublicHttpHandler({
    pin,
    now: () => now,
    invoke: async (name) => {
      if (name === "agent_handshake_accept_invitation") {
        return { responderAccess: nextCapability, sessionId: "session" };
      }
      return { ok: true, name };
    },
  });
  const httpServer = createServer((req, res) => handler(req, res));
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${httpServer.address().port}/handshake/mcp`;
  try {
    const first = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: "11111111-2222-4333-8444-555555555555" },
    });
    const firstHandle = first.body.result.structuredContent.roleAccess;
    const sameAccess = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: "22222222-3333-4444-8555-666666666666" },
    });
    assert.equal(sameAccess.body.result.structuredContent.roleAccess, firstHandle);

    nextCapability = secondCapability;
    const differentAccess = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: "33333333-4444-4555-8666-777777777777" },
    });
    assert.notEqual(differentAccess.body.result.structuredContent.roleAccess, firstHandle);

    nextCapability = expiredCapability;
    const alreadyExpired = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: "44444444-5555-4666-8777-888888888888" },
    });
    assert.equal(alreadyExpired.body.result.isError, true);

    now = 5_000;
    nextCapability = firstCapability;
    const afterExpiry = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: "55555555-6666-4777-8888-999999999999" },
    });
    assert.equal(afterExpiry.body.result.isError, true);

    const expiredHandle = await rpc(url, "tools/call", {
      name: "agent_handshake_status",
      arguments: { access: firstHandle },
    });
    assert.equal(expiredHandle.body.result.isError, true);

    nextCapability = freshCapability;
    const freshAfterExpiry = await rpc(url, "tools/call", {
      name: "agent_handshake_accept_invitation",
      arguments: { invitation: "v".repeat(80), acceptanceIdempotencyKey: "66666666-7777-4888-8999-aaaaaaaaaaaa" },
    });
    assert.notEqual(freshAfterExpiry.body.result.structuredContent.roleAccess, firstHandle);
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
      const handler = createV2PublicHttpHandler({ pin, now: () => 1_000, invoke: async () => { throw candidate.error; } });
      const httpServer = createServer((req, res) => handler(req, res));
      await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
      const url = `http://127.0.0.1:${httpServer.address().port}/handshake/mcp`;
      try {
        const result = await rpc(url, "tools/call", { name: "agent_handshake_status", arguments: { access: roleAccess({ jti: "77777777-8888-4999-8aaa-bbbbbbbbbbbb" }) } });
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
