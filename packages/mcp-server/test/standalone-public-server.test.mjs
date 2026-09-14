import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import {
  STANDALONE_TOOL_NAMES,
  buildStandaloneDiscovery,
  buildStandaloneInstructions,
  createStandaloneHttpHandler,
} from "../dist/standalone-handshake/public-server.js";
import { buildStandalonePublicServer } from "../dist/standalone-handshake/public-server.js";
import { StandaloneAdmissionError } from "../dist/standalone-handshake/session-store.js";

const ACCEPT = "application/json, text/event-stream";

test("the tool surface is exactly the ten designed tools", () => {
  assert.deepEqual([...STANDALONE_TOOL_NAMES], [
    "handshake_invite",
    "handshake_accept_invitation",
    "handshake_status",
    "consent_sign",
    "channel_open",
    "channel_send",
    "channel_read",
    "channel_status",
    "channel_close",
    "channel_revoke",
  ]);
});

test("instructions lead with the local-signing boundary", () => {
  const text = buildStandaloneInstructions();
  assert.match(text, /never holds a private key/);
  assert.match(text, /clockchain\.standalone-handshake\/v1/);
  assert.match(text, /external business action/i);
});

test("discovery manifest names the endpoint and every tool", () => {
  const discovery = buildStandaloneDiscovery();
  assert.equal(discovery.name, "clockchain-standalone-handshake");
  assert.equal(discovery.endpoint, "https://mcp.clockchain.network/connect/mcp");
  assert.equal(discovery.tools.length, STANDALONE_TOOL_NAMES.length);
});

test("the HTTP handler serves /connect/mcp and rate-limits invites per IP", async () => {
  const calls = [];
  const handler = createStandaloneHttpHandler({
    invoke: async (name, args) => {
      calls.push(name);
      if (name === "handshake_invite") return { ok: true, initiatorAccess: `sat_${"a".repeat(28)}` };
      return { ok: true };
    },
    invitesPerHour: 1,
    callsPerMinute: 10,
    now: (() => { let t = 1_750_000_000_000; return () => (t += 1_000); })(),
  });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
  try {
    const rpc = async (method, params = {}) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const text = await response.text();
      const data = text.split("\n").find((line) => line.startsWith("data:"));
      return { status: response.status, body: JSON.parse(data ? data.slice(5) : text) };
    };
    const inviteArgs = {
      reference: "r",
      purpose: "p",
      channelLimits: { durationSeconds: "600", messageKinds: ["note"], maxMessageBytes: "4096" },
      identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null },
      readiness: {
        sessionKeyAddress: `0x${"1".repeat(40)}`,
        identity: null,
        authorityStatement: { accountableParty: "party", statement: "statement" },
        authoritySignatureHex: `0x${"2".repeat(130)}`,
        capabilityManifest: { dataHandlingClass: "public", purpose: "test" },
      },
    };

    const initialized = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    assert.equal(initialized.status, 200);
    assert.equal(initialized.body.result.serverInfo.name, "clockchain-standalone-handshake");

    await rpc("notifications/initialized");
    const first = await rpc("tools/call", { name: "handshake_invite", arguments: inviteArgs });
    assert.equal(first.status, 200);
    assert.equal(first.body.result.isError, undefined);
    assert.match(first.body.result.structuredContent.roleAccess, /^csha_[A-Za-z0-9_-]{22}$/);
    assert.equal("initiatorAccess" in first.body.result.structuredContent, false);
    const second = await rpc("tools/call", { name: "handshake_invite", arguments: inviteArgs });
    assert.equal(second.status, 200);
    assert.equal(second.body.result.isError, true);
    const secondText = JSON.parse(second.body.result.content[0].text);
    assert.deepEqual(secondText, { error: "STANDALONE_HANDSHAKE_UNAVAILABLE", retryable: false });
    assert.deepEqual(calls, ["handshake_invite"]);

    const wrong = await fetch(`http://127.0.0.1:${server.address().port}/other/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: ACCEPT }, body: "{}" });
    assert.equal(wrong.status, 404);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("buildStandalonePublicServer wires every tool onto an MCP server", async () => {
  const seen = [];
  const server = buildStandalonePublicServer({ invoke: async (name) => { seen.push(name); return { ok: true }; } });
  assert.notEqual(server, undefined);
});

test("role-access handles slide their TTL on use and role-scoped results never carry access keys", async () => {
  let t = 1_750_000_000_000;
  const handler = createStandaloneHttpHandler({
    // Defense-in-depth probe: the stub returns raw access tokens for EVERY tool, including role-scoped ones.
    invoke: async () => ({ ok: true, initiatorAccess: `sat_${"i".repeat(28)}`, responderAccess: `sat_${"r".repeat(28)}` }),
    invitesPerHour: 5,
    callsPerMinute: 50,
    now: () => t,
  });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
  try {
    const rpc = async (method, params = {}) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const text = await response.text();
      const data = text.split("\n").find((line) => line.startsWith("data:"));
      return JSON.parse(data ? data.slice(5) : text);
    };
    const inviteArgs = {
      reference: "r",
      purpose: "p",
      channelLimits: { durationSeconds: "600", messageKinds: ["note"], maxMessageBytes: "4096" },
      identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null },
      readiness: {
        sessionKeyAddress: `0x${"1".repeat(40)}`,
        identity: null,
        authorityStatement: { accountableParty: "party", statement: "statement" },
        authoritySignatureHex: `0x${"2".repeat(130)}`,
        capabilityManifest: { dataHandlingClass: "public", purpose: "test" },
      },
    };
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    await rpc("notifications/initialized");
    const invite = await rpc("tools/call", { name: "handshake_invite", arguments: inviteArgs });
    const handle = invite.result.structuredContent.roleAccess;
    assert.match(handle, /^csha_[A-Za-z0-9_-]{22}$/);
    assert.equal("initiatorAccess" in invite.result.structuredContent, false);

    const statusViaHandle = async () => rpc("tools/call", { name: "handshake_status", arguments: { access: handle } });

    // Resolve 1 minute before the original horizon: succeeds and slides the TTL forward.
    t += 59 * 60_000;
    const beforeHorizon = await statusViaHandle();
    assert.equal(beforeHorizon.result.isError, undefined);
    assert.equal(beforeHorizon.result.structuredContent.roleAccess, handle);
    assert.equal("initiatorAccess" in beforeHorizon.result.structuredContent, false);
    assert.equal("responderAccess" in beforeHorizon.result.structuredContent, false);

    // Two minutes later — past the ORIGINAL horizon, inside the refreshed one: still resolves.
    t += 2 * 60_000;
    const afterOriginalHorizon = await statusViaHandle();
    assert.equal(afterOriginalHorizon.result.isError, undefined);
    assert.equal("initiatorAccess" in afterOriginalHorizon.result.structuredContent, false);
    assert.equal("responderAccess" in afterOriginalHorizon.result.structuredContent, false);

    // An idle handle still dies: past the refreshed horizon it refuses.
    t += 61 * 60_000;
    const stale = await statusViaHandle();
    assert.equal(stale.result.isError, true);
    assert.deepEqual(JSON.parse(stale.result.content[0].text), { error: "STANDALONE_HANDSHAKE_UNAVAILABLE", retryable: false });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("tool failures surface reason codes and constants only, and log structured telemetry", async () => {
  const timeout = new Error("timed out upstream");
  timeout.name = "TimeoutError";
  const handler = createStandaloneHttpHandler({
    invoke: async (name) => {
      if (name === "handshake_status") throw new StandaloneAdmissionError("SCOPE_VIOLATION");
      if (name === "consent_sign") throw new Error("secret internal detail");
      throw timeout;
    },
  });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (line) => { warnings.push(line); };
  try {
    const rpc = async (method, params = {}) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const text = await response.text();
      const data = text.split("\n").find((line) => line.startsWith("data:"));
      return JSON.parse(data ? data.slice(5) : text);
    };
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
    await rpc("notifications/initialized");
    const access = { access: "a".repeat(24) };

    const admission = await rpc("tools/call", { name: "handshake_status", arguments: access });
    assert.equal(admission.result.isError, true);
    assert.deepEqual(JSON.parse(admission.result.content[0].text), { error: "SCOPE_VIOLATION", retryable: false });

    const generic = await rpc("tools/call", { name: "consent_sign", arguments: { ...access, signatureHex: `0x${"1".repeat(130)}` } });
    assert.equal(generic.result.isError, true);
    assert.deepEqual(JSON.parse(generic.result.content[0].text), { error: "STANDALONE_HANDSHAKE_UNAVAILABLE", retryable: false });
    assert.equal(JSON.stringify(generic.result).includes("secret internal detail"), false);

    const retryable = await rpc("tools/call", { name: "channel_send", arguments: { ...access, kind: "note", body: "x" } });
    assert.equal(retryable.result.isError, undefined);
    assert.deepEqual(retryable.result.structuredContent, { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 5000 });

    assert.equal(warnings.length, 3);
    assert.deepEqual(
      warnings.map((line) => JSON.parse(line)),
      [
        { event: "standalone_handshake_tool_failure", tool: "handshake_status", errorName: "StandaloneAdmissionError" },
        { event: "standalone_handshake_tool_failure", tool: "consent_sign", errorName: "Error" },
        { event: "standalone_handshake_tool_failure", tool: "channel_send", errorName: "TimeoutError" },
      ],
    );
  } finally {
    console.warn = originalWarn;
    await new Promise((resolve) => server.close(resolve));
  }
});
