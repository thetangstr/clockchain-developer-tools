// Guidance that reaches agents through channels they reliably see: tool descriptions,
// self-describing invitations, and a playbook version on every response.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import {
  STANDALONE_PLAYBOOK_VERSION,
  decodeStandaloneInvitation,
  encodeStandaloneInvitation,
} from "../dist/standalone-handshake/protocol.js";
import { buildStandaloneDiscovery, createStandaloneHttpHandler, standalonePublicEndpoint } from "../dist/standalone-handshake/public-server.js";
import { PLAYBOOK_NOTICE, STANDALONE_TOOL_DEFINITIONS } from "../dist/standalone-handshake/tools.js";
import { validTerms } from "./helpers/standalone-fixtures.mjs";
import { harness } from "./helpers/standalone-harness.mjs";
import { fakeLedger, recoverLocally } from "./helpers/standalone-signer.mjs";

const ACCEPT = "application/json, text/event-stream";
const describe = (name) => STANDALONE_TOOL_DEFINITIONS.find((tool) => tool.name === name).description;

async function serve(handler, fn) {
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
  const call = async (name, args, headers = {}) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT, ...headers },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await response.text();
    const data = text.split("\n").find((line) => line.startsWith("data:"));
    return JSON.parse(JSON.parse(data ? data.slice(5) : text).result.content[0].text);
  };
  try {
    await fn(call);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("tool descriptions carry the rules an agent must not work around", () => {
  const accept = describe("handshake_accept_invitation");
  assert.match(accept, /Call handshake_preview_invitation first to learn the exact required purpose and dataHandlingClass/);
  assert.match(accept, /A failed readiness check does NOT burn the invitation/);
  assert.match(accept, /up to 3 attempts via handshake_retry_readiness/);
  assert.match(accept, /Never ask your user to relay anything to the counterparty/);
  assert.match(describe("handshake_preview_invitation"), /Safe, read-only, burns nothing/);
  assert.match(describe("handshake_invite"), /only that the invitation must reach the counterparty's agent; everything else comes from the server/);
  for (const tool of STANDALONE_TOOL_DEFINITIONS) assert.ok(tool.description.length <= 400, `${tool.name} description stays concise`);
});

test("v2 invitations are readable, self-describing and round-trip; v1 still decodes", () => {
  const sessionId = "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01";
  const secret = "s".repeat(32);
  const invitation = encodeStandaloneInvitation({ sessionId, secret, endpoint: "https://mcp.clockchain.network/staging/connect/mcp" });
  assert.match(invitation, /^chs2\.[A-Za-z0-9_-]+$/);
  assert.deepEqual(decodeStandaloneInvitation(invitation), { v: 2, sessionId, secret, endpoint: "https://mcp.clockchain.network/staging/connect/mcp" });
  const payload = JSON.parse(Buffer.from(invitation.slice(5), "base64url").toString("utf8"));
  assert.equal(payload.next, "handshake_preview_invitation");

  const v1 = Buffer.from(JSON.stringify({ v: 1, sessionId, secret })).toString("base64url");
  assert.deepEqual(decodeStandaloneInvitation(v1), { v: 1, sessionId, secret });
  // Versions cannot be mixed, and a v2 envelope must name its endpoint.
  assert.equal(decodeStandaloneInvitation("chs2." + v1), undefined);
  assert.equal(decodeStandaloneInvitation(Buffer.from(JSON.stringify({ ...payload })).toString("base64url")), undefined);
  const { endpoint: _endpoint, ...noEndpoint } = payload;
  assert.equal(decodeStandaloneInvitation("chs2." + Buffer.from(JSON.stringify(noEndpoint)).toString("base64url")), undefined);
});

test("an issued v2 invitation previews and accepts, and a v1 envelope of the same secret still works", async () => {
  const h = harness();
  const invite = await h.invite();
  assert.ok(invite.invitation.startsWith("chs2."));
  assert.equal(decodeStandaloneInvitation(invite.invitation).endpoint, "https://mcp.clockchain.network/connect/mcp");
  assert.match(invite.tellYourUser, /only needs to reach the other agent/);
  assert.equal((await h.instance.invoke("handshake_preview_invitation", { invitation: invite.invitation })).sessionId, invite.sessionId);

  const other = await h.invite();
  const { sessionId, secret } = decodeStandaloneInvitation(other.invitation);
  const legacy = Buffer.from(JSON.stringify({ v: 1, sessionId, secret })).toString("base64url");
  assert.equal((await h.instance.invoke("handshake_preview_invitation", { invitation: legacy })).sessionId, sessionId);
  assert.equal((await h.accept(legacy)).stage, "ready");
});

test("the invitation endpoint matches the address used, including a /staging prefix", async () => {
  assert.equal(standalonePublicEndpoint({ host: "mcp.clockchain.network", "x-forwarded-prefix": "/staging/" }, {}), "https://mcp.clockchain.network/staging/connect/mcp");
  assert.equal(standalonePublicEndpoint({ "x-forwarded-host": "edge.example", host: "internal:3000" }, {}), "https://edge.example/connect/mcp");
  assert.equal(standalonePublicEndpoint({ host: "anything" }, { STANDALONE_PUBLIC_ENDPOINT: "https://mcp.clockchain.network/staging/connect/mcp" }), "https://mcp.clockchain.network/staging/connect/mcp");
  assert.equal(standalonePublicEndpoint({}, {}), buildStandaloneDiscovery().endpoint);

  const h = harness();
  const handler = createStandaloneHttpHandler({ invoke: (name, args) => h.instance.invoke(name, args), env: {} });
  await serve(handler, async (call) => {
    const invite = await call("handshake_invite", { ...validTerms(), readiness: await h.readiness("initiator") }, { "x-forwarded-prefix": "/staging", "x-forwarded-host": "mcp.clockchain.network" });
    assert.equal(decodeStandaloneInvitation(invite.invitation).endpoint, "https://mcp.clockchain.network/staging/connect/mcp");
  });
});

test("every response carries playbookVersion, and main-path calls without a current version get playbookNotice", async () => {
  const seen = [];
  const handler = createStandaloneHttpHandler({
    invoke: async (name, args) => {
      seen.push(args);
      if (name === "handshake_next") return { action: "wait" };
      if (name === "readiness_prepare") return { record: {}, bytes: "{}", bytesSha256: "0".repeat(64) };
      throw new Error("boom");
    },
  });
  const access = `sat_${"a".repeat(40)}`;
  await serve(handler, async (call) => {
    const missing = await call("handshake_next", { access, waitMs: 0 });
    assert.equal(missing.playbookVersion, STANDALONE_PLAYBOOK_VERSION);
    assert.equal(missing.playbookNotice, PLAYBOOK_NOTICE);
    const older = await call("handshake_next", { access, waitMs: 0, playbookVersion: STANDALONE_PLAYBOOK_VERSION - 1 });
    assert.equal(older.playbookNotice, PLAYBOOK_NOTICE);
    const current = await call("handshake_next", { access, waitMs: 0, playbookVersion: STANDALONE_PLAYBOOK_VERSION });
    assert.equal(current.playbookNotice, undefined);
    // The version hint is consumed by the tool layer, never passed to the coordinator.
    assert.equal(seen.some((args) => "playbookVersion" in args), false);

    const prepared = await call("readiness_prepare", { sessionKeyAddress: `0x${"ab".repeat(20)}`, accountableParty: "p", statement: "s" });
    assert.equal(prepared.playbookVersion, STANDALONE_PLAYBOOK_VERSION);
    assert.equal(prepared.playbookNotice, undefined);
    const failed = await call("handshake_timeline", { access });
    assert.equal(failed.error, "STANDALONE_HANDSHAKE_UNAVAILABLE");
    assert.equal(failed.playbookVersion, STANDALONE_PLAYBOOK_VERSION);
  });
  assert.equal(buildStandaloneDiscovery().playbookVersion, STANDALONE_PLAYBOOK_VERSION);
});

test("accepting without a preview and failing is recoverable by the agent alone", async () => {
  const h = harness();
  const invite = await h.invite();
  const failed = await h.accept(invite.invitation, { capabilityManifest: { dataHandlingClass: "restricted", purpose: validTerms().purpose } });
  assert.equal(failed.stage, "readiness_retry");
  assert.deepEqual(failed.required, { "capabilityManifest.dataHandlingClass": "confidential" });
  assert.match(failed.guidance, /not burned/);
  assert.match(failed.guidance, /recoverable without your user/);
  assert.equal(failed.thenCall, "handshake_next");
  const fixed = await h.instance.invoke("handshake_retry_readiness", {
    access: failed.responderAccess,
    readiness: await h.readiness("responder", { capabilityManifest: { dataHandlingClass: failed.required["capabilityManifest.dataHandlingClass"], purpose: validTerms().purpose } }),
  });
  assert.equal(fixed.stage, "ready");
});

test("a coordinator with no request context writes its configured public endpoint", async () => {
  const instance = createStandaloneCoordinator({ client: fakeLedger(), recoverEip191Address: recoverLocally, publicEndpoint: "https://example.test/connect/mcp" });
  const h = harness();
  const invite = await instance.invoke("handshake_invite", { ...validTerms(), readiness: await h.readiness("initiator") });
  assert.equal(decodeStandaloneInvitation(invite.invitation).endpoint, "https://example.test/connect/mcp");
});
