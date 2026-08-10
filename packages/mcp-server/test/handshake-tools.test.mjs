import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { __resetHandshakeStateStore } from "../dist/handshake/state.js";
import { registerTools } from "../dist/tools.js";

const cfg = { apiKey: "k", clientId: "c", walletId: "w", endpoint: "http://test.local" };

const HANDSHAKE_TOOLS = [
  "handshake_status",
  "handshake_join",
  "handshake_next",
  "handshake_submit",
  "handshake_get_certificate",
];
const AGENT_HANDSHAKE_TOOLS = [
  "agent_handshake_invite",
  "agent_handshake_status",
  "agent_handshake_join",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
];

const KEY_LIKE = /key|private|mnemonic|seed|secret|wallet|signer/i;

function collectWith(coordinator, agentCoordinator = coordinator) {
  const registrations = {};
  registerTools(
    {
      registerTool: (name, meta, handler) => {
        registrations[name] = { meta, handler };
      },
    },
    cfg,
    { agentHandshakeCoordinator: agentCoordinator, handshakeCoordinator: coordinator },
  );
  return registrations;
}

const textOf = (res) => (res.content || []).map((c) => c.text).join("\n");
const jsonOf = (res) => JSON.parse(textOf(res));

test("handshake tools are registered with exact public names and non-secret camelCase inputs", () => {
  const tools = collectWith({});
  for (const name of HANDSHAKE_TOOLS) {
    assert.ok(tools[name], `${name} should be registered`);
  }

  assert.deepEqual(Object.keys(tools.handshake_status.meta.inputSchema), ["sessionId"]);
  assert.deepEqual(Object.keys(tools.handshake_join.meta.inputSchema), ["role", "invitationId", "terms"]);
  assert.deepEqual(Object.keys(tools.handshake_next.meta.inputSchema), ["sessionId", "role", "signingEncoding", "waitMs"]);
  assert.deepEqual(Object.keys(tools.handshake_submit.meta.inputSchema), ["sessionId", "role", "signatureHex"]);
  assert.deepEqual(Object.keys(tools.handshake_get_certificate.meta.inputSchema), ["sessionId"]);
  assert.match(
    tools.handshake_join.meta.description,
    /Payer must supply the exact mandate terms.*Requestor must independently supply the terms it expects/is,
  );

  for (const name of HANDSHAKE_TOOLS) {
    for (const prop of Object.keys(tools[name].meta.inputSchema)) {
      assert.doesNotMatch(prop, KEY_LIKE, `${name}.${prop} must not expose key-like input names`);
      assert.equal(prop.includes("_"), false, `${name}.${prop} must be camelCase`);
    }
  }
});

test("generic handshake tools are additive, exact, and free of payment inputs", () => {
  const tools = collectWith({});
  for (const name of AGENT_HANDSHAKE_TOOLS) assert.ok(tools[name], `${name} should be registered`);
  assert.deepEqual(Object.keys(tools.agent_handshake_invite.meta.inputSchema), ["terms"]);
  assert.deepEqual(Object.keys(tools.agent_handshake_status.meta.inputSchema), ["sessionId"]);
  assert.deepEqual(Object.keys(tools.agent_handshake_join.meta.inputSchema), ["role", "invitationId", "terms"]);
  assert.deepEqual(Object.keys(tools.agent_handshake_next.meta.inputSchema), ["sessionId", "role", "signingEncoding"]);
  assert.deepEqual(Object.keys(tools.agent_handshake_submit.meta.inputSchema), ["sessionId", "role", "signatureHex"]);
  assert.deepEqual(Object.keys(tools.agent_handshake_get_certificate.meta.inputSchema), ["sessionId"]);
  const publicText = JSON.stringify(AGENT_HANDSHAKE_TOOLS.map((name) => tools[name].meta)).toLowerCase();
  for (const word of ["amount", "currency", "invoice", "payer", "payee", "payment", "requestor"]) {
    assert.equal(publicText.includes(word), false, word);
  }
});

test("generic handshake handlers delegate to their own coordinator", async () => {
  const calls = [];
  const coordinator = {
    async status(sessionId) { calls.push(["status", sessionId]); return { mode: "generic", sessionId }; },
    async join(role, invitationId, terms) { calls.push(["join", role, invitationId, terms]); return { role }; },
    async next(sessionId, role, signingEncoding) { calls.push(["next", sessionId, role, signingEncoding]); return { role, sessionId, signingEncoding }; },
    async submit(sessionId, role, signatureHex) { calls.push(["submit", sessionId, role, signatureHex]); return { role }; },
    async getCertificate(sessionId) { calls.push(["certificate", sessionId]); return { sessionId }; },
  };
  const tools = collectWith({}, coordinator);
  const terms = { reference: "NS-1847", statement: "Two stakeholder agents may communicate about NS-1847.", validForMinutes: 45 };
  await tools.agent_handshake_status.handler({ sessionId: "s" });
  await tools.agent_handshake_join.handler({ role: "initiator", terms });
  await tools.agent_handshake_next.handler({ role: "responder", sessionId: "s", signingEncoding: "gzip-base64url" });
  await tools.agent_handshake_submit.handler({ role: "initiator", sessionId: "s", signatureHex: `0x${"1".repeat(130)}` });
  await tools.agent_handshake_get_certificate.handler({ sessionId: "s" });
  assert.deepEqual(calls, [
    ["status", "s"],
    ["join", "initiator", undefined, terms],
    ["next", "s", "responder", "gzip-base64url"],
    ["submit", "s", "initiator", `0x${"1".repeat(130)}`],
    ["certificate", "s"],
  ]);
});

test("handshake handlers delegate every call to the injected coordinator and return JSON text", async () => {
  const calls = [];
  const coordinator = {
    async status(sessionId) {
      calls.push(["status", sessionId]);
      return { ok: "status", sessionId };
    },
    async join(role, invitationId, terms) {
      calls.push(["join", role, invitationId, terms]);
      return { ok: "join", role, invitationId, terms };
    },
    async next(sessionId, role, signingEncoding, waitMs) {
      calls.push(["next", sessionId, role, signingEncoding, waitMs]);
      return { ok: "next", sessionId, role, signingEncoding, waitMs };
    },
    async submit(sessionId, role, signatureHex) {
      calls.push(["submit", sessionId, role, signatureHex]);
      return { ok: "submit", sessionId, role, signatureHex };
    },
    async getCertificate(sessionId) {
      calls.push(["getCertificate", sessionId]);
      return { ok: "certificate", sessionId };
    },
  };
  const tools = collectWith(coordinator);

  assert.deepEqual(jsonOf(await tools.handshake_status.handler({})), { ok: "status" });
  assert.deepEqual(jsonOf(await tools.handshake_status.handler({ sessionId: "s1" })), { ok: "status", sessionId: "s1" });
  assert.deepEqual(jsonOf(await tools.handshake_join.handler({ role: "payer" })), { ok: "join", role: "payer" });
  const terms = {
    amount: { currency: "USD", value: "18750" },
    invoiceReference: "HS-8842",
    purpose: "Invoice HS-8842 against PO NS-1847",
    validForMinutes: 45,
  };
  assert.deepEqual(jsonOf(await tools.handshake_join.handler({
    invitationId: "123e4567-e89b-42d3-a456-426614174001",
    role: "requestor",
    terms,
  })), {
    invitationId: "123e4567-e89b-42d3-a456-426614174001",
    ok: "join",
    role: "requestor",
    terms,
  });
  assert.deepEqual(jsonOf(await tools.handshake_next.handler({ sessionId: "s1", role: "requestor", signingEncoding: "gzip-base64url", waitMs: 1234 })), {
    ok: "next",
    sessionId: "s1",
    role: "requestor",
    signingEncoding: "gzip-base64url",
    waitMs: 1234,
  });
  assert.deepEqual(jsonOf(await tools.handshake_submit.handler({ sessionId: "s1", role: "payer", signatureHex: "0xabc" })), {
    ok: "submit",
    sessionId: "s1",
    role: "payer",
    signatureHex: "0xabc",
  });
  assert.deepEqual(jsonOf(await tools.handshake_get_certificate.handler({ sessionId: "s1" })), {
    ok: "certificate",
    sessionId: "s1",
  });

  assert.deepEqual(calls, [
    ["status", undefined],
    ["status", "s1"],
    ["join", "payer", undefined, undefined],
    ["join", "requestor", "123e4567-e89b-42d3-a456-426614174001", terms],
    ["next", "s1", "requestor", "gzip-base64url", 1234],
    ["submit", "s1", "payer", "0xabc"],
    ["getCertificate", "s1"],
  ]);
});

test('handshake role input rejects "requester"; public enum is payer/requestor only', async () => {
  const coordinator = {
    async join() {
      throw new Error("coordinator should not receive invalid role");
    },
  };
  const tools = collectWith(coordinator);
  const res = await tools.handshake_join.handler({ role: "requester" });
  assert.equal(res.isError, true);
  assert.match(textOf(res), /payer|requestor/);
});

test("handshake_join rejects malformed invitation and invoice terms before coordinator dispatch", async () => {
  let called = false;
  const tools = collectWith({
    async join() {
      called = true;
      return {};
    },
  });
  const valid = {
    amount: { currency: "USD", value: "18750" },
    invoiceReference: "HS-8842",
    purpose: "Invoice HS-8842 against PO NS-1847",
    validForMinutes: 45,
  };
  const invalid = [
    { invitationId: "current", role: "requestor", terms: valid },
    { role: "payer", terms: { ...valid, amount: { currency: "EUR", value: "18750" } } },
    { role: "payer", terms: { ...valid, amount: { currency: "USD", value: "018750" } } },
    { role: "payer", terms: { ...valid, validForMinutes: 29 } },
    { role: "payer", terms: { ...valid, extra: true } },
  ];
  for (const input of invalid) {
    assert.equal((await tools.handshake_join.handler(input)).isError, true);
  }
  assert.equal(called, false);
});

test("full-surface tools lazily construct the runtime coordinator without test injection", async () => {
  const previousRelay = process.env.HANDSHAKE_RELAY;
  const previousFetch = globalThis.fetch;
  const relayUrl = "https://relay.runtime.test";
  const now = Date.now();
  const { publicKey } = generateKeyPairSync("ed25519");
  const operatorPublicKey = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");

  process.env.HANDSHAKE_RELAY = relayUrl;
  __resetHandshakeStateStore();
  globalThis.fetch = async (url) => {
    if (String(url).startsWith(`${relayUrl}/v1/sessions/runtime-session/messages`)) {
      return new Response(JSON.stringify({ ok: true, messages: [] }), {
        headers: { "content-type": "application/json" },
        status: 200,
      });
    }
    assert.equal(String(url), `${relayUrl}/v1/discovery/current`);
    return new Response(JSON.stringify({
      schema: "handshake-discovery/v2",
      expiresAtMs: String(now + 60 * 60 * 1000),
      issuedAtMs: String(now),
      kitRepoUrl: "https://github.com/clockchain/handshake-kit",
      operatorPublicKey,
      paymentMoved: false,
      relayUrl,
      repositorySha: "b".repeat(40),
      sessionId: "runtime-session",
    }), {
      headers: { "content-type": "application/json" },
      status: 200,
    });
  };

  try {
    const registrations = {};
    registerTools(
      { registerTool: (name, meta, handler) => { registrations[name] = { meta, handler }; } },
      cfg,
      { principalId: "opaque-principal" },
    );
    assert.deepEqual(jsonOf(await registrations.handshake_status.handler({})), { sessions: [] });
    const joined = jsonOf(await registrations.handshake_join.handler({ role: "payer" }));
    assert.equal(joined.operatorPublicKey, operatorPublicKey);
    const next = jsonOf(await registrations.handshake_next.handler({
      role: "payer",
      sessionId: joined.sessionId,
      signingEncoding: "gzip-base64url",
    }));
    assert.equal(next.bytesEncoding, "gzip-base64url");
    assert.equal(Object.hasOwn(next, "bytesToSignHex"), false);
    assert.equal(typeof next.bytesToSignGzipBase64Url, "string");
  } finally {
    __resetHandshakeStateStore();
    globalThis.fetch = previousFetch;
    if (previousRelay === undefined) delete process.env.HANDSHAKE_RELAY;
    else process.env.HANDSHAKE_RELAY = previousRelay;
  }
});
