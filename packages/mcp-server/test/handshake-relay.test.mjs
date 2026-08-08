import assert from "node:assert/strict";
import { test } from "node:test";

import { generateRelayKeyPair } from "../dist/handshake/protocol.js";
import {
  HandshakeRelayError,
  HandshakeRelayResultPendingError,
  createHandshakeRelayClient,
  normalizeRelayBaseUrl,
  verifyRelayMessageEnvelope,
} from "../dist/handshake/relay.js";

const TRUSTED_RELAY = "https://relay.clockchain.test";
const SESSION_ID = "123e4567-e89b-42d3-a456-426614174001";
const REPOSITORY_SHA = "b".repeat(40);
const OPERATOR_PUBLIC_KEY = "Klg+xF8O3z+lLsQDXa7kWbnKNLJ/HYc0GWU/OBjjzIY=";
const KIT_REPO_URL = "https://github.com/clockchain/handshake-kit";
const NOW = 1786190400000;

function discovery(overrides = {}) {
  return {
    schema: "handshake-discovery/v2",
    expiresAtMs: String(NOW + 60 * 60 * 1000),
    issuedAtMs: String(NOW),
    kitRepoUrl: KIT_REPO_URL,
    operatorPublicKey: OPERATOR_PUBLIC_KEY,
    paymentMoved: false,
    relayUrl: TRUSTED_RELAY,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    ...overrides,
  };
}

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json", ...init.headers },
    status: init.status ?? 200,
  });
}

function mockFetch(handler) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ init, url: String(url) });
    return handler(String(url), init, calls.length);
  };
  fetch.calls = calls;
  return fetch;
}

test("normalizes trusted relay base URLs without path, credentials, query, or fragment", () => {
  assert.equal(normalizeRelayBaseUrl("https://relay.clockchain.test/"), TRUSTED_RELAY);
  assert.equal(normalizeRelayBaseUrl("https://relay.clockchain.test////"), TRUSTED_RELAY);
  assert.throws(() => normalizeRelayBaseUrl("ftp://relay.clockchain.test"), /RELAY_URL_INVALID/);
  assert.throws(() => normalizeRelayBaseUrl("https://user:pass@relay.clockchain.test"), /RELAY_URL_INVALID/);
  assert.throws(() => normalizeRelayBaseUrl("https://relay.clockchain.test/path"), /RELAY_URL_INVALID/);
});

test("fetches and validates current discovery from the trusted relay", async () => {
  const fetch = mockFetch((url) => {
    assert.equal(url, `${TRUSTED_RELAY}/v1/discovery/current`);
    return jsonResponse(discovery());
  });
  const client = createHandshakeRelayClient({ fetch, now: () => NOW, relayUrl: `${TRUSTED_RELAY}/` });

  const current = await client.fetchDiscovery();

  assert.deepEqual(current, discovery());
});

test("requires canonical discovery v2 fields including kitRepoUrl", async () => {
  const missingKitRepo = createHandshakeRelayClient({
    fetch: async () => jsonResponse(discovery({ kitRepoUrl: undefined })),
    now: () => NOW,
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(missingKitRepo.fetchDiscovery(), { code: "DISCOVERY_INVALID" });

  const badSchema = createHandshakeRelayClient({
    fetch: async () => jsonResponse(discovery({ schema: "clockchain.handshake-relay-discovery/v2" })),
    now: () => NOW,
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(badSchema.fetchDiscovery(), { code: "DISCOVERY_INVALID" });
});

test("rejects expired discovery documents and relayUrl mismatches as SSRF guardrails", async () => {
  const expired = createHandshakeRelayClient({
    fetch: async () => jsonResponse(discovery({ expiresAtMs: String(NOW - 1) })),
    now: () => NOW,
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(expired.fetchDiscovery(), { code: "DISCOVERY_EXPIRED" });

  const mismatch = createHandshakeRelayClient({
    fetch: async () => jsonResponse(discovery({ relayUrl: "https://evil.example" })),
    now: () => NOW,
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(mismatch.fetchDiscovery(), { code: "DISCOVERY_RELAY_MISMATCH" });
});

test("rejects malformed and oversized JSON without leaking response bodies", async () => {
  const malformed = createHandshakeRelayClient({
    fetch: async () => new Response("{not-json", { status: 200 }),
    maxJsonBytes: 100,
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(malformed.fetchDiscovery(), (error) => {
    assert.equal(error.code, "RELAY_JSON_INVALID");
    assert.doesNotMatch(error.message, /not-json/);
    return true;
  });

  const oversized = createHandshakeRelayClient({
    fetch: async () => new Response(JSON.stringify({ padding: "x".repeat(101) }), { status: 200 }),
    maxJsonBytes: 100,
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(oversized.fetchDiscovery(), { code: "RELAY_JSON_OVERSIZED" });
});

test("gets relay messages with nonblocking waitMs=0 and validates response shape", async () => {
  const fetch = mockFetch((url) => {
    assert.equal(url, `${TRUSTED_RELAY}/v1/sessions/${SESSION_ID}/messages?after=7&waitMs=0`);
    return jsonResponse({ ok: true, messages: [] });
  });
  const client = createHandshakeRelayClient({ fetch, relayUrl: TRUSTED_RELAY });

  assert.deepEqual(await client.getMessages({ after: "7", sessionId: SESSION_ID }), {
    messages: [],
  });
});

test("derives highest seq from verified relay messages", async () => {
  const keys = generateRelayKeyPair();
  const envelope = {
    body: { ok: true },
    kind: "proposal",
    privateKeyPem: keys.privateKeyPem,
    role: "requestor",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
    seq: "9",
  };
  const { signRelayEnvelope } = await import("../dist/handshake/protocol.js");
  const signed = signRelayEnvelope(envelope);
  const client = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: true, messages: [signed] }),
    relayUrl: TRUSTED_RELAY,
  });

  assert.deepEqual(await client.getMessages({ after: "0", sessionId: SESSION_ID }), {
    highestSeq: "9",
    messages: [signed],
  });
});

test("accepts arbitrary signed inbound token roles including host", async () => {
  const keys = generateRelayKeyPair();
  const { signRelayEnvelope } = await import("../dist/handshake/protocol.js");
  const signed = signRelayEnvelope({
    body: {
      relayUrl: TRUSTED_RELAY,
      runId: "live-shaped-host-fixture",
    },
    kind: "host_status",
    privateKeyPem: keys.privateKeyPem,
    role: "host",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
    seq: "12",
  });
  const client = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: true, messages: [signed] }),
    relayUrl: TRUSTED_RELAY,
  });

  assert.deepEqual(await client.getMessages({ sessionId: SESSION_ID }), {
    highestSeq: "12",
    messages: [signed],
  });
});

test("rejects signed inbound envelopes from a different session", async () => {
  const keys = generateRelayKeyPair();
  const { signRelayEnvelope } = await import("../dist/handshake/protocol.js");
  const foreign = signRelayEnvelope({
    body: { ok: true },
    kind: "host_status",
    privateKeyPem: keys.privateKeyPem,
    role: "host",
    senderKey: keys.senderKey,
    sessionId: "foreign-session",
    seq: "1",
  });
  const client = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: true, messages: [foreign] }),
    relayUrl: TRUSTED_RELAY,
  });

  await assert.rejects(client.getMessages({ sessionId: SESSION_ID }), { code: "MESSAGE_SESSION_MISMATCH" });
});

test("rejects duplicate inbound message sequences", async () => {
  const keys = generateRelayKeyPair();
  const { signRelayEnvelope } = await import("../dist/handshake/protocol.js");
  const messages = ["2", "2"].map((seq) => signRelayEnvelope({
    body: { seq },
    kind: "proposal",
    privateKeyPem: keys.privateKeyPem,
    role: "requestor",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
    seq,
  }));
  const client = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: true, messages }),
    relayUrl: TRUSTED_RELAY,
  });

  await assert.rejects(client.getMessages({ after: "1", sessionId: SESSION_ID }), { code: "MESSAGE_SEQ_ORDER_INVALID" });
});

test("rejects descending inbound message sequences while allowing gaps", async () => {
  const keys = generateRelayKeyPair();
  const { signRelayEnvelope } = await import("../dist/handshake/protocol.js");
  const descending = ["5", "4"].map((seq) => signRelayEnvelope({
    body: { seq },
    kind: "proposal",
    privateKeyPem: keys.privateKeyPem,
    role: "requestor",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
    seq,
  }));
  const client = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: true, messages: descending }),
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(client.getMessages({ after: "3", sessionId: SESSION_ID }), { code: "MESSAGE_SEQ_ORDER_INVALID" });

  const gaps = ["4", "7"].map((seq) => signRelayEnvelope({
    body: { seq },
    kind: "proposal",
    privateKeyPem: keys.privateKeyPem,
    role: "requestor",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
    seq,
  }));
  const gapClient = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: true, messages: gaps }),
    relayUrl: TRUSTED_RELAY,
  });
  assert.equal((await gapClient.getMessages({ after: "3", sessionId: SESSION_ID })).highestSeq, "7");
});

test("rejects replayed inbound message sequences at or before the requested cursor", async () => {
  const keys = generateRelayKeyPair();
  const { signRelayEnvelope } = await import("../dist/handshake/protocol.js");
  const replay = signRelayEnvelope({
    body: { seq: "3" },
    kind: "proposal",
    privateKeyPem: keys.privateKeyPem,
    role: "requestor",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
    seq: "3",
  });
  const client = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: true, messages: [replay] }),
    relayUrl: TRUSTED_RELAY,
  });

  await assert.rejects(client.getMessages({ after: "5", sessionId: SESSION_ID }), { code: "MESSAGE_SEQ_REPLAY" });
});

test("signs and posts a relay message after reading highest seq, retrying only SEQ_CONFLICT", async () => {
  const keys = generateRelayKeyPair();
  const fetch = mockFetch((url, init, call) => {
    if (call === 1) {
      assert.equal(url, `${TRUSTED_RELAY}/v1/sessions/${SESSION_ID}/messages?after=0&waitMs=0`);
      return jsonResponse({ ok: true, messages: [] });
    }
    if (call === 2) {
      const envelope = JSON.parse(init.body);
      assert.equal(envelope.seq, "1");
      assert.equal(envelope.role, "requestor");
      assert.equal(verifyRelayMessageEnvelope(envelope), true);
      return jsonResponse({ ok: false, error: "SEQ_CONFLICT", detail: { expectedSeq: "3" } }, { status: 409 });
    }
    if (call === 3) {
      const envelope = JSON.parse(init.body);
      assert.equal(envelope.seq, "3");
      assert.equal(envelope.role, "requestor");
      assert.equal(verifyRelayMessageEnvelope(envelope), true);
      return jsonResponse({ ok: true, seq: "3" });
    }
    throw new Error("unexpected fetch");
  });
  const client = createHandshakeRelayClient({ fetch, relayUrl: TRUSTED_RELAY });

  const accepted = await client.postMessage({
    body: { ok: true },
    kind: "proposal",
    privateKeyPem: keys.privateKeyPem,
    role: "requestor",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
  });

  assert.deepEqual(accepted, { ok: true, seq: "3" });
  assert.equal(fetch.calls.length, 3);
  assert.equal(fetch.calls[1].url, `${TRUSTED_RELAY}/v1/sessions/${SESSION_ID}/messages`);
  assert.equal(fetch.calls[2].url, `${TRUSTED_RELAY}/v1/sessions/${SESSION_ID}/messages`);
});

test("does not retry ambiguous network failures while writing", async () => {
  const keys = generateRelayKeyPair();
  const fetch = mockFetch((url, init, call) => {
    if (call === 1) return jsonResponse({ ok: true, messages: [] });
    throw Object.assign(new Error("socket closed after body was sent"), { code: "ECONNRESET" });
  });
  const client = createHandshakeRelayClient({ fetch, relayUrl: TRUSTED_RELAY });

  await assert.rejects(
    client.postMessage({
      body: { ok: true },
      kind: "proposal",
      privateKeyPem: keys.privateKeyPem,
      role: "requestor",
      senderKey: keys.senderKey,
      sessionId: SESSION_ID,
    }),
    { code: "RELAY_NETWORK" },
  );
  assert.equal(fetch.calls.length, 2);
});

test("puts exact evidence triple as base64 under the payer/payee endpoint", async () => {
  const evidence = {
    json: Buffer.from("evidence-json"),
    markdown: "# Evidence",
    marker: Buffer.from("marker"),
  };
  const fetch = mockFetch((url, init) => {
    assert.equal(url, `${TRUSTED_RELAY}/v1/sessions/${SESSION_ID}/evidence/payer`);
    assert.equal(init.method, "PUT");
    assert.deepEqual(JSON.parse(init.body), {
      json: Buffer.from("evidence-json").toString("base64"),
      markdown: Buffer.from("# Evidence", "utf8").toString("base64"),
      marker: Buffer.from("marker").toString("base64"),
    });
    return jsonResponse({ ok: true, role: "payer" });
  });
  const client = createHandshakeRelayClient({ fetch, relayUrl: TRUSTED_RELAY });

  assert.deepEqual(await client.putEvidence({ ...evidence, role: "payer", sessionId: SESSION_ID }), { ok: true, role: "payer" });
  await assert.rejects(
    client.putEvidence({ ...evidence, role: "requestor", sessionId: SESSION_ID }),
    { code: "EVIDENCE_ROLE_INVALID" },
  );
});

test("gets results and reports RESULT_NOT_SET/404 as a typed pending error", async () => {
  const pending = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: false, error: "RESULT_NOT_SET" }, { status: 404 }),
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(pending.getResult({ sessionId: SESSION_ID }), HandshakeRelayResultPendingError);

  const result = { result: { ok: true } };
  const ready = createHandshakeRelayClient({
    fetch: async (url) => {
      assert.equal(String(url), `${TRUSTED_RELAY}/v1/sessions/${SESSION_ID}/result`);
      return jsonResponse(result);
    },
    relayUrl: TRUSTED_RELAY,
  });
  assert.deepEqual(await ready.getResult({ sessionId: SESSION_ID }), result);
});

test("non-2xx relay errors are sanitized typed errors", async () => {
  const client = createHandshakeRelayClient({
    fetch: async () => jsonResponse({ ok: false, error: "NOPE", detail: { token: "secret-token-123" } }, { status: 500 }),
    relayUrl: TRUSTED_RELAY,
  });

  await assert.rejects(client.getMessages({ sessionId: SESSION_ID }), (error) => {
    assert.ok(error instanceof HandshakeRelayError);
    assert.equal(error.code, "NOPE");
    assert.equal(error.status, 500);
    assert.doesNotMatch(error.message, /secret-token-123/);
    assert.equal(Object.hasOwn(error, "detail"), false);
    assert.doesNotMatch(JSON.stringify(error), /secret-token-123/);
    return true;
  });
});

test("aborts stalled response body reads while enforcing the response cap incrementally", async () => {
  const stalled = createHandshakeRelayClient({
    fetch: async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{"));
      },
    }), { status: 200 }),
    relayUrl: TRUSTED_RELAY,
    timeoutMs: 20,
  });
  await assert.rejects(stalled.fetchDiscovery(), { code: "RELAY_TIMEOUT" });

  const oversized = createHandshakeRelayClient({
    fetch: async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`{"padding":"${"x".repeat(60)}`));
        controller.enqueue(new TextEncoder().encode(`${"x".repeat(60)}"}`));
        controller.close();
      },
    }), { status: 200 }),
    maxJsonBytes: 100,
    relayUrl: TRUSTED_RELAY,
  });
  await assert.rejects(oversized.fetchDiscovery(), { code: "RELAY_JSON_OVERSIZED" });
});
