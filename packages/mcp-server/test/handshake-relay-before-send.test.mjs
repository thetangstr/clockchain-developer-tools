// H-REQ-07: the relay client's postMessage takes an optional freshness guard,
// beforeSend. It runs after the client's sequence read and immediately before
// every post attempt; whatever it throws ends the post with no further attempt
// and reaches the caller unchanged. Without it, posting is unchanged.
import assert from "node:assert/strict";
import { test } from "node:test";

import { generateRelayKeyPair } from "../dist/handshake/protocol.js";
import { createHandshakeRelayClient } from "../dist/handshake/relay.js";

const RELAY = "https://relay.clockchain.test";
const SESSION_ID = "123e4567-e89b-42d3-a456-426614174001";

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// A relay stand-in: the sequence read sees an empty log; the first `conflicts`
// post attempts are answered with a sequence conflict, later ones succeed.
function relayStandIn(events, { conflicts = 0 } = {}) {
  let attempts = 0;
  return async (_url, init = {}) => {
    if ((init.method ?? "GET") === "GET") {
      events.push("read");
      return jsonResponse({ ok: true, messages: [] });
    }
    attempts += 1;
    events.push(`post:${JSON.parse(init.body).seq}`);
    if (attempts <= conflicts) {
      return jsonResponse({ ok: false, error: "SEQ_CONFLICT", detail: { expectedSeq: String(attempts + 1) } }, 409);
    }
    return jsonResponse({ ok: true, seq: String(attempts) });
  };
}

function postInput(keys, beforeSend) {
  return {
    body: { ok: true },
    kind: "agent_v2_proposal",
    privateKeyPem: keys.privateKeyPem,
    role: "initiator",
    senderKey: keys.senderKey,
    sessionId: SESSION_ID,
    ...(beforeSend ? { beforeSend } : {}),
  };
}

class WindowClosed extends Error {}

test("H-REQ-07: postMessage runs beforeSend after the sequence read and before every post attempt", async () => {
  const keys = generateRelayKeyPair();
  const events = [];
  const client = createHandshakeRelayClient({ fetch: relayStandIn(events, { conflicts: 1 }), relayUrl: RELAY });

  const result = await client.postMessage(postInput(keys, () => { events.push("guard"); }));

  assert.deepEqual(result, { ok: true, seq: "2" });
  assert.deepEqual(events, ["read", "guard", "post:1", "guard", "post:2"]);
});

test("H-REQ-07: a beforeSend that throws before a retry ends the post with no further attempt", async () => {
  const keys = generateRelayKeyPair();
  const events = [];
  const client = createHandshakeRelayClient({ fetch: relayStandIn(events, { conflicts: 1 }), relayUrl: RELAY });
  const closed = new WindowClosed("window closed");
  let calls = 0;

  await assert.rejects(
    client.postMessage(postInput(keys, () => {
      calls += 1;
      if (calls === 2) throw closed;
    })),
    (error) => error === closed,
  );
  assert.deepEqual(events, ["read", "post:1"]);
});

test("H-REQ-07: a beforeSend that throws before the first attempt sends nothing", async () => {
  const keys = generateRelayKeyPair();
  const events = [];
  const client = createHandshakeRelayClient({ fetch: relayStandIn(events), relayUrl: RELAY });
  const closed = new WindowClosed("window closed");

  await assert.rejects(client.postMessage(postInput(keys, () => { throw closed; })), (error) => error === closed);
  assert.deepEqual(events, ["read"]);
});

test("H-REQ-07: postMessage without beforeSend posts and retries as before", async () => {
  const keys = generateRelayKeyPair();
  const events = [];
  const client = createHandshakeRelayClient({ fetch: relayStandIn(events, { conflicts: 1 }), relayUrl: RELAY });

  assert.deepEqual(await client.postMessage(postInput(keys)), { ok: true, seq: "2" });
  assert.deepEqual(events, ["read", "post:1", "post:2"]);
});
