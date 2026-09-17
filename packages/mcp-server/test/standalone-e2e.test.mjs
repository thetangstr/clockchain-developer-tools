import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";

import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { createStandaloneHttpHandler } from "../dist/standalone-handshake/public-server.js";
import { validTerms, validReadiness } from "./helpers/standalone-fixtures.mjs";

const SIG_INITIATOR = "0x" + "11".repeat(64) + "1b";
const SIG_RESPONDER = "0x" + "22".repeat(64) + "1c";
const ADDR_INITIATOR = "0x" + "11".repeat(20);
const ADDR_RESPONDER = "0x" + "22".repeat(20);

function fakeLedger() {
  const entries = new Map();
  let height = 100;
  return {
    async searchAsset(reference) {
      return [...entries.values()].filter((entry) => entry.assetReferenceId === reference);
    },
    async log({ assetHash, assetReferenceId }) {
      const ledgerId = randomUUID();
      const record = { ledgerId, assetHash, assetReferenceId, blockHeight: String(++height) };
      entries.set(ledgerId, record);
      return { ...record };
    },
    async getLedgerEntry(ledgerId) {
      const record = entries.get(ledgerId);
      return record ? { ...record } : null;
    },
    async getChainRecord(blockHeight, ledgerId) {
      const record = entries.get(ledgerId);
      return record && record.blockHeight === String(blockHeight) ? { ...record } : null;
    },
    async getBlock(blockHeight) {
      return { blockHeight: String(blockHeight), blockTime: "2026-09-14T00:00:00.000Z" };
    },
  };
}

const ACCEPT = "application/json, text/event-stream";

test("two unconnected agents go from invitation to anchored closure over HTTP", async () => {
  let nowMs = 1_750_000_000_000;
  const coordinator = createStandaloneCoordinator({
    client: fakeLedger(),
    now: () => nowMs,
    recoverEip191Address: async ({ signatureHex }) =>
      signatureHex === SIG_INITIATOR ? ADDR_INITIATOR : signatureHex === SIG_RESPONDER ? ADDR_RESPONDER : "0x" + "99".repeat(20),
    resolveIdentity: async () => true,
  });
  const handler = createStandaloneHttpHandler({ invoke: (name, args) => coordinator.invoke(name, args) });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;

  async function call(name, args = {}) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await response.text();
    const data = text.split("\n").find((line) => line.startsWith("data:"));
    const body = JSON.parse(data ? data.slice(5) : text);
    const content = body.result?.content?.[0]?.text;
    return { status: response.status, result: body.result, payload: content ? JSON.parse(content) : body.result };
  }

  try {
    // Buyer proposes; supplier accepts.
    const invite = await call("handshake_invite", {
      ...validTerms(),
      readiness: validReadiness({ sessionKeyAddress: ADDR_INITIATOR, authoritySignatureHex: SIG_INITIATOR }),
    });
    assert.equal(invite.payload.sessionId.length, 36);
    const accept = await call("handshake_accept_invitation", {
      invitation: invite.payload.invitation,
      readiness: validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER }),
    });
    assert.equal(accept.payload.checklist.passed, true);

    // Both sign consent over the same digest; supplier opens.
    const c1 = await call("consent_sign", { access: invite.payload.roleAccess, signatureHex: SIG_INITIATOR });
    assert.equal(c1.payload.stage, "consent_pending");
    const c2 = await call("consent_sign", { access: accept.payload.roleAccess, signatureHex: SIG_RESPONDER });
    assert.equal(c2.payload.stage, "consented");
    const open = await call("channel_open", { access: invite.payload.roleAccess });
    assert.deepEqual(open.payload.anchors.map((a) => a.kind), ["terms-readiness", "consent", "open"]);
    const openStatus = await call("handshake_status", { access: accept.payload.roleAccess });
    assert.equal(openStatus.payload.stage, "open");

    // Bounded exchange: an out-of-scope kind is refused before an in-scope one lands.
    const violation = await call("channel_send", { access: accept.payload.roleAccess, kind: "note", body: "off-scope" });
    assert.match(violation.payload.error, /SCOPE_VIOLATION/);
    // A non-string body reaches the admission check and surfaces the spec'd MALFORMED code.
    const malformed = await call("channel_send", { access: accept.payload.roleAccess, kind: "proposal", body: 42 });
    assert.match(malformed.payload.error, /MALFORMED/);
    const sent = await call("channel_send", { access: accept.payload.roleAccess, kind: "proposal", body: "Ship Tuesdays." });
    assert.equal(sent.payload.seq, 1);
    const read = await call("channel_read", { access: invite.payload.roleAccess });
    assert.equal(read.payload.messages[0].body, "Ship Tuesdays.");
    // A second in-scope message, the other direction, lands at seq 2.
    const second = await call("channel_send", { access: invite.payload.roleAccess, kind: "question", body: "Can you confirm Tuesday?" });
    assert.equal(second.payload.seq, 2);
    // Reads are addressed: each role sees only messages sent to it, never its own.
    const readAfter = await call("channel_read", { access: invite.payload.roleAccess });
    assert.deepEqual(readAfter.payload.messages.map((m) => [m.fromRole, m.seq]), [["responder", 1]]);
    const readResponder = await call("channel_read", { access: accept.payload.roleAccess });
    assert.deepEqual(readResponder.payload.messages.map((m) => [m.fromRole, m.seq]), [["initiator", 2]]);

    // Buyer revokes; the channel is dead for both, and the closure is anchored.
    const revoked = await call("channel_revoke", { access: invite.payload.roleAccess });
    assert.equal(revoked.payload.outcome, "revoked");
    assert.equal(typeof revoked.payload.closureAnchor.ledgerId, "string");
    const after = await call("channel_send", { access: accept.payload.roleAccess, kind: "question", body: "hello?" });
    assert.match(after.payload.error, /REVOKED/);

    // Status tells the whole story to either role.
    const status = await call("handshake_status", { access: accept.payload.roleAccess });
    assert.equal(status.payload.stage, "revoked");
    assert.equal(status.payload.protocol, "clockchain.standalone-handshake/v1");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
