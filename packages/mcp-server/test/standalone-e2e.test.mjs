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

// Two scripted agents finish a handshake knowing only the playbook: every byte they sign
// comes from readiness_prepare or handshake_next and is re-derived locally before signing.
// The one thing passed between them is the invitation string, as the playbook says.
test("two scripted agents complete invite → preview → failed accept → corrected readiness → consent → open → 2 messages → close by looping on handshake_next", async () => {
  const { getAddress } = await import("viem");
  const { canonicalJson, newSessionKey, recoverLocally, sha256Hex, verifyAndSign } = await import("./helpers/standalone-signer.mjs");
  const ALLOWED_TOOLS = new Set([
    "readiness_prepare", "handshake_preview_invitation", "handshake_invite", "handshake_accept_invitation", "handshake_retry_readiness",
    "handshake_next", "consent_sign", "channel_open", "channel_send", "channel_close", "handshake_timeline",
  ]);

  const coordinator = createStandaloneCoordinator({
    client: fakeLedger(),
    now: () => 1_750_000_000_000,
    recoverEip191Address: recoverLocally,
    resolveIdentity: async () => true,
    nextPollMs: 10,
  });
  const handler = createStandaloneHttpHandler({ invoke: (name, args) => coordinator.invoke(name, args) });
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
  const toolsUsed = new Set();

  async function call(name, args) {
    assert.ok(ALLOWED_TOOLS.has(name), `agents may not call ${name}`);
    toolsUsed.add(name);
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: ACCEPT },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    const text = await response.text();
    const data = text.split("\n").find((line) => line.startsWith("data:"));
    const result = JSON.parse(data ? data.slice(5) : text).result;
    return JSON.parse(result.content[0].text);
  }

  const terms = validTerms();
  async function readiness(account, capabilityManifest = { dataHandlingClass: "confidential", purpose: terms.purpose }) {
    const prepared = await call("readiness_prepare", {
      sessionKeyAddress: getAddress(account.address),
      accountableParty: "Acme Buying LLC",
      statement: "I am authorized to discuss delivery options for Acme.",
    });
    assert.equal(prepared.record.sessionKeyAddress, account.address.toLowerCase());
    return {
      sessionKeyAddress: getAddress(account.address),
      identity: null,
      authorityStatement: { accountableParty: prepared.record.accountableParty, statement: prepared.record.statement },
      authoritySignatureHex: await verifyAndSign(account, prepared),
      capabilityManifest,
    };
  }

  // The loop the playbook describes, with a scripted "brain" deciding what to say.
  async function loop({ role, access, sessionId, account, decide, initialManifest }) {
    const transcript = [];
    let cursor;
    let currentManifest = initialManifest;
    for (let step = 0; step < 100; step += 1) {
      const next = await call("handshake_next", { access, waitMs: 2000, ...(cursor === undefined ? {} : { cursor }) });
      transcript.push(next.action);
      if (next.cursor !== undefined) cursor = next.cursor;
      switch (next.action) {
        case "wait":
          assert.equal(typeof next.tellYourUser, "string");
          break;
        case "fix_readiness": {
          // Apply exactly what the server says is required; nothing is asked of any human.
          const manifest = { ...currentManifest };
          for (const [path, value] of Object.entries(next.required)) {
            const [section, field] = path.split(".");
            assert.equal(section, "capabilityManifest", `unexpected required path ${path}`);
            manifest[field] = value;
          }
          currentManifest = manifest;
          const retried = await call("handshake_retry_readiness", { access, readiness: await readiness(account, manifest) });
          assert.equal(retried.error, undefined, JSON.stringify(retried));
          break;
        }
        case "sign": {
          assert.equal(next.sign.record.sessionId, sessionId);
          assert.equal(next.sign.record.role, role);
          assert.equal(next.sign.record.termsDigest, sha256Hex(canonicalJson(next.context.terms)));
          const signed = await call("consent_sign", { access, signatureHex: await verifyAndSign(account, next.sign) });
          assert.equal(signed.error, undefined);
          break;
        }
        case "open": {
          const opened = await call("channel_open", { access });
          assert.ok(opened.error === undefined || opened.error === "ALREADY_OPEN", JSON.stringify(opened));
          break;
        }
        case "respond": {
          for (const message of next.messages) assert.equal(message.untrusted, true);
          const decision = decide(next.messages);
          if (decision.close) {
            const closed = await call("channel_close", { access });
            assert.equal(closed.outcome, "closed");
          } else {
            const sent = await call("channel_send", { access, kind: decision.kind, body: decision.body });
            assert.equal(typeof sent.seq, "number");
          }
          break;
        }
        default:
          return { transcript, access, tellYourUser: next.tellYourUser, terminal: next.terminal, messages: next.messages ?? [] };
      }
    }
    throw new Error(`${role} never reached a terminal action`);
  }

  try {
    const alice = newSessionKey();
    const bob = newSessionKey();
    let handInvitation;
    const invitationPassed = new Promise((resolve) => { handInvitation = resolve; });

    const initiator = (async () => {
      const invite = await call("handshake_invite", { ...terms, readiness: await readiness(alice) });
      handInvitation(invite.invitation);
      const received = [];
      return { received, ...(await loop({
        role: "initiator",
        access: invite.roleAccess,
        sessionId: invite.sessionId,
        account: alice,
        decide: (messages) => {
          received.push(...messages.map((m) => m.body));
          return messages.length === 0 ? { kind: "question", body: "Can we talk Tuesday at 10:00 UTC?" } : { close: true };
        },
      })) };
    })();

    const responder = (async () => {
      const invitation = await invitationPassed;
      // Preview first, then make the staging mistake anyway: a data-handling class that
      // differs from the Initiator's. The session survives it and the loop corrects it.
      const preview = await call("handshake_preview_invitation", { invitation });
      assert.equal(preview.required["capabilityManifest.dataHandlingClass"], "confidential");
      const wrongManifest = { dataHandlingClass: "public", purpose: preview.terms.purpose };
      const accepted = await call("handshake_accept_invitation", { invitation, readiness: await readiness(bob, wrongManifest) });
      assert.equal(accepted.stage, "readiness_retry");
      assert.deepEqual(accepted.codes, ["DATA_CLASS_MISMATCH"]);
      const received = [];
      return { received, ...(await loop({
        initialManifest: wrongManifest,
        role: "responder",
        access: accepted.roleAccess,
        sessionId: accepted.sessionId,
        account: bob,
        decide: (messages) => {
          received.push(...messages.map((m) => m.body));
          return { kind: "proposal", body: "Tuesday at 10:00 UTC works." };
        },
      })) };
    })();

    const [a, b] = await Promise.all([initiator, responder]);
    assert.deepEqual(a.received, ["Tuesday at 10:00 UTC works."]);
    assert.deepEqual(b.received, ["Can we talk Tuesday at 10:00 UTC?"]);
    for (const side of [a, b]) {
      assert.equal(side.terminal.outcome, "closed");
      assert.equal(side.terminal.reason, "CLOSED_BY_INITIATOR");
      assert.deepEqual(side.terminal.anchors.map((anchor) => anchor.kind), ["terms-readiness", "consent", "open", "closure"]);
      assert.ok(side.transcript.includes("sign") && side.transcript.includes("respond"));
      assert.equal(typeof side.tellYourUser, "string");
    }
    assert.ok(b.transcript.includes("fix_readiness"));
    // Both parties see the same server-side history, with the failed attempt in it.
    const timeline = await call("handshake_timeline", { access: a.access });
    assert.deepEqual(timeline.events.map((event) => event.type), [
      "invited", "previewed", "attempt", "attempt", "accepted", "consent", "consent", "open", "message", "message", "close",
    ]);
    assert.deepEqual(timeline.events[2].codes, ["DATA_CLASS_MISMATCH"]);
    assert.deepEqual((await call("handshake_timeline", { access: b.access })).events, timeline.events);
    assert.deepEqual([...toolsUsed].sort(), [...ALLOWED_TOOLS].sort());
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
