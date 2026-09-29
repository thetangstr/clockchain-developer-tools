// Handshake addresses (spec B4): name#fingerprint, listen, invite `to`, review_invitation.
// Everything runs over HTTP through the public tools, with durability on.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { getAddress, keccak256 } from "viem";

import { FINGERPRINT_HEX_LENGTH, addressFor, keyFingerprint, parseAddress } from "../dist/standalone-handshake/address.js";
import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { createMailboxStore, MAX_PENDING_PER_MAILBOX } from "../dist/standalone-handshake/mailbox-store.js";
import { createStandaloneHttpHandler } from "../dist/standalone-handshake/public-server.js";
import { validTerms } from "./helpers/standalone-fixtures.mjs";
import { canonicalJson, fakeLedger, newSessionKey, recoverLocally, sha256Hex, verifyAndSign } from "./helpers/standalone-signer.mjs";

const T = Date.parse("2026-09-14T00:00:00.000Z");
const ACCEPT = "application/json, text/event-stream";

const worlds = [];
test.afterEach(async () => {
  while (worlds.length > 0) await worlds.pop().stop();
});

function world() {
  const dir = mkdtempSync(join(tmpdir(), "standalone-addresses-"));
  const ledger = fakeLedger();
  const clock = { now: T };
  let live;
  async function boot() {
    if (live) await live.stop();
    const coordinator = createStandaloneCoordinator({ client: ledger, now: () => clock.now, recoverEip191Address: recoverLocally, nextPollMs: 5, stateDir: dir, coalesceMs: 20 });
    const handler = createStandaloneHttpHandler({ invoke: (name, args) => coordinator.invoke(name, args), stateDir: dir, env: {}, callsPerMinute: 100_000, invitesPerHour: 1_000, now: () => clock.now });
    const server = createServer((req, res) => { void handler(req, res); });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
    const raw = async (name, args) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
      });
      const text = await response.text();
      const data = text.split("\n").find((line) => line.startsWith("data:"));
      return JSON.parse(data ? data.slice(5) : text).result.content[0].text;
    };
    const call = async (name, args) => JSON.parse(await raw(name, args));
    live = {
      coordinator, call, raw,
      // A crash: nothing closed or flushed.
      async stop() {
        coordinator.discard();
        handler.discard();
        const closed = new Promise((resolve) => server.close(resolve));
        server.closeAllConnections();
        await closed;
      },
    };
    return live;
  }
  const handle = { dir, ledger, clock, boot, stop: async () => { if (live) await live.stop(); live = undefined; } };
  worlds.push(handle);
  return handle;
}

async function readiness(call, account, overrides = {}) {
  const prepared = await call("readiness_prepare", { sessionKeyAddress: getAddress(account.address), accountableParty: "Acme", statement: "Authorized for Acme." });
  return {
    sessionKeyAddress: getAddress(account.address),
    identity: null,
    authorityStatement: { accountableParty: "Acme", statement: "Authorized for Acme." },
    authoritySignatureHex: await verifyAndSign(account, prepared),
    capabilityManifest: { dataHandlingClass: "confidential", purpose: validTerms().purpose },
    ...overrides,
  };
}

// The listener's side, exactly as the playbook describes it.
async function listen(call, account, name, extra = {}) {
  const address = addressFor(name, account.address);
  const challenge = await call("listen_challenge", { address, sessionKeyAddress: getAddress(account.address) });
  const signatureHex = await verifyAndSign(account, challenge.sign);
  const listening = await call("handshake_listen", { address, sessionKeyAddress: getAddress(account.address), nonce: challenge.nonce, signatureHex, ...extra });
  assert.equal(listening.error, undefined, JSON.stringify(listening));
  return { address, listenAccess: listening.listenAccess };
}

async function inviteTo(call, account, to) {
  return call("handshake_invite", { ...validTerms(), readiness: await readiness(call, account), to });
}

// ---------------------------------------------------------------------------
// Addresses and fingerprints
// ---------------------------------------------------------------------------

test("addresses: name#fingerprint, where the fingerprint is keccak256 of the key's 20 bytes", () => {
  const account = newSessionKey();
  const expected = keccak256(account.address.toLowerCase()).slice(2, 2 + FINGERPRINT_HEX_LENGTH);
  assert.equal(FINGERPRINT_HEX_LENGTH, 8);
  assert.equal(keyFingerprint(account.address), expected);
  assert.equal(keyFingerprint(account.address.toLowerCase()), expected, "checksum casing does not matter");
  assert.equal(addressFor("claude-code.alex", account.address), `claude-code.alex#${expected}`);
  assert.deepEqual(parseAddress(` Claude-Code.Alex#${expected.toUpperCase()} `), { address: `claude-code.alex#${expected}`, name: "claude-code.alex", fingerprint: expected });
  for (const bad of ["ab#3f9a1c07", "-alex#3f9a1c07", "alex-#3f9a1c07", "al..ex#3f9a1c07", "alex#3f9a", "alex#3f9a1c0g", "alex", "admin#3f9a1c07", "clockchain.team#3f9a1c07", `${"a".repeat(33)}#3f9a1c07`, "al ex#3f9a1c07", 42]) {
    assert.throws(() => parseAddress(bad), { name: "StandaloneAddressError" }, String(bad));
  }
  assert.doesNotThrow(() => parseAddress(`${"a".repeat(32)}#3f9a1c07`));
});

// ---------------------------------------------------------------------------
// Claiming an address
// ---------------------------------------------------------------------------

test("listen: a challenge nonce works once, expires after 2 minutes, and is bound to its address", async () => {
  const w = world();
  const { call } = await w.boot();
  const alice = newSessionKey();
  const address = addressFor("alice.agent", alice.address);
  const key = getAddress(alice.address);
  const challenge = await call("listen_challenge", { address, sessionKeyAddress: key });
  assert.equal(challenge.sign.record.schema, "clockchain.handshake-listen/v1");
  assert.equal(challenge.sign.bytes, canonicalJson(challenge.sign.record));
  assert.equal(challenge.sign.bytesSha256, sha256Hex(challenge.sign.bytes));
  const signatureHex = await verifyAndSign(alice, challenge.sign);
  assert.match((await call("handshake_listen", { address, sessionKeyAddress: key, nonce: challenge.nonce, signatureHex })).listenAccess, /^csla_[A-Za-z0-9_-]{22}$/);
  assert.equal((await call("handshake_listen", { address, sessionKeyAddress: key, nonce: challenge.nonce, signatureHex })).error, "CHALLENGE_INVALID", "replayed nonce");

  const late = await call("listen_challenge", { address, sessionKeyAddress: key });
  w.clock.now += 2 * 60_000;
  assert.equal((await call("handshake_listen", { address, sessionKeyAddress: key, nonce: late.nonce, signatureHex: await verifyAndSign(alice, late.sign) })).error, "CHALLENGE_INVALID", "expired nonce");

  const other = addressFor("alice.other", alice.address);
  const elsewhere = await call("listen_challenge", { address: other, sessionKeyAddress: key });
  assert.equal((await call("handshake_listen", { address, sessionKeyAddress: key, nonce: elsewhere.nonce, signatureHex: await verifyAndSign(alice, elsewhere.sign) })).error, "CHALLENGE_INVALID", "nonce for another address");
});

test("listen: the wrong key is refused; re-claiming with the same key works and retires the old listenAccess", async () => {
  const w = world();
  const { call } = await w.boot();
  const alice = newSessionKey();
  const mallory = newSessionKey();
  const address = addressFor("alice.agent", alice.address);
  // Mallory's key does not have Alice's fingerprint.
  assert.equal((await call("listen_challenge", { address, sessionKeyAddress: getAddress(mallory.address) })).error, "NOT_ADDRESS_KEY");
  const challenge = await call("listen_challenge", { address });
  const forged = await mallory.signMessage({ message: canonicalJson({ ...challenge.record, sessionKeyAddress: alice.address.toLowerCase() }) });
  assert.equal((await call("handshake_listen", { address, sessionKeyAddress: getAddress(alice.address), nonce: challenge.nonce, signatureHex: forged })).error, "SIGNATURE_INVALID");

  const first = await listen(call, alice, "alice.agent");
  const second = await listen(call, alice, "alice.agent");
  assert.equal(second.address, first.address);
  assert.equal((await call("handshake_next", { access: second.listenAccess, waitMs: 0 })).action, "wait");
  assert.equal(typeof (await call("handshake_next", { access: first.listenAccess, waitMs: 0 })).error, "string", "the old listenAccess is retired");
});

test("mailbox store: a live address belongs to its first claimant; another key with the same fingerprint is refused", () => {
  const store = createMailboxStore({ now: () => T });
  store.claim({ address: "alice.agent#3f9a1c07", ownerKey: "0x" + "11".repeat(20), allow: null, block: [] });
  assert.throws(() => store.claim({ address: "alice.agent#3f9a1c07", ownerKey: "0x" + "22".repeat(20), allow: null, block: [] }), /ADDRESS_TAKEN/);
  assert.doesNotThrow(() => store.claim({ address: "alice.agent#3f9a1c07", ownerKey: "0x" + "11".repeat(20), allow: null, block: [] }));
});

// ---------------------------------------------------------------------------
// Inviting by address
// ---------------------------------------------------------------------------

test("invite `to`: the answer is identical whether the address is listening, absent, blocking or full", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const blocked = newSessionKey();
  const { address } = await listen(call, listener, "listener.agent", { blockInitiators: [keyFingerprint(blocked.address)] });
  const absent = addressFor("nobody.here", newSessionKey().address);
  const shape = (response) => {
    const { sessionId, roleAccess, to, ...rest } = response;
    assert.match(sessionId, /^[0-9a-f-]{36}$/);
    assert.match(roleAccess, /^csha_/);
    return JSON.stringify({ ...rest, tellYourUser: rest.tellYourUser.replace(to, "<to>") });
  };
  const responses = [
    await inviteTo(call, newSessionKey(), address),
    await inviteTo(call, newSessionKey(), absent),
    await inviteTo(call, blocked, address),
  ];
  const shapes = responses.map(shape);
  assert.equal(shapes[1], shapes[0]);
  assert.equal(shapes[2], shapes[0]);
  for (const response of responses) {
    assert.equal(response.invitation, undefined, "no invitation string ever returns");
    assert.equal(response.delivery, "sent; delivered if the address is listening");
  }
});

test("e2e: invite by address, then review -> accept -> consent -> open -> 2 messages -> close, with no invitation string anywhere", async () => {
  const w = world();
  const { call, raw } = await w.boot();
  const initiator = newSessionKey();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "claude-code.alex");
  const initiatorOutput = [];
  const initiatorCall = async (name, args) => {
    const text = await raw(name, args);
    initiatorOutput.push(text);
    return JSON.parse(text);
  };

  const waiting = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  assert.equal(waiting.action, "wait");
  assert.equal(waiting.reason, "AWAITING_INVITATIONS");

  const invite = await initiatorCall("handshake_invite", { ...validTerms(), readiness: await readiness(call, initiator), to: address });
  const a = invite.roleAccess;

  const review = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  assert.equal(review.action, "review_invitation");
  assert.equal(review.listenAccess, listenAccess);
  assert.equal(review.invitation.purpose, validTerms().purpose);
  assert.deepEqual(review.invitation.required["capabilityManifest.dataHandlingClass"], "confidential");
  assert.equal(review.invitation.initiator.keyFingerprint, keyFingerprint(initiator.address));
  assert.equal(review.invitation.initiator.accountableParty, "Acme");
  assert.deepEqual(review.untrustedFields, ["invitation.reference", "invitation.purpose", "invitation.initiator.accountableParty"]);
  assert.equal(review.thenCall, "handshake_accept_from_mailbox");
  assert.equal(review.orCall, "handshake_decline");
  assert.equal(JSON.stringify(review).includes("chs2."), false);

  const accepted = await call("handshake_accept_from_mailbox", { access: listenAccess, invitationId: review.invitationId, readiness: await readiness(call, listener) });
  assert.equal(accepted.stage, "ready", JSON.stringify(accepted));
  const b = accepted.roleAccess;
  assert.match(b, /^csha_/);
  assert.equal(accepted.listenAccess, listenAccess);

  for (const [account, access, useCall] of [[initiator, a, initiatorCall], [listener, b, call]]) {
    const step = await useCall("handshake_next", { access, waitMs: 0 });
    assert.equal(step.action, "sign");
    assert.equal((await useCall("consent_sign", { access, signatureHex: await verifyAndSign(account, step.sign) })).stage !== undefined, true);
  }
  await initiatorCall("channel_open", { access: a });
  await initiatorCall("channel_send", { access: a, kind: "question", body: "Thursday 14:00?" });
  const incoming = await call("handshake_next", { access: b, waitMs: 0 });
  assert.equal(incoming.messages[0].body, "Thursday 14:00?");
  await call("channel_send", { access: b, kind: "proposal", body: "Thursday 14:00 works." });
  assert.equal((await initiatorCall("handshake_next", { access: a, waitMs: 0, cursor: 0 })).messages[0].body, "Thursday 14:00 works.");
  assert.equal((await initiatorCall("channel_close", { access: a })).outcome, "closed");
  assert.equal((await call("handshake_next", { access: b, waitMs: 0, cursor: 1 })).action, "closed");

  // The Initiator never saw an invitation, and its timeline says only that it was sent.
  const everything = initiatorOutput.join("\n");
  assert.equal(everything.includes("chs2."), false);
  assert.equal(/"invitation"\s*:/.test(everything), false);
  const timeline = await initiatorCall("handshake_timeline", { access: a });
  assert.ok(timeline.events.some((event) => event.type === "invitation_sent" && event.to === address));
  assert.equal(timeline.events.some((event) => event.type === "invitation_delivered"), false, "delivery is only in the listener's mailbox timeline");
  const mailbox = await call("handshake_timeline", { access: listenAccess });
  assert.deepEqual(mailbox.events.map((event) => event.type), ["listening", "invitation_delivered", "reviewed", "accepted"]);
});

test("the listener must accept with the address's key, and stays bound to it on retries", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "listener.agent");
  await inviteTo(call, newSessionKey(), address);
  const review = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  const otherKey = newSessionKey();
  assert.equal((await call("handshake_accept_from_mailbox", { access: listenAccess, invitationId: review.invitationId, readiness: await readiness(call, otherKey) })).error, "NOT_MAILBOX_KEY");
  // A fixable failure (data class) with the right key; the retry must keep that key.
  const failed = await call("handshake_accept_from_mailbox", { access: listenAccess, invitationId: review.invitationId, readiness: await readiness(call, listener, { capabilityManifest: { dataHandlingClass: "public", purpose: validTerms().purpose } }) });
  assert.equal(failed.stage, "readiness_retry");
  assert.equal((await call("handshake_retry_readiness", { access: failed.roleAccess, readiness: await readiness(call, otherKey) })).error, "NOT_MAILBOX_KEY");
  assert.equal((await call("handshake_retry_readiness", { access: failed.roleAccess, readiness: await readiness(call, listener) })).stage, "ready");
});

test("decline: the Initiator hears INVITATION_DECLINED at once; the timeline records it and nothing is anchored", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "listener.agent");
  const invite = await inviteTo(call, newSessionKey(), address);
  const review = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  const declined = await call("handshake_decline", { access: listenAccess, invitationId: review.invitationId });
  assert.equal(declined.declined, true);
  const ended = await call("handshake_next", { access: invite.roleAccess, waitMs: 0 });
  assert.equal(ended.action, "abandoned");
  assert.equal(ended.reason, "INVITATION_DECLINED");
  assert.equal(ended.tellYourUser, "The handshake ended without opening a channel: the other agent declined the invitation.");
  assert.ok((await call("handshake_timeline", { access: invite.roleAccess })).events.some((event) => event.type === "declined"));
  assert.equal(w.ledger.entries.size, 0);
  assert.equal((await call("handshake_accept_from_mailbox", { access: listenAccess, invitationId: review.invitationId, readiness: await readiness(call, listener) })).error, "INVITATION_UNAVAILABLE");
  assert.equal((await call("handshake_next", { access: listenAccess, waitMs: 0 })).action, "wait");
});

test("abuse limits: one open invitation per Initiator key, ten per mailbox, allow and block lists", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "busy.agent");
  const repeat = newSessionKey();
  await inviteTo(call, repeat, address);
  await inviteTo(call, repeat, address);
  const first = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  assert.equal(first.openInvitations, 1, "a second invitation from the same key is not delivered");
  for (let i = 0; i < MAX_PENDING_PER_MAILBOX + 2; i += 1) await inviteTo(call, newSessionKey(), address);
  assert.equal((await call("handshake_next", { access: listenAccess, waitMs: 0 })).openInvitations, MAX_PENDING_PER_MAILBOX);

  const friend = newSessionKey();
  const stranger = newSessionKey();
  const picky = newSessionKey();
  const allowOnly = await listen(call, picky, "picky.agent", { allowInitiators: [keyFingerprint(friend.address)] });
  await inviteTo(call, stranger, allowOnly.address);
  assert.equal((await call("handshake_next", { access: allowOnly.listenAccess, waitMs: 0 })).action, "wait", "not on the allowlist");
  await inviteTo(call, friend, allowOnly.address);
  const allowed = await call("handshake_next", { access: allowOnly.listenAccess, waitMs: 0 });
  assert.equal(allowed.invitation.initiator.keyFingerprint, keyFingerprint(friend.address));

  const guarded = newSessionKey();
  const blockSome = await listen(call, guarded, "guarded.agent", { blockInitiators: [keyFingerprint(stranger.address)] });
  await inviteTo(call, stranger, blockSome.address);
  assert.equal((await call("handshake_next", { access: blockSome.listenAccess, waitMs: 0 })).action, "wait", "on the blocklist");
});

test("a listener waiting on handshake_next wakes as soon as an invitation is delivered", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "listener.agent");
  const held = call("handshake_next", { access: listenAccess, waitMs: 10_000 });
  await new Promise((resolve) => setTimeout(resolve, 30));
  const started = Date.now();
  await inviteTo(call, newSessionKey(), address);
  assert.equal((await held).action, "review_invitation");
  assert.ok(Date.now() - started < 2_000);
});

test("crash-restart with a pending mailbox invitation: the listener's handle still works and it still gets the invitation", async () => {
  const w = world();
  let { call } = await w.boot();
  const listener = newSessionKey();
  const initiator = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "listener.agent");
  const invite = await inviteTo(call, initiator, address);
  ({ call } = await w.boot()); // crash: nothing closed or flushed
  const review = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  assert.equal(review.action, "review_invitation");
  assert.equal(review.sessionId, invite.sessionId);
  const accepted = await call("handshake_accept_from_mailbox", { access: listenAccess, invitationId: review.invitationId, readiness: await readiness(call, listener) });
  assert.equal(accepted.stage, "ready");
  assert.equal((await call("handshake_next", { access: invite.roleAccess, waitMs: 0 })).action, "sign");
});
