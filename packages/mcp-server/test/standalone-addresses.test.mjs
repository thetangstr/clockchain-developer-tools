// Handshake addresses (spec B4): name#fingerprint, listen, invite `to`, review_invitation.
// Everything runs over HTTP through the public tools, with durability on.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { getAddress, keccak256 } from "viem";

import { FINGERPRINT_HEX_LENGTH, addressFor, keyFingerprint, parseAddress } from "../dist/standalone-handshake/address.js";
import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { createMailboxStore, MAX_MAILBOXES_PER_CLIENT, MAX_MAILBOXES_PER_KEY, MAX_MAILBOX_EVENTS, MAX_PENDING_PER_MAILBOX, MAX_PENDING_PER_SOURCE } from "../dist/standalone-handshake/mailbox-store.js";
import { clientBucket, createStandaloneHttpHandler } from "../dist/standalone-handshake/public-server.js";
import { createHandleMap } from "../dist/handshake-core/handle-map.js";
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
  async function boot(overrides = {}) {
    if (live) await live.stop();
    const coordinator = createStandaloneCoordinator({ client: ledger, now: () => clock.now, recoverEip191Address: recoverLocally, nextPollMs: 5, stateDir: dir, coalesceMs: 20, ...(overrides.coordinator ?? {}) });
    const handler = createStandaloneHttpHandler({ invoke: (name, args) => coordinator.invoke(name, args), stateDir: dir, env: {}, callsPerMinute: 100_000, invitesPerHour: 1_000, listensPerHour: overrides.listensPerHour ?? 1_000, trustedProxy: "127.0.0.1", now: () => clock.now });
    const server = createServer((req, res) => { void handler(req, res); });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${server.address().port}/connect/mcp`;
    // `from` sets the client IP (X-Forwarded-For through the trusted local proxy); `headers` adds more.
    const raw = async (name, args, from = "198.51.100.1", headers = {}) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: ACCEPT, "x-forwarded-for": from, ...headers },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
      });
      const text = await response.text();
      const data = text.split("\n").find((line) => line.startsWith("data:"));
      return JSON.parse(data ? data.slice(5) : text).result.content[0].text;
    };
    const call = async (name, args, from, headers) => JSON.parse(await raw(name, args, from, headers));
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

let nextIp = 1;
// Each Initiator from its own network unless told otherwise (per-source caps are tested apart).
async function inviteTo(call, account, to, extra = {}, from = `203.0.113.${(nextIp++ % 250) + 1}`) {
  return call("handshake_invite", { ...validTerms(), readiness: await readiness(call, account), to, ...extra }, from);
}

// ---------------------------------------------------------------------------
// Addresses and fingerprints
// ---------------------------------------------------------------------------

test("addresses: name#fingerprint, where the fingerprint is keccak256 of the key's 20 bytes", () => {
  const account = newSessionKey();
  const expected = keccak256(account.address.toLowerCase()).slice(2, 2 + FINGERPRINT_HEX_LENGTH);
  assert.equal(FINGERPRINT_HEX_LENGTH, 20);
  assert.equal(keyFingerprint(account.address), expected);
  assert.equal(keyFingerprint(account.address.toLowerCase()), expected, "checksum casing does not matter");
  assert.equal(addressFor("claude-code.alex", account.address), `claude-code.alex#${expected}`);
  assert.deepEqual(parseAddress(` Claude-Code.Alex#${expected.toUpperCase()} `), { address: `claude-code.alex#${expected}`, name: "claude-code.alex", fingerprint: expected });
  for (const bad of ["ab#3f9a1c07aa55bb66cc77", "-alex#3f9a1c07aa55bb66cc77", "alex-#3f9a1c07aa55bb66cc77", "al..ex#3f9a1c07aa55bb66cc77", "alex#3f9a", "alex#3f9a1c07", "alex#3f9a1c07aa55bb66cc7g", "alex", "admin#3f9a1c07aa55bb66cc77", "clockchain.team#3f9a1c07aa55bb66cc77", `${"a".repeat(33)}#3f9a1c07aa55bb66cc77`, "al ex#3f9a1c07aa55bb66cc77", 42]) {
    assert.throws(() => parseAddress(bad), { name: "StandaloneAddressError" }, String(bad));
  }
  assert.doesNotThrow(() => parseAddress(`${"a".repeat(32)}#3f9a1c07aa55bb66cc77`));
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
  store.claim({ address: "alice.agent#3f9a1c07aa55bb66cc77", ownerKey: "0x" + "11".repeat(20), allow: null, block: [], client: "192.0.2.1" });
  assert.throws(() => store.claim({ address: "alice.agent#3f9a1c07aa55bb66cc77", ownerKey: "0x" + "22".repeat(20), allow: null, block: [], client: "192.0.2.1" }), /ADDRESS_TAKEN/);
  assert.doesNotThrow(() => store.claim({ address: "alice.agent#3f9a1c07aa55bb66cc77", ownerKey: "0x" + "11".repeat(20), allow: null, block: [], client: "192.0.2.1" }));
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
  assert.equal(timeline.events.some((event) => event.type === "invitation_delivered" || event.type === "reviewed"), false, "delivery and review are only in the listener's mailbox timeline");
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
  // Deliveries are coalesced writes (no synchronous write on the invite path, see fix 2):
  // let it land, then crash with nothing closed or flushed.
  await new Promise((resolve) => setTimeout(resolve, 80));
  ({ call } = await w.boot());
  const review = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  assert.equal(review.action, "review_invitation");
  assert.equal(review.sessionId, invite.sessionId);
  const accepted = await call("handshake_accept_from_mailbox", { access: listenAccess, invitationId: review.invitationId, readiness: await readiness(call, listener) });
  assert.equal(accepted.stage, "ready");
  assert.equal((await call("handshake_next", { access: invite.roleAccess, waitMs: 0 })).action, "sign");
});


// ---------------------------------------------------------------------------
// Security review fixes (PR #165)
// ---------------------------------------------------------------------------

// Everything the Initiator can observe, with ids and times masked.
async function initiatorView(call, access) {
  const mask = (value) => JSON.stringify(value)
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, "<id>")
    .replace(/"at":"[^"]+"/g, '"at":"<t>"')
    .replace(/[a-z0-9.-]+#[0-9a-f]{20}/g, "<address>")
    .replace(/csha_[A-Za-z0-9_-]{22}/g, "<handle>");
  return [
    mask(await call("handshake_next", { access, waitMs: 0 })),
    mask(await call("handshake_status", { access })),
    mask(await call("handshake_timeline", { access })),
  ];
}

test("fix 1: before an explicit accept or decline, the Initiator cannot tell delivered-and-reviewed from undeliverable", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "listener.agent");
  const delivered = await inviteTo(call, newSessionKey(), address);
  assert.equal((await call("handshake_next", { access: listenAccess, waitMs: 0 })).action, "review_invitation");
  await call("handshake_next", { access: listenAccess, waitMs: 0 }); // reviewed again
  const undeliverable = await inviteTo(call, newSessionKey(), addressFor("nobody.home", newSessionKey().address));
  assert.deepEqual(await initiatorView(call, delivered.roleAccess), await initiatorView(call, undeliverable.roleAccess));
});

test("fix 2: delivering an invitation does no synchronous durable write; a refusal writes nothing either", async () => {
  const w = world();
  // A long coalescing window so "not written synchronously" and "written soon after" are
  // told apart deterministically, whatever the machine's load.
  const { call } = await w.boot({ coordinator: { coalesceMs: 500 } });
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "listener.agent");
  const dir = join(w.dir, "mailboxes");
  const [file] = readdirSync(dir).filter((name) => name.endsWith(".json"));
  const before = readFileSync(join(dir, file), "utf8");
  const invite = await inviteTo(call, newSessionKey(), address);
  // The invite call has returned; the delivery has not been written synchronously.
  assert.equal(readFileSync(join(dir, file), "utf8"), before);
  await new Promise((resolve) => setTimeout(resolve, 800)); // the coalesced write
  const after = readFileSync(join(dir, file), "utf8");
  assert.notEqual(after, before);
  assert.ok(after.includes("invitation_delivered"));
  // Refused (duplicate sender key is irrelevant here: the address is absent): no mailbox file changes.
  await inviteTo(call, newSessionKey(), addressFor("nobody.home", newSessionKey().address));
  await new Promise((resolve) => setTimeout(resolve, 800));
  assert.equal(readFileSync(join(dir, file), "utf8"), after);
  assert.equal(readdirSync(dir).filter((name) => name.endsWith(".json")).length, 1);
  void invite; void listenAccess;
});

test("fix 3: 80-bit fingerprints, and an Initiator can pin the listener's full key", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "pinned.agent");
  assert.match(address, /^pinned\.agent#[0-9a-f]{20}$/);
  const mismatched = await inviteTo(call, newSessionKey(), address, { toKey: getAddress(newSessionKey().address) });
  assert.equal(mismatched.error, "TO_KEY_NOT_ADDRESS", "a pin must be a key with the address's fingerprint");
  await inviteTo(call, newSessionKey(), address, { toKey: getAddress(listener.address) });
  assert.equal((await call("handshake_next", { access: listenAccess, waitMs: 0 })).action, "review_invitation");
  // The store refuses (silently) a pin that is not the mailbox owner's key.
  const store = createMailboxStore({ now: () => T });
  store.claim({ address: "x.agent#" + "a".repeat(20), ownerKey: "0x" + "11".repeat(20), allow: null, block: [], client: "c" });
  assert.equal(store.deliver({ address: "x.agent#" + "a".repeat(20), invitationId: "mbi_1", sessionId: "s", initiatorFingerprint: "f".repeat(20), expiresAtMs: T + 1e6, client: "d", pinnedKey: "0x" + "22".repeat(20) }), false);
  store.close();
});

test("fix 4: one live listen handle per mailbox; re-claim revokes the old one; a full map evicts instead of refusing", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const first = await listen(call, listener, "listener.agent");
  const second = await listen(call, listener, "listener.agent");
  assert.notEqual(second.listenAccess, first.listenAccess);
  assert.equal(typeof (await call("handshake_next", { access: first.listenAccess, waitMs: 0 })).error, "string", "revoked");
  assert.equal((await call("handshake_next", { access: second.listenAccess, waitMs: 0 })).action, "wait");

  const map = createHandleMap({ label: "t/l", prefix: "csla_", limit: 2, now: () => 1_000, evictWhenFull: true });
  const a1 = map.issue("slt_" + "a".repeat(40), 5_000, { group: "a" });
  map.issue("slt_" + "b".repeat(40), 9_000, { group: "b" });
  const a2 = map.issue("slt_" + "c".repeat(40), 9_000, { group: "a" });
  assert.equal(map.resolve(a1), undefined, "same group: the previous handle is revoked");
  assert.equal(map.size(), 2);
  const d = map.issue("slt_" + "d".repeat(40), 9_000, { group: "d" });
  assert.match(d, /^csla_/, "full: evicts rather than refusing");
  assert.equal(map.size(), 2);
  void a2;
});

test("fix 5: listen rate limit per client (IPv6 by /64), mailbox caps per key and per client, per-source pending cap, small event cap", async () => {
  assert.equal(clientBucket("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
  assert.equal(clientBucket("2001:db8:1:2::9"), "2001:db8:1:2::/64");
  assert.equal(clientBucket("2001:0db8:0001:0002:ffff::1"), "2001:db8:1:2::/64");
  assert.equal(clientBucket("198.51.100.7"), "198.51.100.7");

  const w = world();
  const { call } = await w.boot({ listensPerHour: 3 });
  const probe = newSessionKey();
  const address = addressFor("probe.agent", probe.address);
  for (let i = 0; i < 3; i += 1) assert.equal((await call("listen_challenge", { address }, "2001:db8:5:6::1")).address, address);
  assert.equal((await call("listen_challenge", { address }, "2001:db8:5:6::ffff")).error, "RATE_LIMITED", "same /64");
  assert.equal((await call("listen_challenge", { address }, "2001:db8:5:7::1")).address, address, "another /64");

  const store = createMailboxStore({ now: () => T });
  const key = "0x" + "11".repeat(20);
  for (let i = 0; i < MAX_MAILBOXES_PER_KEY; i += 1) store.claim({ address: `k${i}.agent#${"a".repeat(20)}`, ownerKey: key, allow: null, block: [], client: `c${i}` });
  assert.throws(() => store.claim({ address: `kx.agent#${"a".repeat(20)}`, ownerKey: key, allow: null, block: [], client: "cx" }), /TOO_MANY_ADDRESSES_FOR_KEY/);
  for (let i = 0; i < MAX_MAILBOXES_PER_CLIENT; i += 1) store.claim({ address: `c${i}.agent#${"b".repeat(20)}`, ownerKey: `0x${String(i).padStart(40, "0")}`, allow: null, block: [], client: "one-network" });
  assert.throws(() => store.claim({ address: `cx.agent#${"b".repeat(20)}`, ownerKey: "0x" + "9".repeat(40), allow: null, block: [], client: "one-network" }), /TOO_MANY_ADDRESSES_FOR_CLIENT/);
  store.close();

  const { call: open } = await w.boot();
  const listener = newSessionKey();
  const box = await listen(open, listener, "fill.agent");
  for (let i = 0; i < MAX_PENDING_PER_SOURCE + 2; i += 1) await inviteTo(open, newSessionKey(), box.address, {}, "192.0.2.50");
  assert.equal((await open("handshake_next", { access: box.listenAccess, waitMs: 0 })).openInvitations, MAX_PENDING_PER_SOURCE, "one network fills at most MAX_PENDING_PER_SOURCE");
  assert.ok(MAX_MAILBOX_EVENTS <= 30);
});

test("fix 6: a silent decline ends the Initiator's session exactly like an unanswered invitation", async () => {
  const w = world();
  const { call } = await w.boot();
  const listener = newSessionKey();
  const { address, listenAccess } = await listen(call, listener, "listener.agent");
  const declined = await inviteTo(call, newSessionKey(), address);
  const review = await call("handshake_next", { access: listenAccess, waitMs: 0 });
  const answer = await call("handshake_decline", { access: listenAccess, invitationId: review.invitationId, silent: true });
  assert.deepEqual([answer.declined, answer.silent, answer.sessionId], [true, true, undefined]);
  const unanswered = await inviteTo(call, newSessionKey(), addressFor("nobody.home", newSessionKey().address));
  assert.deepEqual(await initiatorView(call, declined.roleAccess), await initiatorView(call, unanswered.roleAccess));
  // An Initiator keeps polling (which also keeps its handle alive) until the invitation TTL.
  w.clock.now += 30 * 60_000;
  for (const invite of [declined, unanswered]) assert.equal((await call("handshake_next", { access: invite.roleAccess, waitMs: 0 })).action, "wait");
  w.clock.now += 30 * 60_000;
  for (const invite of [declined, unanswered]) {
    const ended = await call("handshake_next", { access: invite.roleAccess, waitMs: 0 });
    assert.equal(ended.reason, "INVITATION_NOT_ACCEPTED", JSON.stringify(ended));
  }
});

test("fix 7: the signed endpoint must be this server's public endpoint", async () => {
  const w = world();
  let { call } = await w.boot();
  const listener = newSessionKey();
  const address = addressFor("listener.agent", listener.address);
  const key = getAddress(listener.address);
  // Challenge asked on one mount, claim attempted through another.
  const challenge = await call("listen_challenge", { address, sessionKeyAddress: key }, "198.51.100.1", { "x-forwarded-host": "mcp.example", "x-forwarded-prefix": "/staging" });
  assert.equal(challenge.endpoint, "https://mcp.example/staging/connect/mcp");
  const signatureHex = await verifyAndSign(listener, challenge.sign);
  assert.equal((await call("handshake_listen", { address, sessionKeyAddress: key, nonce: challenge.nonce, signatureHex }, "198.51.100.1", { "x-forwarded-host": "mcp.example" })).error, "ENDPOINT_MISMATCH");

  // With a configured public endpoint, that is what gets signed, whatever the Host header says.
  ({ call } = await w.boot({ coordinator: { publicEndpoint: "https://mcp.clockchain.network/connect/mcp" } }));
  const pinned = await call("listen_challenge", { address, sessionKeyAddress: key }, "198.51.100.1", { "x-forwarded-host": "evil.example" });
  assert.equal(pinned.sign.record.endpoint, "https://mcp.clockchain.network/connect/mcp");
  const ok = await call("handshake_listen", { address, sessionKeyAddress: key, nonce: pinned.nonce, signatureHex: await verifyAndSign(listener, pinned.sign) }, "198.51.100.1", { "x-forwarded-host": "evil.example" });
  assert.match(ok.listenAccess, /^csla_/);
});
