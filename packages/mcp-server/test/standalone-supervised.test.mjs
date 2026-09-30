// Supervised sessions (S1-S4): preview, recoverable readiness, both-sides reporting, timeline.
import { test } from "node:test";
import assert from "node:assert/strict";

import { getStandaloneTimeline, listStandaloneSessions } from "../dist/standalone-handshake/coordinator.js";
import { MAX_TIMELINE_EVENTS } from "../dist/standalone-handshake/session-store.js";
import { validTerms } from "./helpers/standalone-fixtures.mjs";
import { harness, openedSession } from "./helpers/standalone-harness.mjs";

const T0 = 1_750_000_000_000;
const PURPOSE = validTerms().purpose;
const unavailable = (error) => error.reason === "INVITATION_UNAVAILABLE";
const manifest = (dataHandlingClass, purpose = PURPOSE) => ({ capabilityManifest: { dataHandlingClass, purpose } });

// Blocking and terminal answers must carry a reason, a next step and a sentence for the user.
function assertSupervised(result) {
  if (!["wait", "fix_readiness", "closed", "expired", "revoked", "ready_failed", "abandoned"].includes(result.action)) return;
  for (const field of ["reason", "nextStep", "tellYourUser"]) {
    assert.equal(typeof result[field], "string", `${result.action} lacks ${field}`);
    assert.ok(result[field].length > 0, `${result.action} has an empty ${field}`);
  }
}

// ---------------------------------------------------------------------------
// S1 preview
// ---------------------------------------------------------------------------

test("S1 preview: returns what the Responder must match, marks free text untrusted, and burns nothing", async () => {
  const h = harness({ nowMs: T0 });
  const invite = await h.invite();
  const preview = await h.instance.invoke("handshake_preview_invitation", { invitation: invite.invitation });
  assert.equal(preview.sessionId, invite.sessionId);
  assert.equal(preview.terms.purpose, PURPOSE);
  assert.deepEqual(preview.terms.channelLimits, validTerms().channelLimits);
  assert.deepEqual(preview.terms.identityPolicy, validTerms().identityPolicy);
  assert.deepEqual(preview.required, { "capabilityManifest.dataHandlingClass": "confidential", "capabilityManifest.purpose": PURPOSE, identity: null });
  assert.equal(preview.invitationExpiresAtMs, String(T0 + 60 * 60_000));
  assert.equal(preview.invitationExpiresAt, new Date(T0 + 60 * 60_000).toISOString());
  assert.equal(preview.maxReadinessAttempts, 3);
  assert.deepEqual(preview.untrustedFields, ["terms.reference", "terms.purpose"]);
  assert.equal(typeof preview.untrustedNote, "string");
  assert.equal(preview.thenCall, "handshake_accept_invitation");
  assert.equal(preview.guidance.includes(PURPOSE), false, "guidance never repeats the free text");

  // Previewing twice still leaves the invitation claimable.
  await h.instance.invoke("handshake_preview_invitation", { invitation: invite.invitation });
  const accept = await h.accept(invite.invitation);
  assert.equal(accept.stage, "ready");
});

test("S1 preview: malformed, unknown, tampered, expired and claimed invitations all get the same refusal", async () => {
  const h = harness({ nowMs: T0 });
  const invite = await h.invite();
  const decoded = JSON.parse(Buffer.from(invite.invitation.slice("chs2.".length), "base64url").toString("utf8"));
  const encode = (value) => "chs2." + Buffer.from(JSON.stringify(value)).toString("base64url");
  const preview = (invitation) => h.instance.invoke("handshake_preview_invitation", { invitation });

  await assert.rejects(() => preview("not-an-invitation"), unavailable);
  await assert.rejects(() => preview(encode({ v: 1, sessionId: decoded.sessionId, secret: "x".repeat(32) })), unavailable);
  await assert.rejects(() => preview(encode({ ...decoded, sessionId: "00000000-0000-4000-8000-000000000000" })), unavailable);

  const claimed = await h.invite();
  await h.accept(claimed.invitation);
  await assert.rejects(() => preview(claimed.invitation), unavailable);

  h.setNow(T0 + 60 * 60_000);
  await assert.rejects(() => preview(invite.invitation), unavailable);
});

// ---------------------------------------------------------------------------
// S2 recoverable readiness
// ---------------------------------------------------------------------------

test("S2: a DATA_CLASS then PURPOSE mismatch is corrected in place, with both sides told the facts", async () => {
  const h = harness({ nowMs: T0, coordinator: { nextPollMs: 5 } });
  const invite = await h.invite();

  const first = await h.accept(invite.invitation, manifest("public"));
  assert.equal(first.stage, "readiness_retry");
  assert.equal(first.attempt, 1);
  assert.equal(first.attemptsLeft, 2);
  assert.deepEqual(first.codes, ["DATA_CLASS_MISMATCH"]);
  const b = first.responderAccess;

  const fix1 = await h.next(b);
  assertSupervised(fix1);
  assert.equal(fix1.action, "fix_readiness");
  assert.equal(fix1.reason, "DATA_CLASS_MISMATCH");
  assert.deepEqual(fix1.codes, ["DATA_CLASS_MISMATCH"]);
  assert.deepEqual(fix1.required, { "capabilityManifest.dataHandlingClass": "confidential" });
  assert.equal(fix1.attemptsLeft, 2);
  assert.equal(fix1.thenCall, "handshake_retry_readiness");
  assert.equal(fix1.deadlineMs, String(T0 + 60 * 60_000));
  assert.match(fix1.tellYourUser, /DATA_CLASS_MISMATCH/);
  assert.match(fix1.tellYourUser, /attempt 2 of 3/);

  const waiting1 = await h.next(invite.initiatorAccess);
  assertSupervised(waiting1);
  assert.equal(waiting1.action, "wait");
  assert.equal(waiting1.reason, "COUNTERPARTY_CORRECTING_READINESS");
  assert.equal(waiting1.status, "counterparty correcting readiness (attempt 2/3, DATA_CLASS_MISMATCH)");
  assert.match(waiting1.tellYourUser, /DATA_CLASS_MISMATCH/);

  // Right class, wrong purpose: a different, precise code.
  const second = await h.instance.invoke("handshake_retry_readiness", { access: b, readiness: await h.readiness("responder", manifest("confidential", "Talk about something else")) });
  assert.equal(second.stage, "readiness_retry");
  assert.equal(second.attempt, 2);
  const fix2 = await h.next(b);
  assert.deepEqual(fix2.required, { "capabilityManifest.purpose": PURPOSE });
  assert.equal(fix2.attemptsLeft, 1);
  assert.equal((await h.next(invite.initiatorAccess)).status, "counterparty correcting readiness (attempt 3/3, PURPOSE_MISMATCH)");

  const third = await h.instance.invoke("handshake_retry_readiness", { access: b, readiness: await h.readiness("responder", manifest("confidential")) });
  assert.equal(third.stage, "ready");
  assert.equal(third.attempt, 3);
  assert.equal((await h.next(b)).action, "sign");
  assert.equal((await h.next(invite.initiatorAccess)).action, "sign");
  // Nothing was anchored by the attempts: terms-readiness is anchored only at channel_open.
  assert.equal(h.ledger.entries.size, 0);
});

test("S2: nobody but the first claimant can use the retry", async () => {
  const h = harness({ nowMs: T0 });
  const invite = await h.invite();
  const failed = await h.accept(invite.invitation, manifest("public"));
  assert.equal(failed.stage, "readiness_retry");
  // The invitation is burned by the first claim: a third party can neither claim nor preview it.
  await assert.rejects(() => h.accept(invite.invitation));
  await assert.rejects(() => h.instance.invoke("handshake_preview_invitation", { invitation: invite.invitation }), unavailable);
  // The retry is bound to the responder's access.
  const readiness = await h.readiness("responder");
  await assert.rejects(() => h.instance.invoke("handshake_retry_readiness", { access: invite.initiatorAccess, readiness }), (error) => error.reason === "NOT_RESPONDER");
  await assert.rejects(() => h.instance.invoke("handshake_retry_readiness", { access: "sat_" + "z".repeat(43), readiness }), { name: "StandaloneCoordinatorError" });
  // The genuine Responder still can.
  assert.equal((await h.instance.invoke("handshake_retry_readiness", { access: failed.responderAccess, readiness })).stage, "ready");
  await assert.rejects(() => h.instance.invoke("handshake_retry_readiness", { access: failed.responderAccess, readiness }), (error) => error.reason === "NOT_IN_RETRY");
});

test("S2: after the third failed attempt both sides get ready_failed with the same reason", async () => {
  const h = harness({ nowMs: T0 });
  const invite = await h.invite();
  const failed = await h.accept(invite.invitation, manifest("public"));
  const b = failed.responderAccess;
  const wrong = await h.readiness("responder", manifest("restricted"));
  assert.equal((await h.instance.invoke("handshake_retry_readiness", { access: b, readiness: wrong })).stage, "readiness_retry");
  const last = await h.instance.invoke("handshake_retry_readiness", { access: b, readiness: wrong });
  assert.equal(last.stage, "ready_failed");
  assert.equal(last.attemptsLeft, 0);
  const results = [await h.next(invite.initiatorAccess), await h.next(b)];
  for (const result of results) {
    assertSupervised(result);
    assert.equal(result.action, "ready_failed");
    assert.equal(result.reason, "DATA_CLASS_MISMATCH");
    assert.equal(result.terminal.attempts, 3);
    assert.match(result.nextStep, /new invitation/);
  }
  assert.match(results[0].tellYourUser, /the other agent's readiness/);
  assert.match(results[1].tellYourUser, /my readiness/);
  const corrected = await h.readiness("responder");
  await assert.rejects(() => h.instance.invoke("handshake_retry_readiness", { access: b, readiness: corrected }), (error) => error.reason === "NOT_IN_RETRY");
});

test("S2: a retry left past the invitation TTL ends as abandoned (READINESS_NOT_CORRECTED)", async () => {
  const h = harness({ nowMs: T0 });
  const invite = await h.invite();
  const failed = await h.accept(invite.invitation, manifest("public"));
  h.setNow(T0 + 60 * 60_000);
  for (const access of [invite.initiatorAccess, failed.responderAccess]) {
    const result = await h.next(access);
    assertSupervised(result);
    assert.equal(result.action, "abandoned");
    assert.equal(result.reason, "READINESS_NOT_CORRECTED");
  }
  const late = await h.readiness("responder");
  await assert.rejects(() => h.instance.invoke("handshake_retry_readiness", { access: failed.responderAccess, readiness: late }), (error) => error.reason === "ABANDONED");
});

test("S2: a repeated fix_readiness is held rather than spun", async () => {
  const h = harness({ nowMs: T0, coordinator: { nextPollMs: 20 } });
  const invite = await h.invite();
  const failed = await h.accept(invite.invitation, manifest("public"));
  assert.equal((await h.next(failed.responderAccess, { waitMs: 5_000 })).action, "fix_readiness");
  const started = Date.now();
  const repeat = await h.next(failed.responderAccess, { waitMs: 250 });
  assert.equal(repeat.action, "fix_readiness");
  assert.ok(Date.now() - started >= 200);
});

// ---------------------------------------------------------------------------
// S3 + S4: reporting and the timeline
// ---------------------------------------------------------------------------

test("S3: every blocking and terminal answer carries reason, nextStep and tellYourUser, and never a body", async () => {
  const h = harness({ nowMs: T0 });
  const invite = await h.invite();
  const seen = [];
  const next = async (access, extra) => { const result = await h.next(access, extra); seen.push(result); return result; };
  await next(invite.initiatorAccess);
  const accept = await h.accept(invite.invitation);
  await h.consent("initiator", invite.initiatorAccess);
  await next(invite.initiatorAccess);
  await h.consent("responder", accept.responderAccess);
  await h.instance.invoke("channel_open", { access: invite.initiatorAccess });
  await next(accept.responderAccess);
  const secret = "The secret code word is PELICAN.";
  await h.instance.invoke("channel_send", { access: invite.initiatorAccess, kind: "question", body: secret });
  await h.instance.invoke("channel_revoke", { access: accept.responderAccess });
  await next(invite.initiatorAccess);
  await next(accept.responderAccess);
  assert.deepEqual(seen.map((result) => result.action), ["wait", "wait", "wait", "revoked", "revoked"]);
  for (const result of seen) {
    assertSupervised(result);
    for (const field of ["reason", "nextStep", "tellYourUser", "guidance"]) assert.equal(result[field].includes("PELICAN"), false);
  }
  assert.equal(seen[3].tellYourUser, "The other agent revoked the channel; the handshake is over.");
  assert.equal(seen[4].tellYourUser, "I revoked the channel; the handshake is over.");
});

test("S4: the timeline records the whole session in order, with anchors and digests but never a body", async () => {
  const h = harness({ nowMs: T0 });
  const invite = await h.invite();
  await h.instance.invoke("handshake_preview_invitation", { invitation: invite.invitation });
  const failed = await h.accept(invite.invitation, manifest("public"));
  const a = invite.initiatorAccess;
  const b = failed.responderAccess;
  await h.instance.invoke("handshake_retry_readiness", { access: b, readiness: await h.readiness("responder") });
  await h.consent("initiator", a);
  await h.consent("responder", b);
  await h.instance.invoke("channel_open", { access: b });
  const bodies = ["Can we talk Tuesday?", "Tuesday works."];
  await h.instance.invoke("channel_send", { access: a, kind: "question", body: bodies[0] });
  await h.instance.invoke("channel_send", { access: b, kind: "proposal", body: bodies[1] });
  await h.instance.invoke("channel_close", { access: a });

  const mine = await h.instance.invoke("handshake_timeline", { access: a });
  const theirs = await h.instance.invoke("handshake_timeline", { access: b });
  assert.deepEqual(mine.events, theirs.events);
  assert.equal(mine.stage, "closed");
  assert.equal(mine.droppedEvents, 0);
  assert.deepEqual(mine.events.map((event) => event.type), [
    "invited", "previewed", "attempt", "attempt", "accepted", "consent", "consent", "open", "message", "message", "close",
  ]);
  for (const event of mine.events) assert.match(event.at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  const [, , attempt1, attempt2] = mine.events;
  assert.deepEqual([attempt1.attempt, attempt1.passed, attempt1.codes], [1, false, ["DATA_CLASS_MISMATCH"]]);
  assert.deepEqual([attempt2.attempt, attempt2.passed, attempt2.codes], [2, true, []]);
  assert.deepEqual(mine.events.filter((event) => event.type === "consent").map((event) => event.role), ["initiator", "responder"]);
  const open = mine.events.find((event) => event.type === "open");
  assert.deepEqual(open.anchors.map((anchor) => anchor.kind), ["terms-readiness", "consent", "open"]);
  for (const anchor of open.anchors) {
    assert.match(anchor.digest, /^[0-9a-f]{64}$/);
    assert.match(anchor.blockHeight, /^\d+$/);
    assert.equal(typeof anchor.ledgerId, "string");
  }
  const messages = mine.events.filter((event) => event.type === "message");
  assert.deepEqual(messages.map((event) => [event.seq, event.kind, event.fromRole]), [[1, "question", "initiator"], [2, "proposal", "responder"]]);
  for (const event of messages) assert.equal("body" in event, false);
  assert.equal(mine.events.at(-1).byRole, "initiator");
  assert.equal(mine.events.at(-1).anchor.kind, "closure");
  const serialized = JSON.stringify(mine);
  for (const body of bodies) assert.equal(serialized.includes(body), false);

  // The operator view sees the same session through the exported functions.
  const summary = listStandaloneSessions(h.instance).find((item) => item.sessionId === invite.sessionId);
  assert.equal(summary.stage, "closed");
  assert.equal(summary.attempts, 2);
  assert.equal(summary.eventCount, mine.events.length);
  assert.deepEqual(getStandaloneTimeline(h.instance, invite.sessionId).events, mine.events);
  assert.equal(getStandaloneTimeline(h.instance, "00000000-0000-4000-8000-000000000000"), undefined);
});

test("S4: the timeline is bounded and always keeps the terminal event", async () => {
  const h = harness({ nowMs: T0 });
  const { a, b } = await openedSession(h);
  for (let i = 0; i < MAX_TIMELINE_EVENTS; i += 1) await h.instance.invoke("channel_send", { access: i % 2 ? a : b, kind: "question", body: `m${i}` });
  h.setNow(T0 + 11 * 60_000); // past the default 10-minute reply window
  const timeline = await h.instance.invoke("handshake_timeline", { access: a });
  assert.equal(timeline.stage, "stalled");
  assert.equal(timeline.events.length, MAX_TIMELINE_EVENTS + 1);
  assert.ok(timeline.droppedEvents > 0);
  assert.equal(timeline.events.at(-1).type, "turn_timeout");
});
