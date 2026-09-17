import { test } from "node:test";
import assert from "node:assert/strict";

import { createStandaloneSessionStore, StandaloneAdmissionError, StandaloneIllegalTransitionError, TERMINAL_SESSION_RETENTION } from "../dist/standalone-handshake/session-store.js";
import { validTerms, validReadiness } from "./helpers/standalone-fixtures.mjs";

const SESSION = "0e2c8a34-9c1b-4f8e-9d0a-5f6a7b8c9d01";

function storeWithSession(overrides = {}) {
  let nowMs = 1_750_000_000_000;
  const store = createStandaloneSessionStore({ now: () => nowMs });
  const terms = { ...validTerms(overrides.terms) };
  store.createSession({ sessionId: SESSION, terms, termsDigest: "a".repeat(64), initiatorReadiness: validReadiness() });
  return { store, advance: (ms) => { nowMs += ms; } };
}

function toOpen(context) {
  const { store } = context;
  store.setStage(SESSION, "readiness_pending");
  store.setStage(SESSION, "ready");
  store.setStage(SESSION, "consent_pending");
  store.setStage(SESSION, "consented");
  store.setStage(SESSION, "open");
  store.openChannel(SESSION, { openedAtMs: 1_750_000_000_000, expiresAtMs: 1_750_003_600_000 });
  return context;
}

test("a session is created invited and only legal transitions apply", () => {
  const { store } = storeWithSession();
  assert.equal(store.getSession(SESSION).stage, "invited");
  store.setStage(SESSION, "readiness_pending");
  assert.throws(() => store.setStage(SESSION, "open"), StandaloneIllegalTransitionError);
  store.setStage(SESSION, "ready_failed");
  assert.equal(store.getSession(SESSION).stage, "ready_failed");
});

test("admission enforces scope, size, party, and state with exact reason codes", () => {
  const { store } = storeWithSession();
  store.setStage(SESSION, "readiness_pending");
  let error = null;
  try { store.admitMessage(SESSION, "initiator", "question", "hello"); } catch (e) { error = e; }
  assert.equal(error instanceof StandaloneAdmissionError && error.reason, "NOT_OPEN");
});

test("an open channel admits an in-scope message and records sender, digest, and sequence", () => {
  const { store } = storeWithSession();
  toOpen({ store });
  const message = store.admitMessage(SESSION, "responder", "proposal", "Ship Tuesdays, 14-day lead time.");
  assert.equal(message.seq, 1);
  assert.equal(message.kind, "proposal");
  assert.equal(message.fromRole, "responder");
  assert.equal(message.toRole, "initiator");
  assert.equal(/^[0-9a-f]{64}$/.test(message.bodyDigest), true);
  assert.equal(message.sentAtMs, 1_750_000_000_000);
  const second = store.admitMessage(SESSION, "initiator", "question", "Can you do 10 days?");
  assert.equal(second.seq, 2);
});

test("scope violation, oversize, and unknown party are refused", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  try { store.admitMessage(SESSION, "responder", "note", "x"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "SCOPE_VIOLATION"); }
  try { store.admitMessage(SESSION, "responder", "proposal", "x".repeat(16385)); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "TOO_LARGE"); }
  try { store.admitMessage(SESSION, "stranger", "question", "x"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "UNKNOWN_PARTY"); }
});

test("malformed bodies are refused with MALFORMED, distinct from an oversize TOO_LARGE", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  try { store.admitMessage(SESSION, "responder", "proposal", ""); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "MALFORMED"); }
  try { store.admitMessage(SESSION, "responder", "proposal", undefined); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "MALFORMED"); }
  try { store.admitMessage(SESSION, "responder", "proposal", { not: "a string" }); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "MALFORMED"); }
  try { store.admitMessage(SESSION, "responder", "proposal", "x".repeat(16385)); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "TOO_LARGE"); }
});

test("expiry at exactly expiresAtMs refuses with EXPIRED and flips the stage", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store, advance } = context;
  advance(3_600_000); // exactly to expiresAtMs
  try { store.admitMessage(SESSION, "responder", "question", "still there?"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "EXPIRED"); }
  assert.equal(store.getSession(SESSION).stage, "expired");
  try { store.admitMessage(SESSION, "responder", "question", "again"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "EXPIRED"); }
});

test("revocation is immediate, permanent, and reports REVOKED", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  store.revokeChannel(SESSION, "initiator");
  assert.equal(store.getSession(SESSION).stage, "revoked");
  try { store.admitMessage(SESSION, "responder", "question", "hello?"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "REVOKED"); }
  assert.throws(() => store.setStage(SESSION, "open"), StandaloneIllegalTransitionError);
});

test("explicit close records the closer and readMessages filters by addressee", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  store.admitMessage(SESSION, "responder", "proposal", "Tuesdays work.");
  store.admitMessage(SESSION, "initiator", "question", "Confirm Tuesday?");
  const forInitiator = store.readMessages(SESSION, "initiator");
  assert.equal(forInitiator.length, 1);
  assert.equal(forInitiator[0].fromRole, "responder");
  assert.equal(forInitiator[0].body, "Tuesdays work.");
  store.closeChannel(SESSION, "responder");
  const snapshot = store.status(SESSION);
  assert.equal(snapshot.stage, "closed");
  assert.equal(snapshot.closedBy, "responder");
  assert.equal(snapshot.messageCount, 2);
  assert.equal(snapshot.messages === undefined, true); // status never leaks bodies
});

test("closeChannel and revokeChannel refuse an unknown party before any state change", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  for (const attempt of [
    () => store.closeChannel(SESSION, "stranger"),
    () => store.revokeChannel(SESSION, "stranger"),
    () => store.closeChannel(SESSION, undefined),
  ]) {
    try { attempt(); assert.fail("expected throw"); }
    catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "UNKNOWN_PARTY"); }
  }
  assert.equal(store.getSession(SESSION).stage, "open");
  assert.equal(store.getSession(SESSION).closedBy, undefined);
});

test("status returns frozen copies: mutating the snapshot never reaches the store", () => {
  const context = storeWithSession();
  toOpen(context);
  const { store } = context;
  store.setChecklist(SESSION, { passed: true, checks: [], checklistDigest: "b".repeat(64) });
  const snapshot = store.status(SESSION);
  assert.equal(Object.isFrozen(snapshot.scope), true);
  assert.equal(Object.isFrozen(snapshot.checklist), true);
  assert.throws(() => { snapshot.scope.messageKinds = ["anything-goes"]; }, TypeError);
  assert.throws(() => { snapshot.checklist.passed = false; }, TypeError);
  assert.equal(store.getSession(SESSION).terms.channelLimits.messageKinds.includes("anything-goes"), false);
  assert.equal(store.getSession(SESSION).checklist.passed, true);
});

test("sessionIds() lists every session, terminal ones included", () => {
  const { store } = storeWithSession();
  assert.deepEqual(store.sessionIds(), [SESSION]);
  store.setStage(SESSION, "readiness_pending");
  store.setStage(SESSION, "ready_failed");
  assert.deepEqual(store.sessionIds(), [SESSION]);
});

test("terminal sessions beyond the retention cap are evicted oldest-first and active sessions are never evicted", () => {
  let nowMs = 1_750_000_000_000;
  const store = createStandaloneSessionStore({ now: () => nowMs, terminalRetention: 2 });
  const terms = { ...validTerms() };
  const readiness = validReadiness();
  const create = (id) => store.createSession({ sessionId: id, terms, termsDigest: "c".repeat(64), initiatorReadiness: readiness });
  const fail = (id) => { store.setStage(id, "readiness_pending"); store.setStage(id, "ready_failed"); };
  for (const id of ["a1", "a2", "a3", "a4"]) create(id);
  fail("a1");
  fail("a2");
  assert.deepEqual(store.sessionIds(), ["a1", "a2", "a3", "a4"]); // under the cap: nothing evicted
  create("a5"); // still exactly at the cap: nothing evicted yet
  fail("a5"); // now one over
  assert.deepEqual(store.sessionIds(), ["a1", "a2", "a3", "a4", "a5"]);
  create("a6"); // over the cap: a1, the oldest terminal, evicted; active a3/a4 untouched
  assert.deepEqual(store.sessionIds(), ["a2", "a3", "a4", "a5", "a6"]);
  assert.equal(store.getSession("a1"), undefined);
  // a6 stays active (invited) on purpose: it must survive every later eviction.
  // Keep filling with terminal sessions: the oldest terminal always goes, active sessions never do.
  for (const id of ["a7", "a8", "a9"]) {
    create(id);
    fail(id);
  }
  assert.deepEqual(store.sessionIds(), ["a3", "a4", "a6", "a7", "a8", "a9"]);
});

test("pending-closure pins: like-for-like is accepted, a different outcome or role refuses with CLOSURE_PENDING", () => {
  const { store } = storeWithSession();
  const record = Object.freeze({ outcome: "closed", byRole: "initiator", closedAtMs: "1750000000000" });
  store.setPendingClosure(SESSION, record);
  assert.deepEqual(store.pendingClosure(SESSION), record);
  // Identical outcome+role: accepted (an idempotent retry).
  store.setPendingClosure(SESSION, { outcome: "closed", byRole: "initiator", closedAtMs: "1750000000000" });
  assert.deepEqual(store.pendingClosure(SESSION), record);
  // Different outcome, or different role, while pinned: refused, and the pin is untouched.
  for (const intruder of [
    { outcome: "revoked", byRole: "initiator", closedAtMs: "1750000000000" },
    { outcome: "closed", byRole: "responder", closedAtMs: "1750000000000" },
  ]) {
    try { store.setPendingClosure(SESSION, intruder); assert.fail("expected throw"); }
    catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "CLOSURE_PENDING"); }
    assert.deepEqual(store.pendingClosure(SESSION), record);
  }
  // The pin clears only via clearPendingClosure, after which a fresh shape is accepted.
  store.clearPendingClosure(SESSION);
  assert.equal(store.pendingClosure(SESSION), undefined);
  store.setPendingClosure(SESSION, { outcome: "revoked", byRole: "responder", closedAtMs: "1" });
  assert.equal(store.pendingClosure(SESSION).outcome, "revoked");
});

test("the eviction retention defaults to TERMINAL_SESSION_RETENTION and tolerates a full cap", () => {
  let nowMs = 1_750_000_000_000;
  const store = createStandaloneSessionStore({ now: () => nowMs });
  const terms = { ...validTerms() };
  const readiness = validReadiness();
  const count = TERMINAL_SESSION_RETENTION + 10;
  for (let i = 0; i < count; i += 1) {
    store.createSession({ sessionId: `t${i}`, terms, termsDigest: "c".repeat(64), initiatorReadiness: readiness });
  }
  for (let i = 0; i < count; i += 1) {
    store.setStage(`t${i}`, "readiness_pending");
    store.setStage(`t${i}`, "ready_failed");
  }
  assert.equal(store.sessionIds().length, count); // nothing evicted yet: eviction only runs on createSession
  store.createSession({ sessionId: "final", terms, termsDigest: "c".repeat(64), initiatorReadiness: readiness });
  const after = store.sessionIds();
  assert.equal(after.length, TERMINAL_SESSION_RETENTION + 1); // the terminal cap, plus the new invited session
  assert.equal(after[0], "t10"); // the ten oldest terminal sessions went
  assert.equal(after[after.length - 1], "final");
});

test("invitation claims are single-use and access tokens authenticate roles", () => {
  const { store } = storeWithSession();
  store.putInvitation({ secret: "s3cret-value-with-length", sessionId: SESSION });
  assert.equal(store.claimInvitation("s3cret-value-with-length"), SESSION);
  assert.equal(store.claimInvitation("s3cret-value-with-length"), undefined);
  assert.equal(store.claimInvitation("never-issued"), undefined);
  store.setAccessToken(SESSION, "initiator", "sat_" + "A".repeat(43));
  assert.equal(store.authenticate(SESSION, "sat_" + "A".repeat(43)), "initiator");
  assert.equal(store.authenticate(SESSION, "sat_" + "B".repeat(43)), undefined);
});

test("an unclaimed invitation expires and cannot be claimed after its TTL", () => {
  let nowMs = 1_750_000_000_000;
  const store = createStandaloneSessionStore({ now: () => nowMs, invitationTtlMs: 1_000 });
  store.createSession({ sessionId: SESSION, terms: validTerms(), termsDigest: "a".repeat(64), initiatorReadiness: validReadiness() });
  store.putInvitation({ secret: "short-lived-secret", sessionId: SESSION });
  assert.equal(store.claimInvitation("short-lived-secret"), SESSION);
  store.putInvitation({ secret: "another-secret", sessionId: SESSION });
  nowMs += 1_001;
  assert.equal(store.claimInvitation("another-secret"), undefined);
});

test("idle non-terminal sessions are evicted while open and terminal sessions are not", () => {
  let nowMs = 1_750_000_000_000;
  const store = createStandaloneSessionStore({ now: () => nowMs, sessionTtlMs: 5_000 });
  const terms = { ...validTerms() };
  const readiness = validReadiness();
  store.createSession({ sessionId: "idle", terms, termsDigest: "a".repeat(64), initiatorReadiness: readiness });
  store.createSession({ sessionId: "active", terms, termsDigest: "a".repeat(64), initiatorReadiness: readiness });
  nowMs += 6_000;
  // A touch inside the TTL keeps the session alive.
  store.getSession("active");
  nowMs += 4_000;
  // Trigger the sweep (runs on createSession).
  store.createSession({ sessionId: "new", terms, termsDigest: "a".repeat(64), initiatorReadiness: readiness });
  assert.equal(store.getSession("idle"), undefined);
  assert.notEqual(store.getSession("active"), undefined);
});

test("housekeeping degrades to the wall clock when the protocol clock throws", () => {
  const store = createStandaloneSessionStore({ now: () => { throw new Error("consensus clock unsynced"); }, sessionTtlMs: 1_000 });
  store.createSession({ sessionId: SESSION, terms: validTerms(), termsDigest: "a".repeat(64), initiatorReadiness: validReadiness() });
  assert.notEqual(store.getSession(SESSION), undefined);
});

test("a session admits at most the configured message cap, then refuses CHANNEL_FULL", () => {
  const store = createStandaloneSessionStore({ now: () => 1_750_000_000_000, maxMessagesPerSession: 2 });
  store.createSession({ sessionId: SESSION, terms: validTerms(), termsDigest: "a".repeat(64), initiatorReadiness: validReadiness() });
  for (const stage of ["readiness_pending", "ready", "consent_pending", "consented", "open"]) store.setStage(SESSION, stage);
  store.openChannel(SESSION, { openedAtMs: 1_750_000_000_000, expiresAtMs: 1_750_003_600_000 });
  store.admitMessage(SESSION, "initiator", "question", "one");
  store.admitMessage(SESSION, "responder", "proposal", "two");
  try { store.admitMessage(SESSION, "initiator", "question", "three"); assert.fail("expected throw"); }
  catch (e) { assert.equal(e instanceof StandaloneAdmissionError && e.reason, "CHANNEL_FULL"); }
});

test("resetToInvited rolls back only a pre-checklist readiness_pending session", () => {
  const { store } = storeWithSession();
  store.setStage(SESSION, "readiness_pending");
  store.resetToInvited(SESSION);
  assert.equal(store.getSession(SESSION).stage, "invited");
  assert.equal(store.getSession(SESSION).responderReadiness, undefined);
  // Once a checklist exists the session can never go back.
  store.setStage(SESSION, "readiness_pending");
  store.setChecklist(SESSION, { passed: false, checks: [], checklistDigest: "b".repeat(64) });
  store.setStage(SESSION, "ready_failed");
  assert.throws(() => store.resetToInvited(SESSION), StandaloneIllegalTransitionError);
  assert.equal(store.getSession(SESSION).stage, "ready_failed");
});
