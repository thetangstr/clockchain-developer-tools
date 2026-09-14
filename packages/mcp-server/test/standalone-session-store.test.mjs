import { test } from "node:test";
import assert from "node:assert/strict";

import { createStandaloneSessionStore, StandaloneAdmissionError, StandaloneIllegalTransitionError } from "../dist/standalone-handshake/session-store.js";
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
