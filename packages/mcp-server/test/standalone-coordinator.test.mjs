import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { normalizeStandaloneClosure, standaloneCanonicalRecord } from "../dist/standalone-handshake/protocol.js";
import { StandaloneAdmissionError } from "../dist/standalone-handshake/session-store.js";
import { validTerms, validReadiness } from "./helpers/standalone-fixtures.mjs";

const SIG_INITIATOR = "0x" + "11".repeat(64) + "1b";
const SIG_RESPONDER = "0x" + "22".repeat(64) + "1c";
const ADDR_INITIATOR = "0x" + "11".repeat(20);
const ADDR_RESPONDER = "0x" + "22".repeat(20);
const REQUIRED_IDENTITY_POLICY = { erc8004: "required_existing_or_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" };
const FAKE_BLOCK_TIME = "2026-09-14T00:00:00.000Z";

class TransientLedgerError extends Error {
  constructor() {
    super("transient ledger failure");
    this.name = "TransientLedgerError";
  }
}

function fakeLedger() {
  const entries = new Map();
  let height = 100;
  return {
    blocks: entries,
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
      return { blockHeight: String(blockHeight), blockTime: FAKE_BLOCK_TIME };
    },
  };
}

// Fault-injection wrapper: fails the Nth client.log call outright, or every closure log, until repaired.
function flakyLedger() {
  const inner = fakeLedger();
  let calls = 0;
  let failOnLogCall = -1;
  let failClosureLogs = false;
  return {
    blocks: inner.blocks,
    failOnNthLog(n) { failOnLogCall = n; },
    failClosureLogs() { failClosureLogs = true; },
    repair() { failOnLogCall = -1; failClosureLogs = false; },
    async searchAsset(reference) { return inner.searchAsset(reference); },
    async log(args) {
      calls += 1;
      if (calls === failOnLogCall) throw new TransientLedgerError();
      if (failClosureLogs && String(args.assetReferenceId).endsWith(":closure")) throw new TransientLedgerError();
      return inner.log(args);
    },
    async getLedgerEntry(ledgerId) { return inner.getLedgerEntry(ledgerId); },
    async getChainRecord(blockHeight, ledgerId) { return inner.getChainRecord(blockHeight, ledgerId); },
    async getBlock(blockHeight) { return inner.getBlock(blockHeight); },
  };
}

function coordinator(ledger = fakeLedger(), overrides = {}) {
  let nowMs = 1_750_000_000_000;
  const instance = createStandaloneCoordinator({
    client: ledger,
    now: () => nowMs,
    recoverEip191Address: async ({ signatureHex }) =>
      signatureHex === SIG_INITIATOR ? ADDR_INITIATOR : signatureHex === SIG_RESPONDER ? ADDR_RESPONDER : "0x" + "99".repeat(20),
    resolveIdentity: overrides.resolveIdentity ?? (async () => true),
    ...overrides.coordinator,
  });
  return { ...instance, advance: (ms) => { nowMs += ms; }, peek: () => nowMs };
}

async function openSession(instance, termsOverrides = {}, readinessOverrides = {}) {
  const invite = await instance.invoke("handshake_invite", {
    ...validTerms(termsOverrides),
    readiness: validReadiness({ sessionKeyAddress: ADDR_INITIATOR, authoritySignatureHex: SIG_INITIATOR, ...(readinessOverrides.initiator ?? {}) }),
  });
  assert.equal(invite.stage, undefined);
  const accept = await instance.invoke("handshake_accept_invitation", {
    invitation: invite.invitation,
    readiness: validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER, ...(readinessOverrides.responder ?? {}) }),
  });
  return { invite, accept };
}

async function consentAndOpen(instance, session) {
  const statusI = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(statusI.stage, "ready");
  const consent1 = await instance.invoke("consent_sign", { access: session.invite.initiatorAccess, signatureHex: SIG_INITIATOR });
  assert.equal(consent1.stage, "consent_pending");
  const consent2 = await instance.invoke("consent_sign", { access: session.accept.responderAccess, signatureHex: SIG_RESPONDER });
  assert.equal(consent2.stage, "consented");
  const receipt = await instance.invoke("channel_open", { access: session.invite.initiatorAccess });
  assert.equal(receipt.anchors.length, 3);
  assert.deepEqual(receipt.anchors.map((a) => a.kind), ["terms-readiness", "consent", "open"]);
  assert.equal(receipt.externalBusinessActionPerformed, false);
  return receipt;
}

test("invite → accept passes the checklist and issues both role accesses", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  assert.equal(session.invite.invitation.length >= 80, true);
  assert.equal(typeof session.invite.initiatorAccess, "string");
  assert.equal(session.accept.stage, "ready");
  assert.equal(session.accept.checklist.passed, true);
  assert.equal(typeof session.accept.responderAccess, "string");
});

test("a failed checklist lands in ready_failed with reason codes, never open", async () => {
  const instance = coordinator(fakeLedger(), { resolveIdentity: async () => false });
  const session = await openSession(
    instance,
    { identityPolicy: REQUIRED_IDENTITY_POLICY },
    {
      initiator: { identity: { agentId: "1", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } },
      responder: { identity: { agentId: "2", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" } },
    },
  );
  assert.equal(session.accept.stage, "ready_failed");
  assert.equal(session.accept.checklist.passed, false);
  await assert.rejects(() => instance.invoke("channel_open", { access: session.invite.initiatorAccess }), StandaloneCoordinatorErrorNamed());
});

function StandaloneCoordinatorErrorNamed() {
  return (error) => error?.name === "StandaloneCoordinatorError";
}

test("consent requires a signature that recovers to the party's own session key", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await instance.invoke("consent_sign", { access: session.invite.initiatorAccess, signatureHex: SIG_INITIATOR });
  await assert.rejects(
    () => instance.invoke("consent_sign", { access: session.accept.responderAccess, signatureHex: SIG_INITIATOR }),
    (error) => error?.name === "StandaloneCoordinatorError",
  );
});

test("opening anchors three chained transitions and the receipt is internally consistent", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  const receipt = await consentAndOpen(instance, session);
  assert.equal(/^[0-9a-f]{64}$/.test(receipt.termsDigest), true);
  assert.equal(receipt.checklistDigest, session.accept.checklist.checklistDigest);
  for (const anchor of receipt.anchors) {
    assert.equal(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(anchor.ledgerId), true);
    assert.equal(typeof anchor.blockHeight, "string");
  }
});

test("channel_open anchors before mutating: a transient anchor failure leaves the session consented and retryable", async () => {
  const ledger = flakyLedger();
  const instance = coordinator(ledger);
  const session = await openSession(instance);
  await instance.invoke("consent_sign", { access: session.invite.initiatorAccess, signatureHex: SIG_INITIATOR });
  await instance.invoke("consent_sign", { access: session.accept.responderAccess, signatureHex: SIG_RESPONDER });
  ledger.failOnNthLog(2); // the CONSENT transition's log call
  await assert.rejects(
    () => instance.invoke("channel_open", { access: session.invite.initiatorAccess }),
    (error) => error instanceof Error && error.name === "TransientLedgerError",
  );
  let status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "consented");
  ledger.repair();
  const receipt = await instance.invoke("channel_open", { access: session.invite.initiatorAccess });
  assert.equal(receipt.anchors.length, 3);
  assert.deepEqual(receipt.anchors.map((a) => a.kind), ["terms-readiness", "consent", "open"]);
  status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "open");
  // The session clock starts at the ledger's consensus block time, not the server clock.
  assert.equal(receipt.openedAtMs, String(Date.parse(FAKE_BLOCK_TIME)));
  assert.equal(receipt.expiresAtMs, String(Date.parse(FAKE_BLOCK_TIME) + 3_600_000));
  // The retry reused the already-anchored first transition instead of duplicating it.
  const seeded = await ledger.searchAsset(`standalone-handshake-v1:${session.invite.sessionId}:terms-readiness`);
  assert.equal(seeded.length, 1);
});

test("the anchored CONSENT and OPEN transition records carry both parties' consent digests", async () => {
  const ledger = fakeLedger();
  const instance = coordinator(ledger);
  const session = await openSession(instance);
  const consentInitiator = await instance.invoke("consent_sign", { access: session.invite.initiatorAccess, signatureHex: SIG_INITIATOR });
  const consentResponder = await instance.invoke("consent_sign", { access: session.accept.responderAccess, signatureHex: SIG_RESPONDER });
  const receipt = await instance.invoke("channel_open", { access: session.invite.initiatorAccess });
  const base = {
    protocol: "clockchain.standalone-handshake/v1",
    sessionId: session.invite.sessionId,
    reference: session.invite.reference,
    termsDigest: receipt.termsDigest,
    checklistDigest: receipt.checklistDigest,
    initiator: { sessionKeyAddress: ADDR_INITIATOR },
    responder: { sessionKeyAddress: ADDR_RESPONDER },
    externalBusinessActionPerformed: false,
  };
  const consentDigests = { initiator: consentInitiator.consentDigest, responder: consentResponder.consentDigest };
  const termsReadiness = { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "TERMS_READINESS", sequence: "1", predecessor: null };
  const consent = { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "CONSENT", sequence: "2", predecessor: standaloneCanonicalRecord(termsReadiness).digest, consentDigests };
  const open = { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "OPEN", sequence: "3", predecessor: standaloneCanonicalRecord(consent).digest, consentDigests };
  assert.equal(receipt.anchors[0].digest, standaloneCanonicalRecord(termsReadiness).digest);
  assert.equal(receipt.anchors[1].digest, standaloneCanonicalRecord(consent).digest);
  assert.equal(receipt.anchors[2].digest, standaloneCanonicalRecord(open).digest);
  // The ledger record under the consent reference is exactly that transition record.
  const anchoredConsent = await ledger.searchAsset(`standalone-handshake-v1:${session.invite.sessionId}:consent`);
  assert.equal(anchoredConsent.length, 1);
  assert.equal(anchoredConsent[0].assetHash, standaloneCanonicalRecord(consent).digest);
});

test("anchoring fails hard when the reference already holds a different digest, and never appends", async () => {
  const ledger = fakeLedger();
  let logs = 0;
  const counting = { ...ledger, log: async (args) => { logs += 1; return ledger.log(args); } };
  const instance = coordinator(counting);
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  assert.equal(logs, 3);
  await ledger.log({ assetHash: "e".repeat(64), assetReferenceId: `standalone-handshake-v1:${session.invite.sessionId}:closure` });
  await assert.rejects(
    () => instance.invoke("channel_close", { access: session.invite.initiatorAccess }),
    (error) => error instanceof Error && error.name === "StandaloneCoordinatorError",
  );
  assert.equal(logs, 3); // the guard fired before any append
  const status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "open");
});

test("closure anchors before mutating: a transient failure leaves the channel open and the retry re-anchors the pinned digest", async () => {
  const ledger = flakyLedger();
  ledger.failClosureLogs();
  const instance = coordinator(ledger);
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  await assert.rejects(
    () => instance.invoke("channel_close", { access: session.invite.initiatorAccess }),
    (error) => error instanceof Error && error.name === "TransientLedgerError",
  );
  let status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "open");
  // Pin-survival semantics: the failed anchor leaves the pin in place for the retry.
  const pinnedAfterFailure = instance.store.pendingClosure(session.invite.sessionId);
  assert.equal(pinnedAfterFailure?.outcome, "closed");
  assert.equal(pinnedAfterFailure?.byRole, "initiator");
  ledger.repair();
  instance.advance(5_000); // a re-dated closure record would digest differently
  const closed = await instance.invoke("channel_close", { access: session.invite.initiatorAccess });
  assert.equal(closed.outcome, "closed");
  const reference = `standalone-handshake-v1:${session.invite.sessionId}:closure`;
  const records = await ledger.searchAsset(reference);
  assert.equal(records.length, 1);
  const pinnedDigest = standaloneCanonicalRecord(normalizeStandaloneClosure({
    schema: "clockchain.standalone-handshake-closure/v1",
    protocol: "clockchain.standalone-handshake/v1",
    sessionId: session.invite.sessionId,
    outcome: "closed",
    byRole: "initiator",
    closedAtMs: String(1_750_000_000_000), // the pinned record keeps the pre-failure date
    externalBusinessActionPerformed: false,
  })).digest;
  assert.equal(records[0].assetHash, pinnedDigest);
  assert.equal(closed.closureAnchor.digest, pinnedDigest);
  status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "closed");
  // The pin clears only after the store mutation succeeds, as the last coordinator step.
  assert.equal(instance.store.pendingClosure(session.invite.sessionId), undefined);
});

test("an expired channel refuses closure with EXPIRED before any ledger write", async () => {
  let closureLogs = 0;
  const ledger = fakeLedger();
  const counting = { ...ledger, log: async (args) => { if (String(args.assetReferenceId).endsWith(":closure")) closureLogs += 1; return ledger.log(args); } };
  const instance = coordinator(counting);
  const session = await openSession(instance);
  const receipt = await consentAndOpen(instance, session);
  instance.advance(Number(receipt.expiresAtMs) + 1 - instance.peek()); // past the channel clock
  for (const name of ["channel_close", "channel_revoke"]) {
    let error = null;
    try { await instance.invoke(name, { access: session.invite.initiatorAccess }); } catch (e) { error = e; }
    assert.equal(error instanceof StandaloneAdmissionError && error.reason, "EXPIRED");
  }
  assert.equal(closureLogs, 0);
  const reference = `standalone-handshake-v1:${session.invite.sessionId}:closure`;
  assert.equal((await ledger.searchAsset(reference)).length, 0);
  const status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "expired");
});

test("a different outcome while a closure pin exists refuses with CLOSURE_PENDING and the ledger is untouched", async () => {
  const ledger = flakyLedger();
  ledger.failClosureLogs();
  const instance = coordinator(ledger);
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  const reference = `standalone-handshake-v1:${session.invite.sessionId}:closure`;
  await assert.rejects(
    () => instance.invoke("channel_close", { access: session.invite.initiatorAccess }),
    (error) => error instanceof Error && error.name === "TransientLedgerError",
  );
  assert.equal((await ledger.searchAsset(reference)).length, 0);
  // The responder's revoke is a different outcome than the pinned close: refused before anchoring.
  let error = null;
  try { await instance.invoke("channel_revoke", { access: session.accept.responderAccess }); } catch (e) { error = e; }
  assert.equal(error instanceof StandaloneAdmissionError && error.reason, "CLOSURE_PENDING");
  assert.equal((await ledger.searchAsset(reference)).length, 0);
  // The like-for-like retry still lands the identical pinned record once the ledger heals.
  ledger.repair();
  const closed = await instance.invoke("channel_close", { access: session.invite.initiatorAccess });
  assert.equal(closed.outcome, "closed");
  assert.equal((await ledger.searchAsset(reference)).length, 1);
});

test("the closure pin persists across a failed anchor and only clearPendingClosure removes it", async () => {
  const ledger = flakyLedger();
  ledger.failClosureLogs();
  const instance = coordinator(ledger);
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  const sessionId = session.invite.sessionId;
  await assert.rejects(
    () => instance.invoke("channel_close", { access: session.invite.initiatorAccess }),
    (error) => error instanceof Error && error.name === "TransientLedgerError",
  );
  const pinned = instance.store.pendingClosure(sessionId);
  assert.equal(pinned?.outcome, "closed");
  assert.equal(pinned?.byRole, "initiator");
  assert.equal(pinned?.closedAtMs, String(1_750_000_000_000)); // dated at prepare time, not re-dated
  instance.store.clearPendingClosure(sessionId);
  assert.equal(instance.store.pendingClosure(sessionId), undefined);
});

test("channel flows end to end: send, read, close — with an anchored closure", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  const sent = await instance.invoke("channel_send", { access: session.accept.responderAccess, kind: "proposal", body: "Tuesdays, 14-day lead." });
  assert.equal(sent.seq, 1);
  const read = await instance.invoke("channel_read", { access: session.invite.initiatorAccess });
  assert.equal(read.messages.length, 1);
  assert.equal(read.messages[0].body, "Tuesdays, 14-day lead.");
  const closed = await instance.invoke("channel_close", { access: session.invite.initiatorAccess });
  assert.equal(closed.outcome, "closed");
  assert.equal(closed.byRole, "initiator");
  assert.equal(typeof closed.closureAnchor.ledgerId, "string");
  await assert.rejects(
    () => instance.invoke("channel_send", { access: session.accept.responderAccess, kind: "question", body: "anyone?" }),
    (error) => error?.name === "StandaloneAdmissionError",
  );
});

test("revocation mid-conversation stops admission and anchors the revocation", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  await instance.invoke("channel_send", { access: session.accept.responderAccess, kind: "question", body: "ready to talk?" });
  const revoked = await instance.invoke("channel_revoke", { access: session.accept.responderAccess });
  assert.equal(revoked.outcome, "revoked");
  await assert.rejects(
    () => instance.invoke("channel_send", { access: session.invite.initiatorAccess, kind: "question", body: "hello?" }),
    (error) => error instanceof Error && error.name === "StandaloneAdmissionError",
  );
});

test("expiry: the channel clock starts at the open anchor's consensus block time", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  const receipt = await consentAndOpen(instance, session);
  assert.equal(receipt.openedAtMs, String(Date.parse(FAKE_BLOCK_TIME)));
  assert.equal(receipt.expiresAtMs, String(Date.parse(FAKE_BLOCK_TIME) + 3_600_000));
  instance.advance(Number(receipt.expiresAtMs) + 1 - instance.peek());
  await assert.rejects(
    () => instance.invoke("channel_send", { access: session.invite.initiatorAccess, kind: "question", body: "still open?" }),
    (error) => error instanceof Error && error.name === "StandaloneAdmissionError",
  );
  const status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "expired");
});

test("status is role-gated: a bad access token is refused", async () => {
  const instance = coordinator();
  await assert.rejects(() => instance.invoke("handshake_status", { access: "sat_" + "Z".repeat(43) }), (error) => error?.name === "StandaloneCoordinatorError");
});

test("a transient identity-resolution failure restores the invitation and the retry succeeds", async () => {
  let failIdentity = true;
  const instance = coordinator(fakeLedger(), {
    resolveIdentity: async () => {
      if (failIdentity) throw new Error("sepolia rpc down");
      return true;
    },
  });
  const terms = { ...validTerms(), identityPolicy: REQUIRED_IDENTITY_POLICY };
  const readiness = (addr, sig, agentId) => validReadiness({
    sessionKeyAddress: addr,
    authoritySignatureHex: sig,
    identity: { agentId, chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
  });
  const invite = await instance.invoke("handshake_invite", { ...terms, readiness: readiness(ADDR_INITIATOR, SIG_INITIATOR, "1") });
  // First accept: the identity RPC dies mid-checklist. The caller sees a retryable
  // transient error, not a permanently bricked session.
  await assert.rejects(
    () => instance.invoke("handshake_accept_invitation", { invitation: invite.invitation, readiness: readiness(ADDR_RESPONDER, SIG_RESPONDER, "2") }),
    (error) => error?.name === "StandaloneTransientCoordinatorError",
  );
  assert.equal(instance.store.getSession(invite.sessionId).stage, "invited");
  // The same invitation is claimable again and the full flow completes.
  failIdentity = false;
  const accept = await instance.invoke("handshake_accept_invitation", { invitation: invite.invitation, readiness: readiness(ADDR_RESPONDER, SIG_RESPONDER, "2") });
  assert.equal(accept.stage, "ready");
  assert.equal(accept.checklist.passed, true);
});

test("a tampered or foreign invitation is refused", async () => {
  const instance = coordinator();
  const invite = (sid) => instance.invoke("handshake_invite", {
    ...validTerms(),
    readiness: validReadiness({ sessionKeyAddress: ADDR_INITIATOR, authoritySignatureHex: SIG_INITIATOR }),
  });
  const a = await invite();
  const b = await invite();
  const decoded = JSON.parse(Buffer.from(a.invitation, "base64url").toString("utf8"));
  // Genuine unclaimed secret for session A, but the embedded sessionId points at B.
  const tampered = Buffer.from(JSON.stringify({ ...decoded, sessionId: b.sessionId })).toString("base64url");
  await assert.rejects(
    () => instance.invoke("handshake_accept_invitation", { invitation: tampered, readiness: validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER }) }),
    StandaloneCoordinatorErrorNamed(),
  );
  // A well-formed envelope with a fabricated secret is refused the same way.
  const forged = Buffer.from(JSON.stringify({ v: 1, sessionId: b.sessionId, secret: "not-a-real-secret" })).toString("base64url");
  await assert.rejects(
    () => instance.invoke("handshake_accept_invitation", { invitation: forged, readiness: validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER }) }),
    StandaloneCoordinatorErrorNamed(),
  );
  // The untampered invitation still claims cleanly.
  const accept = await instance.invoke("handshake_accept_invitation", { invitation: a.invitation, readiness: validReadiness({ sessionKeyAddress: ADDR_RESPONDER, authoritySignatureHex: SIG_RESPONDER }) });
  assert.equal(accept.sessionId, a.sessionId);
});

test("an access token only ever authenticates its own session and role", async () => {
  const instance = coordinator();
  const a = await openSession(instance);
  const b = await openSession(instance);
  const status = await instance.invoke("handshake_status", { access: a.invite.initiatorAccess });
  assert.equal(status.sessionId, a.invite.sessionId);
  assert.notEqual(status.sessionId, b.invite.sessionId);
  // The token derives the session — A's initiator token can never act on B.
  const statusB = await instance.invoke("handshake_status", { access: b.accept.responderAccess });
  assert.equal(statusB.sessionId, b.invite.sessionId);
});

test("an unparseable open-anchor block time fails transiently and the retry succeeds", async () => {
  const ledger = fakeLedger();
  let blockTime = "not-a-timestamp";
  const timed = { ...ledger, getBlock: async (h) => ({ blockHeight: String(h), blockTime }) };
  const instance = coordinator(timed);
  const session = await openSession(instance);
  await instance.invoke("consent_sign", { access: session.invite.initiatorAccess, signatureHex: SIG_INITIATOR });
  await instance.invoke("consent_sign", { access: session.accept.responderAccess, signatureHex: SIG_RESPONDER });
  await assert.rejects(
    () => instance.invoke("channel_open", { access: session.invite.initiatorAccess }),
    (error) => error?.name === "StandaloneTransientCoordinatorError",
  );
  // The session is still consented — the anchors were written but the channel never opened.
  const status = await instance.invoke("handshake_status", { access: session.invite.initiatorAccess });
  assert.equal(status.stage, "consented");
  blockTime = FAKE_BLOCK_TIME;
  const receipt = await instance.invoke("channel_open", { access: session.invite.initiatorAccess });
  assert.equal(receipt.openedAtMs, String(Date.parse(FAKE_BLOCK_TIME)));
  assert.equal(receipt.anchors.length, 3);
});
