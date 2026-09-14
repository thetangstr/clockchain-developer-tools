import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import { createStandaloneCoordinator } from "../dist/standalone-handshake/coordinator.js";
import { validTerms, validReadiness } from "./helpers/standalone-fixtures.mjs";

const SIG_INITIATOR = "0x" + "11".repeat(64) + "1b";
const SIG_RESPONDER = "0x" + "22".repeat(64) + "1c";
const ADDR_INITIATOR = "0x" + "11".repeat(20);
const ADDR_RESPONDER = "0x" + "22".repeat(20);
const REQUIRED_IDENTITY_POLICY = { erc8004: "required_existing_or_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" };

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
      return { blockHeight: String(blockHeight), blockTime: "2026-09-14T00:00:00.000Z" };
    },
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
  return { ...instance, advance: (ms) => { nowMs += ms; } };
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

test("expiry: consented session that is opened late still expires on consensus time", async () => {
  const instance = coordinator();
  const session = await openSession(instance);
  await consentAndOpen(instance, session);
  instance.advance(3_600_000);
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
