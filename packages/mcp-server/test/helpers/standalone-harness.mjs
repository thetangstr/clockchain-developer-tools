// A coordinator plus two viem-keyed parties, driven through coordinator.invoke the way
// the public tools are, with every signed byte re-derived locally before signing.
import assert from "node:assert/strict";

import { getAddress } from "viem";

import { createStandaloneCoordinator } from "../../dist/standalone-handshake/coordinator.js";
import { validTerms } from "./standalone-fixtures.mjs";
import { fakeLedger, newSessionKey, recoverLocally, verifyAndSign } from "./standalone-signer.mjs";

export const PARTY = "Acme Buying LLC";
export const STATEMENT = "I am authorized to discuss delivery options for Acme.";

export function harness(options = {}) {
  let nowMs = options.nowMs ?? 1_750_000_000_000;
  const ledger = fakeLedger();
  const instance = createStandaloneCoordinator({
    client: ledger,
    now: () => nowMs,
    recoverEip191Address: recoverLocally,
    resolveIdentity: async () => true,
    nextPollMs: 5,
    ...options.coordinator,
  });
  const keys = { initiator: newSessionKey(), responder: newSessionKey() };
  async function readiness(role, overrides = {}) {
    const account = keys[role];
    const prepared = await instance.invoke("readiness_prepare", { sessionKeyAddress: getAddress(account.address), accountableParty: PARTY, statement: STATEMENT });
    return {
      sessionKeyAddress: getAddress(account.address),
      identity: null,
      authorityStatement: { accountableParty: PARTY, statement: STATEMENT },
      authoritySignatureHex: await verifyAndSign(account, prepared),
      capabilityManifest: { dataHandlingClass: "confidential", purpose: validTerms().purpose },
      ...overrides,
    };
  }
  const next = (access, extra = {}) => instance.invoke("handshake_next", { access, waitMs: 0, ...extra });
  return {
    instance,
    ledger,
    keys,
    next,
    readiness,
    setNow(value) { nowMs = value; },
    async invite() {
      return instance.invoke("handshake_invite", { ...validTerms(), readiness: await readiness("initiator") });
    },
    async accept(invitation, overrides) {
      return instance.invoke("handshake_accept_invitation", { invitation, readiness: await readiness("responder", overrides) });
    },
    async consent(role, access) {
      const step = await next(access);
      assert.equal(step.action, "sign");
      return instance.invoke("consent_sign", { access, signatureHex: await verifyAndSign(keys[role], step.sign) });
    },
  };
}

export async function openedSession(h) {
  const invite = await h.invite();
  const accept = await h.accept(invite.invitation);
  await h.consent("initiator", invite.initiatorAccess);
  await h.consent("responder", accept.responderAccess);
  await h.instance.invoke("channel_open", { access: invite.initiatorAccess });
  return { a: invite.initiatorAccess, b: accept.responderAccess };
}

