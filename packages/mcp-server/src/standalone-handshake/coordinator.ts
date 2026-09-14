import { randomBytes, randomUUID } from "node:crypto";

import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";

import { canonicalBytes } from "../handshake/protocol.js";
import { recoverEip191Address, resolveOwnedAgentRegistration } from "../handshake/evm.js";

import { evaluateStandaloneReadiness } from "./checklist.js";
import {
  DIGEST,
  STANDALONE_HANDSHAKE_PROTOCOL,
  SIGNATURE,
  buildStandaloneConsentRecord,
  normalizeStandaloneClosure,
  normalizeStandaloneReadiness,
  normalizeStandaloneTerms,
  standaloneCanonicalRecord,
} from "./protocol.js";
import { createStandaloneSessionStore } from "./session-store.js";

export class StandaloneCoordinatorError extends Error {
  constructor(message = "Standalone handshake coordinator refused.") {
    super(message);
    this.name = "StandaloneCoordinatorError";
  }
}

export class StandaloneTransientCoordinatorError extends Error {
  constructor() {
    super("Standalone handshake coordinator is temporarily unavailable.");
    this.name = "StandaloneTransientCoordinatorError";
  }
}

const KIND_REFERENCES = { TERMS_READINESS: "terms-readiness", CONSENT: "consent", OPEN: "open" } as const;

async function anchorStandalone(client: any, record: Readonly<Record<string, any>>, reference: string, canWrite: boolean): Promise<any> {
  const digest = standaloneCanonicalRecord(record).digest;
  const found = await client.searchAsset(reference);
  const matches = (Array.isArray(found) ? found : []).filter((entry: any) => entry.assetReferenceId === reference && entry.assetHash === digest);
  if (matches.length > 1) throw new StandaloneCoordinatorError();
  let ledgerRecord = matches[0];
  if (!ledgerRecord && canWrite) {
    ledgerRecord = await client.log({ assetHash: digest, assetReferenceId: reference, additionalInfo: `standalone handshake v1 ${record.kind ?? record.schema}` });
  }
  if (!ledgerRecord) throw new StandaloneTransientCoordinatorError();
  const ledgerId = String(ledgerRecord.ledgerId ?? "");
  if (!/^[0-9a-f-]{36}$/.test(ledgerId)) throw new StandaloneCoordinatorError();
  const ledger = await client.getLedgerEntry(ledgerId);
  if (!ledger || ledger.ledgerId === undefined || ledger.assetHash === undefined) throw new StandaloneTransientCoordinatorError();
  const blockHeight = String(ledger.blockHeight ?? "");
  if (!/^(?:0|[1-9][0-9]*)$/.test(blockHeight) || ledger.assetHash !== digest) throw new StandaloneCoordinatorError();
  const chain = await client.getChainRecord(blockHeight, ledgerId);
  if (!chain || chain.assetHash !== digest || String(chain.blockHeight) !== blockHeight) throw new StandaloneCoordinatorError();
  const block = await client.getBlock(blockHeight);
  const blockTimeRaw = String(block.blockTime ?? block.madMarzulloTime ?? "");
  if (!blockTimeRaw) throw new StandaloneTransientCoordinatorError();
  return Object.freeze({ digest, blockHeight, blockTimeRaw, ledgerId });
}

export function createStandaloneCoordinator(options: {
  client?: any;
  now?: () => number;
  rpcUrl?: string;
  recoverEip191Address?: (input: { bytes: Buffer; signatureHex: string }) => Promise<string>;
  resolveIdentity?: (identity: Readonly<Record<string, any>> | null, sessionKeyAddress: string) => Promise<boolean>;
} = {}) {
  if (!options.client) throw new StandaloneCoordinatorError("A ledger client is required.");
  const client = options.client;
  const now = options.now ?? Date.now;
  const store = createStandaloneSessionStore({ now });
  const recover = options.recoverEip191Address;
  const resolveIdentity =
    options.resolveIdentity ??
    (async () => {
      throw new StandaloneCoordinatorError("Identity resolution is not configured.");
    });

  function authedSession(args: Record<string, unknown>): { session: any; role: string } {
    const access = args.access;
    if (typeof access !== "string" || !access.startsWith("sat_")) throw new StandaloneCoordinatorError();
    // Sessions are few in V1; linear scan keeps the store the single source of truth.
    for (const sessionId of storeSessionIds()) {
      const role = store.authenticate(sessionId, access);
      if (role !== undefined) return { session: store.requireSession(sessionId), role };
    }
    throw new StandaloneCoordinatorError();
  }

  let cachedIds: string[] = [];
  function storeSessionIds(): string[] {
    return cachedIds;
  }

  return {
    store,

    async invoke(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
      if (name === "handshake_invite") {
        const terms = normalizeStandaloneTerms({ reference: args.reference, purpose: args.purpose, channelLimits: args.channelLimits, identityPolicy: args.identityPolicy });
        const readiness = normalizeStandaloneReadiness(args.readiness, terms.identityPolicy.erc8004);
        const termsDigest = standaloneCanonicalRecord(terms).digest;
        const sessionId = randomUUID();
        store.createSession({ sessionId, terms, termsDigest, initiatorReadiness: readiness });
        const secret = randomBytes(24).toString("base64url");
        store.putInvitation({ secret, sessionId });
        const initiatorAccess = `sat_${randomBytes(32).toString("base64url")}`;
        store.setAccessToken(sessionId, "initiator", initiatorAccess);
        cachedIds.push(sessionId);
        const invitation = Buffer.from(JSON.stringify({ v: 1, sessionId, secret })).toString("base64url");
        return { sessionId, reference: terms.reference, invitation, initiatorAccess };
      }

      if (name === "handshake_accept_invitation") {
        const invitation = args.invitation;
        if (typeof invitation !== "string" || invitation.length < 80 || invitation.length > 4096) throw new StandaloneCoordinatorError();
        let decoded: any;
        try {
          decoded = JSON.parse(Buffer.from(invitation, "base64url").toString("utf8"));
        } catch {
          throw new StandaloneCoordinatorError();
        }
        if (decoded?.v !== 1 || typeof decoded.sessionId !== "string" || typeof decoded.secret !== "string") throw new StandaloneCoordinatorError();
        const sessionId = store.claimInvitation(decoded.secret);
        if (sessionId === undefined || sessionId !== decoded.sessionId) throw new StandaloneCoordinatorError();
        const session = store.requireSession(sessionId);
        if (session.stage !== "invited") throw new StandaloneCoordinatorError();
        const responderReadiness = normalizeStandaloneReadiness(args.readiness, session.terms.identityPolicy.erc8004);
        store.setResponderReadiness(sessionId, responderReadiness);
        store.setStage(sessionId, "readiness_pending");
        const checklist = await evaluateStandaloneReadiness({
          sessionId,
          terms: session.terms,
          termsDigest: session.termsDigest,
          initiator: session.initiatorReadiness,
          responder: responderReadiness,
          resolveIdentity: requiredIdentity(session) ? resolveIdentity : async () => true,
          recoverAddress: recover ?? (async () => {
            throw new StandaloneCoordinatorError("Signature recovery is not configured.");
          }),
        });
        store.setChecklist(sessionId, checklist);
        store.setStage(sessionId, checklist.passed ? "ready" : "ready_failed");
        const responderAccess = `sat_${randomBytes(32).toString("base64url")}`;
        store.setAccessToken(sessionId, "responder", responderAccess);
        return { sessionId, stage: checklist.passed ? "ready" : "ready_failed", checklist, responderAccess };
      }

      if (name === "handshake_status" || name === "channel_status") {
        const { session } = authedSession(args);
        const snapshot: any = store.status(session.sessionId);
        return { ...snapshot, protocol: STANDALONE_HANDSHAKE_PROTOCOL };
      }

      if (name === "consent_sign") {
        const { session, role } = authedSession(args);
        const signatureHex = args.signatureHex;
        if (typeof signatureHex !== "string" || !SIGNATURE.test(signatureHex)) throw new StandaloneCoordinatorError();
        if (session.stage !== "ready" && session.stage !== "consent_pending") throw new StandaloneCoordinatorError();
        const readiness = role === "initiator" ? session.initiatorReadiness : session.responderReadiness;
        const checklist = session.checklist;
        if (!checklist?.passed || typeof checklist.checklistDigest !== "string" || !DIGEST.test(checklist.checklistDigest)) throw new StandaloneCoordinatorError();
        const consentRecord = buildStandaloneConsentRecord({ sessionId: session.sessionId, role, termsDigest: session.termsDigest, checklistDigest: checklist.checklistDigest });
        let recovered = "";
        try {
          recovered = (await (recover ?? failMissing())({ bytes: canonicalBytes(consentRecord), signatureHex })).toLowerCase();
        } catch (error) {
          if ((error as Error)?.name === "StandaloneCoordinatorError") throw error;
          recovered = "";
        }
        if (recovered !== String(readiness.sessionKeyAddress).toLowerCase()) throw new StandaloneCoordinatorError();
        if (session.stage === "ready") store.setStage(session.sessionId, "consent_pending");
        store.setConsent(session.sessionId, role, standaloneCanonicalRecord(consentRecord).digest);
        const stage = store.bothConsented(session.sessionId) ? (store.setStage(session.sessionId, "consented"), "consented") : "consent_pending";
        return { sessionId: session.sessionId, role, stage, consentDigest: standaloneCanonicalRecord(consentRecord).digest };
      }

      if (name === "channel_open") {
        const { session, role } = authedSession(args);
        if (session.stage !== "consented" || !store.bothConsented(session.sessionId)) throw new StandaloneCoordinatorError();
        const openedAtMs = now();
        const expiresAtMs = openedAtMs + Number(session.terms.channelLimits.durationSeconds) * 1000;
        store.setStage(session.sessionId, "open");
        store.openChannel(session.sessionId, { openedAtMs, expiresAtMs });
        const base = {
          protocol: STANDALONE_HANDSHAKE_PROTOCOL,
          sessionId: session.sessionId,
          reference: session.terms.reference,
          termsDigest: session.termsDigest,
          checklistDigest: session.checklist.checklistDigest,
          initiator: { sessionKeyAddress: session.initiatorReadiness.sessionKeyAddress },
          responder: { sessionKeyAddress: session.responderReadiness.sessionKeyAddress },
          externalBusinessActionPerformed: false,
        };
        const transitions: Array<Record<string, any>> = [
          { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "TERMS_READINESS", sequence: "1", predecessor: null },
          { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "CONSENT", sequence: "2", predecessor: "" },
          { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "OPEN", sequence: "3", predecessor: "" },
        ];
        transitions[1].predecessor = standaloneCanonicalRecord(transitions[0]).digest;
        transitions[2].predecessor = standaloneCanonicalRecord(transitions[1]).digest;
        const anchors: any[] = [];
        // Transition ownership is initiator/responder/initiator, but this standalone coordinator is the single
        // mediator (both parties' tokens live in one store, and consent_sign anchors nothing), so it writes all
        // three transitions on the session's behalf; a missing counterpart record would otherwise deadlock open.
        for (let index = 0; index < transitions.length; index += 1) {
          const reference = `standalone-handshake-v1:${session.sessionId}:${KIND_REFERENCES[transitions[index].kind as keyof typeof KIND_REFERENCES]}`;
          const receipt = await anchorStandalone(client, transitions[index], reference, true);
          anchors.push({ kind: KIND_REFERENCES[transitions[index].kind as keyof typeof KIND_REFERENCES], ...receipt });
        }
        return {
          schema: "clockchain.standalone-handshake-opening/v1",
          protocol: STANDALONE_HANDSHAKE_PROTOCOL,
          sessionId: session.sessionId,
          reference: session.terms.reference,
          termsDigest: session.termsDigest,
          checklistDigest: session.checklist.checklistDigest,
          openedAtMs: String(openedAtMs),
          expiresAtMs: String(expiresAtMs),
          anchors: Object.freeze(anchors),
          externalBusinessActionPerformed: false,
        };
      }

      if (name === "channel_send") {
        const { session, role } = authedSession(args);
        const message = store.admitMessage(session.sessionId, role, String(args.kind ?? ""), typeof args.body === "string" ? args.body : "");
        const { body: _body, ...publicMessage } = message;
        return publicMessage;
      }

      if (name === "channel_read") {
        const { session, role } = authedSession(args);
        return { sessionId: session.sessionId, stage: store.getSession(session.sessionId).stage, messages: store.readMessages(session.sessionId, role) };
      }

      if (name === "channel_close" || name === "channel_revoke") {
        const { session, role } = authedSession(args);
        const outcome = name === "channel_close" ? "closed" : "revoked";
        (outcome === "closed" ? store.closeChannel : store.revokeChannel).call(store, session.sessionId, role);
        const closureRecord = normalizeStandaloneClosure({
          schema: "clockchain.standalone-handshake-closure/v1",
          protocol: STANDALONE_HANDSHAKE_PROTOCOL,
          sessionId: session.sessionId,
          outcome,
          byRole: role,
          closedAtMs: String(now()),
          externalBusinessActionPerformed: false,
        });
        const anchor = await anchorStandalone(client, closureRecord, `standalone-handshake-v1:${session.sessionId}:closure`, true);
        return { sessionId: session.sessionId, outcome, byRole: role, closureAnchor: anchor };
      }

      throw new StandaloneCoordinatorError(`Unknown tool ${name}.`);
    },
  };

  function requiredIdentity(session: any): boolean {
    return session.terms.identityPolicy.erc8004 !== "not_required";
  }

  function failMissing(): never {
    throw new StandaloneCoordinatorError("Signature recovery is not configured.");
  }
}

export function createRuntimeStandaloneCoordinator(env: Record<string, string | undefined> = process.env) {
  const rpcUrl = env.SEPOLIA_RPC_URL ?? "";
  const client = new ClockchainClient(readConfigFromEnv(env));
  return createStandaloneCoordinator({
    client,
    rpcUrl,
    recoverEip191Address: ({ bytes, signatureHex }) => recoverEip191Address({ bytes, signatureHex, rpcUrl }),
    resolveIdentity: async (identity, sessionKeyAddress) => {
      if (!identity) return false;
      const registration = await resolveOwnedAgentRegistration({
        rpcUrl,
        registryAddress: identity.registryAddress,
        address: sessionKeyAddress,
      });
      return registration !== null && registration.agentId === identity.agentId;
    },
  });
}
