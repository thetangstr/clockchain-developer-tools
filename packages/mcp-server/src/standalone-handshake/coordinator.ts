import { randomBytes, randomUUID } from "node:crypto";

import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";
import { ClockchainClock } from "@clockchain/clock-sdk";

import { canonicalBytes } from "../handshake/protocol.js";
import { recoverEip191Address, resolveOwnedAgentRegistration } from "../handshake/evm.js";

import { evaluateStandaloneReadiness } from "./checklist.js";
import { createHoldRegistry, standaloneRequestContext } from "./long-poll.js";
import {
  BUSY_RETRY_AFTER_MS,
  DEFAULT_NEXT_WAIT_MS,
  MAX_NEXT_WAIT_MS,
  MAX_NEXT_WAIT_POLLS,
  NEXT_WAIT_POLL_MS,
  UNTRUSTED_TERMS_FIELDS,
  UNTRUSTED_TERMS_NOTE,
  evaluateStandaloneNext,
  lastFailureCodes,
  promptKey,
} from "./next.js";
import {
  DIGEST,
  STANDALONE_HANDSHAKE_PROTOCOL,
  SIGNATURE,
  buildStandaloneConsentRecord,
  normalizeStandaloneClosure,
  normalizeStandaloneReadiness,
  normalizeStandaloneTerms,
  prepareStandaloneAuthority,
  standaloneCanonicalRecord,
} from "./protocol.js";
import { READINESS_MAX_ATTEMPTS, createStandaloneSessionStore, StandaloneAdmissionError } from "./session-store.js";

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

function boundedNextWaitMs(value: unknown): number {
  if (value === undefined || value === null) return DEFAULT_NEXT_WAIT_MS;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new StandaloneCoordinatorError();
  return Math.min(value, MAX_NEXT_WAIT_MS);
}

function nextCursor(value: unknown): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new StandaloneCoordinatorError();
  return value;
}

// Tools whose success changes a session: holds on that session re-evaluate at once.
const SESSION_MUTATING_TOOLS = new Set(["handshake_accept_invitation", "handshake_retry_readiness", "consent_sign", "channel_open", "channel_send", "channel_close", "channel_revoke"]);

// One uniform refusal for every way an invitation can be unusable (malformed, unknown,
// expired, already claimed), so preview cannot be used to enumerate sessions.
function invitationUnavailable(): never {
  throw new StandaloneAdmissionError("INVITATION_UNAVAILABLE");
}

function decodeInvitation(invitation: unknown): { sessionId: string; secret: string } | undefined {
  if (typeof invitation !== "string" || invitation.length < 80 || invitation.length > 4096) return undefined;
  try {
    const decoded = JSON.parse(Buffer.from(invitation, "base64url").toString("utf8"));
    if (decoded?.v !== 1 || typeof decoded.sessionId !== "string" || typeof decoded.secret !== "string") return undefined;
    return { sessionId: decoded.sessionId, secret: decoded.secret };
  } catch {
    return undefined;
  }
}

function anchorSummary(anchor: Record<string, any>): Record<string, unknown> {
  return { kind: anchor.kind, blockHeight: anchor.blockHeight, digest: anchor.digest, ledgerId: anchor.ledgerId };
}

const KIND_REFERENCES = { TERMS_READINESS: "terms-readiness", CONSENT: "consent", OPEN: "open" } as const;

async function anchorStandalone(client: any, record: Readonly<Record<string, any>>, reference: string, canWrite: boolean): Promise<any> {
  const digest = standaloneCanonicalRecord(record).digest;
  const found = await client.searchAsset(reference);
  const underReference = (Array.isArray(found) ? found : []).filter((entry: any) => entry.assetReferenceId === reference);
  // Fail hard on a conflicting anchor: the reference already exists with a different digest.
  if (underReference.some((entry: any) => entry.assetHash !== digest)) throw new StandaloneCoordinatorError();
  const matches = underReference.filter((entry: any) => entry.assetHash === digest);
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
  /** handshake_next long-poll slice; defaults to NEXT_WAIT_POLL_MS. */
  nextPollMs?: number;
  /**
   * Monotonic clock that bounds a handshake_next hold. Deliberately separate from `now`
   * (the protocol clock): a long-poll budget is wall-time resource management.
   */
  waitClock?: () => number;
  /** Global cap on concurrent handshake_next holds; defaults to MAX_HOLDS. */
  maxHolds?: number;
  /** Cap on concurrent holds per client (IP); defaults to MAX_HOLDS_PER_CLIENT. */
  maxHoldsPerClient?: number;
  /** Window from acceptance to channel_open before a session is abandoned. */
  preOpenTtlMs?: number;
} = {}) {
  if (!options.client) throw new StandaloneCoordinatorError("A ledger client is required.");
  const client = options.client;
  const now = options.now ?? Date.now;
  const store = createStandaloneSessionStore({ now, preOpenTtlMs: options.preOpenTtlMs });
  const holds = createHoldRegistry({ maxHolds: options.maxHolds, maxHoldsPerClient: options.maxHoldsPerClient });
  const nextPollMs = options.nextPollMs ?? NEXT_WAIT_POLL_MS;
  const waitClock = options.waitClock ?? (() => performance.now());
  // Either party may open, and a looping agent on each side can call channel_open at the
  // same moment. Concurrent calls for one session share a single in-flight open, so the
  // opening transitions are anchored once.
  const openings = new Map<string, Promise<Record<string, unknown>>>();
  const recover = options.recoverEip191Address;
  const resolveIdentity =
    options.resolveIdentity ??
    (async () => {
      throw new StandaloneCoordinatorError("Identity resolution is not configured.");
    });

  function authedSession(args: Record<string, unknown>): { session: any; role: string } {
    const access = args.access;
    if (typeof access !== "string" || !access.startsWith("sat_")) throw new StandaloneCoordinatorError();
    const found = store.authenticateToken(access);
    if (found === undefined) throw new StandaloneCoordinatorError();
    return found;
  }

  return {
    store,

    /** Concurrent handshake_next holds, for tests and telemetry. */
    activeHolds(): number {
      return holds.size();
    },

    async invoke(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
      const result = await dispatch(name, args);
      if (SESSION_MUTATING_TOOLS.has(name) && typeof result.sessionId === "string") holds.notify(result.sessionId);
      return result;
    },
  };

  async function dispatch(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (name === "readiness_prepare") {
      // Public and stateless: the exact authority bytes the checklist will verify.
      return { ...prepareStandaloneAuthority({ sessionKeyAddress: args.sessionKeyAddress, accountableParty: args.accountableParty, statement: args.statement }), protocol: STANDALONE_HANDSHAKE_PROTOCOL, thenCall: "handshake_invite or handshake_accept_invitation" };
    }

    if (name === "handshake_next") return next(args);

    if (name === "handshake_preview_invitation") {
      // Public and read-only: what a Responder's readiness must match. Burns nothing.
      const decoded = decodeInvitation(args.invitation) ?? invitationUnavailable();
      const invitation = store.peekInvitation(decoded.secret);
      if (invitation === undefined || invitation.sessionId !== decoded.sessionId) invitationUnavailable();
      const session = store.getSession(invitation.sessionId);
      if (session === undefined || session.stage !== "invited") invitationUnavailable();
      store.appendEvent(session.sessionId, { type: "previewed" });
      const identityRequired = session.terms.identityPolicy.erc8004 !== "not_required";
      return {
        protocol: STANDALONE_HANDSHAKE_PROTOCOL,
        sessionId: session.sessionId,
        terms: session.terms,
        required: {
          "capabilityManifest.dataHandlingClass": session.initiatorReadiness.capabilityManifest.dataHandlingClass,
          "capabilityManifest.purpose": session.terms.purpose,
          identity: identityRequired ? "an ERC-8004 registration on eip155:11155111 owned by your sessionKeyAddress" : null,
        },
        invitationExpiresAtMs: String(invitation.expiresAtMs),
        invitationExpiresAt: new Date(invitation.expiresAtMs).toISOString(),
        maxReadinessAttempts: READINESS_MAX_ATTEMPTS,
        untrustedFields: UNTRUSTED_TERMS_FIELDS,
        untrustedNote: UNTRUSTED_TERMS_NOTE,
        guidance:
          `${UNTRUSTED_TERMS_NOTE} To accept, build a readiness whose capabilityManifest has exactly the values in required (and identity as shown), ` +
          "sign its authority record via readiness_prepare, then call handshake_accept_invitation with this invitation before invitationExpiresAt. Previewing claims nothing.",
        thenCall: "handshake_accept_invitation",
      };
    }

    if (name === "handshake_invite") {
      const terms = normalizeStandaloneTerms({ reference: args.reference, purpose: args.purpose, channelLimits: args.channelLimits, identityPolicy: args.identityPolicy });
      const readiness = normalizeStandaloneReadiness(args.readiness, terms.identityPolicy.erc8004);
      const termsDigest = standaloneCanonicalRecord(terms).digest;
      const sessionId = randomUUID();
      store.createSession({ sessionId, terms, termsDigest, initiatorReadiness: readiness });
      const secret = randomBytes(24).toString("base64url");
      store.putInvitation({ secret, sessionId, expiresAtMs: store.requireSession(sessionId).invitationExpiresAtMs });
      const initiatorAccess = `sat_${randomBytes(32).toString("base64url")}`;
      store.setAccessToken(sessionId, "initiator", initiatorAccess);
      const invitation = Buffer.from(JSON.stringify({ v: 1, sessionId, secret })).toString("base64url");
      return { sessionId, reference: terms.reference, invitation, initiatorAccess };
    }

    if (name === "handshake_accept_invitation") {
      const decoded = decodeInvitation(args.invitation);
      if (decoded === undefined) throw new StandaloneCoordinatorError();
      const sessionId = store.claimInvitation(decoded.secret);
      if (sessionId === undefined || sessionId !== decoded.sessionId) {
        // A claimed-but-mismatched envelope restores the claim so that tampering
        // with the embedded sessionId cannot burn a genuine invitation.
        if (sessionId !== undefined) store.putInvitation({ secret: decoded.secret, sessionId });
        throw new StandaloneCoordinatorError();
      }
      const session = store.requireSession(sessionId);
      if (session.stage !== "invited") throw new StandaloneCoordinatorError();
      const readiness = normalizeStandaloneReadiness(args.readiness, session.terms.identityPolicy.erc8004);
      // The first claim burns the invitation. A failed checklist does not end the session:
      // the same Responder corrects its readiness through handshake_retry_readiness, which
      // is bound to the responder access issued here, so nobody else can take over.
      const outcome = await readinessAttempt(session, readiness, {
        previousStage: "invited",
        onRollback: () => store.putInvitation({ secret: decoded.secret, sessionId, expiresAtMs: session.invitationExpiresAtMs }),
      });
      const responderAccess = `sat_${randomBytes(32).toString("base64url")}`;
      store.setAccessToken(sessionId, "responder", responderAccess);
      return { ...outcome, responderAccess };
    }

    if (name === "handshake_retry_readiness") {
      const { session, role } = authedSession(args);
      if (role !== "responder") throw new StandaloneAdmissionError("NOT_RESPONDER");
      refuseIfAbandoned(session.sessionId);
      if (session.stage !== "readiness_retry") throw new StandaloneAdmissionError("NOT_IN_RETRY");
      const readiness = normalizeStandaloneReadiness(args.readiness, session.terms.identityPolicy.erc8004);
      return readinessAttempt(session, readiness, { previousStage: "readiness_retry" });
    }

    if (name === "handshake_timeline") {
      const { session, role } = authedSession(args);
      const timeline = store.timeline(session.sessionId);
      return { sessionId: session.sessionId, role, stage: store.getSession(session.sessionId).stage, events: timeline?.events ?? [], droppedEvents: timeline?.dropped ?? 0 };
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
      refuseIfAbandoned(session.sessionId);
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
      // The open deadline may have passed while recovery was awaited. Settle it now, with no
      // await before the stage writes below, so the refusal is a clean ABANDONED rather than
      // an illegal-transition error from setStage.
      refuseIfAbandoned(session.sessionId);
      if (session.stage === "ready") store.setStage(session.sessionId, "consent_pending");
      store.setConsent(session.sessionId, role, standaloneCanonicalRecord(consentRecord).digest);
      store.appendEvent(session.sessionId, { type: "consent", role, consentDigest: standaloneCanonicalRecord(consentRecord).digest });
      const stage = store.bothConsented(session.sessionId) ? (store.setStage(session.sessionId, "consented"), "consented") : "consent_pending";
      return { sessionId: session.sessionId, role, stage, consentDigest: standaloneCanonicalRecord(consentRecord).digest };
    }

    if (name === "channel_open") {
      const { session } = authedSession(args);
      const inFlight = openings.get(session.sessionId);
      if (inFlight !== undefined) return inFlight;
      // The counterparty already opened it: a distinct reason code, so a looping agent
      // knows to carry on with handshake_next rather than treat this as a failure.
      if (session.stage === "open") throw new StandaloneAdmissionError("ALREADY_OPEN");
      refuseIfAbandoned(session.sessionId);
      if (session.stage !== "consented" || !store.bothConsented(session.sessionId)) throw new StandaloneCoordinatorError();
      const opening = openChannel(session);
      openings.set(session.sessionId, opening);
      try {
        return await opening;
      } finally {
        openings.delete(session.sessionId);
      }
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
      // Pre-touch: an expired channel was ended by the clock, so refuse before any ledger write.
      if (store.getSession(session.sessionId)?.stage === "expired") throw new StandaloneAdmissionError("EXPIRED");
      const outcome = name === "channel_close" ? "closed" : "revoked";
      // Peek-then-clear-late: the closure record is pinned in the store before anchoring and
      // cleared only after the store mutation succeeds, so the pin survives anchor failures
      // AND store-mutation failures and a retry re-anchors the byte-identical record. The
      // candidate reuses the pinned closedAtMs while a like-for-like pin exists; a different
      // outcome or role while pinned is refused by setPendingClosure (CLOSURE_PENDING) before
      // the ledger is touched.
      const pinned = store.pendingClosure(session.sessionId);
      const closureRecord = normalizeStandaloneClosure({
        schema: "clockchain.standalone-handshake-closure/v1",
        protocol: STANDALONE_HANDSHAKE_PROTOCOL,
        sessionId: session.sessionId,
        outcome,
        byRole: role,
        closedAtMs: String(pinned?.closedAtMs ?? Math.floor(now())),
        externalBusinessActionPerformed: false,
      });
      store.setPendingClosure(session.sessionId, closureRecord);
      const anchor = await anchorStandalone(client, closureRecord, `standalone-handshake-v1:${session.sessionId}:closure`, true);
      (outcome === "closed" ? store.closeChannel : store.revokeChannel).call(store, session.sessionId, role);
      store.addAnchors(session.sessionId, [{ kind: outcome === "closed" ? "closure" : "revocation", ...anchor }]);
      store.appendEvent(session.sessionId, { type: outcome === "closed" ? "close" : "revoke", byRole: role, anchor: anchorSummary({ kind: outcome === "closed" ? "closure" : "revocation", ...anchor }) });
      store.clearPendingClosure(session.sessionId);
      return { sessionId: session.sessionId, outcome, byRole: role, closureAnchor: anchor };
    }

    throw new StandaloneCoordinatorError(`Unknown tool ${name}.`);
  }

  // Long-polls until the role has something to do. Waits are held in slices on a bounded
  // hold (see long-poll.ts): a newer call for the same role supersedes this one, the hold
  // ends when the request goes away, and when no hold is available the caller gets the
  // current answer at once with a longer retryAfterMs.
  async function next(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const { session, role } = authedSession(args);
    const waitMs = boundedNextWaitMs(args.waitMs);
    const cursor = nextCursor(args.cursor);
    // A cursor past the last admitted seq would silently hide every message up to it, so it
    // is refused rather than clamped; omitting the cursor re-reads from the start.
    if (cursor > store.lastSeq(session.sessionId)) throw new StandaloneAdmissionError("MALFORMED");
    const startedAt = waitClock();
    const evaluate = () => {
      const current = store.getSession(session.sessionId);
      if (current === undefined) throw new StandaloneAdmissionError("SESSION_ENDED");
      return { current, result: evaluateStandaloneNext({ store, session: current, role, cursor, now, maxAttempts: READINESS_MAX_ATTEMPTS }) };
    };
    // An actionable prompt (the opener's "send first", a fix_readiness) goes out at once the
    // first time; a repeat is held like a wait so an agent that has not acted cannot spin.
    const holdable = (result: Record<string, any>, _current: any) => {
      const key = promptKey(result);
      return result.action === "wait" || (key !== undefined && store.wasPrompted(session.sessionId, `${role}:${key}`));
    };
    const deliver = (result: Record<string, any>) => {
      const key = promptKey(result);
      if (key !== undefined) store.markPrompted(session.sessionId, `${role}:${key}`);
      return result;
    };

    let { current, result } = evaluate();
    if (waitMs === 0 || !holdable(result, current)) return deliver(result);
    const context = standaloneRequestContext.getStore();
    const hold = holds.acquire({ roleKey: `${session.sessionId}:${role}`, sessionId: session.sessionId, clientKey: context?.clientKey ?? "local", signal: context?.signal });
    // No hold slot: answer now (a wait, or a repeated send-first prompt) with a longer
    // retryAfterMs so a busy server does not invite a spin.
    if (hold === undefined) return deliver({ ...result, retryAfterMs: BUSY_RETRY_AFTER_MS });
    try {
      for (let polls = 0; polls < MAX_NEXT_WAIT_POLLS; polls += 1) {
        const budgetMs = waitMs - (waitClock() - startedAt);
        if (budgetMs <= 0) break;
        await hold.sleep(Math.min(nextPollMs, budgetMs));
        ({ current, result } = evaluate());
        if (!holdable(result, current)) return deliver(result);
        if (hold.superseded) return { ...result, superseded: true };
        if (hold.aborted) return result;
      }
      return deliver(result);
    } finally {
      hold.release();
    }
  }

  async function openChannel(session: any): Promise<Record<string, unknown>> {
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
    const consentDigests = Object.freeze({ initiator: session.consents.initiator, responder: session.consents.responder });
    const transitions: Array<Record<string, any>> = [
      { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "TERMS_READINESS", sequence: "1", predecessor: null },
      { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "CONSENT", sequence: "2", predecessor: "", consentDigests },
      { ...base, schema: "clockchain.standalone-handshake-transition/v1", kind: "OPEN", sequence: "3", predecessor: "", consentDigests },
    ];
    transitions[1].predecessor = standaloneCanonicalRecord(transitions[0]).digest;
    transitions[2].predecessor = standaloneCanonicalRecord(transitions[1]).digest;
    // Re-check the open deadline before anything is written to the ledger.
    refuseIfAbandoned(session.sessionId);
    const anchors: any[] = [];
    // Transition ownership is initiator/responder/initiator, but this standalone coordinator is the single
    // mediator (both parties' tokens live in one store, and consent_sign anchors nothing), so it writes all
    // three transitions on the session's behalf; a missing counterpart record would otherwise deadlock open.
    for (let index = 0; index < transitions.length; index += 1) {
      const reference = `standalone-handshake-v1:${session.sessionId}:${KIND_REFERENCES[transitions[index].kind as keyof typeof KIND_REFERENCES]}`;
      const receipt = await anchorStandalone(client, transitions[index], reference, true);
      anchors.push({ kind: KIND_REFERENCES[transitions[index].kind as keyof typeof KIND_REFERENCES], ...receipt });
    }
    // Anchor before mutate: every transition is witnessed before the session becomes an open, usable channel,
    // so a transient anchor failure leaves the stage at "consented" and channel_open can simply be retried.
    // The session's clock starts at the ledger's consensus time (the open anchor's block time), not the server clock.
    // An unparseable block time is a transient upstream defect: fail rather than silently
    // restarting the session clock on the server wall clock. The anchors already exist, so a
    // retry re-anchors the identical records and re-reads the block.
    const anchorOpenMs = Date.parse(anchors[anchors.length - 1].blockTimeRaw);
    if (Number.isNaN(anchorOpenMs)) throw new StandaloneTransientCoordinatorError();
    const openedAtMs = anchorOpenMs;
    // Anchoring awaits the ledger, so the open deadline can pass mid-flight. The session is
    // then abandoned and stays abandoned: the opening anchors already on the ledger witness
    // a consented opening that never took effect, and the caller gets a clean ABANDONED
    // instead of an illegal-transition error from setStage. No await separates this check
    // from the stage write below, so the outcome is deterministic.
    refuseIfAbandoned(session.sessionId);
    const expiresAtMs = openedAtMs + Number(session.terms.channelLimits.durationSeconds) * 1000;
    store.setStage(session.sessionId, "open");
    store.openChannel(session.sessionId, { openedAtMs, expiresAtMs });
    store.addAnchors(session.sessionId, anchors);
    store.appendEvent(session.sessionId, { type: "open", anchors: anchors.map(anchorSummary) });
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

  // Runs one readiness attempt for the Responder (first claim or a retry). Pass: ready.
  // Fail: readiness_retry while attempts remain and every failure is the Responder's to
  // fix; otherwise ready_failed for both. Nothing is anchored here: the terms-readiness
  // transition is anchored by channel_open, which only a passed checklist can reach.
  async function readinessAttempt(session: any, readiness: Readonly<Record<string, any>>, options: { previousStage: "invited" | "readiness_retry"; onRollback?: () => void }): Promise<Record<string, unknown>> {
    const sessionId = session.sessionId;
    const previousReadiness = session.responderReadiness;
    store.setResponderReadiness(sessionId, readiness);
    store.setStage(sessionId, "readiness_pending");
    let checklist;
    try {
      checklist = await evaluateStandaloneReadiness({
        sessionId,
        terms: session.terms,
        termsDigest: session.termsDigest,
        initiator: session.initiatorReadiness,
        responder: readiness,
        resolveIdentity: requiredIdentity(session) ? resolveIdentity : async () => true,
        recoverAddress: recover ?? (async () => {
          throw new StandaloneCoordinatorError("Signature recovery is not configured.");
        }),
      });
    } catch (error) {
      // Evaluation died mid-flight (e.g. the identity-resolution RPC dropped): never a
      // completed checklist, so it does not count as an attempt. Roll back so the identical
      // call can be retried instead of bricking the session in readiness_pending.
      store.rollbackAttempt(sessionId, { stage: options.previousStage, readiness: previousReadiness });
      options.onRollback?.();
      if (error instanceof StandaloneCoordinatorError || error instanceof StandaloneTransientCoordinatorError) throw error;
      throw new StandaloneTransientCoordinatorError();
    }
    store.setChecklist(sessionId, checklist);
    const codes = [...new Set(checklist.failures.map((failure) => failure.code))];
    const attempt = store.recordAttempt(sessionId, { passed: checklist.passed, codes });
    const responderCanFix = checklist.failures.every((failure) => failure.party === "responder");
    let stage: string;
    if (checklist.passed) {
      stage = "ready";
      store.setStage(sessionId, stage);
      store.appendEvent(sessionId, { type: "accepted", attempt });
    } else if (responderCanFix && attempt < READINESS_MAX_ATTEMPTS) {
      stage = "readiness_retry";
      store.setStage(sessionId, stage);
    } else {
      stage = "ready_failed";
      store.setStage(sessionId, stage);
      store.appendEvent(sessionId, { type: "ready_failed", reason: codes.join(","), attempts: attempt });
    }
    const retry = stage === "readiness_retry";
    return {
      sessionId,
      stage,
      checklist,
      attempt,
      attemptsLeft: retry ? READINESS_MAX_ATTEMPTS - attempt : 0,
      ...(retry ? { codes, thenCall: "handshake_next" } : {}),
    };
  }

  function refuseIfAbandoned(sessionId: string): void {
    if (store.getSession(sessionId)?.stage === "abandoned") throw new StandaloneAdmissionError("ABANDONED");
  }

  function requiredIdentity(session: any): boolean {
    return session.terms.identityPolicy.erc8004 !== "not_required";
  }

  function failMissing(): never {
    throw new StandaloneCoordinatorError("Signature recovery is not configured.");
  }
}

// The mcp container is given EVM_RPC_URL (compose); SEPOLIA_RPC_URL is only set on the
// host service. Reading SEPOLIA_RPC_URL alone left rpcUrl empty in production, so every
// signature recovery threw and the checklist reported AUTHORITY_INVALID for everyone.
export function resolveStandaloneRpcUrl(env: Record<string, string | undefined>): string {
  return env.SEPOLIA_RPC_URL || env.EVM_RPC_URL || "";
}

const warnedHoldLimitVars = new Set<string>();

// Hold caps from env. Only a positive integer is accepted: NaN would silently remove a cap
// and 0 would make every call busy, so anything else falls back to the default, with one
// warning per variable.
export function resolveStandaloneHoldLimits(env: Record<string, string | undefined>): { maxHolds?: number; maxHoldsPerClient?: number } {
  const limits: { maxHolds?: number; maxHoldsPerClient?: number } = {};
  const read = (name: string): number | undefined => {
    const raw = env[name];
    if (raw === undefined || raw.trim() === "") return undefined;
    if (/^[1-9][0-9]{0,8}$/.test(raw.trim())) return Number(raw.trim());
    if (!warnedHoldLimitVars.has(name)) {
      warnedHoldLimitVars.add(name);
      console.warn(JSON.stringify({ event: "standalone_handshake_invalid_hold_limit", variable: name }));
    }
    return undefined;
  };
  const maxHolds = read("STANDALONE_NEXT_MAX_HOLDS");
  const maxHoldsPerClient = read("STANDALONE_NEXT_MAX_HOLDS_PER_CLIENT");
  if (maxHolds !== undefined) limits.maxHolds = maxHolds;
  if (maxHoldsPerClient !== undefined) limits.maxHoldsPerClient = maxHoldsPerClient;
  return limits;
}

export function createRuntimeStandaloneCoordinator(env: Record<string, string | undefined> = process.env) {
  const rpcUrl = resolveStandaloneRpcUrl(env);
  const client = new ClockchainClient(readConfigFromEnv(env));
  // All protocol time judgments run on Clockchain consensus time: a disciplined
  // local clock synced against the ledger's timestamp endpoint, never the server
  // wall clock. Until the first sync succeeds (and if it never does), calls that
  // need time fail closed with a retryable transient error; housekeeping falls
  // back to the wall clock inside the store.
  const clock = new ClockchainClock(client, {
    autoResyncMs: Number(env.STANDALONE_CLOCK_RESYNC_MS ?? "60000"),
  });
  void clock.sync().catch(() => undefined);
  return createStandaloneCoordinator({
    client,
    rpcUrl,
    now: () => {
      try {
        // epochMs carries sub-millisecond monotonic noise; protocol timestamps are
        // integer milliseconds, so floor before they reach decimal-validated records.
        return Math.floor(clock.now().epochMs);
      } catch {
        throw new StandaloneTransientCoordinatorError();
      }
    },
    recoverEip191Address: ({ bytes, signatureHex }) => recoverEip191Address({ bytes, signatureHex, rpcUrl }),
    ...resolveStandaloneHoldLimits(env),
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

type StandaloneCoordinatorLike = { store: { listSessions(): readonly any[]; timeline(sessionId: string): { events: readonly any[]; dropped: number } | undefined } };

/** Operator view (no HTTP route yet): a summary of every retained session. */
export function listStandaloneSessions(coordinator: StandaloneCoordinatorLike): readonly any[] {
  return coordinator.store.listSessions();
}

/** Operator view (no HTTP route yet): one session's timeline, or undefined once evicted. */
export function getStandaloneTimeline(coordinator: StandaloneCoordinatorLike, sessionId: string): { events: readonly any[]; dropped: number } | undefined {
  return coordinator.store.timeline(sessionId);
}
