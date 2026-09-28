import { randomBytes, randomUUID } from "node:crypto";

import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";
import { ClockchainClock } from "@clockchain/clock-sdk";

import { canonicalBytes } from "../handshake/protocol.js";
import { recoverEip191Address, resolveOwnedAgentRegistration } from "../handshake/evm.js";

import { evaluateStandaloneReadiness } from "./checklist.js";
import { createHoldRegistry, standaloneRequestContext } from "./long-poll.js";
import { BUSY_RETRY_AFTER_MS, DEFAULT_NEXT_WAIT_MS, MAX_NEXT_WAIT_MS, MAX_NEXT_WAIT_POLLS, NEXT_WAIT_POLL_MS, evaluateStandaloneNext } from "./next.js";
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
import { createStandaloneSessionStore, StandaloneAdmissionError } from "./session-store.js";

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
const SESSION_MUTATING_TOOLS = new Set(["handshake_accept_invitation", "consent_sign", "channel_open", "channel_send", "channel_close", "channel_revoke"]);

// A respond with nothing to respond to: the Initiator's "send the first message" prompt.
function isOpenerPrompt(result: Record<string, any>): boolean {
  return result.action === "respond" && Array.isArray(result.messages) && result.messages.length === 0;
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
      if (sessionId === undefined || sessionId !== decoded.sessionId) {
        // A claimed-but-mismatched envelope restores the claim so that tampering
        // with the embedded sessionId cannot burn a genuine invitation.
        if (sessionId !== undefined) store.putInvitation({ secret: decoded.secret, sessionId });
        throw new StandaloneCoordinatorError();
      }
      const session = store.requireSession(sessionId);
      if (session.stage !== "invited") throw new StandaloneCoordinatorError();
      const responderReadiness = normalizeStandaloneReadiness(args.readiness, session.terms.identityPolicy.erc8004);
      store.setResponderReadiness(sessionId, responderReadiness);
      store.setStage(sessionId, "readiness_pending");
      let checklist;
      try {
        checklist = await evaluateStandaloneReadiness({
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
      } catch (error) {
        // Evaluation died mid-flight (e.g. the identity-resolution RPC dropped) — never
        // a completed checklist. Roll the session back to invited and restore the
        // invitation so the responder can retry the identical claim instead of
        // bricking the session in readiness_pending forever.
        store.resetToInvited(sessionId);
        store.putInvitation({ secret: decoded.secret, sessionId });
        if (error instanceof StandaloneCoordinatorError || error instanceof StandaloneTransientCoordinatorError) throw error;
        throw new StandaloneTransientCoordinatorError();
      }
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
      const { session } = authedSession(args);
      const inFlight = openings.get(session.sessionId);
      if (inFlight !== undefined) return inFlight;
      // The counterparty already opened it: a distinct reason code, so a looping agent
      // knows to carry on with handshake_next rather than treat this as a failure.
      if (session.stage === "open") throw new StandaloneAdmissionError("ALREADY_OPEN");
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
      return { current, result: evaluateStandaloneNext({ store, session: current, role, cursor, now }) };
    };
    // The opener prompt goes out at once the first time; a repeat is held like a wait so an
    // agent that has not sent yet cannot spin on it.
    const holdable = (result: Record<string, any>, current: any) => result.action === "wait" || (isOpenerPrompt(result) && current.openerPrompted);
    const deliver = (result: Record<string, any>) => {
      if (isOpenerPrompt(result)) store.markOpenerPrompted(session.sessionId);
      return result;
    };

    let { current, result } = evaluate();
    if (waitMs === 0 || !holdable(result, current)) return deliver(result);
    const context = standaloneRequestContext.getStore();
    const hold = holds.acquire({ roleKey: `${session.sessionId}:${role}`, sessionId: session.sessionId, clientKey: context?.clientKey ?? "local", signal: context?.signal });
    if (hold === undefined) return deliver(result.action === "wait" ? { ...result, retryAfterMs: BUSY_RETRY_AFTER_MS } : result);
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
    const expiresAtMs = openedAtMs + Number(session.terms.channelLimits.durationSeconds) * 1000;
    store.setStage(session.sessionId, "open");
    store.openChannel(session.sessionId, { openedAtMs, expiresAtMs });
    store.addAnchors(session.sessionId, anchors);
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
    ...(env.STANDALONE_NEXT_MAX_HOLDS ? { maxHolds: Number(env.STANDALONE_NEXT_MAX_HOLDS) } : {}),
    ...(env.STANDALONE_NEXT_MAX_HOLDS_PER_CLIENT ? { maxHoldsPerClient: Number(env.STANDALONE_NEXT_MAX_HOLDS_PER_CLIENT) } : {}),
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
