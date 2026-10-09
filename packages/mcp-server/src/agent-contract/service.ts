import {
  closeSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync,
  readFileSync, renameSync, rmSync, writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";

import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import { guidanceDigests, type GuidanceDigests } from "./tools-list.js";
import { verifyCertificateEnvelope, type HostRootPin } from "./certificate.js";
import type { AnchorWrite, ContractAnchor } from "./anchor.js";
import { mintTerminalReceipt, type TerminalReceipt, type TerminalReceiptFields } from "./close-emitter.js";
import { createTerminalOutbox, type TerminalAnchorJob, type TerminalJob } from "./terminal-jobs.js";
import { makeReceipt, checkReceiptDraft, chainHead, type ReceiptFields, type ServerReceipt, RECEIPT_CHAIN_GENESIS } from "./receipts.js";
import type { ContractSigner } from "./envelope.js";
import { CONTRACT_TOOL_DEFS, type ApprovalRecord, type ContractFeatures, type ContractRole } from "./schemas.js";
import type { ContractRefusalCode } from "./refusals.js";
import { createBusinessOps, type BusinessOps } from "./business.js";
import type { SettlementRail } from "./settlement-rail.js";
import { createSimWorld, type SimFaults, type SimRun, type SimTicket, type SimWorld } from "./sim/index.js";
import { eip191RecoverPublicKey, isCanonicalEip191Signature, publicKeyToAddress } from "./eip191.js";
import { createRunRouter, keyIdOfChain } from "./run-routing.js";
import { createPolicyRegistry, type PolicyRegistry } from "./policy-registry.js";
import { BRIEF_ANCHOR_SUBJECT, createServerAnchors, termsDigestOf, type ContractBrief, type ServerAnchors } from "./server-anchors.js";
import { createMilestoneLog, type MilestoneLog, type MilestoneTracker } from "./milestone-log.js";

/**
 * Run-scoped contract state and the `contract_bind` decision logic
 * (LLD §3 — this slice: bind + status only; sim/business tools arrive in
 * later N4b slices).
 *
 * A run's identity is `sessionId` + `canonicalDigest(result)` — SIGNED
 * certificate content only, so unsigned envelope decoration cannot mint a
 * second identity for the same session. One handshake maps to at most one
 * contract run; a second envelope claiming the same sessionId with a
 * different result digest is a substitution attempt and is refused.
 *
 * C2 (orchestrator decision, LLD rev 6.2): each bearer token is provisioned
 * `token:role:keyId:agentId:side`, and `contract_bind` only seats a principal
 * when the certificate's party on that side carries exactly that ERC-8004
 * `agentId`. The two roles must sit on DIFFERENT sides. The run records
 * `{buyer: side/agentId, provider: side/agentId}`.
 *
 * Ordering invariants:
 * - A run is created ONLY after every check passes — a refused bind leaves
 *   no state behind.
 * - The bind receipt is signed BEFORE the state mutation commits; a receipt
 *   failure means no commit (and a loud error), never a bound run with an
 *   empty chain.
 * - Used sessionIds are persisted (`stateDir/used-sessions.json`) before the
 *   commit is considered done — a restart can never start a second genesis
 *   for an already-bound handshake.
 */

export type ContractSide = "initiator" | "responder";

export interface ContractPrincipal {
  readonly keyId: string;
  readonly role: ContractRole;
  /**
   * ERC-8004 agent id this principal claims (from its provisioned token).
   * `"*"` (N4b-7 late binding): the id is taken from the certificate's party
   * on this principal's side at contract_bind and pinned write-once.
   */
  readonly agentId: string;
  /** The handshake side the token pins this principal to. */
  readonly side: ContractSide;
}

export interface BoundRole {
  readonly principalKeyId: string;
  readonly agentId: string;
  readonly side: ContractSide;
  readonly signerKey: { keyId: string; publicKeyHex: string };
  readonly approvalKey: { keyId: string; publicKeyHex: string };
  readonly boundAt: string;
  /** N4b-7 (MEDIUM-2): how the agentId was established — kept for replays. */
  readonly bindMode: "static" | "late";
  /** N4b-7: whether the session-key possession statement verified. */
  readonly bindStatement: "verified" | "absent";
  readonly bindAssurance: "agentId-pinned-token" | "late-certificate-party" | "session-key-possession";
  /** CDT-GAPS gap 1 (CONTRACT_ROLE_BRIEFS): the brief digest this role's bind bound (null: none). */
  readonly briefDigest?: string | null;
}

export type ContractStage =
  | "rendezvous" | "handshake" | "bound" | "mandated" | "negotiating"
  | "agreed" | "booked" | "verified" | "settled" | "terminal";

/**
 * N4b-8 (gap 4): the outcome of anchoring one subject (the agreement digest
 * or the terminal receipt-chain head) via the tsa_issue-backed anchor.
 * "anchoring" while in flight; a failure is recorded here and surfaced in
 * contract_status — never silent.
 */
export interface AnchorRunState {
  /**
   * N4b-9 (F13): "anchored" only when the backing confirms block+time;
   * a resolved-but-unconfirmed write is "pending" (retained for polling),
   * never reported as anchored.
   */
  status: "anchoring" | "pending" | "anchored" | "failed";
  /** The anchored subject — agreementDigest or the terminal chain head. */
  digest: string;
  /** `tsa:<commitmentId>` when anchored. */
  anchorId?: string;
  eventHash?: string;
  ledger?: { ledgerId: string; blockHeight: string | null; time: string | null; status: string };
  error?: string;
  /** final only (server-anchors.ts): the run-chain length the final head covers; null when taken from the job after a restart. */
  receiptCount?: number | null;
}

export interface OfferRecord {
  offerId: string;
  payload: Record<string, unknown>;
  role: ContractRole;
  principalKeyId: string;
  /** "superseded": a same-party offer replaced it — it can never be accepted. */
  state: "live" | "accepted" | "rejected" | "superseded";
  /** Monotonic per-run sequence — "latest live" is decided by this, not map order. */
  seq: number;
  submittedAt: string;
}

export interface AgreementRecord {
  agreementId: string;
  offerId: string;
  offerDigest: string;
  agreementDigest: string;
  offerPayload: Record<string, unknown>;
  acceptPayload: Record<string, unknown>;
  itineraryId: string;
  currency: string;
  fareMinor: number;
  feeMinor: number;
  totalMinor: number;
  formedAt: string;
}

export interface ContractRun {
  readonly runId: string;
  /** canonicalDigest of the signed certificate `result` — the run's digest half. */
  readonly resultDigest: string;
  readonly sessionPublicKey: string;
  readonly createdAtMs: number;
  /**
   * Half-bound run release: the run certificate's acceptUntilMs (validUntil +
   * grace). Past it no bind can verify this session, so a run still missing a
   * party can never complete — it ends `expired_unbound`, freeing its seats.
   * Absent on runs built outside bind (never expires this way).
   * QA F-5: capped at first bind + halfBoundTimeoutMs (default 10 min), so a
   * run whose counterparty never binds frees the bound party's key quickly
   * instead of holding it until the certificate window closes.
   */
  readonly bindDeadlineMs?: number;
  /**
   * QA F-5: why the run ended, when the terminal state alone does not say
   * (e.g. `counterparty_never_bound` for a half-bound withdraw or expiry).
   * Server-side evidence only — set once, with the terminal transition.
   */
  terminalReason?: string;
  readonly bound: Partial<Record<ContractRole, BoundRole>>;
  readonly receipts: ServerReceipt[];
  /** N3: each principal has its OWN receipt budget within a run. */
  readonly receiptsByPrincipal: Map<string, number>;
  /** This run's closed sim world (ticketing + payment rail). */
  simRun?: SimRun;
  /** Config-seeded sim fault active on this run, if any (A2 evidence). */
  simFault?: SimFaults;
  /** Signed-envelope nonces already consumed, per run (§13 rev 6.1). */
  readonly claimedNonces: Set<string>;
  mandate?: {
    digest: string;
    mandateId: string;
    capMinor: number;
    currency: string;
    allowedItineraryIds: string[];
    /**
     * Flexible family policy: 2 (the default, absent) or 3. For a v3
     * mandate `capMinor` carries `maxCapMinor`, `partySize` carries the
     * traveler's per-run party, and an empty `allowedItineraryIds` means any
     * catalog itinerary.
     */
    mandateVersion?: 2 | 3;
    maxCapMinor?: number;
    partyMin?: number;
    partyMax?: number;
    /** The traveler's per-run, unsigned trip statement (recorded, enforced). */
    trip?: { origin: string; destination: string; partySize: number; budgetMinor: number };
    /**
     * N4b-9 (F16 → D12): the principal-signed traveller count (v2.2).
     * The booking issues exactly this many tickets and verification
     * recomputes match against it — never model-supplied.
     */
    partySize?: number;
    expiresAt: string;
    /** The family-principal address the mandate signature recovered to. */
    principalAddress: string;
    submittedAt: string;
  };
  readonly offers: Map<string, OfferRecord>;
  offerSeq: number;
  agreement?: AgreementRecord;
  booking?: {
    orderRef: string;
    pnr: string;
    tickets: SimTicket[];
    bookedAt: string;
    /** N4b-8 (gap 6): digest of {envelope, signatureHex, approval} — a byte-identical replay returns this record's result. */
    requestDigest: string;
  };
  /** N4b-4: the provider-side simulated cancel result (terminal "cancelled"). */
  cancellation?: { orderRef: string; cancelledAt: string };
  verification?: {
    result: "match" | "mismatch";
    verificationDigest: string;
    findingsDigest: string;
    agreementId: string;
    agreementDigest: string;
    orderRef: string;
    bookingRef: string;
    flagged: boolean;
    submittedAt: string;
  };
  settlement?: {
    transferId: string;
    status: "authorized" | "released";
    /** N4b-10 (D13): which rail released the settlement + rail intent id. */
    paymentRail?: "simulated" | "stripe_test_mode";
    paymentIntentId?: string;
  };
  settlementPrepared?: boolean;
  /**
   * N4b-10 (D13): the Stripe rail's created-but-unconfirmed PaymentIntent
   * — its id rides inside the signed settlement payload.
   */
  settlementIntent?: { paymentIntentId: string; status: string };
  /**
   * N4b-10 (D13): settlement_prepare stopped awaiting the test key —
   * surfaced honestly in contract_status / settlement_status; cleared
   * when a prepare lands an envelope.
   */
  awaitingStripeTestKey?: boolean;
  /**
   * N4b-10 (D13): idempotent settlement_authorize replay — the recorded
   * request digest + result body (mirrors booking.requestDigest).
   */
  settlementRequest?: { digest: string; result: Record<string, unknown> };
  /**
   * The principal signature verified at `mandate_prepare`, pinned to that
   * envelope's nonce. `mandate_submit` replays it against the envelope's
   * flat-mandate payload (CONTRACT-PAYLOADS-v2 §Mandate) — the signature
   * itself never rides inside the signed payload.
   */
  mandatePrepared?: { nonce: string; mandateSignature: string; mandate?: Record<string, unknown> };
  /**
   * N6g-2 (observer R12): cryptographically verified approval records
   * collected at consequential submits — wire fields verbatim plus
   * `boundDigest`, the receipted `*_prepare` responseDigest the record
   * binds to in feed evidence (the wire `digest` stays the
   * envelope-binding approval tuple; an auditor recomputes it via
   * computeApprovalDigest).
   */
  approvalRecords?: { record: ApprovalRecord; boundDigest?: string }[];
  terminalState: string | null;
  /**
   * N4b-8 (gap 3): the terminal close delivery to the telemetry sink —
   * delivering/delivered/failed, attempt count and last error. Surfaced in
   * contract_status; a permanently failed close is never silent.
   */
  telemetryClose?: {
    status: "delivering" | "delivered" | "failed";
    attempts: number;
    lastError?: string;
    deliveredAt?: string;
    receiptDigest: string;
  };
  /**
   * N4b-8 (gap 4): anchor outcomes per subject — "agreement" is anchored at
   * formation, "terminal" at the terminal transition (the chain head at that
   * moment; post-terminal evidence receipts still chain on top).
   */
  anchors?: {
    agreement?: AnchorRunState;
    terminal?: AnchorRunState;
    /** Server-side anchors (server-anchors.ts) — recorded, never chained. */
    terms?: AnchorRunState;
    brief?: AnchorRunState;
    final?: AnchorRunState;
    /** CDT-GAPS gap 1 (CONTRACT_ROLE_BRIEFS): each role's own brief anchor. */
    briefBuyer?: AnchorRunState;
    briefProvider?: AnchorRunState;
  };
  /**
   * Milestone log (milestone-log.ts, CONTRACT_MILESTONE_LOG — default off):
   * per-milestone receipt attribution and the sealed entries' write states.
   * Absent whenever the flag is off.
   */
  milestoneLog?: MilestoneTracker;
  stage: ContractStage;
  /**
   * M4: per-run HMAC salt for cap-bearing call argsDigests — generated at
   * genesis, never persisted to the observer feed, disclosed only through
   * the verifier-scoped `/contract/run-salt` endpoint.
   */
  readonly runSalt: string;
}

export type BindOutcome =
  | {
      ok: true;
      runId: string;
      role: ContractRole;
      boundAt: string;
      result: Record<string, unknown>;
      receipt: ServerReceipt;
      run: ContractRun;
    }
  | { ok: false; code: ContractRefusalCode };

export interface ContractService {
  bind(
    principal: ContractPrincipal,
    args: {
      certificate: unknown;
      signerKey: unknown;
      approvalKey: unknown;
      listingId?: unknown;
      /** Bind by reference: the certificate must name exactly this session. */
      expectedSessionId?: string;
      /** N4b-7 (DRAFT): optional session-key possession statement + sig. */
      bindStatement?: unknown;
      bindStatementSignature?: unknown;
    },
    evidence: {
      argsDigest: string;
      serverNonce: string;
      tool: string;
      sourceIp?: string;
      mcpSessionId?: string;
      clientInfo?: { name: string; version: string };
    },
  ): BindOutcome;
  /**
   * N4b-7 (P-GAP): issue a single-use, short-TTL nonce the caller signs into
   * its DRAFT bindStatement to prove session-key possession. Nonces are
   * in-memory only — an unissued or expired one simply refuses at bind.
   */
  issueBindChallenge(principal: ContractPrincipal):
    { ok: true; challenge: string; expiresAt: string } | { ok: false; code: ContractRefusalCode };
  /**
   * Record a call's receipt onto the run chain (run-scoped, order-committed).
   * At a cap this REFUSES — it never throws (N3: a refusal is a result, an
   * exception is an outage).
   */
  recordReceipt(
    run: ContractRun,
    fields: Omit<ReceiptFields, "runId">,
  ): { ok: true; receipt: ServerReceipt } | { ok: false; code: ContractRefusalCode };
  /**
   * N4b-3 receipts-first gate: true iff the receipt for THIS call could be
   * built and appended right now — budget AND schema — checked by the caller
   * BEFORE any dispatch so a consequential action can never run unevidenced.
   * `run === undefined` checks the pre-bind chain instead.
   */
  checkReceiptEvidence(
    run: ContractRun | undefined,
    principal: ContractPrincipal,
    fields: Omit<ReceiptFields, "runId" | "outcome" | "responseDigest" | "principal">,
  ): { ok: true } | { ok: false; code: ContractRefusalCode };
  /**
   * Reserve-before-dispatch (N4b-2b fix): true iff a receipt COULD be appended
   * for this principal right now. The caller checks this BEFORE dispatching —
   * a consequential call whose receipt can't be written must not happen.
   */
  canReceipt(run: ContractRun, principalKeyId: string): boolean;
  runFor(runId: string): ContractRun | undefined;
  /**
   * O-3: the run a call routes to — by (keyId, mcpSessionId) above
   * CONTRACT_MAX_RUNS_PER_KEY=1, by keyId alone at the default cap.
   */
  runIdForPrincipal(keyId: string, mcpSessionId?: string): string | undefined;
  /**
   * Pre-bind routing: true once the run has ended — terminal, TTL-expired, or
   * half-bound past its bind deadline (#179). The run stays observable, but
   * its seats are released (#176) and its chain no longer captures the bound
   * keyIds' pre-bind calls.
   */
  runEnded(run: ContractRun): boolean;
  /** N4b-8 (gap 4): whether a run anchor is configured (contract_status uses it for the "disabled" summary). */
  readonly anchorConfigured: boolean;
  /** N4b-10 (D13): the configured settlement rail id — "simulated" or "stripe_test_mode" (contract_status reports it). */
  readonly settlementRailId: "simulated" | "stripe_test_mode";
  /**
   * N4b-9 (F14): the persisted terminal job for a run — survives restart,
   * so contract_status can still render a terminal run whose in-memory
   * record is gone.
   */
  terminalJobFor(runId: string): TerminalJob | undefined;
  /** N4b-9 (F14): persisted jobs still owed work (close delivery or anchor confirmation) — for boot recovery. */
  pendingTerminalJobs(): TerminalJob[];
  /**
   * N4b-9 (F14): record a terminal-close delivery outcome. Mints the
   * evidence onto the run chain while the run lives; after a restart the
   * run is gone and the receipt is minted into the job's persisted
   * evidence (same signer, chained on the recorded transition tip).
   */
  recordTerminalOutcome(
    runId: string,
    outcome: "delivered" | "failed",
    detail: { receiptDigest: string; attempts: number; lastError?: string; response?: unknown },
  ): void;
  /** N4b-9 (F14): persist emitter delivery state into the outbox job. */
  persistTerminalClose(runId: string, state: { status: "delivering" | "delivered" | "failed"; attempts: number; lastError?: string; deliveredAt?: string }): void;
  /**
   * N4b-9 (F14): bounded shutdown drain — waits for in-flight anchor calls
   * and the wired `onDrain` (close emitter) up to `deadlineMs`. A deadline
   * expiry never hangs shutdown; unfinished jobs stay persisted for the
   * next boot.
   */
  drain(deadlineMs: number): Promise<void>;
  /**
   * Move a run to its terminal state and retire the sim world entry
   * (post-terminal retention lives in the world itself). The triggering
   * principal rides along so the close emitter can receipt the delivery
   * outcome against the caller that ended the run.
   */
  endRun(run: ContractRun, terminalState: string, principal?: ContractPrincipal, reason?: ContractTerminalReason): void;
  /**
   * M1/N4b-3: append to the principal's active PRE-BIND segment — segments
   * seal at each bind and roll by count, so polling can never lock a
   * principal out of the evidence chain.
   */
  recordPreBind(
    principal: ContractPrincipal,
    fields: Omit<ReceiptFields, "runId" | "principal">,
  ): { ok: true; receipt: ServerReceipt } | { ok: false; code: ContractRefusalCode };
  /** Seal the active pre-bind segment at a successful bind (N4b-3). */
  sealPreBindSegment(keyId: string, mcpSessionId?: string): void;
  /**
   * CDT-SEC M3: the transport dropped this MCP session (closed, deleted or
   * idle-swept). Above cap 1 its pre-bind chain is evicted unless a bind
   * captured it (then it goes when that run is dropped). Optional so test
   * doubles of the service need not implement it.
   */
  sessionDropped?(keyId: string, mcpSessionId: string): void;
  /**
   * A principal's segmented pre-bind chain for the observer feed. O-3:
   * above cap 1 the chain is per MCP session — `mcpSessionId` selects it.
   */
  preBindFeed(keyId: string, mcpSessionId?: string): {
    principalKeyId: string;
    head: string;
    /** prevHash the oldest RETAINED receipt links to — genesis unless rolled. */
    anchor: string;
    /** True when older segments have rolled off (truncated prefix). */
    truncated: boolean;
    receipts: ServerReceipt[];
    segments: { anchor: string; receipts: ServerReceipt[] }[];
  } | undefined;
  /** Read-only receipt feed for the observer endpoint (N4b-2b): head + chain. */
  receiptFeed(runId: string): {
    runId: string;
    head: string;
    receipts: ServerReceipt[];
    /** M1: each bound principal's pre-bind chain, served beside the run's. */
    preBind: (NonNullable<ReturnType<ContractService["preBindFeed"]>> & { role: ContractRole })[];
    /**
     * N6g-2 (observer H1): SIMULATED labels keyed by the receipt that
     * carried sim-derived evidence — always present (possibly empty).
     */
    simLabels: {
      receiptId: string;
      simulated: boolean;
      /** N4b-10 (D13): settlement-family labels carry the rail + its text. */
      paymentRail?: "simulated" | "stripe_test_mode";
      label?: string;
    }[];
    /**
     * N6g-2 (observer R12): the consequential-submit approval records the
     * service verified. `digest` is the RECEIPT linkage — the `*_prepare`
     * responseDigest covering the approved envelope; `ts` is ISO-8601.
     * Wire decision vocabulary ("allow"/"deny") is kept verbatim.
     */
    approvalRecords?: {
      role: ContractRole;
      action: string;
      digest: string;
      policyDigest: string;
      decision: string;
      ts: string;
      approverKeyId: string;
      signature: string;
    }[];
    /**
     * N6g-2 (observer R10c): the surface's published guidance digests per
     * role — exactly what `tools/list` and `initialize.instructions` serve.
     */
    guidance: Record<ContractRole, GuidanceDigests>;
  } | undefined;
  /**
   * M4: the per-scope argsDigest salt — `{ runId }` for a run's salt,
   * `{ keyId }` for a principal's pre-bind salts (one PER SEGMENT — `salt`
   * is the active segment's, `salts` covers every retained segment).
   * Disclosed ONLY through the verifier-scoped endpoint.
   */
  saltFor(query: { runId?: string; keyId?: string; mcpSessionId?: string }):
    { scope: "run" | "pre-bind"; id: string; salt: string; salts?: string[] } | undefined;
  /** M4: a principal's ACTIVE pre-bind segment salt (lazily created). O-3: per session above cap 1. */
  preBindSaltFor(keyId: string, mcpSessionId?: string): string;
  /**
   * Mandates without a restart: register a principal-signed buyer policy
   * digest (policy-registry.ts). The caller receipts the call.
   */
  registerPolicy: PolicyRegistry["register"];
  /**
   * Server-side anchors: serve a pinned brief; CDT-SEC M4: one anchor per
   * brief digest shared by every scope (the run, else the pre-bind chain).
   */
  getBrief: ServerAnchors["getBrief"];
  /** Bounded wait for a terminal run's final anchor (contract_status awaits it before reporting). */
  awaitFinalAnchor(runId: string): Promise<void>;
  /** The pre-bind scope id for brief anchors served before a bind. */
  preBindBriefScope(keyId: string, mcpSessionId?: string): string;
  /**
   * M5: the env-gated surface features this service serves (all off = the
   * b04059e surface). The transport, the server card and the receipt feed
   * read guidance through it.
   */
  readonly features: ContractFeatures;
  /**
   * M5: CONTRACT_SERVER_ANCHORS=1 — the server-side terms / brief / final
   * anchors fire (with an anchor configured) and contract_status reports
   * them. Off = the b04059e anchors only.
   */
  readonly serverAnchors: boolean;
  /** CDT-GAPS gap 1: CONTRACT_ROLE_BRIEFS is configured (per-role brief anchors). */
  readonly roleBriefs: boolean;
  /**
   * CONTRACT_MILESTONE_LOG=1 with a log-capable anchor configured: the six
   * per-milestone entries are written and contract_status reports them
   * (anchors.milestones). Off = no milestone state, no surface change.
   */
  readonly milestoneLog: boolean;
  /** CONTRACT_MILESTONE_LOG: this run's Clockchain calls (writes + lookups) through the run anchor; undefined when off. */
  clockchainCallsFor(runId: string): { writes: number; lookups: number } | undefined;
  /** The business-tool semantics layer (everything except bind/status). */
  business: BusinessOps;
  /** Release the state-dir lock (simulate a restart in tests / shutdown). */
  close(): void;
}

const boundKeySchema = z.object({
  keyId: z.string().min(1).max(64),
  // lower-case even-length hex only (LOW): upper-case or odd-length forms are
  // rejected outright rather than normalised.
  publicKeyHex: z.string().regex(/^0x(?:[0-9a-f]{2}){32,66}$/),
}).strict();

const DEFAULT_MAX_RUNS = 1024;
const DEFAULT_MAX_RECEIPTS_PER_RUN = 4096;
const DEFAULT_MAX_RECEIPTS_PER_PRINCIPAL = 512;
/**
 * N4b-3 review fix: the pre-bind chain is SEGMENTED, never a single capped
 * array — a segment seals at each bind and rolls at `preBindSegmentMax`
 * receipts; the oldest segments roll off past `preBindMaxSegments`. Each new
 * segment's first receipt's `prevHash` is the prior segment's head (the
 * anchor is carried forward, so the retained window stays verifiable), and
 * each segment carries its OWN argsDigest salt (LOW: salts rotate).
 */
interface PreBindSegment {
  salt: string;
  receipts: ServerReceipt[];
  sealed: boolean;
}
const DEFAULT_PREBIND_SEGMENT_MAX = 256;
const DEFAULT_PREBIND_MAX_SEGMENTS = 8;
/** CDT-SEC M3: pre-bind chains kept per keyId above cap 1 (oldest uncaptured evicted). */
export const MAX_PREBIND_CHAINS_PER_KEY = 16;
/** N4b-7: outstanding bind-statement challenge caps (swept by TTL). */
const MAX_BIND_CHALLENGES = 1024;
const MAX_BIND_CHALLENGES_PER_PRINCIPAL = 8;
/** The runId sentinel pre-bind receipts are scoped under (no run exists yet). */
const PRE_BIND_SCOPE = "pre-bind";

/**
 * N6g-2 (observer H1): tools whose receipted evidence is sim-derived. The
 * tool def's `simulated` flag covers the data calls; the sim-family
 * `*_prepare` responses are signed envelopes whose payloads bind sim-world
 * artifacts (booking terms on the sim board, the sim-rail settlement
 * amount) — they are labelled SIMULATED in the feed the same way.
 */
const SIM_LABELLED_TOOLS: ReadonlySet<string> = new Set([
  ...CONTRACT_TOOL_DEFS.filter((d) => d.simulated).map((d) => d.name),
  "booking_prepare",
  "booking_cancel_prepare",
  "settlement_prepare",
]);
const RUN_TTL_MS = 24 * 3600_000; // LLD §3: run-scoped state TTL is 24h
/** QA F-5: default bound on how long a run may stay half-bound after its first bind. */
export const DEFAULT_HALF_BOUND_TIMEOUT_MS = 10 * 60_000;
/** QA F-5: server-recorded reasons for a terminal transition. */
export type ContractTerminalReason = "counterparty_never_bound";
const USED_SESSIONS_FILE = "used-sessions.json";
const USED_MANDATES_FILE = "used-mandates.json";
const AGENT_BINDINGS_FILE = "agent-bindings.json";
const LOCK_FILE = "used-sessions.lock";

/**
 * Fail CLOSED (N1): an absent file means a fresh dir; a file that exists but
 * is unreadable, unparseable or wrongly shaped is a hard startup error — the
 * route must answer misconfigured, never silently start from "empty".
 */
function loadUsedSessions(stateDir: string): Map<string, string> {
  const file = path.join(stateDir, USED_SESSIONS_FILE);
  if (!existsSync(file)) return new Map();
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!isPlainRecord(raw) || !isPlainRecord(raw.sessions)) {
    throw new Error(`corrupt ${USED_SESSIONS_FILE}`);
  }
  for (const v of Object.values(raw.sessions)) {
    if (typeof v !== "string") throw new Error(`corrupt ${USED_SESSIONS_FILE}`);
  }
  return new Map(Object.entries(raw.sessions) as [string, string][]);
}

/**
 * N4b-7 late binding: the agentId a `*`-token keyId was bound to, durable —
 * `{keyId: {agentId, runId}}`. While that run is live, a second bind of the
 * same token to a different agentId or a different run refuses
 * STATE_REFUSED; once the run is terminal / TTL-expired / dropped, the next
 * run's bind replaces the record (late-bind release).
 */
interface AgentBinding {
  agentId: string;
  runId: string;
}

/**
 * N4b-7: a `contract_bind_challenge` nonce — issued to one principal keyId,
 * single-use, short-TTL. `used` flips only when a statement carrying it
 * commits to a bound seat.
 */
interface BindChallenge {
  keyId: string;
  /** LOW-4: issue time — the statement's issuedAt must sit within
   *  [issuedAtMs, issuedAtMs + TTL], not merely before server expiry. */
  issuedAtMs: number;
  expiresAtMs: number;
  used: boolean;
}

/**
 * Same fail-closed rule as used-sessions: corrupt ≠ empty (N1).
 * O-3: a keyId maps to a LIST of bindings (one per live run, bounded by
 * CONTRACT_MAX_RUNS_PER_KEY). The on-disk form stays `{agentId, runId}`
 * for a single binding — byte-compatible with the pre-O-3 file — and is an
 * array only when a keyId holds more than one.
 */
function loadAgentBindings(stateDir: string): Map<string, AgentBinding[]> {
  const file = path.join(stateDir, AGENT_BINDINGS_FILE);
  if (!existsSync(file)) return new Map();
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!isPlainRecord(raw) || !isPlainRecord(raw.bindings)) {
    throw new Error(`corrupt ${AGENT_BINDINGS_FILE}`);
  }
  const isBinding = (v: unknown): v is AgentBinding =>
    isPlainRecord(v) && typeof v.agentId === "string" && typeof v.runId === "string";
  const out = new Map<string, AgentBinding[]>();
  for (const [keyId, v] of Object.entries(raw.bindings)) {
    const list = Array.isArray(v) ? v : [v];
    if (list.length === 0 || !list.every(isBinding)) {
      throw new Error(`corrupt ${AGENT_BINDINGS_FILE}`);
    }
    out.set(keyId, list.map((b) => ({ agentId: b.agentId, runId: b.runId })));
  }
  return out;
}

/** Same durable-write discipline as persistUsedSessions (N1). */
function persistAgentBindings(stateDir: string, bindings: ReadonlyMap<string, readonly AgentBinding[]>): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, AGENT_BINDINGS_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    const wire = Object.fromEntries(
      [...bindings].map(([keyId, list]) => [keyId, list.length === 1 ? list[0] : list]),
    );
    writeFileSync(fd, JSON.stringify({ bindings: wire }));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dirFd = openSync(stateDir, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

/**
 * N4b-7 (P-GAP, DRAFT schema): verify a bind statement — the caller's proof
 * that it possesses the handshake session key of the certificate side it
 * claims. EVERY field check lives here so the audit agent's final schema
 * (PR #159) is a one-place change: domain/runId/side/tokenKeyId/serverKeyId
 * must name this exact bind, the challenge must be live, unconsumed and
 * issued to this principal, and the EIP-191 signature over
 * canonicalDigest(statement) must recover to the certificate party's
 * `sessionKeyAddress` — NOT the hostSessionKeyCertificate.
 */
function verifyBindStatement(fields: {
  statement: unknown;
  signatureHex: unknown;
  principal: ContractPrincipal;
  sessionId: string;
  serverKeyId: string;
  expectedSessionKeyAddress: string;
  challenge: BindChallenge | undefined;
  challengeTtlMs: number;
  nowMs: number;
}): boolean {
  const st = fields.statement;
  if (!isPlainRecord(st)) return false;
  if (
    st.domain !== "agent-contract.bind/v1" ||
    st.runId !== fields.sessionId ||
    st.side !== fields.principal.side ||
    st.tokenKeyId !== fields.principal.keyId ||
    st.serverKeyId !== fields.serverKeyId ||
    typeof st.challenge !== "string" ||
    typeof st.issuedAt !== "string"
  ) return false;
  const ch = fields.challenge;
  if (ch === undefined || ch.used || ch.expiresAtMs <= fields.nowMs || ch.keyId !== fields.principal.keyId) {
    return false;
  }
  // LOW-4: issuedAt is bounded to the challenge's own window — a statement
  // predating the challenge (or outliving its TTL) proves nothing about
  // this nonce.
  const issuedAtMs = Date.parse(st.issuedAt);
  if (
    !Number.isFinite(issuedAtMs) ||
    issuedAtMs < ch.issuedAtMs ||
    issuedAtMs > ch.issuedAtMs + fields.challengeTtlMs
  ) return false;
  // LOW-5: the statement path requires canonical signature form — v in
  // {27,28} and low-s — before recovery (role-sig semantics untouched).
  if (typeof fields.signatureHex !== "string" || !isCanonicalEip191Signature(fields.signatureHex)) {
    return false;
  }
  const recovered = eip191RecoverPublicKey(Buffer.from(canonicalDigest(st).slice(2), "hex"), fields.signatureHex);
  if (recovered === null) return false;
  return publicKeyToAddress(recovered).toLowerCase() === fields.expectedSessionKeyAddress.toLowerCase();
}

/** Durable write: tmp file → fsync → rename → fsync the directory (N1). */
function persistUsedSessions(stateDir: string, used: ReadonlyMap<string, string>): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, USED_SESSIONS_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ sessions: Object.fromEntries(used) }));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dirFd = openSync(stateDir, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

/**
 * LOW (N4b-3): a used-mandate record carries the mandate's expiry so entries
 * can be pruned once `expiresAt + grace` has passed. `expiresAtMs: null`
 * means "no expiry on record" (legacy string entries from the v1 file
 * shape) — those are kept forever: pruning what you can't prove expired
 * would silently re-open single-use.
 */
interface UsedMandate {
  runId: string;
  expiresAtMs: number | null;
}

/**
 * Used mandateIds per family principal — same durability contract as
 * used-sessions (N4B2B-CHANGES-2 §3): absent file = fresh dir; a corrupt or
 * unreadable record is a hard startup error, never silently "empty".
 * LOW (N4b-3): entries past `expiresAt + grace` are pruned at load; the v1
 * file shape (plain string values) is still accepted and never pruned.
 */
function loadUsedMandates(
  stateDir: string,
  nowMs: number,
  graceMs: number,
): Map<string, UsedMandate> {
  const file = path.join(stateDir, USED_MANDATES_FILE);
  if (!existsSync(file)) return new Map();
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!isPlainRecord(raw) || !isPlainRecord(raw.mandates)) {
    throw new Error(`corrupt ${USED_MANDATES_FILE}`);
  }
  const out = new Map<string, UsedMandate>();
  for (const [k, v] of Object.entries(raw.mandates)) {
    let record: UsedMandate;
    if (typeof v === "string") {
      record = { runId: v, expiresAtMs: null }; // legacy v1 entry
    } else if (
      isPlainRecord(v) && typeof v.runId === "string" &&
      (typeof v.expiresAt === "string" || v.expiresAt === null || v.expiresAt === undefined)
    ) {
      const expiresAtMs = typeof v.expiresAt === "string" ? Date.parse(v.expiresAt) : null;
      if (expiresAtMs !== null && !Number.isFinite(expiresAtMs)) {
        throw new Error(`corrupt ${USED_MANDATES_FILE}`);
      }
      record = { runId: v.runId, expiresAtMs };
    } else {
      throw new Error(`corrupt ${USED_MANDATES_FILE}`);
    }
    // Pruned at load ONLY when expiry is provable and past the grace window.
    if (record.expiresAtMs !== null && nowMs > record.expiresAtMs + graceMs) continue;
    out.set(k, record);
  }
  return out;
}

/** Durable write — identical fsync/rename discipline to used-sessions. */
function persistUsedMandates(stateDir: string, used: ReadonlyMap<string, UsedMandate>): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, USED_MANDATES_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  // v2 on-disk shape: {runId, expiresAt} — expiry rides as the original ISO
  // timestamp (or null for legacy never-expire entries).
  const mandates = Object.fromEntries(
    [...used.entries()].map(([k, v]) => [
      k,
      { runId: v.runId, expiresAt: v.expiresAtMs === null ? null : new Date(v.expiresAtMs).toISOString() },
    ]),
  );
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ mandates }));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dirFd = openSync(stateDir, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

/**
 * Exclusive lock on the state directory (N2 + pre-N7 fixes):
 * - The lock records {pid, bootId}. The container runs node as PID 1, so a
 *   recycled pid is alive forever — a lock whose pid is OURS but whose bootId
 *   is not this process's boot id is stale (a prior boot) and is recovered.
 * - The lock body is written to a temp file and HARD-LINKED into place, so an
 *   empty or half-written lock file can only exist if we crashed mid-link —
 *   it is never treated as stale (fail closed: refuse, don't take over).
 * - SIGTERM/SIGINT release the lock before exit.
 */
const PROCESS_BOOT_ID = randomBytes(16).toString("hex");

function acquireStateLock(stateDir: string, preExit?: () => Promise<void>): () => void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, LOCK_FILE);
  linkLock(file);
  let held = true;
  // N4b-9 (F14): drain terminal jobs for a bounded window before release —
  // a graceful shutdown still delivers/persists what it can.
  const onTerm = () => {
    void Promise.resolve(preExit?.())
      .finally(() => { try { release(); } finally { process.exit(143); } });
  };
  const onInt = () => {
    void Promise.resolve(preExit?.())
      .finally(() => { try { release(); } finally { process.exit(130); } });
  };
  process.on("SIGTERM", onTerm);
  process.on("SIGINT", onInt);
  function release(): void {
    if (held) {
      held = false;
      process.off("SIGTERM", onTerm);
      process.off("SIGINT", onInt);
      rmSync(file, { force: true });
    }
  }
  return release;
}

function linkLock(file: string): void {
  const tmp = `${file}.${process.pid}.${PROCESS_BOOT_ID}.tmp`;
  for (let attempt = 0; attempt < 2; attempt++) {
    writeFileSync(tmp, JSON.stringify({
      pid: process.pid,
      bootId: PROCESS_BOOT_ID,
      at: new Date().toISOString(),
    }));
    try {
      linkSync(tmp, file); // atomic create — EEXIST if a lock is present
      return;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    } finally {
      rmSync(tmp, { force: true });
    }
    const holder = lockHolder(file);
    if (holder === null) {
      // Unreadable/empty/half-written — never treated as stale; refuse.
      throw new Error(`contract state dir lock is unreadable: ${file}`);
    }
    const stale =
      (holder.pid === process.pid && holder.bootId !== PROCESS_BOOT_ID) ||
      (holder.pid !== process.pid && !pidAlive(holder.pid));
    if (!stale) {
      throw new Error(`contract state dir is locked by pid ${holder.pid}: ${file}`);
    }
    rmSync(file, { force: true }); // stale — break and retry the link once
  }
  throw new Error(`contract state dir is locked: ${file}`);
}

interface LockHolder { pid: number; bootId: string | undefined }

function lockHolder(file: string): LockHolder | null {
  try {
    const raw = JSON.parse(readFileSync(file, "utf8"));
    const pid = Number(raw?.pid);
    if (!Number.isInteger(pid) || pid <= 0) return null;
    return { pid, bootId: typeof raw?.bootId === "string" ? raw.bootId : undefined };
  } catch {
    return null;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** N11f: registry addresses compare case-insensitively (checksummed vs lowercase). */
function sameAddress(a: unknown, b: unknown): boolean {
  return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
}

/** N11f: a role's policy pin — one digest, or a set (the buyer digest rotates per run). */
export type PolicyDigestPin = string | readonly string[] | ReadonlySet<string>;
/** Hard cap on digests per role. */
export const MAX_POLICY_DIGESTS_PER_ROLE = 64;

/**
 * Validate and normalize `policyDigests` to a Set per role. Every digest must
 * be exact lowercase `0x` + 64 hex; each role needs 1..64 distinct digests.
 */
export function normalizePolicyDigests(
  raw: Readonly<Record<ContractRole, PolicyDigestPin>> | undefined,
): Readonly<Record<ContractRole, ReadonlySet<string>>> {
  const fail = (): never => {
    throw new Error(
      `policyDigests {buyer,provider} are required (1..${MAX_POLICY_DIGESTS_PER_ROLE} per role, each 0x + 64 lower hex)`,
    );
  };
  if (raw === undefined || raw === null) return fail();
  const one = (pin: PolicyDigestPin | undefined): ReadonlySet<string> => {
    const list = typeof pin === "string" ? [pin] : pin === undefined ? [] : [...pin];
    if (list.length === 0 || list.length > MAX_POLICY_DIGESTS_PER_ROLE) return fail();
    for (const d of list) if (typeof d !== "string" || !/^0x[0-9a-f]{64}$/.test(d) || /^0x0{64}$/.test(d)) return fail();
    return new Set(list);
  };
  return Object.freeze({ buyer: one(raw.buyer), provider: one(raw.provider) });
}

export function createContractService(options: {
  hostRoots: readonly HostRootPin[];
  signer: ContractSigner;
  now?: () => number;
  graceMs?: number;
  stateDir?: string;
  /**
   * N4b-11 (L3): retention cap on FINISHED jobs persisted to
   * `terminal-jobs.json` (default 256) — the file cannot grow forever.
   * A job is finished once its close is delivered/failed/absent AND no
   * anchor job is still anchoring/pending; unfinished jobs are never
   * dropped, and the least-recently-updated finished jobs go first.
   */
  terminalJobsMaxFinished?: number;
  maxRuns?: number;
  /**
   * O-3: `CONTRACT_MAX_RUNS_PER_KEY` — live runs one bearer keyId may hold
   * at once (default 1 = one live run per keyId, the pre-O-3 behaviour).
   * Above 1, runs are routed per (keyId, mcpSessionId) — see run-routing.ts.
   */
  maxRunsPerKey?: number;
  maxReceiptsPerRun?: number;
  maxReceiptsPerPrincipal?: number;
  runTtlMs?: number;
  /**
   * QA F-5: how long (ms) a run may stay HALF-BOUND after its first bind
   * before it ends `expired_unbound` (reason `counterparty_never_bound`) and
   * releases the bound party's key. Default 10 min; 0 = only the
   * certificate window (validUntil + grace) bounds it, as before.
   * Env: CONTRACT_HALF_BOUND_TIMEOUT_MS.
   */
  halfBoundTimeoutMs?: number;
  /**
   * CDT-GAPS gap 2: CONTRACT_EXPIRE_AT_TTL=1 (default off). A run still
   * non-terminal at its TTL is ENDED, not silently dropped: terminal state
   * `expired` (both roles bound) or `expired_unbound` (a role missing), with
   * the terminal job, terminal anchor, close and final anchor of any other
   * terminal transition. Off: the run is dropped at its TTL as before.
   */
  expireAtTtl?: boolean;
  /**
   * CDT-GAPS gap 2: how long a TTL-expired run stays in memory (observable,
   * its close/anchor outcomes chained on the live run) before it is dropped
   * (default 15 min).
   */
  expiredHoldMs?: number;
  /** Optional pin: certificates must attest this exact ERC-8004 chain+registry. */
  expectedErc8004?: { chainId: string; registryAddress: string };
  /** Test seam (CDT-SEC M2): the policy-registration secp256k1 recovery. */
  recoverPolicySigner?: (digest32: Buffer, signature: string) => Uint8Array | null;
  /** Closed sim world (ticketing + payment rail); one is created if absent. */
  sim?: SimWorld;
  /**
   * N4b-5: config-only sim fault seeds keyed by runId (A2 adverse cases).
   * Applied only when the service creates the world (`sim` absent); an
   * injected world carries its own seeds. Never reachable via tool args.
   */
  simFaults?: Readonly<Record<string, SimFaults>>;
  /** N4b-3: receipts per pre-bind chain segment before it rolls (default 256). */
  preBindSegmentMax?: number;
  /** N4b-3: retained pre-bind segments per principal (default 8). */
  preBindMaxSegments?: number;
  /**
   * N4b-4: the published key's `validUntil` (ms epoch; null/undefined = no
   * expiry). Past it, the server REFUSES TO SIGN — no receipts, no envelopes,
   * so no call may dispatch at all (everything is evidenced or refused).
   */
  signerValidUntilMs?: number | null;
  /**
   * §13 policy pins, REQUIRED (N4b-2b fix): `CONTRACT_POLICY_DIGESTS` —
   * `buyer:0x…,provider:0x…`. Approval records must carry exactly the role's
   * pinned digest; no pin means no consequential action can ever pass.
   */
  policyDigests: Readonly<Record<ContractRole, PolicyDigestPin>>;
  /** `CONTRACT_PRINCIPALS`: buyer keyId → pinned family-principal address. */
  principals?: ReadonlyMap<string, string>;
  /** O-2: `CONTRACT_DIRECTORY` — directory name → pinned provider keyId. */
  directory?: ReadonlyMap<string, string>;
  /**
   * N4b-7 (P-GAP): `CONTRACT_REQUIRE_BIND_STATEMENT=1` — every contract_bind
   * must carry a verified session-key possession statement. At L the
   * statement is optional but a presented one is still verified.
   */
  requireBindStatement?: boolean;
  /** N4b-7: `contract_bind_challenge` nonce TTL (default 60s). */
  bindChallengeTtlMs?: number;
  /**
   * N4b-8 (gap 2): accept legacy unbound v:2 seals — CONTRACT_LEVEL=L only.
   * Absent/false: only the listing-bound v:4 wire delivers.
   */
  allowLegacySealV2?: boolean;
  /**
   * N4b-8 (gap 3): terminal-transition hook — the config layer wires the
   * telemetry close emitter here. Fired once per run at endRun, AFTER the
   * terminal state is recorded; the triggering principal is passed so the
   * delivery outcome can be receipted on the run chain.
   */
  onTerminalRun?: (run: ContractRun, terminalState: string, principal: ContractPrincipal | undefined, receipt: TerminalReceipt) => void;
  /**
   * O-1: mints the terminal receipt in place of the v1 default — the config
   * layer wires telemetry-lanes.ts here (v2 for a lane-linked run).
   */
  mintTerminalReceipt?: (fields: TerminalReceiptFields, signer: ContractSigner) => TerminalReceipt;
  /**
   * O-1: fired once both seats are bound — the config layer links the run's
   * lanes. Integration (O-1 x O-3): above CONTRACT_MAX_RUNS_PER_KEY=1 it
   * carries, per role, the MCP sessions the router maps to THIS run, so a
   * run links only its own sessions' lanes (never a sibling run's). At cap 1
   * it is undefined and every unlinked lane of the bound keyIds is linked.
   */
  onRunBound?: (run: ContractRun, sessions?: Record<ContractRole, string[]>) => void;
  /**
   * CDT-SEC L5: above cap 1, an MCP session dropped while routed to no run —
   * no bind can capture its telemetry lane any more (O-3 links only the
   * sessions routed to the run), so the lane store may release it.
   */
  onSessionReleased?: (keyId: string, mcpSessionId: string) => void;
  /**
   * N4b-9 (F14): awaited inside `drain(deadlineMs)` — the config layer wires
   * the close emitter's bounded flush here.
   */
  onDrain?: () => Promise<void>;
  /**
   * N4b-8 (gap 4): the run anchor — production wiring is
   * `createTsaContractAnchor` (tsa_issue over the in-process Clockchain
   * client); tests inject a fake. Anchors the agreement digest at formation
   * and the receipt-chain head at terminal; outcomes land on run.anchors
   * and are receipted (anchored AND failed).
   */
  anchor?: ContractAnchor;
  /**
   * N4b-9 (F13): delay before re-confirming a `pending_confirmation`
   * anchor write (default 30s), and the max confirm attempts before the
   * job rests as `pending` (restart recovery resumes it). 0 disables.
   */
  anchorConfirmDelayMs?: number;
  anchorConfirmMaxAttempts?: number;
  /**
   * Server-side anchors (server-anchors.ts): the frozen, digest-pinned
   * brief templates served by contract_get_brief (CONTRACT_BRIEFS), and
   * the bounded waits for the brief anchor (before the brief returns) and
   * the final anchor (before contract_status reports a terminal run).
   */
  briefs?: ReadonlyMap<string, ContractBrief>;
  /** M5: CONTRACT_SERVER_ANCHORS=1 (default off) — fire terms/brief/final anchors. */
  serverAnchors?: boolean;
  /**
   * CONTRACT_MILESTONE_LOG=1 (default off) — write the per-milestone
   * Clockchain log (milestone-log.ts) through `anchor.log`. Inert without
   * an anchor that implements `log`.
   */
  milestoneLog?: boolean;
  /**
   * CDT-GAPS gap 1: CONTRACT_ROLE_BRIEFS (default off) — role → brief NAME
   * (a key of `briefs`). Each role's brief is anchored in its own slot and
   * bound by that role's contract_bind (`briefDigest`); a configured brief's
   * anchor is issued at start-up. Present (even with one role) = role mode.
   */
  roleBriefs?: Partial<Record<ContractRole, string>>;
  /**
   * M5: CONTRACT_POLICY_REGISTRATION=1 (default off) — serve
   * contract_register_policy; off, persisted registrations authorize nothing.
   */
  policyRegistration?: boolean;
  /**
   * Flexible family policy: CONTRACT_FLEX_POLICY=1 (default off) — accept the
   * v3 mandate and the per-run `trip` on mandate_submit; off, both are refused
   * and the surface is byte-identical to before.
   */
  flexPolicy?: boolean;
  /** CONTRACT_PRIVATE_FLOOR=1 (default off): all-in pricing + the provider-side private floor (business.ts). */
  privateFloor?: { floorBps: number };
  briefAnchorAwaitMs?: number;
  /** CDT-SEC M4: minimum wait before a failed brief anchor is retried (default 60 s). */
  briefRetryMs?: number;
  finalAnchorAwaitMs?: number;
  /** Injectable for tests; defaults to an unref'd setTimeout. */
  sleep?: (ms: number) => Promise<void>;
  /**
   * N4b-10 (spec D13): the Stripe TEST-mode settlement rail
   * (CONTRACT_SETTLEMENT_RAIL=stripe_test_mode). Absent = the default
   * simulated rail. Passed through to business — only the settlement
   * prepare/authorize cases touch it.
   */
  settlementRail?: SettlementRail;
}): ContractService {
  const now = options.now ?? Date.now;
  const sim = options.sim ?? createSimWorld({
    now,
    ttlMs: options.runTtlMs ?? RUN_TTL_MS,
    faults: options.simFaults,
  });
  const maxRuns = options.maxRuns ?? DEFAULT_MAX_RUNS;
  const maxReceiptsPerRun = options.maxReceiptsPerRun ?? DEFAULT_MAX_RECEIPTS_PER_RUN;
  const maxReceiptsPerPrincipal = options.maxReceiptsPerPrincipal ?? DEFAULT_MAX_RECEIPTS_PER_PRINCIPAL;
  const runTtlMs = options.runTtlMs ?? RUN_TTL_MS;
  const halfBoundTimeoutMs = options.halfBoundTimeoutMs ?? DEFAULT_HALF_BOUND_TIMEOUT_MS;
  const expireAtTtl = options.expireAtTtl === true;
  const expiredHoldMs = options.expiredHoldMs ?? 15 * 60_000;
  /** CDT-GAPS gap 2: runId → when its TTL expiry was made terminal. */
  const ttlExpiredAt = new Map<string, number>();
  // Fail closed at construction: without the policy pins every approval
  // check would be ambiguous — never silently degrade.
  const policyDigests = normalizePolicyDigests(options.policyDigests);
  // M5: each surface feature is on only when its env configured it.
  const features: ContractFeatures = Object.freeze({
    ...((options.directory?.size ?? 0) > 0 ? { directory: true } : {}),
    ...(options.policyRegistration === true ? { policyRegistration: true } : {}),
    ...(options.flexPolicy === true ? { flexPolicy: true } : {}),
    ...((options.briefs?.size ?? 0) > 0 ? { briefs: true } : {}),
  });
  const serverAnchorsOn = options.serverAnchors === true;
  // CONTRACT_MILESTONE_LOG (default off) — live only with a log-capable anchor.
  const milestoneLogOn = options.milestoneLog === true && options.anchor?.log !== undefined;
  /**
   * Milestone log: per-run Clockchain call counts (writes + lookups through
   * the run anchor), reported in contract_status. Shared brief anchors are
   * not a run's calls. Off: no wrapper — `runAnchor` IS options.anchor.
   */
  const clockchainCalls = new Map<string, { writes: number; lookups: number }>();
  /** anchorId / ledgerId → runId, so a confirm (which names no run) is counted. */
  const callOwner = new Map<string, string>();
  /**
   * Review M3: counting never writes terminal-jobs.json by itself. A live
   * run's count is in memory and rides the next tracker/entry save (and the
   * endRun enqueue); a run no longer in memory counts onto its job object,
   * persisted with the next save of the outbox.
   */
  const countCall = (runId: string | undefined, writes: number, lookups: number): void => {
    if (runId === undefined || (writes === 0 && lookups === 0)) return;
    const job = runs.has(runId) ? undefined : outbox.get(runId);
    const c = job !== undefined
      ? (job.clockchainCalls ??= { writes: 0, lookups: 0 })
      : clockchainCalls.get(runId) ?? { writes: 0, lookups: 0 };
    c.writes += writes;
    c.lookups += lookups;
    if (job === undefined) clockchainCalls.set(runId, c);
  };
  const runAnchor: ContractAnchor | undefined = !milestoneLogOn || options.anchor === undefined
    ? options.anchor
    : (() => {
        const base = options.anchor;
        const owned = (runId: string | undefined, w: AnchorWrite): AnchorWrite => {
          if (runId !== undefined) {
            callOwner.set(w.anchorId, runId);
            if (w.anchor.ledgerId !== "") callOwner.set(w.anchor.ledgerId, runId);
          }
          return w;
        };
        return {
          async anchor(input) {
            const runId = input.runId === BRIEF_ANCHOR_SUBJECT ? undefined : input.runId;
            countCall(runId, 1, 0);
            return owned(runId, await base.anchor(input));
          },
          ...(base.confirm !== undefined ? {
            async confirm(anchorId: string) {
              countCall(callOwner.get(anchorId), 0, 1);
              return base.confirm!(anchorId);
            },
          } : {}),
          async log(input) {
            const runId = input.runId;
            try {
              const w = await base.log!(input);
              countCall(runId, w.reused === true ? 0 : 1, 1);
              return owned(runId, w);
            } catch (err) {
              countCall(runId, 0, 1);
              throw err;
            }
          },
          ...(base.confirmLog !== undefined ? {
            async confirmLog(ledgerId: string) {
              countCall(callOwner.get(ledgerId), 0, 1);
              return base.confirmLog!(ledgerId);
            },
          } : {}),
        };
      })();
  // CDT-GAPS gap 1: role → brief digest. An unknown name fails construction.
  const roleBriefDigests: Partial<Record<ContractRole, string>> | undefined = (() => {
    if (options.roleBriefs === undefined) return undefined;
    const out: Partial<Record<ContractRole, string>> = {};
    for (const [role, name] of Object.entries(options.roleBriefs) as [ContractRole, string | undefined][]) {
      if (name === undefined) continue;
      const brief = options.briefs?.get(name);
      if (brief === undefined) throw new Error(`role brief ${role}:${name} is not a configured brief`);
      out[role] = brief.digest;
    }
    return out;
  })();
  const runs = new Map<string, ContractRun>();
  /** O-3: live-run routing per (keyId, mcpSessionId slot), capped per keyId. */
  const router = createRunRouter(options.maxRunsPerKey);
  /** M1/N4b-3: per-principal SEGMENTED pre-bind chains — the run genesis
   *  links each side's head (`preBindHead`); each bind seals the active
   *  segment and the oldest segments roll off past `preBindMaxSegments`.
   *  O-3: keyed by `router.chainKey(keyId, mcpSessionId)` — the keyId at
   *  cap 1, per session above it. */
  const preBindChains = new Map<string, PreBindSegment[]>();
  /** O-3: the pre-bind chain each bound seat linked at bind (`runId|role`). */
  const boundChains = new Map<string, string>();
  /**
   * CDT-SEC M3: each keyId's pre-bind chain keys, oldest first — bounds the
   * chains per keyId and lets `saltFor` read one key's chains without a scan.
   */
  const chainsByKey = new Map<string, Set<string>>();
  /** M3: chains whose MCP session dropped while a bind still captured them. */
  const orphanedChains = new Set<string>();
  const chainCaptured = (chain: string): boolean => {
    for (const linked of boundChains.values()) if (linked === chain) return true;
    return false;
  };
  function forgetChain(chain: string): void {
    preBindChains.delete(chain);
    serverAnchors.dropScope(briefScopeOf(chain));
    orphanedChains.delete(chain);
    const keyId = keyIdOfChain(chain);
    const set = chainsByKey.get(keyId);
    set?.delete(chain);
    if (set?.size === 0) chainsByKey.delete(keyId);
  }
  const preBindSegmentMax = options.preBindSegmentMax ?? DEFAULT_PREBIND_SEGMENT_MAX;
  const preBindMaxSegments = options.preBindMaxSegments ?? DEFAULT_PREBIND_MAX_SEGMENTS;
  /**
   * N4b-4 key validity at the source: once the published `validUntil` has
   * passed the signer is dead — checked in the receipt preflight AND at every
   * makeReceipt call site so nothing executes unevidenced.
   */
  const signerValidUntilMs = options.signerValidUntilMs ?? null;
  const signingOpen = (): boolean => signerValidUntilMs === null || now() <= signerValidUntilMs;
  let releaseLock: (() => void) | undefined;
  let usedSessions: Map<string, string> = new Map();
  let usedMandates: Map<string, UsedMandate> = new Map();
  // N4b-7: write-once {keyId → {agentId, runId}} for late-bound (*) tokens.
  // O-3: one entry per live run of the keyId (≤ maxRunsPerKey).
  let agentBindings: Map<string, AgentBinding[]> = new Map();
  /**
   * N4b-9 (F14): the durable terminal outbox — close receipts, anchor
   * subjects, delivery/anchor outcomes, and post-restart evidence survive
   * the in-memory run. In-memory-only when no stateDir is configured.
   */
  const outbox = createTerminalOutbox(options.stateDir, options.terminalJobsMaxFinished);
  /**
   * N4b-9 (F14): a persist failure must never strand async terminal work
   * that already executed (anchor outcome recording, post-transition
   * evidence) — the in-memory job is still recorded (every later mutation
   * retries the durable write). N4b-11 (M3): the terminal transition
   * itself does NOT take this path — `endRun` enqueues via the
   * fail-closed `outbox.updateDurable`, where a persist failure throws
   * BEFORE the run is marked terminal.
   */
  const updateJob = (runId: string, mutate: (job: TerminalJob) => void): TerminalJob | undefined => {
    try {
      return outbox.update(runId, now(), mutate);
    } catch {
      return outbox.get(runId);
    }
  };
  /**
   * F14: mint a post-transition evidence receipt into the persisted job —
   * the post-restart path, when the in-memory run is gone. Chains on the
   * job's last evidence receipt, else the recorded transition tip.
   */
  const mintJobEvidence = (job: TerminalJob, fields: Omit<ReceiptFields, "runId">): void => {
    const prev = job.evidence.at(-1) ?? job.prevReceipt ?? null;
    try {
      job.evidence.push(makeReceipt(prev, { ...fields, runId: job.runId, ts: now() }, options.signer));
    } catch { /* a mint failure must not fault the async recovery path */ }
  };
  /**
   * F14: one outcome-minting path for async terminal work (anchor results,
   * close-delivery outcomes). Run alive → mint on the run chain AND mirror
   * into the persisted job; run gone (post-restart) → mint into the job.
   */
  const recordTerminalEvidence = (
    runId: string,
    fields: Omit<ReceiptFields, "runId">,
  ): void => {
    const run = runs.get(runId);
    const job = outbox.get(runId);
    if (run !== undefined) {
      const minted = recordRunReceipt(run, fields);
      if (minted.ok && job !== undefined) {
        updateJob(runId, (j) => { j.evidence.push(minted.receipt); });
      }
      return;
    }
    if (job !== undefined) {
      updateJob(runId, (j) => mintJobEvidence(j, fields));
    }
  };
  /**
   * F14: every outstanding async anchor op (issue or confirm) — drained
   * with a deadline at shutdown.
   */
  const anchorOps = new Set<Promise<void>>();
  const trackAnchorOp = (p: Promise<void>, runId?: string): void => {
    anchorOps.add(p);
    void p.finally(() => {
      anchorOps.delete(p);
      // Server-side anchors: a settled agreement/terminal op may make the
      // run's final anchor eligible.
      if (runId !== undefined) serverAnchors.scheduleFinal(runId);
    });
  };
  /** F14: assigned after `drain` is defined; the lock's signal handlers drain through it. */
  let drainForExit: (() => Promise<void>) | undefined;
  // N4b-7: live bind-statement challenges (in-memory — a nonce never needs
  // to survive a restart; an expired/unissued one simply refuses).
  const bindChallenges = new Map<string, BindChallenge>();
  const bindChallengeTtlMs = options.bindChallengeTtlMs ?? 60_000;
  // LOW (N4b-3): retention window for used-mandate entries = expiresAt +
  // graceMs (the same clock-skew grace used elsewhere; default 10 min).
  const mandateGraceMs = options.graceMs ?? 600_000;
  if (options.stateDir !== undefined) {
    // N1/N2: lock the dir first (a second process is refused outright), then
    // load — a corrupt/unreadable record is a startup failure, not "empty".
    // F14: the SIGTERM/SIGINT handlers drain terminal jobs for a bounded
    // window (shutdownDrainMs) before the lock is released and we exit.
    releaseLock = acquireStateLock(options.stateDir, () =>
      (drainForExit ?? (() => Promise.resolve()))());
    try {
      usedSessions = loadUsedSessions(options.stateDir);
      usedMandates = loadUsedMandates(options.stateDir, now(), mandateGraceMs);
      agentBindings = loadAgentBindings(options.stateDir);
    } catch (err) {
      releaseLock();
      throw err;
    }
  }
  // Mandates without a restart: the buyer pin set business checks is LIVE —
  // env pins plus THAT keyId's unexpired, pin-current principal-signed
  // registrations (CDT-SEC M1). L1: registrations are bound to this server's
  // signer keyId and ERC-8004 chain pin.
  let policyRegistry: PolicyRegistry;
  try {
    policyRegistry = createPolicyRegistry({
      stateDir: options.stateDir,
      envBuyer: policyDigests.buyer,
      principals: options.principals,
      maxPerRole: MAX_POLICY_DIGESTS_PER_ROLE,
      now,
      audience: options.signer.keyId,
      chainId: options.expectedErc8004?.chainId ?? null,
      ...(options.recoverPolicySigner !== undefined ? { recoverPublicKey: options.recoverPolicySigner } : {}),
    });
  } catch (err) {
    releaseLock?.();
    throw err;
  }
  const livePolicyDigests: Readonly<Record<ContractRole, ReadonlySet<string>>> = Object.freeze({
    buyer: policyDigests.buyer,
    provider: policyDigests.provider,
  });
  // M1: per-keyId buyer set. M5: with registration off only the env pins
  // authorize (b04059e) — no lookup is handed to business at all.
  const buyerPolicyDigestsFor = features.policyRegistration === true
    ? (keyId: string): ReadonlySet<string> => policyRegistry.buyerFor(keyId)
    : undefined;

  /**
   * Single-use mandate ledger (N4B2B-CHANGES-2 §3): `mandateId` is claimed
   * ONCE per family principal (the mandate's signer — principalAddress, not
   * the buyer keyId). The durable record is written before the claim is
   * considered made; a write failure means the mandate never commits.
   */
  function claimMandate(
    principalAddress: string,
    mandateId: string,
    runId: string,
    expiresAtMs: number,
  ): "ok" | "used" | "unavailable" {
    const key = `${principalAddress.toLowerCase()}:${mandateId}`;
    // LOW (N4b-3): keep the in-memory ledger pruned between loads — an entry
    // whose retention window (expiresAt + grace) has passed no longer blocks.
    const t = now();
    const live = new Map<string, UsedMandate>();
    for (const [k, v] of usedMandates) {
      if (v.expiresAtMs !== null && t > v.expiresAtMs + mandateGraceMs) continue;
      live.set(k, v);
    }
    if (live.has(key)) return "used";
    const next = new Map(live);
    next.set(key, { runId, expiresAtMs });
    if (options.stateDir !== undefined) {
      try {
        persistUsedMandates(options.stateDir, next);
      } catch {
        return "unavailable";
      }
    }
    usedMandates = next;
    return "ok";
  }

  /**
   * Half-bound run release: the run is still missing a party and its
   * certificate's bind window (validUntil + grace) has closed — no bind can
   * ever verify it again, so the run can never become fully bound.
   */
  function unboundPastDeadline(run: ContractRun): boolean {
    return run.terminalState === null &&
      run.bindDeadlineMs !== undefined &&
      now() > run.bindDeadlineMs &&
      (run.bound.buyer === undefined || run.bound.provider === undefined);
  }

  function runEnded(run: ContractRun): boolean {
    return run.terminalState !== null || now() >= run.createdAtMs + runTtlMs || unboundPastDeadline(run);
  }

  /**
   * Half-bound run release: make every dead half-bound run terminal
   * `expired_unbound` (receipted terminal job, close + anchor like any other
   * terminal transition). The seat release itself does not depend on this
   * succeeding — runEnded already treats such a run as ended — so a failed
   * durable enqueue only defers the terminal record to the next sweep.
   */
  function expireUnboundRuns(): void {
    for (const run of runs.values()) {
      if (!unboundPastDeadline(run)) continue;
      try {
        endRun(run, "expired_unbound", undefined, "counterparty_never_bound");
      } catch { /* fail-closed enqueue: retried on the next sweep */ }
    }
  }

  /**
   * The ACTIVE pre-bind segment — the last one if it has room and isn't
   * sealed by a bind; otherwise a fresh segment with a fresh salt. Segments
   * roll off oldest-first once `preBindMaxSegments` is exceeded.
   */
  function activePreBindSegment(keyId: string): PreBindSegment {
    let segments = preBindChains.get(keyId);
    if (segments === undefined) {
      segments = [];
      preBindChains.set(keyId, segments);
      // M3: index the new chain under its keyId; past the per-key cap the
      // oldest chain no bind captured is evicted.
      const owner = keyIdOfChain(keyId);
      let set = chainsByKey.get(owner);
      if (set === undefined) {
        set = new Set();
        chainsByKey.set(owner, set);
      }
      set.add(keyId);
      if (set.size > MAX_PREBIND_CHAINS_PER_KEY) {
        for (const old of set) {
          if (old !== keyId && !chainCaptured(old)) {
            forgetChain(old);
            break;
          }
        }
      }
    }
    const last = segments.at(-1);
    if (last === undefined || last.sealed || last.receipts.length >= preBindSegmentMax) {
      segments.push({ salt: randomBytes(32).toString("hex"), receipts: [], sealed: false });
      while (segments.length > preBindMaxSegments) segments.shift();
    }
    return segments.at(-1)!;
  }

  /** The last receipt across all retained segments — a new segment's `prev`. */
  function preBindTailFor(keyId: string): ServerReceipt | null {
    const segments = preBindChains.get(keyId);
    if (segments === undefined) return null;
    for (let i = segments.length - 1; i >= 0; i--) {
      const tail = segments[i]!.receipts.at(-1);
      if (tail !== undefined) return tail;
    }
    return null;
  }

  /**
   * Seal the principal's active pre-bind segment — called at a successful
   * bind so subsequent pre-bind evidence starts a fresh segment with a
   * rotated salt (N4b-3). A no-op when the chain is empty.
   */
  function sealPreBindSegment(keyId: string): void {
    const last = preBindChains.get(keyId)?.at(-1);
    if (last !== undefined && last.receipts.length > 0) last.sealed = true;
  }

  /** M4: the ACTIVE segment's pre-bind salt — created lazily on first need. */
  function preBindSaltFor(keyId: string, mcpSessionId?: string): string {
    return activePreBindSegment(router.chainKey(keyId, mcpSessionId)).salt;
  }

  /** The head of a principal's pre-bind chain, or undefined if it has none. */
  function preBindHeadFor(keyId: string): string | undefined {
    const tail = preBindTailFor(keyId);
    return tail === null ? undefined : canonicalDigest(tail);
  }

  /** One pre-bind chain (by chain key) as the observer feed renders it. */
  function preBindFeedFor(chainKey: string): ReturnType<ContractService["preBindFeed"]> {
    const segments = preBindChains.get(chainKey);
    if (segments === undefined) return undefined;
    const nonEmpty = segments.filter((s) => s.receipts.length > 0);
    if (nonEmpty.length === 0) return undefined;
    const first = nonEmpty[0]!.receipts[0]!;
    const receipts = nonEmpty.flatMap((s) => s.receipts.map((r) => structuredClone(r)));
    return {
      // O-3: a per-session chain still reports its owning keyId.
      principalKeyId: keyIdOfChain(chainKey),
      head: canonicalDigest(nonEmpty.at(-1)!.receipts.at(-1)!),
      anchor: first.prevHash,
      truncated: first.prevHash !== RECEIPT_CHAIN_GENESIS,
      receipts,
      segments: nonEmpty.map((s) => ({
        anchor: s.receipts[0]!.prevHash,
        receipts: s.receipts.map((r) => structuredClone(r)),
      })),
    };
  }

  function dropRun(runId: string): void {
    const dropped = runs.get(runId);
    if (dropped !== undefined) {
      try { milestoneLog?.dropped(dropped); } catch { /* never block a drop */ }
    }
    // Review L2: the per-run call bookkeeping goes with the run; its count
    // moves onto the job object (persisted with the next outbox save).
    if (milestoneLog !== undefined) {
      const c = clockchainCalls.get(runId);
      const job = outbox.get(runId);
      if (c !== undefined && job !== undefined) job.clockchainCalls = { ...c };
      clockchainCalls.delete(runId);
      for (const [id, owner] of callOwner) if (owner === runId) callOwner.delete(id);
    }
    runs.delete(runId);
    ttlExpiredAt.delete(runId);
    router.dropRun(runId);
    boundChains.delete(`${runId}|buyer`);
    boundChains.delete(`${runId}|provider`);
    serverAnchors.dropScope(`run:${runId}`);
    // M3: a dropped session's chain was kept only for this run's feed.
    for (const chain of [...orphanedChains]) {
      if (!chainCaptured(chain)) forgetChain(chain);
    }
  }

  const pastTtl = (run: ContractRun): boolean => now() >= run.createdAtMs + runTtlMs;

  /**
   * CDT-GAPS gap 2 (CONTRACT_EXPIRE_AT_TTL=1): a run still non-terminal at
   * its TTL ends like any other terminal transition — `expired` when both
   * roles are bound, `expired_unbound` when one is missing (the same state
   * the half-bound bind-deadline release uses). endRun is write-once and its
   * enqueue fail-closed; a failure leaves the run for the next sweep.
   */
  function expireTtlRuns(): void {
    if (!expireAtTtl) return;
    for (const run of runs.values()) {
      if (run.terminalState !== null || !pastTtl(run)) continue;
      const bothBound = run.bound.buyer !== undefined && run.bound.provider !== undefined;
      // Marked held BEFORE endRun: its hooks (close emitter state, anchor
      // outcomes) re-enter evictEnded synchronously and must not drop it.
      ttlExpiredAt.set(run.runId, now());
      try {
        endRun(run, bothBound ? "expired" : "expired_unbound", undefined, bothBound ? undefined : "counterparty_never_bound");
      } catch {
        ttlExpiredAt.delete(run.runId); // fail-closed enqueue: retried on the next sweep
      }
    }
  }

  /**
   * M4/M5: TTL-expired runs are always removed. Terminal-but-fresh runs stay
   * observable (contract_status, receipt feed) and are only dropped under
   * capacity pressure — evidence survives the terminal transition.
   * CDT-GAPS gap 2: a run made terminal BY its TTL is held for expiredHoldMs
   * like a fresh terminal run — observable in contract_status and the feed,
   * its close and anchor outcomes chained on the live run, the final anchor
   * covering them with a receiptCount — then dropped (capacity pressure may
   * drop it sooner, as for any ended run).
   */
  function evictEnded(): void {
    expireUnboundRuns();
    expireTtlRuns();
    for (const [runId, run] of runs) {
      if (!pastTtl(run)) continue;
      const heldSince = ttlExpiredAt.get(runId);
      if (heldSince !== undefined && now() < heldSince + expiredHoldMs) continue;
      ttlExpiredAt.delete(runId);
      dropRun(runId);
    }
  }
  function evictForCapacity(): void {
    for (const [runId, run] of runs) {
      if (runs.size < maxRuns) return;
      if (runEnded(run)) dropRun(runId);
    }
  }

  function issueBindChallenge(
    principal: ContractPrincipal,
  ): { ok: true; challenge: string; expiresAt: string } | { ok: false; code: ContractRefusalCode } {
    const nowMs = now();
    for (const [nonce, rec] of bindChallenges) {
      if (rec.expiresAtMs <= nowMs) bindChallenges.delete(nonce);
    }
    if (bindChallenges.size >= MAX_BIND_CHALLENGES) return { ok: false, code: "RATE_LIMITED" };
    let outstanding = 0;
    for (const rec of bindChallenges.values()) {
      if (rec.keyId === principal.keyId && !rec.used) outstanding++;
    }
    if (outstanding >= MAX_BIND_CHALLENGES_PER_PRINCIPAL) return { ok: false, code: "RATE_LIMITED" };
    const challenge = randomBytes(32).toString("hex");
    const expiresAtMs = nowMs + bindChallengeTtlMs;
    bindChallenges.set(challenge, { keyId: principal.keyId, issuedAtMs: nowMs, expiresAtMs, used: false });
    return { ok: true, challenge, expiresAt: new Date(expiresAtMs).toISOString() };
  }

  function bind(
    principal: ContractPrincipal,
    args: {
      certificate: unknown;
      signerKey: unknown;
      approvalKey: unknown;
      listingId?: unknown;
      expectedSessionId?: string;
      bindStatement?: unknown;
      bindStatementSignature?: unknown;
    },
    evidence: {
      argsDigest: string;
      serverNonce: string;
      tool: string;
      sourceIp?: string;
      mcpSessionId?: string;
      clientInfo?: { name: string; version: string };
    },
  ): BindOutcome {
    evictEnded(); // M4/M5: free cap slots before deciding
    // O-3: the caller's pre-bind chain (the keyId's at cap 1).
    const preBindChain = router.chainKey(principal.keyId, evidence.mcpSessionId);
    // N4: buyer ≡ initiator, provider ≡ responder — enforced at token parse
    // (startup error) AND again here at bind.
    if ((principal.role === "buyer") !== (principal.side === "initiator")) {
      return { ok: false, code: "ROLE_REFUSED" };
    }

    // LOW (N4b-3): a provider bind may name the listing the handshake came
    // through; ONLY that listing is consumed (at the commit point below).
    // If one is named it must be a live listing the provider owns — a foreign
    // or spent listingId refuses before any state is claimed or mutated.
    const bindListingId = typeof args.listingId === "string" ? args.listingId : undefined;
    if (
      principal.role === "provider" && bindListingId !== undefined &&
      !business.consumableListing(principal.keyId, bindListingId)
    ) {
      return { ok: false, code: "LISTING_UNAVAILABLE" };
    }

    const signerKey = boundKeySchema.safeParse(args.signerKey);
    const approvalKey = boundKeySchema.safeParse(args.approvalKey);
    if (!signerKey.success || !approvalKey.success) return { ok: false, code: "CERTIFICATE_INVALID" };
    // The approval key must be a DIFFERENT key from the signer key — a single
    // compromised signer key must not be able to mint consequential approvals.
    if (
      signerKey.data.keyId === approvalKey.data.keyId ||
      signerKey.data.publicKeyHex === approvalKey.data.publicKeyHex
    ) {
      return { ok: false, code: "CERTIFICATE_INVALID" };
    }

    const verdict = verifyCertificateEnvelope(args.certificate, {
      hostRoots: options.hostRoots,
      now,
      graceMs: options.graceMs,
    });
    if (!verdict.ok) return { ok: false, code: "CERTIFICATE_INVALID" };
    // Bind by reference: a resolved certificate must name the presented
    // session — a relay answering with another session's (valid) envelope
    // can never seat the caller in a different run.
    if (args.expectedSessionId !== undefined && verdict.sessionId !== args.expectedSessionId) {
      return { ok: false, code: "CERTIFICATE_INVALID" };
    }

    // C2 + LOW: the certificate's party on the principal's claimed side must
    // carry the provisioned {agentId, chainId, registryAddress} — the FULL
    // ERC-8004 triple anchored to the attested identityPolicy, not just the
    // id. (P-GAP: possession of the party's handshake session key is not yet
    // proven — the token↔agentId pin is the whole assurance, see
    // bindAssurance on the result/receipt.)
    const parties = verdict.result.parties as Record<string, unknown> | undefined;
    const party = isPlainRecord(parties?.[principal.side]) ? parties[principal.side] as Record<string, unknown> : undefined;
    const erc8004 = isPlainRecord(party?.erc8004) ? party.erc8004 : null;
    const policy = isPlainRecord(verdict.result.identityPolicy) ? verdict.result.identityPolicy : null;
    const pinned = options.expectedErc8004;
    // N4b-7: a `*`-token binds the agentId LATE — taken from the certificate's
    // party on the token's side, pinned write-once below. Static tokens keep
    // the exact provisioned-agentId equality check.
    const lateBinding = principal.agentId === "*";
    if (
      erc8004 === null || policy === null ||
      (!lateBinding && erc8004.agentId !== principal.agentId) ||
      erc8004.chainId !== policy.chainId ||
      !sameAddress(erc8004.registryAddress, policy.registryAddress) ||
      (pinned !== undefined &&
        (policy.chainId !== pinned.chainId || !sameAddress(policy.registryAddress, pinned.registryAddress)))
    ) {
      return { ok: false, code: "CERTIFICATE_INVALID" };
    }
    const boundAgentId = lateBinding ? erc8004.agentId as string : principal.agentId;

    // N4b-7 P-GAP hook (DRAFT schema): a presented statement must verify;
    // when the deployment requires it, absence refuses too. HIGH-1 (review):
    // a LATE (`*`) bind ALWAYS requires one, at every level — the agentId
    // comes from the certificate, so only session-key possession proves the
    // caller is that party; without it any verified certificate is an
    // identity takeover. The challenge is consumed at COMMIT, not here — a
    // refused bind leaves the nonce usable.
    const statementPresent =
      args.bindStatement !== undefined || args.bindStatementSignature !== undefined;
    if ((lateBinding || options.requireBindStatement === true) && !statementPresent) {
      return { ok: false, code: "BIND_STATEMENT_INVALID" };
    }

    // N4b-7: the token keyId's bind records {agentId, runId} durably. While
    // that run is LIVE, a bind to a different agentId or a different run is
    // refused — including a replay of another handshake's certificate. The
    // record is RUN-scoped (late-bind release): once the recorded run is
    // terminal, TTL-expired, or gone from memory (dropped/evicted/restart —
    // a dropped run can never re-open: usedSessions refuses its genesis),
    // the keyId may bind a NEW run. That bind still passes the mandatory
    // statement check above (HIGH-1), so it can only claim the agentId whose
    // session key it proves — never another party's.
    // O-3: the keyId holds up to `router.cap` live bindings (one per live
    // run). At cap 1 this is exactly the single-record rule above; above 1,
    // concurrent live runs of one `*` keyId must all carry the same agentId.
    let nextAgentBindings: AgentBinding[] | undefined;
    if (lateBinding) {
      const recorded = agentBindings.get(principal.keyId) ?? [];
      const same = recorded.find((b) => b.runId === verdict.sessionId);
      if (same !== undefined) {
        if (same.agentId !== boundAgentId) return { ok: false, code: "STATE_REFUSED" };
      } else {
        const live = recorded.filter((b) => {
          const r = runs.get(b.runId);
          return r !== undefined && !runEnded(r);
        });
        if (live.length >= router.cap) return { ok: false, code: "STATE_REFUSED" };
        if (live.some((b) => b.agentId !== boundAgentId)) return { ok: false, code: "STATE_REFUSED" };
        // Late-bind release: ended runs' bindings are replaced by this run's.
        nextAgentBindings = [...live, { agentId: boundAgentId, runId: verdict.sessionId }];
      }
    }

    let consumedChallenge: BindChallenge | undefined;
    if (statementPresent) {
      const statement = args.bindStatement;
      const challenge = isPlainRecord(statement) && typeof statement.challenge === "string"
        ? bindChallenges.get(statement.challenge)
        : undefined;
      const sessionKeyAddress = typeof party?.sessionKeyAddress === "string" ? party.sessionKeyAddress : "";
      if (
        statement === undefined ||
        !verifyBindStatement({
          statement,
          signatureHex: args.bindStatementSignature,
          principal,
          sessionId: verdict.sessionId,
          serverKeyId: options.signer.keyId,
          expectedSessionKeyAddress: sessionKeyAddress,
          challenge,
          challengeTtlMs: bindChallengeTtlMs,
          nowMs: now(),
        })
      ) {
        return { ok: false, code: "BIND_STATEMENT_INVALID" };
      }
      consumedChallenge = challenge;
    }

    // Idempotent re-bind on the same run requires an identical
    // {resultDigest, signerKey, approvalKey}; anything else is a refusal.
    const sameSeat = (prior: ContractRun): BoundRole | undefined => {
      const mine = prior.bound[principal.role];
      return mine === undefined ||
        verdict.sessionId !== prior.runId ||
        mine.signerKey.keyId !== signerKey.data.keyId ||
        mine.signerKey.publicKeyHex !== signerKey.data.publicKeyHex ||
        mine.approvalKey.keyId !== approvalKey.data.keyId ||
        mine.approvalKey.publicKeyHex !== approvalKey.data.publicKeyHex ||
        verdict.resultDigest !== prior.resultDigest
        ? undefined
        : mine;
    };
    // O-3: the caller's routing slot — `*` at cap 1 (every session of the
    // keyId shares it, the pre-O-3 rule), its MCP session above 1.
    const slot = router.slotFor(evidence.mcpSessionId);
    const priorRunId = router.getSlot(principal.keyId, slot);
    if (priorRunId !== undefined) {
      const prior = runs.get(priorRunId);
      if (prior !== undefined && !runEnded(prior)) {
        const mine = sameSeat(prior);
        if (mine === undefined) return { ok: false, code: "STATE_REFUSED" };
        return idempotentOutcome(prior, principal.role, mine.boundAt, evidence.serverNonce);
      }
      // M5: the previous run has ended — the seat is free for a new run.
      router.deleteSlot(principal.keyId, slot);
    }
    if (router.cap > 1) {
      // O-3: the keyId's OTHER live runs (other sessions' slots).
      const live = router.runIds(principal.keyId)
        .map((id) => runs.get(id))
        .filter((r): r is ContractRun => r !== undefined && !runEnded(r));
      const resumed = live.find((r) => r.runId === verdict.sessionId);
      if (resumed !== undefined) {
        // Resume: the same bind on a NEW MCP session re-attaches this
        // session to the live run — idempotent by content, no receipt.
        const mine = sameSeat(resumed);
        if (mine === undefined) return { ok: false, code: "STATE_REFUSED" };
        router.set(principal.keyId, slot, resumed.runId);
        return idempotentOutcome(resumed, principal.role, mine.boundAt, evidence.serverNonce);
      }
      if (live.length >= router.cap) return { ok: false, code: "STATE_REFUSED" };
    }

    const existing = runs.get(verdict.sessionId);
    if (existing !== undefined) {
      if (existing.resultDigest !== verdict.resultDigest) {
        // Same sessionId, different signed content → substitution attempt.
        return { ok: false, code: "CERTIFICATE_INVALID" };
      }
      const occupant = existing.bound[principal.role];
      if (occupant !== undefined) {
        if (occupant.principalKeyId !== principal.keyId) return { ok: false, code: "SEAT_TAKEN" };
        return idempotentOutcome(existing, principal.role, occupant.boundAt, evidence.serverNonce);
      }
      // Half-bound run release: an ended run (withdrawn, expired_unbound, …)
      // never takes a new seat — no post-terminal bind, no receipt appended
      // after the terminal transition.
      if (runEnded(existing)) return { ok: false, code: "STATE_REFUSED" };
      const otherRole: ContractRole = principal.role === "buyer" ? "provider" : "buyer";
      const other = existing.bound[otherRole];
      if (other !== undefined && (other.side === principal.side || other.principalKeyId === principal.keyId)) {
        // The two roles must sit on different sides; one principal, one seat.
        return { ok: false, code: "ROLE_REFUSED" };
      }
    } else {
      // No live run for this sessionId: a restart must never open a second
      // genesis for an already-bound handshake.
      if (usedSessions.has(verdict.sessionId)) return { ok: false, code: "STATE_REFUSED" };
      if (runs.size >= maxRuns) evictForCapacity();
      if (runs.size >= maxRuns) return { ok: false, code: "RATE_LIMITED" };
    }

    // Every check passed — build the result and SIGN THE RECEIPT before any
    // state mutation commits. A receipt failure here aborts the bind with no
    // partial state (H2).
    // N4b-7 (MEDIUM-2): the assurance claim must describe what was actually
    // proven — a late bind took the agentId from the certificate party
    // (statement always verified there), a static+statement bind proved
    // session-key possession, a plain static bind is the token pin alone.
    const bindMode = lateBinding ? "late" as const : "static" as const;
    const bindStatementOutcome = statementPresent ? "verified" as const : "absent" as const;
    const bindAssurance = lateBinding
      ? "late-certificate-party" as const
      : statementPresent ? "session-key-possession" as const : "agentId-pinned-token" as const;
    const boundAt = new Date(now()).toISOString();
    // CDT-GAPS gap 1: the role's brief digest is part of the bind result, so
    // the bind receipt's responseDigest binds it — no client call needed.
    let roleBriefDigest: string | null | undefined;
    if (roleBriefDigests !== undefined) {
      try {
        roleBriefDigest = serverAnchors.roleBriefFor(principal.role, briefScopeOf(preBindChain));
      } catch {
        roleBriefDigest = roleBriefDigests[principal.role] ?? null;
      }
    }
    const resultBody = {
      runId: verdict.sessionId,
      role: principal.role,
      bound: true,
      boundAt,
      side: principal.side,
      serverNonce: evidence.serverNonce,
      bindMode,
      bindStatement: bindStatementOutcome,
      bindAssurance,
      ...(roleBriefDigest !== undefined ? { briefDigest: roleBriefDigest } : {}),
    };
    const runId = verdict.sessionId;
    const prevReceipt = existing === undefined ? null : (existing.receipts.at(-1) ?? null);
    const run: ContractRun = existing ?? {
      runId,
      resultDigest: verdict.resultDigest,
      sessionPublicKey: verdict.sessionPublicKey,
      createdAtMs: now(),
      bindDeadlineMs: halfBoundTimeoutMs > 0
        ? Math.min(verdict.acceptUntilMs, now() + halfBoundTimeoutMs)
        : verdict.acceptUntilMs,
      bound: {},
      receipts: [],
      receiptsByPrincipal: new Map(),
      claimedNonces: new Set(),
      offers: new Map(),
      offerSeq: 0,
      terminalState: null,
      simRun: sim.forRun(runId),
      stage: "handshake",
      runSalt: randomBytes(32).toString("hex"),
    };
    // N4b-5: record the config-seeded sim fault on the run for evidence.
    if (run.simRun?.faults !== undefined) run.simFault = run.simRun.faults;
    // N3: refuse (never throw) at the run cap or this principal's own budget.
    const principalReceipts = run.receiptsByPrincipal.get(principal.keyId) ?? 0;
    if (run.receipts.length >= maxReceiptsPerRun || principalReceipts >= maxReceiptsPerPrincipal) {
      return { ok: false, code: "RATE_LIMITED" };
    }

    // N4b-3/N4b-4: the receipt is built (and schema-validated) BEFORE any
    // state mutation — and signing is refused past the key's validUntil.
    if (!signingOpen()) return { ok: false, code: "CONTRACT_UNAVAILABLE" };
    let receipt: ServerReceipt;
    try {
      receipt = makeReceipt(prevReceipt, {
        runId,
        tool: evidence.tool,
        argsDigest: evidence.argsDigest,
        principal: { role: principal.role, keyId: principal.keyId },
        outcome: "ok",
        responseDigest: canonicalDigest(resultBody),
        serverNonce: evidence.serverNonce,
        sourceIp: evidence.sourceIp,
        mcpSessionId: evidence.mcpSessionId,
        clientInfo: evidence.clientInfo,
        bindAssurance,
        // N4b-7: evidence records how the agentId was established and whether
        // the session-key-possession statement was verified (P-GAP).
        bindMode,
        bindStatement: bindStatementOutcome,
        // M1: the bind receipt carries THIS principal's pre-bind chain head —
        // the run chain's link back to the evidence that preceded it.
        // O-3: the chain of THIS session above cap 1.
        preBindHead: preBindHeadFor(preBindChain),
        // N4b-6: bind receipts on a fault-seeded run carry the marker too.
        ...(run.simFault !== undefined ? { simFault: run.simFault } : {}),
        ts: now(),
      }, options.signer);
    } catch {
      return { ok: false, code: "CONTRACT_UNAVAILABLE" };
    }

    // N1: for a NEW run the used-session record is persisted BEFORE any
    // in-memory state changes. If the write fails the bind fails with no
    // state change and no receipt — never a run the restart guard forgot.
    // N4b-7: the late-binding record is written FIRST — a crash between the
    // two writes then leaves an unused binding, not an unrecorded session.
    // Late-bind release: a binding whose run ended is REPLACED by this run's.
    const newBinding: AgentBinding[] | undefined = nextAgentBindings;
    if (options.stateDir !== undefined && (existing === undefined || newBinding !== undefined)) {
      const nextBindings = new Map(agentBindings);
      if (newBinding !== undefined) nextBindings.set(principal.keyId, newBinding);
      const nextSessions = new Map(usedSessions);
      if (existing === undefined) nextSessions.set(verdict.sessionId, runId);
      try {
        if (newBinding !== undefined) persistAgentBindings(options.stateDir, nextBindings);
        if (existing === undefined) persistUsedSessions(options.stateDir, nextSessions);
      } catch {
        return { ok: false, code: "CONTRACT_UNAVAILABLE" };
      }
      if (newBinding !== undefined) agentBindings = nextBindings;
      if (existing === undefined) usedSessions = nextSessions;
    } else {
      if (newBinding !== undefined) agentBindings.set(principal.keyId, newBinding);
      if (existing === undefined) usedSessions.set(verdict.sessionId, runId);
    }

    run.bound[principal.role] = {
      principalKeyId: principal.keyId,
      agentId: boundAgentId,
      side: principal.side,
      signerKey: signerKey.data,
      approvalKey: approvalKey.data,
      boundAt,
      bindMode,
      bindStatement: bindStatementOutcome,
      bindAssurance,
      ...(roleBriefDigest !== undefined ? { briefDigest: roleBriefDigest } : {}),
    };
    run.receipts.push(receipt);
    run.receiptsByPrincipal.set(principal.keyId, principalReceipts + 1);
    try { milestoneLog?.observe(run, receipt); } catch { /* a milestone bug must never break a bind */ }
    if (run.bound.buyer !== undefined && run.bound.provider !== undefined) run.stage = "bound";
    if (existing === undefined) runs.set(runId, run);
    router.set(principal.keyId, slot, runId);
    boundChains.set(`${runId}|${principal.role}`, preBindChain);
    // O-1 x O-3: the link hook runs AFTER the router maps this seat, so the
    // run id it links is the one this session routes to, and (above cap 1)
    // the lane set is limited to the sessions routed to this run.
    if (run.bound.buyer !== undefined && run.bound.provider !== undefined) {
      const sessionsOf = (role: ContractRole): string[] => {
        const keyId = run.bound[role]?.principalKeyId;
        return keyId === undefined ? [] : router.sessionSlotsFor(keyId, runId);
      };
      const sessions = router.cap > 1 ? { buyer: sessionsOf("buyer"), provider: sessionsOf("provider") } : undefined;
      try { options.onRunBound?.(run, sessions); } catch { /* a link bug must never break the bind */ }
    }
    // LOW (N4b-3): commit-time consumption — the provider's successful bind
    // consumes ONLY the named listing (ownership probed above).
    if (principal.role === "provider" && bindListingId !== undefined) {
      business.consumeListing(principal.keyId, bindListingId);
    }
    // N4b-7: commit-time consumption — the verified statement's challenge
    // nonce burns exactly once, with the seat it proved.
    if (consumedChallenge !== undefined) consumedChallenge.used = true;
    // N4b-3: a successful bind SEALS this principal's pre-bind segment — the
    // next pre-bind call starts a fresh segment (fresh salt) anchored on the
    // sealed head, so the lifetime cap can never lock a principal out.
    sealPreBindSegment(preBindChain);
    // Server-side anchors: the run's terms at its creating bind; a brief
    // anchored on this seat's pre-bind scope becomes the run's brief anchor.
    try {
      if (existing === undefined) serverAnchors.fireTerms(run, termsDigestOf(verdict.result, verdict.resultDigest));
      serverAnchors.carryBrief(run, briefScopeOf(preBindChain));
      if (roleBriefDigest !== undefined && roleBriefDigest !== null) {
        serverAnchors.attachRoleBrief(run, principal.role, roleBriefDigest);
      }
    } catch { /* an anchor bug must never break a committed bind */ }
    return { ok: true, runId, role: principal.role, boundAt, result: resultBody, receipt, run };
  }

  function idempotentOutcome(
    run: ContractRun,
    role: ContractRole,
    boundAt: string,
    serverNonce: string,
  ): BindOutcome {
    return {
      ok: true,
      runId: run.runId,
      role,
      boundAt,
      result: {
        runId: run.runId,
        role,
        bound: true,
        boundAt,
        side: run.bound[role]?.side,
        serverNonce,
        bindMode: run.bound[role]?.bindMode,
        bindStatement: run.bound[role]?.bindStatement,
        bindAssurance: run.bound[role]?.bindAssurance,
        ...(run.bound[role]?.briefDigest !== undefined ? { briefDigest: run.bound[role]?.briefDigest } : {}),
        idempotent: true,
      },
      // An idempotent re-bind appends no receipt: nothing changed.
      receipt: run.receipts.at(-1) as ServerReceipt,
      run,
    };
  }

  /**
   * N4b-8 (gap 4): fire an async anchor for `kind` and record the outcome —
   * anchored AND failed — as a run receipt. The digest is captured
   * synchronously (agreement: the agreementDigest; terminal: the chain head
   * AT the terminal transition) so post-terminal evidence receipts never
   * retroactively change what was anchored.
   */
  const sleep = options.sleep ?? ((ms: number): Promise<void> => new Promise((r) => {
    const t = setTimeout(r, ms);
    t.unref?.();
  }));
  const anchorConfirmDelayMs = options.anchorConfirmDelayMs ?? 30_000;
  const anchorConfirmMaxAttempts = options.anchorConfirmMaxAttempts ?? 4;
  /** The anchor scope id of a pre-bind chain (brief anchors served before a bind). */
  const briefScopeOf = (chainKey: string): string => `pre-bind:${chainKey.replace("\u0000", "/")}`;
  // Server-side anchors (terms / brief / final): new module, same
  // in-process ContractAnchor, outcomes recorded on run + job, never chained.
  const serverAnchors = createServerAnchors({
    // M5: without CONTRACT_SERVER_ANCHORS=1 every server-side anchor is a no-op.
    anchor: serverAnchorsOn ? runAnchor : undefined,
    getRun: (runId) => runs.get(runId),
    getJob: (runId) => outbox.get(runId),
    updateJob: (runId, mutate) => void updateJob(runId, mutate),
    track: (p) => trackAnchorOp(p),
    sleep,
    confirmDelayMs: anchorConfirmDelayMs,
    confirmMaxAttempts: anchorConfirmMaxAttempts,
    ...(options.briefs !== undefined ? { briefs: options.briefs } : {}),
    ...(options.briefAnchorAwaitMs !== undefined ? { briefAnchorAwaitMs: options.briefAnchorAwaitMs } : {}),
    ...(options.finalAnchorAwaitMs !== undefined ? { finalAnchorAwaitMs: options.finalAnchorAwaitMs } : {}),
    ...(options.briefRetryMs !== undefined ? { briefRetryMs: options.briefRetryMs } : {}),
    ...(roleBriefDigests !== undefined ? { roleBriefs: roleBriefDigests } : {}),
    now,
    // Milestone log: a failed referenced anchor makes its milestone fall back to an own write.
    ...(milestoneLogOn ? { onRunAnchorFailed: (runId: string) => milestoneLog?.anchorFailed(runId) } : {}),
  });
  // Milestone log (CONTRACT_MILESTONE_LOG, default off): undefined = every
  // hook below is a no-op and no run or job carries milestone state.
  const milestoneLog: MilestoneLog | undefined = milestoneLogOn
    ? createMilestoneLog({
        anchor: runAnchor as ContractAnchor & Required<Pick<ContractAnchor, "log">>,
        getRun: (runId) => runs.get(runId),
        getJob: (runId) => outbox.get(runId),
        updateJob: (runId, mutate) => void updateJob(runId, (job) => {
          mutate(job);
          const c = clockchainCalls.get(runId);
          if (c !== undefined) job.clockchainCalls = { ...c };
        }),
        updateJobDurable: (runId, mutate) => void outbox.updateDurable(runId, now(), (job) => {
          mutate(job);
          const c = clockchainCalls.get(runId);
          if (c !== undefined) job.clockchainCalls = { ...c };
        }),
        track: (p) => trackAnchorOp(p),
        sleep,
        confirmDelayMs: anchorConfirmDelayMs,
        confirmMaxAttempts: anchorConfirmMaxAttempts,
        finalAnchors: serverAnchorsOn,
        now,
      })
    : undefined;

  const fireAnchor = (run: ContractRun, kind: "agreement" | "terminal"): void => {
    const anchor = runAnchor;
    if (anchor === undefined) return;
    const digest = kind === "agreement" ? run.agreement?.agreementDigest : chainHead(run.receipts);
    if (digest === null || digest === undefined) return;
    const anchors = (run.anchors ??= {});
    // F11: the anchor subject is write-once — a second terminal transition
    // never replaces the first anchored head.
    if (anchors[kind] !== undefined) return;
    anchors[kind] = { status: "anchoring", digest };
    // F14: the anchor job is durably enqueued BEFORE the async dispatch —
    // a crash mid-flight leaves "anchoring" for boot recovery to re-drive.
    updateJob(run.runId, (job) => {
      job.anchors = {
        ...job.anchors,
        [kind]: { kind, digest, status: "anchoring" },
      };
    });
    const principalFor = (): { role: "buyer" | "provider"; keyId: string } | undefined =>
      run.bound.buyer !== undefined
        ? { role: "buyer" as const, keyId: run.bound.buyer.principalKeyId }
        : run.bound.provider !== undefined
          ? { role: "provider" as const, keyId: run.bound.provider.principalKeyId }
          : undefined;
    const receiptOutcome = (outcome: "anchor_anchored" | "anchor_failed", response: unknown): void => {
      const p = principalFor() ?? outbox.get(run.runId)?.principal ?? undefined;
      if (p === undefined) return;
      try {
        recordTerminalEvidence(run.runId, {
          tool: "anchor",
          surface: "anchoring",
          argsDigest: canonicalDigest({ runId: run.runId, kind, digest }),
          argsDigestScheme: "canonical",
          principal: p,
          outcome,
          responseDigest: canonicalDigest(response),
          responseDigestScheme: "canonical",
        });
      } catch { /* a recording failure must not fault the async path */ }
    };
    const persistAnchor = (state: AnchorRunState): void => {
      updateJob(run.runId, (job) => {
        job.anchors = { ...job.anchors, [kind]: { kind, ...state } };
      });
    };
    const op = Promise.resolve()
      .then(() => anchor.anchor({ kind, runId: run.runId, digestHex: digest }))
      .then((write) => {
        // F13: a RESOLVED write is anchored only when the backing confirms
        // block+time; pending_confirmation stays "pending" and is re-checked.
        const confirmed = write.anchor.status === "anchored" &&
          write.anchor.blockHeight !== null && write.anchor.time !== null;
        const next: AnchorRunState = {
          status: confirmed ? "anchored" : "pending", digest,
          anchorId: write.anchorId, eventHash: write.eventHash, ledger: write.anchor,
        };
        anchors[kind] = next;
        persistAnchor(next);
        if (confirmed) {
          receiptOutcome("anchor_anchored", write);
        } else {
          scheduleAnchorConfirm(run, kind, digest, write.anchorId, 1);
        }
      })
      .catch((err) => {
        const error = err instanceof Error ? err.message : String(err);
        const next: AnchorRunState = { status: "failed", digest, error };
        anchors[kind] = next;
        persistAnchor(next);
        receiptOutcome("anchor_failed", { error });
        try { milestoneLog?.anchorFailed(run.runId); } catch { /* never fault the anchor path */ }
      });
    trackAnchorOp(op, run.runId);
  };

  /**
   * F13: re-confirm a pending anchor. `confirm` when the backing supports
   * polling, else re-issue (idempotent — the deterministic commitmentId
   * resolves the same on-chain object with its current confirmation state).
   * A poll ERROR keeps the job pending — a transport hiccup never turns a
   * landed write into a failure. Bounded by anchorConfirmMaxAttempts; the
   * job then rests as "pending" and restart recovery resumes it.
   */
  const scheduleAnchorConfirm = (run: ContractRun, kind: "agreement" | "terminal", digest: string, anchorId: string, attempt: number): void => {
    const anchor = runAnchor;
    if (anchor === undefined || anchorConfirmDelayMs <= 0) return;
    const op = sleep(anchorConfirmDelayMs)
      .then(() => anchor.confirm !== undefined
        ? anchor.confirm(anchorId)
        : anchor.anchor({ kind, runId: run.runId, digestHex: digest }).then((w) => w.anchor))
      .then((ledger) => {
        const state = run.anchors?.[kind];
        if (state === undefined || state.status !== "pending") return;
        const confirmed = ledger.status === "anchored" &&
          ledger.blockHeight !== null && ledger.time !== null;
        if (confirmed) {
          const next: AnchorRunState = { ...state, status: "anchored", ledger };
          run.anchors![kind] = next;
          updateJob(run.runId, (job) => {
            job.anchors = { ...job.anchors, [kind]: { kind, ...next } };
          });
          const p =
            run.bound.buyer !== undefined
              ? { role: "buyer" as const, keyId: run.bound.buyer.principalKeyId }
              : run.bound.provider !== undefined
                ? { role: "provider" as const, keyId: run.bound.provider.principalKeyId }
                : outbox.get(run.runId)?.principal ?? undefined;
          if (p !== undefined) {
            try {
              recordTerminalEvidence(run.runId, {
                tool: "anchor",
                surface: "anchoring",
                argsDigest: canonicalDigest({ runId: run.runId, kind, digest: state.digest }),
                argsDigestScheme: "canonical",
                principal: p,
                outcome: "anchor_anchored",
                responseDigest: canonicalDigest({ anchorId, ledger }),
                responseDigestScheme: "canonical",
              });
            } catch { /* a recording failure must not fault the async path */ }
          }
        } else {
          state.ledger = ledger;
          updateJob(run.runId, (job) => {
            const aj = job.anchors?.[kind];
            if (aj !== undefined && aj.status === "pending") aj.ledger = ledger;
          });
          if (attempt < anchorConfirmMaxAttempts) scheduleAnchorConfirm(run, kind, digest, anchorId, attempt + 1);
        }
      })
      .catch(() => {
        if (attempt < anchorConfirmMaxAttempts) scheduleAnchorConfirm(run, kind, digest, anchorId, attempt + 1);
      });
    trackAnchorOp(op, run.runId);
  };

  /**
   * N4b-9 (F14): boot recovery for a persisted anchor job whose in-memory
   * run is gone. `anchoring` means the process died mid-issue → re-issue
   * (the deterministic commitmentId resolves the same on-chain object);
   * `pending` means awaiting confirmation → confirm/re-issue reads the
   * current chain state. Outcomes mint into the job's persisted evidence.
   * Re-arms under the same `anchorConfirmMaxAttempts` budget as the live
   * confirm loop (N4b-11 L3) — a still-pending job past the budget rests
   * for the next boot.
   */
  const recoverAnchorJob = (job: TerminalJob, aj: TerminalAnchorJob, attempt = 1): void => {
    const anchor = runAnchor;
    if (anchor === undefined) return;
    const runId = job.runId;
    const persist = (status: TerminalAnchorJob["status"], extra?: Partial<TerminalAnchorJob>): void =>
      void updateJob(runId, (j) => {
        j.anchors = { ...j.anchors, [aj.kind]: { ...j.anchors?.[aj.kind], kind: aj.kind, digest: aj.digest, status, ...extra } as TerminalAnchorJob };
      });
    const evidence = (outcome: "anchor_anchored" | "anchor_failed", response: unknown): void => {
      const p = job.principal ?? undefined;
      if (p === undefined) return;
      updateJob(runId, (j) => mintJobEvidence(j, {
        tool: "anchor",
        surface: "anchoring",
        argsDigest: canonicalDigest({ runId, kind: aj.kind, digest: aj.digest }),
        argsDigestScheme: "canonical",
        principal: p,
        outcome,
        responseDigest: canonicalDigest(response),
        responseDigestScheme: "canonical",
      }));
    };
    // N4b-11 (L3): the recovered confirm loop carries the SAME budget as
    // the live path — at `anchorConfirmMaxAttempts` the job rests as
    // "pending" and the NEXT boot resumes it. Unbounded polling here would
    // let a permanently-unconfirmable anchor burn the process forever.
    const rearm = (): void => {
      if (anchorConfirmDelayMs <= 0 || attempt >= anchorConfirmMaxAttempts) return;
      const op2 = sleep(anchorConfirmDelayMs)
        .then(() => {
          const freshJob = outbox.get(runId);
          const fresh = freshJob?.anchors?.[aj.kind];
          if (freshJob !== undefined && fresh !== undefined && fresh.status === "pending") {
            recoverAnchorJob(freshJob, fresh, attempt + 1);
          }
        });
      trackAnchorOp(op2);
    };
    const poll = anchor.confirm !== undefined && aj.anchorId !== undefined
      ? anchor.confirm(aj.anchorId).then((ledger) => ({ ledger }))
      // Only agreement/terminal jobs reach this path (boot recovery loop).
      : anchor.anchor({ kind: aj.kind as "agreement" | "terminal", runId, digestHex: aj.digest }).then((w) => ({ write: w }));
    const op = Promise.resolve(poll)
      .then((r) => {
        if ("write" in r) {
          const confirmed = r.write!.anchor.status === "anchored" &&
            r.write!.anchor.blockHeight !== null && r.write!.anchor.time !== null;
          persist(confirmed ? "anchored" : "pending", {
            anchorId: r.write!.anchorId, eventHash: r.write!.eventHash, ledger: r.write!.anchor,
          });
          if (confirmed) evidence("anchor_anchored", r.write!);
          else rearm();
        } else {
          const ledger = r.ledger!;
          const confirmed = ledger.status === "anchored" &&
            ledger.blockHeight !== null && ledger.time !== null;
          persist(confirmed ? "anchored" : "pending", { ledger });
          if (confirmed) evidence("anchor_anchored", { anchorId: aj.anchorId, ledger });
          else rearm();
        }
      })
      .catch((err) => {
        // A recovery transport error is NOT an anchor failure — the write
        // may have landed. Keep the job pending so the next boot retries.
        const message = err instanceof Error ? err.message : String(err);
        if (aj.status === "anchoring") persist("pending", { error: `recovery: ${message}` });
      });
    trackAnchorOp(op, runId);
  };

  const endRun = (run: ContractRun, terminalState: string, principal?: ContractPrincipal, reason?: ContractTerminalReason): void => {
    // N4b-9 (F11): the terminal transition is WRITE-ONCE. A cleanup
    // cancellation after verification_failed (or any second endRun) is
    // receipted by the call itself but never changes the terminal state,
    // never re-fires the close emitter, and never re-anchors — the first
    // transition owns the close identity and the anchor subject.
    if (run.terminalState !== null) return;
    // N4b-9 (F14): durably enqueue the terminal job BEFORE the transition is
    // acknowledged — the immutable close receipt, the anchor subject (the
    // chain tip at this instant), the bound principals, and the run-chain
    // state needed to mint post-restart evidence are all on disk first.
    const receipt = options.onTerminalRun !== undefined
      ? (options.mintTerminalReceipt ?? mintTerminalReceipt)(
          { runId: run.runId, terminalState, ts: new Date(now()).toISOString() },
          options.signer,
        )
      : undefined;
    // N4b-11 (M3): the enqueue is FAIL-CLOSED. A persist failure throws out
    // of dispatch (the caller gets an error, never a success), the
    // un-persisted mutation is rolled back inside the outbox, and the run
    // below is left untouched — nothing terminal is acknowledged without
    // the durable record. A retry re-mints and rebuilds the same job.
    outbox.updateDurable(run.runId, now(), (job) => {
      job.terminalState = terminalState;
      if (reason !== undefined) job.terminalReason = reason;
      job.principal = principal !== undefined
        ? { role: principal.role, keyId: principal.keyId }
        : null;
      job.boundKeyIds = [
        run.bound.buyer?.principalKeyId,
        run.bound.provider?.principalKeyId,
      ].filter((k): k is string => k !== undefined);
      job.prevReceipt = run.receipts.at(-1) ?? null;
      // Server-side anchors recorded on the live run so far join the job.
      for (const k of ["terms", "brief", "briefBuyer", "briefProvider"] as const) {
        const st = run.anchors?.[k];
        if (st !== undefined) job.anchors = { ...job.anchors, [k]: { kind: k, ...st } };
      }
      // Milestone log: the entries sealed so far join the job (flag off: none).
      const ml = milestoneLog?.snapshot(run);
      if (ml !== undefined) job.milestoneLog = ml;
      const calls = milestoneLog !== undefined ? clockchainCalls.get(run.runId) : undefined;
      if (calls !== undefined) job.clockchainCalls = { ...calls };
      if (receipt !== undefined) {
        job.receipt = receipt;
        job.receiptDigest = canonicalDigest(receipt);
        job.close = { status: "delivering", attempts: 0 };
      }
    });
    // "settled" is itself a named terminal stage; every other terminal reason
    // reads stage:"terminal" with terminalState carrying the why.
    run.stage = terminalState === "settled" ? "settled" : "terminal";
    run.terminalState = terminalState;
    if (reason !== undefined) run.terminalReason = reason;
    sim.markTerminal(run.runId);
    // N4b-8 (gap 4): anchor the receipt-chain head at the terminal
    // transition BEFORE the close emitter runs — the anchored head is the
    // head at terminality; close/anchor evidence receipts chain on after it.
    try {
      fireAnchor(run, "terminal");
    } catch { /* an anchor bug must never break the terminal transition */ }
    // N4b-8 (gap 3): the close emitter POSTs the signed terminal receipt to
    // the telemetry sink — async, retried, outcome receipted onto the run.
    try {
      if (receipt !== undefined) {
        options.onTerminalRun?.(run, terminalState, principal, receipt);
      }
    } catch { /* an emitter bug must never break the terminal transition */ }
    // Milestone log: seal what is left once the terminal call's own receipt is in.
    try { milestoneLog?.terminal(run); } catch { /* never break the terminal transition */ }
    serverAnchors.scheduleFinal(run.runId);
  };
  const business = createBusinessOps({
    signer: options.signer,
    now,
    sim,
    signingOpen,
    flexPolicy: features.flexPolicy === true,
    ...(options.privateFloor !== undefined ? { privateFloor: { floorBps: options.privateFloor.floorBps } } : {}),
    policyDigests: livePolicyDigests,
    ...(buyerPolicyDigestsFor !== undefined ? { buyerPolicyDigestsFor } : {}),
    ...(options.principals !== undefined ? { principals: options.principals } : {}),
    // O-2: directory pins + standing-listing persistence (business-owned).
    ...(options.directory !== undefined ? { directory: options.directory } : {}),
    ...(options.stateDir !== undefined ? { stateDir: options.stateDir } : {}),
    claimMandate,
    endRun,
    allowLegacySealV2: options.allowLegacySealV2 === true,
    // N4b-8 (gap 4): business fires the anchor at agreement formation;
    // the service owns the async call + the outcome receipt.
    ...(options.anchor !== undefined ? { anchorRun: fireAnchor } : {}),
    // N4b-10 (D13): absent = the default simulated settlement rail.
    ...(options.settlementRail !== undefined ? { settlementRail: options.settlementRail } : {}),
  });

  /**
   * The shared receipt-append used by the public recordReceipt AND by async
   * server-side evidence writers (telemetry_close outcome, anchor outcome).
   * Same rules: refuse at caps or when signing is closed — never throw.
   */
  const recordRunReceipt = (
    run: ContractRun,
    fields: Omit<ReceiptFields, "runId">,
  ): { ok: true; receipt: ServerReceipt } | { ok: false; code: ContractRefusalCode } => {
    evictEnded();
    if (!signingOpen()) return { ok: false, code: "CONTRACT_UNAVAILABLE" };
    const count = run.receiptsByPrincipal.get(fields.principal.keyId) ?? 0;
    if (run.receipts.length >= maxReceiptsPerRun || count >= maxReceiptsPerPrincipal) {
      return { ok: false, code: "RATE_LIMITED" };
    }
    // N4b-3: a receipt that can't be built is a refusal, never a throw —
    // the caller already ran this validation pre-dispatch, so this branch
    // should be unreachable; it exists so a post-dispatch surprise can
    // never become a 500.
    let receipt: ServerReceipt;
    try {
      receipt = makeReceipt(
        run.receipts.at(-1) ?? null,
        // N4b-6: every receipt on a fault-seeded run carries the marker —
        // server-derived evidence, never caller-supplied.
        { ...fields, runId: run.runId, simFault: run.simFault, ts: now() },
        options.signer,
      );
    } catch {
      return { ok: false, code: "CONTRACT_UNAVAILABLE" };
    }
    run.receipts.push(receipt);
    run.receiptsByPrincipal.set(fields.principal.keyId, count + 1);
    try { milestoneLog?.observe(run, receipt); } catch { /* a milestone bug must never fault a receipt */ }
    return { ok: true, receipt };
  };

  // N4b-9 (F14): restart recovery — persisted anchor jobs that died
  // mid-issue ("anchoring") or are awaiting confirmation ("pending") are
  // re-driven against the backing; outcomes mint into the job's persisted
  // evidence (the run is gone after a restart).
  if (options.anchor !== undefined) {
    for (const job of outbox.unfinished()) {
      for (const aj of [job.anchors?.agreement, job.anchors?.terminal]) {
        if (aj !== undefined && (aj.status === "anchoring" || aj.status === "pending")) {
          recoverAnchorJob(job, aj);
        }
      }
      // Server-side anchors re-drive unchained (server-anchors.ts).
      for (const aj of [
        job.anchors?.terms, job.anchors?.brief, job.anchors?.final,
        job.anchors?.briefBuyer, job.anchors?.briefProvider,
      ]) {
        if (aj !== undefined && (aj.status === "anchoring" || aj.status === "pending")) {
          serverAnchors.recover(job, aj);
        }
      }
      // Milestone log: seed the call counts and owners, then close / interrupt /
      // re-drive (idempotent re-issue).
      if (milestoneLog !== undefined) {
        if (job.clockchainCalls !== undefined) clockchainCalls.set(job.runId, { ...job.clockchainCalls });
        for (const a of Object.values(job.anchors ?? {})) if (a?.anchorId !== undefined) callOwner.set(a.anchorId, job.runId);
        for (const e of job.milestoneLog?.entries ?? []) {
          if (e.ledger?.ledgerId) callOwner.set(e.ledger.ledgerId, job.runId);
        }
        milestoneLog.recover(job);
      }
    }
  }

  drainForExit = () => drainImpl(5_000);

  async function drainImpl(deadlineMs: number): Promise<void> {
    const pending = [...anchorOps, ...(options.onDrain !== undefined ? [options.onDrain()] : [])];
    const timeout = sleep(deadlineMs).then(() => "timeout" as const);
    await Promise.race([
      Promise.allSettled(pending).then(() => "settled" as const),
      timeout,
    ]);
  }

  return {
    bind,
    issueBindChallenge,
    features,
    serverAnchors: serverAnchorsOn,
    roleBriefs: roleBriefDigests !== undefined,
    milestoneLog: milestoneLog !== undefined,
    clockchainCallsFor: (runId) => {
      if (milestoneLog === undefined) return undefined;
      const c = clockchainCalls.get(runId) ?? outbox.get(runId)?.clockchainCalls;
      return c === undefined ? { writes: 0, lookups: 0 } : { ...c };
    },
    registerPolicy: (principal, input) => features.policyRegistration === true
      ? policyRegistry.register(principal, input)
      : { ok: false, code: "NOT_FOUND" },
    getBrief: (name, scope) => serverAnchors.getBrief(name, scope),
    awaitFinalAnchor: (runId) => serverAnchors.awaitFinal(runId),
    preBindBriefScope: (keyId, mcpSessionId) => briefScopeOf(router.chainKey(keyId, mcpSessionId)),
    business,
    anchorConfigured: options.anchor !== undefined,
    settlementRailId: options.settlementRail?.railId ?? "simulated",
    recordReceipt: recordRunReceipt,
    // N4b-9 (F14): terminal outbox surface — status visibility for a
    // recovered run, close-state persistence, post-restart outcome minting,
    // pending jobs for emitter resume, and the bounded drain.
    terminalJobFor(runId) {
      return outbox.get(runId);
    },
    pendingTerminalJobs() {
      return outbox.unfinished();
    },
    recordTerminalOutcome(runId, outcome, detail) {
      const run = runs.get(runId);
      const job = outbox.get(runId);
      const terminalState = run?.terminalState ?? job?.terminalState ?? null;
      const principal = job?.principal
        ?? (run?.bound.buyer !== undefined
          ? { role: "buyer" as const, keyId: run.bound.buyer.principalKeyId }
          : undefined)
        ?? (run?.bound.provider !== undefined
          ? { role: "provider" as const, keyId: run.bound.provider.principalKeyId }
          : undefined);
      if (principal === null || principal === undefined) return;
      recordTerminalEvidence(runId, {
        tool: "telemetry_close",
        surface: "anchoring",
        argsDigest: canonicalDigest({ runId, terminalState, receiptDigest: detail.receiptDigest }),
        argsDigestScheme: "canonical",
        principal,
        outcome: `telemetry_close_${outcome}`,
        responseDigest: canonicalDigest(
          detail.response !== undefined ? detail.response : { error: detail.lastError ?? null, attempts: detail.attempts },
        ),
        responseDigestScheme: "canonical",
      });
      serverAnchors.scheduleFinal(runId);
    },
    persistTerminalClose(runId, state) {
      updateJob(runId, (job) => {
        job.close = { status: state.status, attempts: state.attempts, lastError: state.lastError, deliveredAt: state.deliveredAt };
      });
      serverAnchors.scheduleFinal(runId);
    },
    drain: drainImpl,
    checkReceiptEvidence(run, principal, fields) {
      evictEnded(); // same hygiene as the old canReceipt gate
      // N4b-4: past the key's validUntil nothing can be signed — no receipt,
      // no envelope — so the call is refused BEFORE any dispatch.
      if (!signingOpen()) return { ok: false, code: "CONTRACT_UNAVAILABLE" };
      if (run !== undefined) {
        // Budget AND buildability, before any dispatch (N4b-3).
        const count = run.receiptsByPrincipal.get(principal.keyId) ?? 0;
        if (run.receipts.length >= maxReceiptsPerRun || count >= maxReceiptsPerPrincipal) {
          return { ok: false, code: "RATE_LIMITED" };
        }
        const ok = checkReceiptDraft(run.receipts.at(-1) ?? null, {
          ...fields,
          runId: run.runId,
          simFault: run.simFault,
          principal: { role: principal.role, keyId: principal.keyId },
        });
        return ok ? { ok: true } : { ok: false, code: "CONTRACT_UNAVAILABLE" };
      }
      const prev = preBindTailFor(router.chainKey(principal.keyId, fields.mcpSessionId));
      const ok = checkReceiptDraft(prev, {
        ...fields,
        runId: PRE_BIND_SCOPE,
        principal: { role: principal.role, keyId: principal.keyId },
      });
      return ok ? { ok: true } : { ok: false, code: "CONTRACT_UNAVAILABLE" };
    },
    canReceipt(run, principalKeyId) {
      evictEnded();
      const count = run.receiptsByPrincipal.get(principalKeyId) ?? 0;
      return run.receipts.length < maxReceiptsPerRun && count < maxReceiptsPerPrincipal;
    },
    runFor(runId) {
      evictEnded();
      return runs.get(runId);
    },
    recordPreBind(principal, fields) {
      // N4b-3: segments roll by count — capacity is never the reason a poll
      // is refused; a build failure (unreachable after the pre-dispatch
      // check) is a refusal, never a throw.
      if (!signingOpen()) return { ok: false, code: "CONTRACT_UNAVAILABLE" };
      const chain = router.chainKey(principal.keyId, fields.mcpSessionId);
      const segment = activePreBindSegment(chain);
      let receipt: ServerReceipt;
      try {
        receipt = makeReceipt(preBindTailFor(chain), {
          ...fields,
          runId: PRE_BIND_SCOPE,
          principal: { role: principal.role, keyId: principal.keyId },
          ts: now(),
        }, options.signer);
      } catch {
        return { ok: false, code: "CONTRACT_UNAVAILABLE" };
      }
      segment.receipts.push(receipt);
      return { ok: true, receipt };
    },
    sealPreBindSegment(keyId, mcpSessionId) {
      sealPreBindSegment(router.chainKey(keyId, mcpSessionId));
    },
    sessionDropped(keyId, mcpSessionId) {
      // At cap 1 the chain is the keyId's own — never per session.
      if (router.cap === 1) return;
      // L5: a session routed to no run can never be linked by a later bind.
      if (router.getSlot(keyId, router.slotFor(mcpSessionId)) === undefined) {
        try { options.onSessionReleased?.(keyId, mcpSessionId); } catch { /* release is best-effort */ }
      }
      const chain = router.chainKey(keyId, mcpSessionId);
      if (!preBindChains.has(chain)) return;
      if (chainCaptured(chain)) orphanedChains.add(chain);
      else forgetChain(chain);
    },
    preBindFeed(keyId, mcpSessionId) {
      return preBindFeedFor(router.chainKey(keyId, mcpSessionId));
    },
    receiptFeed(runId) {
      evictEnded();
      const run = runs.get(runId);
      if (run === undefined) return undefined;
      const head = run.receipts.length === 0
        ? RECEIPT_CHAIN_GENESIS
        : canonicalDigest(run.receipts[run.receipts.length - 1]!);
      // M1/N4b-3: the bound principals' pre-bind chain SEGMENTS ride the feed
      // so the observer can audit the evidence that preceded the run.
      const preBind: (NonNullable<ReturnType<ContractService["preBindFeed"]>> & { role: ContractRole })[] = [];
      for (const role of ["buyer", "provider"] as const) {
        const bound = run.bound[role];
        if (bound === undefined) continue;
        // O-3: the chain this seat linked at bind (the keyId's at cap 1).
        const feed = preBindFeedFor(boundChains.get(`${runId}|${role}`) ?? bound.principalKeyId);
        if (feed !== undefined) preBind.push({ ...feed, role });
      }
      return {
        runId, head,
        receipts: run.receipts.map((r) => structuredClone(r)),
        preBind,
        // N6g-2 (H1): every sim-backed receipt is labelled in the feed —
        // keyed by receiptId, `simulated` is always true on emission.
        // N4b-10 (D13): settlement-family labels name the rail that produced
        // them — "stripe_test_mode" carries the "no real money" text. The
        // rail is decided from the run's recorded paymentRail evidence
        // (settlement record, created intent, awaiting stop), NEVER from
        // `simulated: true` — which stays true on both rails.
        simLabels: run.receipts
          .filter((r) => SIM_LABELLED_TOOLS.has(r.tool))
          .map((r) => {
            if (!r.tool.startsWith("settlement")) {
              return { receiptId: r.receiptId, simulated: true };
            }
            const rail = run.settlement?.paymentRail
              ?? (run.settlementIntent !== undefined || run.awaitingStripeTestKey === true
                ? "stripe_test_mode" : options.settlementRail?.railId ?? "simulated");
            return {
              receiptId: r.receiptId,
              simulated: true,
              paymentRail: rail,
              label: rail === "stripe_test_mode" ? "Stripe TEST mode — no real money" : "simulated — no real money",
            };
          }),
        // N6g-2 (R12): verified consequential-submit approvals, bound to
        // the receipted `*_prepare` response that carried the envelope.
        ...(run.approvalRecords !== undefined && run.approvalRecords.length > 0
          ? {
              approvalRecords: run.approvalRecords.map(({ record, boundDigest }) => ({
                role: record.role,
                action: record.action,
                digest: boundDigest ?? record.digest,
                policyDigest: record.policyDigest,
                decision: record.decision,
                ts: new Date(record.ts).toISOString(),
                approverKeyId: record.approverKeyId,
                signature: record.signature,
              })),
            }
          : {}),
        // N6g-2 (R10c): the published per-role guidance digests — what the
        // transport's tools/list and instructions actually serve.
        guidance: {
          buyer: guidanceDigests("buyer", features),
          provider: guidanceDigests("provider", features),
        },
        // N4b-6: a seeded sim fault is disclosed at feed level too.
        ...(run.simFault !== undefined ? { simFault: run.simFault } : {}),
      };
    },
    saltFor(query) {
      if (query.runId !== undefined) {
        const run = runs.get(query.runId);
        return run === undefined
          ? undefined
          : { scope: "run" as const, id: query.runId, salt: run.runSalt };
      }
      if (query.keyId !== undefined) {
        // Only a principal that HAS pre-bind receipts gets a salt — never
        // materialize salts for an unknown keyId. `salt` is the ACTIVE
        // segment's; `salts` covers every retained segment (N4b-3 LOW:
        // salts rotate per segment).
        // O-3: above cap 1 a keyId has one chain per MCP session —
        // `mcpSessionId` selects one; without it every chain of the keyId
        // contributes its salts (the active `salt` is the newest chain's).
        // M3: the per-key index, never a scan of every tenant's chains.
        const chainKeys = query.mcpSessionId !== undefined || router.cap === 1
          ? [router.chainKey(query.keyId, query.mcpSessionId)]
          : [...(chainsByKey.get(query.keyId) ?? [])];
        const segments = chainKeys
          .flatMap((k) => preBindChains.get(k) ?? [])
          .filter((s) => s.receipts.length > 0);
        if (segments.length === 0) return undefined;
        return {
          scope: "pre-bind" as const,
          id: query.keyId,
          salt: segments.at(-1)!.salt,
          salts: segments.map((s) => s.salt),
        };
      }
      return undefined;
    },
    preBindSaltFor,
    endRun,
    runEnded,
    runIdForPrincipal(keyId, mcpSessionId) {
      evictEnded();
      const runId = router.get(keyId, mcpSessionId);
      if (runId !== undefined) {
        const run = runs.get(runId);
        // Terminal-but-unexpired runs still resolve: contract_status and the
        // receipt feed remain observable until the run's TTL evicts it. The
        // transport receipts an ENDED run's pre-bind calls on the keyId's
        // pre-bind chain instead (see PRE_BIND_TOOLS in server.ts).
        if (run !== undefined) return runId;
      }
      // N4b-9 (F14): a terminal run whose in-memory record is gone (restart)
      // still resolves for a bound caller via its persisted outbox job —
      // contract_status renders the terminal record, not "rendezvous".
      for (const job of outbox.all()) {
        if (job.terminalState === null) continue;
        if (job.boundKeyIds?.includes(keyId) === true || job.principal?.keyId === keyId) {
          return job.runId;
        }
      }
      return undefined;
    },
    close() {
      releaseLock?.();
    },
  };
}
