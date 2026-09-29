import {
  closeSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync,
  readFileSync, renameSync, rmSync, writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";

import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import { verifyCertificateEnvelope, type HostRootPin } from "./certificate.js";
import { makeReceipt, checkReceiptDraft, type ReceiptFields, type ServerReceipt, RECEIPT_CHAIN_GENESIS } from "./receipts.js";
import type { ContractSigner } from "./envelope.js";
import type { ContractRole } from "./schemas.js";
import type { ContractRefusalCode } from "./refusals.js";
import { createBusinessOps, type BusinessOps } from "./business.js";
import { createSimWorld, type SimFaults, type SimRun, type SimTicket, type SimWorld } from "./sim/index.js";

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
  /** ERC-8004 agent id this principal claims (from its provisioned token). */
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
}

export type ContractStage =
  | "rendezvous" | "handshake" | "bound" | "mandated" | "negotiating"
  | "agreed" | "booked" | "verified" | "settled" | "terminal";

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
    expiresAt: string;
    /** The family-principal address the mandate signature recovered to. */
    principalAddress: string;
    submittedAt: string;
  };
  readonly offers: Map<string, OfferRecord>;
  offerSeq: number;
  agreement?: AgreementRecord;
  booking?: { orderRef: string; pnr: string; tickets: SimTicket[]; bookedAt: string };
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
  settlement?: { transferId: string; status: "authorized" | "released" };
  settlementPrepared?: boolean;
  terminalState: string | null;
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
    args: { certificate: unknown; signerKey: unknown; approvalKey: unknown; listingId?: unknown },
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
  runIdForPrincipal(keyId: string): string | undefined;
  /**
   * Move a run to its terminal state and retire the sim world entry
   * (post-terminal retention lives in the world itself).
   */
  endRun(run: ContractRun, terminalState: string): void;
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
  sealPreBindSegment(keyId: string): void;
  /** A principal's segmented pre-bind chain for the observer feed. */
  preBindFeed(keyId: string): {
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
  } | undefined;
  /**
   * M4: the per-scope argsDigest salt — `{ runId }` for a run's salt,
   * `{ keyId }` for a principal's pre-bind salts (one PER SEGMENT — `salt`
   * is the active segment's, `salts` covers every retained segment).
   * Disclosed ONLY through the verifier-scoped endpoint.
   */
  saltFor(query: { runId?: string; keyId?: string }):
    { scope: "run" | "pre-bind"; id: string; salt: string; salts?: string[] } | undefined;
  /** M4: a principal's ACTIVE pre-bind segment salt (lazily created). */
  preBindSaltFor(keyId: string): string;
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
/** The runId sentinel pre-bind receipts are scoped under (no run exists yet). */
const PRE_BIND_SCOPE = "pre-bind";
const RUN_TTL_MS = 24 * 3600_000; // LLD §3: run-scoped state TTL is 24h
const USED_SESSIONS_FILE = "used-sessions.json";
const USED_MANDATES_FILE = "used-mandates.json";
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

/** Durable write: tmp file → fsync → rename → fsync the directory (N1). */
function persistUsedSessions(stateDir: string, used: ReadonlyMap<string, string>): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, USED_SESSIONS_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w");
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
  const fd = openSync(tmp, "w");
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

function acquireStateLock(stateDir: string): () => void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, LOCK_FILE);
  linkLock(file);
  let held = true;
  const onTerm = () => { try { release(); } finally { process.exit(143); } };
  const onInt = () => { try { release(); } finally { process.exit(130); } };
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

export function createContractService(options: {
  hostRoots: readonly HostRootPin[];
  signer: ContractSigner;
  now?: () => number;
  graceMs?: number;
  stateDir?: string;
  maxRuns?: number;
  maxReceiptsPerRun?: number;
  maxReceiptsPerPrincipal?: number;
  runTtlMs?: number;
  /** Optional pin: certificates must attest this exact ERC-8004 chain+registry. */
  expectedErc8004?: { chainId: string; registryAddress: string };
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
  policyDigests: Readonly<Record<ContractRole, string>>;
  /** `CONTRACT_PRINCIPALS`: buyer keyId → pinned family-principal address. */
  principals?: ReadonlyMap<string, string>;
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
  if (
    options.policyDigests === undefined ||
    !/^0x[0-9a-f]{64}$/.test(options.policyDigests.buyer ?? "") ||
    !/^0x[0-9a-f]{64}$/.test(options.policyDigests.provider ?? "")
  ) {
    // Fail closed at construction: without the policy pins every approval
    // check would be ambiguous — never silently degrade.
    throw new Error("policyDigests {buyer,provider} are required (0x + 64 lower hex)");
  }
  const runs = new Map<string, ContractRun>();
  const principalRuns = new Map<string, string>();
  /** M1/N4b-3: per-principal SEGMENTED pre-bind chains — the run genesis
   *  links each side's head (`preBindHead`); each bind seals the active
   *  segment and the oldest segments roll off past `preBindMaxSegments`. */
  const preBindChains = new Map<string, PreBindSegment[]>();
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
  // LOW (N4b-3): retention window for used-mandate entries = expiresAt +
  // graceMs (the same clock-skew grace used elsewhere; default 10 min).
  const mandateGraceMs = options.graceMs ?? 600_000;
  if (options.stateDir !== undefined) {
    // N1/N2: lock the dir first (a second process is refused outright), then
    // load — a corrupt/unreadable record is a startup failure, not "empty".
    releaseLock = acquireStateLock(options.stateDir);
    try {
      usedSessions = loadUsedSessions(options.stateDir);
      usedMandates = loadUsedMandates(options.stateDir, now(), mandateGraceMs);
    } catch (err) {
      releaseLock();
      throw err;
    }
  }

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

  function runEnded(run: ContractRun): boolean {
    return run.terminalState !== null || now() >= run.createdAtMs + runTtlMs;
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
  function preBindSaltFor(keyId: string): string {
    return activePreBindSegment(keyId).salt;
  }

  /** The head of a principal's pre-bind chain, or undefined if it has none. */
  function preBindHeadFor(keyId: string): string | undefined {
    const tail = preBindTailFor(keyId);
    return tail === null ? undefined : canonicalDigest(tail);
  }

  function dropRun(runId: string): void {
    runs.delete(runId);
    for (const [keyId, rid] of principalRuns) {
      if (rid === runId) principalRuns.delete(keyId);
    }
  }

  /**
   * M4/M5: TTL-expired runs are always removed. Terminal-but-fresh runs stay
   * observable (contract_status, receipt feed) and are only dropped under
   * capacity pressure — evidence survives the terminal transition.
   */
  function evictEnded(): void {
    for (const [runId, run] of runs) {
      if (now() >= run.createdAtMs + runTtlMs) dropRun(runId);
    }
  }
  function evictForCapacity(): void {
    for (const [runId, run] of runs) {
      if (runs.size < maxRuns) return;
      if (runEnded(run)) dropRun(runId);
    }
  }

  function bind(
    principal: ContractPrincipal,
    args: { certificate: unknown; signerKey: unknown; approvalKey: unknown; listingId?: unknown },
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
    if (
      erc8004 === null || policy === null ||
      erc8004.agentId !== principal.agentId ||
      erc8004.chainId !== policy.chainId ||
      erc8004.registryAddress !== policy.registryAddress ||
      (pinned !== undefined &&
        (policy.chainId !== pinned.chainId || policy.registryAddress !== pinned.registryAddress))
    ) {
      return { ok: false, code: "CERTIFICATE_INVALID" };
    }

    const priorRunId = principalRuns.get(principal.keyId);
    if (priorRunId !== undefined) {
      const prior = runs.get(priorRunId);
      if (prior !== undefined && !runEnded(prior)) {
        // Idempotent re-bind on the same run requires an identical
        // {resultDigest, signerKey, approvalKey}; anything else is a refusal.
        const mine = prior.bound[principal.role];
        if (
          mine === undefined ||
          verdict.sessionId !== prior.runId ||
          mine.signerKey.keyId !== signerKey.data.keyId ||
          mine.signerKey.publicKeyHex !== signerKey.data.publicKeyHex ||
          mine.approvalKey.keyId !== approvalKey.data.keyId ||
          mine.approvalKey.publicKeyHex !== approvalKey.data.publicKeyHex ||
          verdict.resultDigest !== prior.resultDigest
        ) return { ok: false, code: "STATE_REFUSED" };
        return idempotentOutcome(prior, principal.role, mine.boundAt, evidence.serverNonce);
      }
      // M5: the previous run has ended — the seat is free for a new run.
      principalRuns.delete(principal.keyId);
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
    const boundAt = new Date(now()).toISOString();
    const resultBody = {
      runId: verdict.sessionId,
      role: principal.role,
      bound: true,
      boundAt,
      side: principal.side,
      serverNonce: evidence.serverNonce,
      bindAssurance: "agentId-pinned-token" as const,
    };
    const runId = verdict.sessionId;
    const prevReceipt = existing === undefined ? null : (existing.receipts.at(-1) ?? null);
    const run: ContractRun = existing ?? {
      runId,
      resultDigest: verdict.resultDigest,
      sessionPublicKey: verdict.sessionPublicKey,
      createdAtMs: now(),
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
        bindAssurance: "agentId-pinned-token",
        // M1: the bind receipt carries THIS principal's pre-bind chain head —
        // the run chain's link back to the evidence that preceded it.
        preBindHead: preBindHeadFor(principal.keyId),
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
    if (existing === undefined && options.stateDir !== undefined) {
      const next = new Map(usedSessions);
      next.set(verdict.sessionId, runId);
      try {
        persistUsedSessions(options.stateDir, next);
      } catch {
        return { ok: false, code: "CONTRACT_UNAVAILABLE" };
      }
      usedSessions = next;
    } else if (existing === undefined) {
      usedSessions.set(verdict.sessionId, runId);
    }

    run.bound[principal.role] = {
      principalKeyId: principal.keyId,
      agentId: principal.agentId,
      side: principal.side,
      signerKey: signerKey.data,
      approvalKey: approvalKey.data,
      boundAt,
    };
    run.receipts.push(receipt);
    run.receiptsByPrincipal.set(principal.keyId, principalReceipts + 1);
    if (run.bound.buyer !== undefined && run.bound.provider !== undefined) run.stage = "bound";
    if (existing === undefined) runs.set(runId, run);
    principalRuns.set(principal.keyId, runId);
    // LOW (N4b-3): commit-time consumption — the provider's successful bind
    // consumes ONLY the named listing (ownership probed above).
    if (principal.role === "provider" && bindListingId !== undefined) {
      business.consumeListing(principal.keyId, bindListingId);
    }
    // N4b-3: a successful bind SEALS this principal's pre-bind segment — the
    // next pre-bind call starts a fresh segment (fresh salt) anchored on the
    // sealed head, so the lifetime cap can never lock a principal out.
    sealPreBindSegment(principal.keyId);
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
        bindAssurance: "agentId-pinned-token" as const,
        idempotent: true,
      },
      // An idempotent re-bind appends no receipt: nothing changed.
      receipt: run.receipts.at(-1) as ServerReceipt,
      run,
    };
  }

  const endRun = (run: ContractRun, terminalState: string): void => {
    // "settled" is itself a named terminal stage; every other terminal reason
    // reads stage:"terminal" with terminalState carrying the why.
    run.stage = terminalState === "settled" ? "settled" : "terminal";
    run.terminalState = terminalState;
    sim.markTerminal(run.runId);
  };
  const business = createBusinessOps({
    signer: options.signer,
    now,
    sim,
    signingOpen,
    policyDigests: options.policyDigests,
    ...(options.principals !== undefined ? { principals: options.principals } : {}),
    claimMandate,
    endRun,
  });

  return {
    bind,
    business,
    recordReceipt(run, fields) {
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
      return { ok: true, receipt };
    },
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
      const prev = preBindTailFor(principal.keyId);
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
      const segment = activePreBindSegment(principal.keyId);
      let receipt: ServerReceipt;
      try {
        receipt = makeReceipt(preBindTailFor(principal.keyId), {
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
    sealPreBindSegment,
    preBindFeed(keyId) {
      const segments = preBindChains.get(keyId);
      if (segments === undefined) return undefined;
      const nonEmpty = segments.filter((s) => s.receipts.length > 0);
      if (nonEmpty.length === 0) return undefined;
      const first = nonEmpty[0]!.receipts[0]!;
      const receipts = nonEmpty.flatMap((s) => s.receipts.map((r) => structuredClone(r)));
      return {
        principalKeyId: keyId,
        head: canonicalDigest(nonEmpty.at(-1)!.receipts.at(-1)!),
        anchor: first.prevHash,
        truncated: first.prevHash !== RECEIPT_CHAIN_GENESIS,
        receipts,
        segments: nonEmpty.map((s) => ({
          anchor: s.receipts[0]!.prevHash,
          receipts: s.receipts.map((r) => structuredClone(r)),
        })),
      };
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
        const feed = this.preBindFeed(bound.principalKeyId);
        if (feed !== undefined) preBind.push({ ...feed, role });
      }
      return {
        runId, head,
        receipts: run.receipts.map((r) => structuredClone(r)),
        preBind,
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
        const segments = (preBindChains.get(query.keyId) ?? []).filter((s) => s.receipts.length > 0);
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
    runIdForPrincipal(keyId) {
      evictEnded();
      const runId = principalRuns.get(keyId);
      if (runId === undefined) return undefined;
      const run = runs.get(runId);
      // Terminal-but-unexpired runs still resolve: contract_status and the
      // receipt feed remain observable until the run's TTL evicts it.
      return run !== undefined ? runId : undefined;
    },
    close() {
      releaseLock?.();
    },
  };
}
