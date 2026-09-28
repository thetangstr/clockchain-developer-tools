import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync,
  readFileSync, renameSync, rmSync, writeFileSync,
} from "node:fs";
import path from "node:path";

import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import { verifyCertificateEnvelope, type HostRootPin } from "./certificate.js";
import { makeReceipt, type ServerReceipt } from "./receipts.js";
import type { ContractSigner } from "./envelope.js";
import type { ContractRole } from "./schemas.js";
import type { ContractRefusalCode } from "./refusals.js";

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
  stage: ContractStage;
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
    args: { certificate: unknown; signerKey: unknown; approvalKey: unknown },
    evidence: { argsDigest: string; serverNonce: string; tool: string; sourceIp?: string },
  ): BindOutcome;
  /**
   * Record a call's receipt onto the run chain (run-scoped, order-committed).
   * At a cap this REFUSES — it never throws (N3: a refusal is a result, an
   * exception is an outage).
   */
  recordReceipt(
    run: ContractRun,
    fields: Omit<Parameters<typeof makeReceipt>[1], "runId">,
  ): { ok: true; receipt: ServerReceipt } | { ok: false; code: "RATE_LIMITED" };
  runFor(runId: string): ContractRun | undefined;
  runIdForPrincipal(keyId: string): string | undefined;
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
const RUN_TTL_MS = 24 * 3600_000; // LLD §3: run-scoped state TTL is 24h
const USED_SESSIONS_FILE = "used-sessions.json";
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
 * Exclusive lock on the state directory (N2): two processes sharing the
 * volume must not interleave used-session writes — the second is refused.
 */
function acquireStateLock(stateDir: string): () => void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, LOCK_FILE);
  const fd = tryLock(file);
  writeFileSync(fd, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
  closeSync(fd);
  let held = true;
  return () => {
    if (held) {
      held = false;
      rmSync(file, { force: true });
    }
  };
}

function tryLock(file: string): number {
  try {
    return openSync(file, "wx");
  } catch {
    // Crash recovery: a lock whose recorded pid is dead is stale — remove it
    // and retry once. A lock held by a LIVE process refuses the second one.
    const pid = lockPid(file);
    if (pid !== null && pidAlive(pid)) {
      throw new Error(`contract state dir is locked by pid ${pid}: ${file}`);
    }
    rmSync(file, { force: true });
    return openSync(file, "wx");
  }
}

function lockPid(file: string): number | null {
  try {
    const raw = JSON.parse(readFileSync(file, "utf8"));
    const pid = Number(raw?.pid);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
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
}): ContractService {
  const now = options.now ?? Date.now;
  const maxRuns = options.maxRuns ?? DEFAULT_MAX_RUNS;
  const maxReceiptsPerRun = options.maxReceiptsPerRun ?? DEFAULT_MAX_RECEIPTS_PER_RUN;
  const maxReceiptsPerPrincipal = options.maxReceiptsPerPrincipal ?? DEFAULT_MAX_RECEIPTS_PER_PRINCIPAL;
  const runTtlMs = options.runTtlMs ?? RUN_TTL_MS;
  const runs = new Map<string, ContractRun>();
  const principalRuns = new Map<string, string>();
  let releaseLock: (() => void) | undefined;
  let usedSessions: Map<string, string> = new Map();
  if (options.stateDir !== undefined) {
    // N1/N2: lock the dir first (a second process is refused outright), then
    // load — a corrupt/unreadable record is a startup failure, not "empty".
    releaseLock = acquireStateLock(options.stateDir);
    try {
      usedSessions = loadUsedSessions(options.stateDir);
    } catch (err) {
      releaseLock();
      throw err;
    }
  }

  function runEnded(run: ContractRun): boolean {
    return run.stage === "terminal" || now() >= run.createdAtMs + runTtlMs;
  }

  /** M4/M5: ended runs are REMOVED — they no longer hold a cap slot. */
  function evictEnded(): void {
    for (const [runId, run] of runs) {
      if (!runEnded(run)) continue;
      runs.delete(runId);
      for (const [keyId, rid] of principalRuns) {
        if (rid === runId) principalRuns.delete(keyId);
      }
    }
  }

  function bind(
    principal: ContractPrincipal,
    args: { certificate: unknown; signerKey: unknown; approvalKey: unknown },
    evidence: { argsDigest: string; serverNonce: string; tool: string; sourceIp?: string },
  ): BindOutcome {
    evictEnded(); // M4/M5: free cap slots before deciding
    // N4: buyer ≡ initiator, provider ≡ responder — enforced at token parse
    // (startup error) AND again here at bind.
    if ((principal.role === "buyer") !== (principal.side === "initiator")) {
      return { ok: false, code: "ROLE_REFUSED" };
    }

    const signerKey = boundKeySchema.safeParse(args.signerKey);
    const approvalKey = boundKeySchema.safeParse(args.approvalKey);
    if (!signerKey.success || !approvalKey.success) return { ok: false, code: "CERTIFICATE_INVALID" };

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
      stage: "handshake",
    };
    // N3: refuse (never throw) at the run cap or this principal's own budget.
    const principalReceipts = run.receiptsByPrincipal.get(principal.keyId) ?? 0;
    if (run.receipts.length >= maxReceiptsPerRun || principalReceipts >= maxReceiptsPerPrincipal) {
      return { ok: false, code: "RATE_LIMITED" };
    }

    const receipt = makeReceipt(prevReceipt, {
      runId,
      tool: evidence.tool,
      argsDigest: evidence.argsDigest,
      principal: { role: principal.role, keyId: principal.keyId },
      outcome: "ok",
      responseDigest: canonicalDigest(resultBody),
      serverNonce: evidence.serverNonce,
      sourceIp: evidence.sourceIp,
      bindAssurance: "agentId-pinned-token",
      ts: now(),
    }, options.signer);

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

  return {
    bind,
    recordReceipt(run, fields) {
      evictEnded();
      const count = run.receiptsByPrincipal.get(fields.principal.keyId) ?? 0;
      if (run.receipts.length >= maxReceiptsPerRun || count >= maxReceiptsPerPrincipal) {
        return { ok: false, code: "RATE_LIMITED" };
      }
      const receipt = makeReceipt(
        run.receipts.at(-1) ?? null,
        { ...fields, runId: run.runId, ts: now() },
        options.signer,
      );
      run.receipts.push(receipt);
      run.receiptsByPrincipal.set(fields.principal.keyId, count + 1);
      return { ok: true, receipt };
    },
    runFor(runId) {
      evictEnded();
      return runs.get(runId);
    },
    runIdForPrincipal(keyId) {
      evictEnded();
      const runId = principalRuns.get(keyId);
      if (runId === undefined) return undefined;
      const run = runs.get(runId);
      return run !== undefined && !runEnded(run) ? runId : undefined;
    },
    close() {
      releaseLock?.();
    },
  };
}
