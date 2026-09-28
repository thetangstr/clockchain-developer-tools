import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
  /** Record a call's receipt onto the run chain (run-scoped, order-committed). */
  recordReceipt(
    run: ContractRun,
    fields: Omit<Parameters<typeof makeReceipt>[1], "runId">,
  ): ServerReceipt;
  runFor(runId: string): ContractRun | undefined;
  runIdForPrincipal(keyId: string): string | undefined;
}

const boundKeySchema = z.object({
  keyId: z.string().min(1).max(64),
  publicKeyHex: z.string().regex(/^0x[0-9a-fA-F]{64,132}$/),
}).strict();

const DEFAULT_MAX_RUNS = 1024;
const DEFAULT_MAX_RECEIPTS_PER_RUN = 1024;
const RUN_TTL_MS = 24 * 3600_000; // LLD §3: run-scoped state TTL is 24h
const USED_SESSIONS_FILE = "used-sessions.json";

function loadUsedSessions(stateDir: string | undefined): Map<string, string> {
  if (stateDir === undefined) return new Map();
  try {
    const raw = JSON.parse(readFileSync(path.join(stateDir, USED_SESSIONS_FILE), "utf8"));
    const sessions = isPlainRecord(raw?.sessions) ? raw.sessions : {};
    return new Map(
      Object.entries(sessions).filter(([, v]) => typeof v === "string") as [string, string][],
    );
  } catch {
    return new Map();
  }
}

function persistUsedSessions(stateDir: string | undefined, used: ReadonlyMap<string, string>): void {
  if (stateDir === undefined) return;
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, USED_SESSIONS_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ sessions: Object.fromEntries(used) }));
  renameSync(tmp, file);
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
  runTtlMs?: number;
}): ContractService {
  const now = options.now ?? Date.now;
  const maxRuns = options.maxRuns ?? DEFAULT_MAX_RUNS;
  const maxReceiptsPerRun = options.maxReceiptsPerRun ?? DEFAULT_MAX_RECEIPTS_PER_RUN;
  const runTtlMs = options.runTtlMs ?? RUN_TTL_MS;
  const runs = new Map<string, ContractRun>();
  const principalRuns = new Map<string, string>();
  const usedSessions = loadUsedSessions(options.stateDir);

  function runEnded(run: ContractRun): boolean {
    return run.stage === "terminal" || now() >= run.createdAtMs + runTtlMs;
  }

  function bind(
    principal: ContractPrincipal,
    args: { certificate: unknown; signerKey: unknown; approvalKey: unknown },
    evidence: { argsDigest: string; serverNonce: string; tool: string; sourceIp?: string },
  ): BindOutcome {
    const signerKey = boundKeySchema.safeParse(args.signerKey);
    const approvalKey = boundKeySchema.safeParse(args.approvalKey);
    if (!signerKey.success || !approvalKey.success) return { ok: false, code: "CERTIFICATE_INVALID" };

    const verdict = verifyCertificateEnvelope(args.certificate, {
      hostRoots: options.hostRoots,
      now,
      graceMs: options.graceMs,
    });
    if (!verdict.ok) return { ok: false, code: "CERTIFICATE_INVALID" };

    // C2: the certificate's party on the principal's claimed side must carry
    // exactly its provisioned agentId. (P-GAP: possession of the party's
    // handshake session key is not yet proven — the token↔agentId pin is the
    // whole assurance, see bindAssurance on the result/receipt.)
    const parties = verdict.result.parties as Record<string, unknown> | undefined;
    const party = isPlainRecord(parties?.[principal.side]) ? parties[principal.side] as Record<string, unknown> : undefined;
    const erc8004 = isPlainRecord(party?.erc8004) ? party.erc8004 : null;
    if (erc8004 === null || erc8004.agentId !== principal.agentId) {
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

    const run: ContractRun = existing ?? {
      runId,
      resultDigest: verdict.resultDigest,
      sessionPublicKey: verdict.sessionPublicKey,
      createdAtMs: now(),
      bound: {},
      receipts: [],
      stage: "handshake",
    };
    if (run.receipts.length >= maxReceiptsPerRun) return { ok: false, code: "RATE_LIMITED" };
    run.bound[principal.role] = {
      principalKeyId: principal.keyId,
      agentId: principal.agentId,
      side: principal.side,
      signerKey: signerKey.data,
      approvalKey: approvalKey.data,
      boundAt,
    };
    run.receipts.push(receipt);
    if (run.bound.buyer !== undefined && run.bound.provider !== undefined) run.stage = "bound";
    if (existing === undefined) {
      runs.set(runId, run);
      usedSessions.set(verdict.sessionId, runId);
      persistUsedSessions(options.stateDir, usedSessions);
    }
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
      if (run.receipts.length >= maxReceiptsPerRun) {
        throw new Error("recordReceipt: run receipt cap reached");
      }
      const receipt = makeReceipt(run.receipts.at(-1) ?? null, { ...fields, runId: run.runId, ts: now() }, options.signer);
      run.receipts.push(receipt);
      return receipt;
    },
    runFor(runId) {
      return runs.get(runId);
    },
    runIdForPrincipal(keyId) {
      const runId = principalRuns.get(keyId);
      if (runId === undefined) return undefined;
      const run = runs.get(runId);
      return run !== undefined && !runEnded(run) ? runId : undefined;
    },
  };
}
