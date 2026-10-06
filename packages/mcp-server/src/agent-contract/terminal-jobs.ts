/**
 * N4b-9 (F14): the durable terminal outbox.
 *
 * The first terminal transition of a run enqueues — BEFORE the transition
 * is acknowledged — a persisted job carrying everything a restart needs to
 * finish what was started:
 *
 *  - the runId + terminal state (write-once terminal identity);
 *  - the immutable minted close receipt (the close identity — the same
 *    bytes are redelivered on recovery, never re-minted);
 *  - the anchor subjects (agreement digest / terminal chain head) and
 *    each anchor job's outcome;
 *  - the chain tip at the terminal transition (`prevReceipt`) plus the
 *    triggering principal, so post-restart delivery/anchor outcomes can
 *    still be minted as signed evidence receipts after the in-memory run
 *    is gone;
 *  - the evidence receipts minted so far (the persisted copy of what the
 *    live run chain also carries).
 *
 * File: `<stateDir>/terminal-jobs.json`, written with the same tmp +
 * fsync + rename + dirsync discipline as used-sessions/used-mandates.
 * A corrupt file is a hard startup error, never silently "empty".
 */
import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync,
  renameSync, writeFileSync,
} from "node:fs";
import path from "node:path";

import type { TerminalReceipt } from "./close-emitter.js";
import type { ServerReceipt } from "./receipts.js";

export const TERMINAL_JOBS_FILE = "terminal-jobs.json";
export const TERMINAL_JOBS_SCHEMA = "ac-terminal-jobs/v1";
/** N4b-11 (L3): default retention cap on FINISHED jobs in the durable file. */
export const DEFAULT_TERMINAL_JOBS_MAX_FINISHED = 256;

/** A persisted anchor job — mirrors AnchorRunState plus the subject digest. */
export interface TerminalAnchorJob {
  kind: "agreement" | "terminal" | "terms" | "brief" | "final";
  digest: string;
  status: "anchoring" | "pending" | "anchored" | "failed";
  /** final only: the run-chain length the final head covers (null after a restart). */
  receiptCount?: number | null;
  anchorId?: string;
  eventHash?: string;
  ledger?: { ledgerId: string; blockHeight: string | null; time: string | null; status: string };
  error?: string;
}

export interface TerminalCloseJob {
  status: "delivering" | "delivered" | "failed";
  attempts: number;
  lastError?: string;
  deliveredAt?: string;
}

export interface TerminalJob {
  runId: string;
  /** Null until the first terminal transition lands it (write-once). */
  terminalState: string | null;
  /** The immutable close receipt — absent only when no emitter is armed. */
  receipt?: TerminalReceipt;
  /** sha256 of the canonical receipt. */
  receiptDigest?: string;
  /** The principal that triggered the terminal transition (outcome minting). */
  principal?: { role: "buyer" | "provider"; keyId: string } | null;
  /**
   * Both bound principals' keyIds at the transition — post-restart the run
   * is gone, so this is how contract_status still resolves the run for a
   * bound caller.
   */
  boundKeyIds?: string[];
  /**
   * The run-chain tip receipt at the terminal transition — the preimage of
   * the anchored terminal head, and the `prev` for post-restart evidence
   * minting once the in-memory run is gone.
   */
  prevReceipt?: ServerReceipt | null;
  close?: TerminalCloseJob;
  anchors?: {
    agreement?: TerminalAnchorJob;
    terminal?: TerminalAnchorJob;
    /** Server-side anchors (server-anchors.ts): recorded here, never chained. */
    terms?: TerminalAnchorJob;
    brief?: TerminalAnchorJob;
    final?: TerminalAnchorJob;
  };
  /** Post-transition evidence receipts (mirror of the live run chain). */
  evidence: ServerReceipt[];
  updatedAtMs: number;
}

export function createTerminalJob(runId: string, nowMs: number): TerminalJob {
  return { runId, terminalState: null, evidence: [], updatedAtMs: nowMs };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function loadTerminalJobs(stateDir: string): Map<string, TerminalJob> {
  const file = path.join(stateDir, TERMINAL_JOBS_FILE);
  if (!existsSync(file)) return new Map();
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!isRecord(raw) || raw.schema !== TERMINAL_JOBS_SCHEMA || !Array.isArray(raw.jobs)) {
    throw new Error(`corrupt ${TERMINAL_JOBS_FILE}`);
  }
  const out = new Map<string, TerminalJob>();
  for (const j of raw.jobs) {
    if (!isRecord(j) || typeof j.runId !== "string") {
      throw new Error(`corrupt ${TERMINAL_JOBS_FILE}`);
    }
    out.set(j.runId, j as unknown as TerminalJob);
  }
  return out;
}

/**
 * N4b-11 (L3): a job is FINISHED — prunable — once its close is
 * delivered/failed/absent AND no anchor job is still anchoring/pending
 * (the exact complement of the `unfinished()` predicate). Unfinished jobs
 * are never dropped: they are the recovery state.
 */
function anchorJobOpen(j: TerminalJob): boolean {
  const a = j.anchors;
  return a !== undefined && [a.agreement, a.terminal, a.terms, a.brief, a.final].some(
    (x) => x !== undefined && (x.status === "anchoring" || x.status === "pending"),
  );
}

function isFinishedJob(j: TerminalJob): boolean {
  const closeDone = j.close === undefined || j.close.status !== "delivering";
  return closeDone && !anchorJobOpen(j);
}

/**
 * Durable write: tmp file → fsync → rename → fsync the directory.
 * N4b-11 (L3): bounded retention — finished jobs beyond `maxFinished`
 * (least-recently `updatedAtMs` first) are left out of the durable write
 * so the file cannot grow forever. The in-memory map is untouched: a
 * later mutation simply re-persists the job.
 */
function persistTerminalJobs(
  stateDir: string,
  jobs: ReadonlyMap<string, TerminalJob>,
  maxFinished: number,
): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, TERMINAL_JOBS_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  const finished = [...jobs.values()]
    .map((j, insertion) => ({ j, insertion }))
    .filter(({ j }) => isFinishedJob(j))
    // Most-recent first; a same-ms tie keeps the later-ENQUEUED job (Map
    // order is insertion order — a re-set keeps its original slot).
    .sort((a, b) => (b.j.updatedAtMs - a.j.updatedAtMs) || (b.insertion - a.insertion));
  const dropped = new Set(finished.slice(Math.max(0, maxFinished)).map(({ j }) => j.runId));
  const fd = openSync(tmp, "w");
  try {
    writeFileSync(fd, JSON.stringify({
      schema: TERMINAL_JOBS_SCHEMA,
      jobs: [...jobs.values()].filter((j) => !dropped.has(j.runId)),
    }));
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
 * The per-service outbox handle. In-memory when no stateDir is configured
 * (tests without durability still exercise the same code path); every
 * mutation durably persists when a stateDir exists.
 */
export interface TerminalOutbox {
  get(runId: string): TerminalJob | undefined;
  /** Get-or-create + mutate + persist. A persist failure THROWS — the caller decides whether the transition may proceed. */
  update(runId: string, nowMs: number, mutate: (job: TerminalJob) => void): TerminalJob;
  /**
   * N4b-11 (M3): the fail-closed variant for transitions that must NOT be
   * acknowledged without the durable write (the terminal enqueue). The
   * mutation is applied to a copy; a persist failure restores the prior
   * in-memory entry — or drops a new one — before rethrowing, so the
   * outbox never carries a mutation the durable file does not have.
   */
  updateDurable(runId: string, nowMs: number, mutate: (job: TerminalJob) => void): TerminalJob;
  all(): TerminalJob[];
  /** Jobs still owed work: close not delivered/failed, or anchor jobs still anchoring/pending. */
  unfinished(): TerminalJob[];
}

export function createTerminalOutbox(
  stateDir: string | undefined,
  maxFinished: number = DEFAULT_TERMINAL_JOBS_MAX_FINISHED,
): TerminalOutbox {
  const jobs: Map<string, TerminalJob> =
    stateDir === undefined ? new Map() : loadTerminalJobs(stateDir);
  const save = (): void => {
    if (stateDir !== undefined) persistTerminalJobs(stateDir, jobs, maxFinished);
  };
  return {
    get: (runId) => jobs.get(runId),
    update(runId, nowMs, mutate) {
      const job = jobs.get(runId) ?? createTerminalJob(runId, nowMs);
      mutate(job);
      job.updatedAtMs = nowMs;
      jobs.set(runId, job);
      save();
      return job;
    },
    updateDurable(runId, nowMs, mutate) {
      const prev = jobs.get(runId);
      const job = prev === undefined
        ? createTerminalJob(runId, nowMs)
        : structuredClone(prev);
      mutate(job);
      job.updatedAtMs = nowMs;
      jobs.set(runId, job);
      try {
        save();
      } catch (err) {
        // Fail closed: the un-persisted mutation leaves no trace — a retry
        // rebuilds the job from the last durable state.
        if (prev === undefined) jobs.delete(runId);
        else jobs.set(runId, prev);
        throw err;
      }
      return job;
    },
    all: () => [...jobs.values()],
    unfinished() {
      return [...jobs.values()].filter((j) =>
        (j.close !== undefined && j.close.status === "delivering") || anchorJobOpen(j),
      );
    },
  };
}
