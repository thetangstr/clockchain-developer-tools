/**
 * Milestone log (MILESTONE-TIMELINE.md §4, "Option A"): a server-side,
 * per-milestone Clockchain log written by the contract server at each
 * business-milestone transition. Behind CONTRACT_MILESTONE_LOG=1 (default
 * off); off, nothing here runs and no surface changes.
 *
 * Six milestones, in order: discover, proposal, negotiation, agreement,
 * execution, settlement. Every run-chain receipt (business/handshake
 * surface; never the server's own `anchoring` evidence) is attributed to
 * one milestone. When a milestone completes, its entry is SEALED:
 *
 *   payload = { schema: "ac.milestone-log/v1", runId, milestone, index,
 *               firstTs, lastTs, receiptIds[], approvalDigests[],
 *               prevEntryDigest }
 *   digest  = sha256(canonicalJson(payload))   (0x hex; canonical.ts)
 *
 * and written through the run's ContractAnchor (`log`) as that asset hash
 * under `ac-milestone:<runId>:<n>-<milestone>`. `prevEntryDigest` is the
 * previous sealed entry's digest (null for discover), so the entries form
 * one chain a verifier walks in order. The payload holds only ids, digests
 * and times — receipt ids are digests of signed receipts; approval digests
 * are the receipt-linked digests the observer feed already publishes.
 *
 * When a milestone completes (what the server can observe):
 *   - discover:    the buyer's mandate_submit succeeds. That needs both
 *                  binds (a mandate needs a fully bound run), so it covers
 *                  binds + mandate. Pre-bind calls (rendezvous, handshake)
 *                  are not run receipts; each bind receipt's `preBindHead`
 *                  commits to that principal's pre-bind chain instead.
 *   - proposal:    the first offer_submit succeeds (once discover sealed;
 *                  a provider offer made before the mandate is held until
 *                  the mandate seals discover).
 *   - negotiation: an agreement forms (offer_accept_submit). Empty when the
 *                  first offer was accepted — sealed with no receipts.
 *   - agreement:   offer_accept_submit succeeds.
 *   - execution:   verification_submit succeeds.
 *   - settlement:  the terminal transition.
 * At ANY terminal transition every milestone up to the last one that holds
 * a receipt is sealed; later milestones are never written ("not-reached").
 *
 * Attribution: a tool with a fixed milestone (MILESTONE_TOOL_CLASS) goes to
 * that milestone, unless it is already sealed — then to the first open one.
 * Stage-agnostic tools (status reads, contract_withdraw, …) take the first
 * open milestone, i.e. the deal stage at that moment.
 *
 * Writes: one per sealed entry, serialized per run (ledger order == index
 * order), idempotent per (reference, digest) in the adapter, with the same
 * honest anchoring → pending → anchored | failed states, bounded confirm
 * loop and boot recovery as the server-side anchors. Entries are recorded on
 * the run and its durable terminal job — never chained as receipts.
 *
 * Restart limits (documented in docs/agent-contract/MILESTONE-LOG.md): live
 * runs are in-memory, so a live run's open milestones die with it (as its
 * receipts do). Entries already on a terminal job are recovered; entries a
 * crash prevented from sealing at terminal render as "lost".
 */
import type { AnchorWrite, ContractAnchor } from "./anchor.js";
import { canonicalDigest } from "./canonical.js";
import type { ServerReceipt } from "./receipts.js";
import type { ContractRun } from "./service.js";
import type { TerminalJob, TerminalMilestoneJob } from "./terminal-jobs.js";

export const MILESTONE_LOG_SCHEMA = "ac.milestone-log/v1" as const;
export const MILESTONES = ["discover", "proposal", "negotiation", "agreement", "execution", "settlement"] as const;
export type Milestone = (typeof MILESTONES)[number];

/** Tools whose receipts belong to a fixed milestone. Every other run-chain tool takes the first open milestone. */
export const MILESTONE_TOOL_CLASS: Readonly<Record<string, Milestone>> = Object.freeze({
  contract_bind: "discover",
  mandate_prepare: "discover",
  mandate_submit: "discover",
  catalog_quote: "proposal",
  offer_prepare: "proposal",
  offer_submit: "proposal",
  offer_reject: "negotiation",
  offer_accept_prepare: "agreement",
  offer_accept_submit: "agreement",
  booking_prepare: "execution",
  booking_execute: "execution",
  booking_lookup: "execution",
  booking_cancel_prepare: "execution",
  booking_cancel_submit: "execution",
  verification_prepare: "execution",
  verification_submit: "execution",
  settlement_prepare: "settlement",
  settlement_authorize: "settlement",
});

/** An `ok` receipt of these tools completes every milestone through the named one. */
const CLOSERS: Readonly<Record<string, Milestone>> = Object.freeze({
  offer_accept_submit: "agreement",
  verification_submit: "execution",
});

export const milestoneReferenceId = (runId: string, m: Milestone): string =>
  `ac-milestone:${runId}:${MILESTONES.indexOf(m) + 1}-${m}`;
/** Plain text only — the gateway strips punctuation from additional_info. */
export const milestoneAdditionalInfo = (m: Milestone): string => `agent contract milestone ${m}`;

export interface MilestonePayload {
  schema: typeof MILESTONE_LOG_SCHEMA;
  runId: string;
  milestone: Milestone;
  index: number;
  firstTs: string | null;
  lastTs: string | null;
  receiptIds: string[];
  approvalDigests: string[];
  prevEntryDigest: string | null;
}

export interface MilestoneEntryState {
  index: number;
  milestone: Milestone;
  referenceId: string;
  /** sha256(canonicalJson(payload)) — the anchored asset hash. */
  digest: string;
  payload: MilestonePayload;
  status: "anchoring" | "pending" | "anchored" | "failed";
  anchorId?: string;
  eventHash?: string;
  ledger?: AnchorWrite["anchor"];
  error?: string;
}

interface Bucket {
  receiptIds: string[];
  approvalDigests: string[];
  firstTs: number | null;
  lastTs: number | null;
}

/** Per-run, in-memory attribution state (on ContractRun.milestoneLog). */
export interface MilestoneTracker {
  buckets: Bucket[];
  /** How many milestones are sealed (0..6) — the first open one is MILESTONES[sealed]. */
  sealed: number;
  /** The terminal close ran: nothing more is attributed or sealed. */
  closed: boolean;
  mandateSeen: boolean;
  offerSeen: boolean;
  /** run.approvalRecords already attributed. */
  approvalsSeen: number;
  prevDigest: string | null;
  entries: MilestoneEntryState[];
}

export function createMilestoneTracker(): MilestoneTracker {
  return {
    buckets: MILESTONES.map(() => ({ receiptIds: [], approvalDigests: [], firstTs: null, lastTs: null })),
    sealed: 0, closed: false, mandateSeen: false, offerSeen: false, approvalsSeen: 0, prevDigest: null, entries: [],
  };
}

const iso = (ms: number | null): string | null => (ms === null ? null : new Date(ms).toISOString());

/** Seal every open milestone up to and including index `k` (0-based), in order. */
function sealThrough(t: MilestoneTracker, runId: string, k: number): MilestoneEntryState[] {
  const out: MilestoneEntryState[] = [];
  while (t.sealed <= k && t.sealed < MILESTONES.length) {
    const i = t.sealed;
    const m = MILESTONES[i]!;
    const b = t.buckets[i]!;
    const payload: MilestonePayload = {
      schema: MILESTONE_LOG_SCHEMA,
      runId,
      milestone: m,
      index: i + 1,
      firstTs: iso(b.firstTs),
      lastTs: iso(b.lastTs),
      receiptIds: [...b.receiptIds].sort(),
      approvalDigests: [...b.approvalDigests],
      prevEntryDigest: t.prevDigest,
    };
    const digest = canonicalDigest(payload);
    t.prevDigest = digest;
    t.sealed += 1;
    const entry: MilestoneEntryState = {
      index: i + 1, milestone: m, referenceId: milestoneReferenceId(runId, m), digest, payload, status: "anchoring",
    };
    t.entries.push(entry);
    out.push(entry);
  }
  return out;
}

/**
 * Terminal close: seal through the last milestone holding any evidence (or
 * the last already sealed). Milestones after it are never written.
 */
export function closeMilestones(t: MilestoneTracker, runId: string): MilestoneEntryState[] {
  if (t.closed) return [];
  t.closed = true;
  let last = t.sealed - 1;
  t.buckets.forEach((b, i) => {
    if (b.receiptIds.length > 0 || b.approvalDigests.length > 0) last = Math.max(last, i);
  });
  return sealThrough(t, runId, last);
}

/**
 * Pure attribution step for one appended run-chain receipt. `approvals` are
 * the approval digests the service verified during this call. Returns the
 * entries this receipt sealed (in order), already marked "anchoring".
 */
export function observeMilestoneReceipt(
  t: MilestoneTracker,
  runId: string,
  receipt: Pick<ServerReceipt, "receiptId" | "tool" | "surface" | "outcome" | "ts">,
  approvals: readonly string[],
  runTerminal: boolean,
): MilestoneEntryState[] {
  if (t.closed || receipt.surface === "anchoring") return [];
  const sealed: MilestoneEntryState[] = [];
  if (t.sealed < MILESTONES.length) {
    const cls = MILESTONE_TOOL_CLASS[receipt.tool];
    const i = Math.max(cls === undefined ? 0 : MILESTONES.indexOf(cls), t.sealed);
    const b = t.buckets[i]!;
    b.receiptIds.push(receipt.receiptId);
    b.approvalDigests.push(...approvals);
    b.firstTs ??= receipt.ts;
    b.lastTs = receipt.ts;
    if (receipt.outcome === "ok") {
      if (receipt.tool === "mandate_submit") {
        t.mandateSeen = true;
        sealed.push(...sealThrough(t, runId, MILESTONES.indexOf(t.offerSeen ? "proposal" : "discover")));
      } else if (receipt.tool === "offer_submit") {
        t.offerSeen = true;
        if (t.mandateSeen) sealed.push(...sealThrough(t, runId, MILESTONES.indexOf("proposal")));
      } else {
        const closer = CLOSERS[receipt.tool];
        if (closer !== undefined) sealed.push(...sealThrough(t, runId, MILESTONES.indexOf(closer)));
      }
    }
  }
  if (runTerminal) sealed.push(...closeMilestones(t, runId));
  return sealed;
}

/** One contract_status row per milestone (always six, in order). */
export interface RenderedMilestone {
  index: number;
  milestone: Milestone;
  assetReferenceId: string;
  /** open: not complete yet · not-reached: the run ended before it · lost: the run ended but a restart lost its evidence before it sealed. */
  status: "open" | "not-reached" | "lost" | "anchoring" | "pending" | "anchored" | "failed";
  digest: string | null;
  anchorId: string | null;
  eventHash: string | null;
  ledger: AnchorWrite["anchor"] | null;
  error: string | null;
  payload: MilestonePayload | null;
}

export function renderMilestones(
  runId: string,
  src: { closed: boolean; entries: readonly (MilestoneEntryState | TerminalMilestoneJob)[] } | undefined,
  /** The run ended (terminal) — unsealed rows are not-reached (closed) or lost (never closed). */
  ended: boolean,
): RenderedMilestone[] {
  return MILESTONES.map((m, i) => {
    const e = src?.entries.find((x) => x.index === i + 1);
    if (e === undefined) {
      return {
        index: i + 1, milestone: m, assetReferenceId: milestoneReferenceId(runId, m),
        status: src?.closed === true ? "not-reached" : ended ? "lost" : "open",
        digest: null, anchorId: null, eventHash: null, ledger: null, error: null, payload: null,
      };
    }
    return {
      index: e.index, milestone: m, assetReferenceId: e.referenceId, status: e.status,
      digest: e.digest, anchorId: e.anchorId ?? null, eventHash: e.eventHash ?? null,
      ledger: e.ledger ?? null, error: e.error ?? null, payload: e.payload as MilestonePayload,
    };
  });
}

export interface MilestoneLog {
  /** After a receipt was appended to `run`'s chain (bind included). */
  observe(run: ContractRun, receipt: ServerReceipt): void;
  /** At the terminal transition (endRun): close on the next macrotask if no receipt closed it first. */
  terminal(run: ContractRun): void;
  /** endRun, inside the durable enqueue: the run's milestone state for its job. */
  snapshot(run: ContractRun): TerminalJob["milestoneLog"] | undefined;
  /** Boot recovery for a persisted entry left anchoring/pending. */
  recover(job: TerminalJob, entry: TerminalMilestoneJob): void;
}

export function createMilestoneLog(deps: {
  anchor: ContractAnchor & Required<Pick<ContractAnchor, "log">>;
  getRun(runId: string): ContractRun | undefined;
  getJob(runId: string): TerminalJob | undefined;
  updateJob(runId: string, mutate: (job: TerminalJob) => void): void;
  track(p: Promise<void>): void;
  sleep(ms: number): Promise<void>;
  confirmDelayMs: number;
  confirmMaxAttempts: number;
}): MilestoneLog {
  const anchor = deps.anchor;
  /** Per-run write queue: entries are issued strictly in index order. */
  const queues = new Map<string, Promise<void>>();

  const toJob = (e: MilestoneEntryState | TerminalMilestoneJob): TerminalMilestoneJob => structuredClone({
    index: e.index, milestone: e.milestone, referenceId: e.referenceId, digest: e.digest,
    payload: e.payload as unknown as Record<string, unknown>, status: e.status,
    ...(e.anchorId !== undefined ? { anchorId: e.anchorId } : {}),
    ...(e.eventHash !== undefined ? { eventHash: e.eventHash } : {}),
    ...(e.ledger !== undefined ? { ledger: e.ledger } : {}),
    ...(e.error !== undefined ? { error: e.error } : {}),
  });

  /** Record an entry state on the live run and (when one exists) its terminal job — never creates a job. */
  function record(runId: string, next: MilestoneEntryState | TerminalMilestoneJob): void {
    const t = deps.getRun(runId)?.milestoneLog;
    if (t !== undefined) {
      const i = t.entries.findIndex((x) => x.index === next.index);
      if (i >= 0) t.entries[i] = { ...(next as MilestoneEntryState) };
    }
    if (deps.getJob(runId) === undefined) return;
    deps.updateJob(runId, (job) => {
      const ml = (job.milestoneLog ??= { closed: false, entries: [] });
      const i = ml.entries.findIndex((x) => x.index === next.index);
      if (i >= 0) ml.entries[i] = toJob(next);
      else ml.entries.push(toJob(next));
    });
  }

  function markClosed(runId: string): void {
    if (deps.getJob(runId) === undefined) return;
    deps.updateJob(runId, (job) => {
      const ml = (job.milestoneLog ??= { closed: false, entries: [] });
      ml.closed = true;
    });
  }

  function confirm(runId: string, prior: MilestoneEntryState | TerminalMilestoneJob, attempt: number): void {
    if (deps.confirmDelayMs <= 0 || attempt > deps.confirmMaxAttempts) return;
    const ledgerId = prior.ledger?.ledgerId;
    deps.track(deps.sleep(deps.confirmDelayMs)
      .then(() => anchor.confirmLog !== undefined && ledgerId !== undefined && ledgerId !== ""
        ? anchor.confirmLog(ledgerId)
        : anchor.log({ referenceId: prior.referenceId, digestHex: prior.digest, additionalInfo: milestoneAdditionalInfo(prior.milestone as Milestone) })
          .then((w) => w.anchor))
      .then((ledger) => {
        const confirmed = ledger.status === "anchored" && ledger.blockHeight !== null && ledger.time !== null;
        const next = { ...prior, status: confirmed ? "anchored" as const : "pending" as const, ledger };
        record(runId, next);
        if (!confirmed) confirm(runId, next, attempt + 1);
      })
      .catch(() => confirm(runId, prior, attempt + 1)));
  }

  /** Issue one entry (idempotent in the adapter); record every state. */
  function write(runId: string, entry: MilestoneEntryState | TerminalMilestoneJob): Promise<void> {
    return Promise.resolve()
      .then(() => anchor.log({
        referenceId: entry.referenceId,
        digestHex: entry.digest,
        additionalInfo: milestoneAdditionalInfo(entry.milestone as Milestone),
      }))
      .then((w) => {
        const confirmed = w.anchor.status === "anchored" && w.anchor.blockHeight !== null && w.anchor.time !== null;
        const next = {
          ...entry, status: confirmed ? "anchored" as const : "pending" as const,
          anchorId: w.anchorId, eventHash: w.eventHash, ledger: w.anchor,
        };
        delete (next as { error?: string }).error;
        record(runId, next);
        if (!confirmed) confirm(runId, next, 1);
      })
      .catch((err) => {
        record(runId, { ...entry, status: "failed", error: err instanceof Error ? err.message : String(err) });
      });
  }

  function enqueue(runId: string, entries: readonly (MilestoneEntryState | TerminalMilestoneJob)[]): void {
    for (const entry of entries) {
      const prev = queues.get(runId) ?? Promise.resolve();
      const op = prev.then(() => write(runId, entry));
      queues.set(runId, op);
      deps.track(op);
      void op.finally(() => { if (queues.get(runId) === op) queues.delete(runId); });
    }
  }

  /** Close the run's tracker (terminal): seal what is left, persist, write. */
  function close(run: ContractRun): void {
    const t = run.milestoneLog;
    if (t === undefined || t.closed) return;
    const sealed = closeMilestones(t, run.runId);
    afterSeal(run, sealed);
  }

  function afterSeal(run: ContractRun, sealed: readonly MilestoneEntryState[]): void {
    const t = run.milestoneLog!;
    if (sealed.length > 0) for (const e of sealed) record(run.runId, e);
    if (t.closed) markClosed(run.runId);
    enqueue(run.runId, sealed);
  }

  return {
    observe(run, receipt) {
      const t = (run.milestoneLog ??= createMilestoneTracker());
      if (t.closed) return;
      const recs = run.approvalRecords ?? [];
      const approvals = recs.slice(t.approvalsSeen).map(({ record: r, boundDigest }) => boundDigest ?? r.digest);
      t.approvalsSeen = recs.length;
      const sealed = observeMilestoneReceipt(t, run.runId, receipt, approvals, run.terminalState !== null);
      afterSeal(run, sealed);
    },
    terminal(run) {
      run.milestoneLog ??= createMilestoneTracker();
      // The terminal call's own receipt is appended after endRun returns;
      // observe() closes on it. This deferred close covers sweeps (TTL,
      // half-bound release) where no receipt follows.
      setImmediate(() => {
        try { close(run); } catch { /* a milestone bug must never fault the terminal path */ }
      });
    },
    snapshot(run) {
      const t = run.milestoneLog;
      if (t === undefined) return undefined;
      return { closed: t.closed, entries: t.entries.map(toJob) };
    },
    recover(job, entry) {
      if (entry.status !== "anchoring" && entry.status !== "pending") return;
      // Re-issue: the adapter finds the existing record under the same
      // reference + hash (no second write) and reports its current state.
      enqueue(job.runId, [entry]);
    },
  };
}
