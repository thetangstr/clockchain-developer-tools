/**
 * Milestone log (MILESTONE-TIMELINE.md §4, "Option A", with the founder's
 * 2026-10-06 answers): a server-side, per-milestone Clockchain log kept by
 * the contract server at each business-milestone transition. Behind
 * CONTRACT_MILESTONE_LOG=1 (default off); off, nothing here runs and no
 * surface changes.
 *
 * Six milestones, in order: discover, proposal, negotiation, agreement,
 * execution, settlement. Each run-chain receipt of a state-changing or
 * fixed-milestone tool is a MEMBER of one milestone; status polls are not
 * members but are counted (`pollCount`) so nothing is hidden. The server's
 * own `anchoring`-surface receipts are neither. When a milestone completes
 * its entry is SEALED:
 *
 *   payload = { schema: "ac.milestone-log/v1", runId, milestone, index,
 *               firstTs, lastTs, receiptIds[], approvalDigests[], pollCount,
 *               anchorRef, prevEntryDigest }
 *   digest  = sha256(canonicalJson(payload))   (0x hex; canonical.ts)
 *
 * `prevEntryDigest` chains all six entries. "Index over anchors": where the
 * run already has a server anchor for the milestone (`anchorRef`) the entry
 * references it and writes nothing new:
 *   discover   → terms (else the run's brief anchor)   [CONTRACT_SERVER_ANCHORS]
 *   agreement  → agreement                             [always, with an anchor]
 *   settlement → final (one per run; covers every receipt incl. the settling call) [CONTRACT_SERVER_ANCHORS]
 * Every other milestone (and any of these without its anchor) is an OWN
 * write: the digest as asset hash under `ac-milestone:<runId>:<n>-<milestone>`.
 * Settlement is ALWAYS also an own write (it still names `final` in
 * anchorRef), so the chain head's own payload hash is on Clockchain. A
 * referenced entry's payload is committed by the next own write's
 * prevEntryDigest. If a referenced anchor FAILS, the entry falls back to its
 * own write ("own-write (fallback)") — same payload, same digest.
 *
 * Transitions (server-observable):
 *   discover    both contract binds succeeded
 *   proposal    the first offer_submit succeeded (the mandate is proposal)
 *   negotiation an agreement formed (empty when the first offer was accepted);
 *               sealed and queued BEFORE the agreement anchor is sent, which
 *               then runs on the same per-run write queue (QA F-6: ledger
 *               order = protocol order)
 *   agreement   offer_accept_submit succeeded
 *   execution   verification_submit succeeded
 *   settlement  the terminal transition
 * Any terminal transition seals through the last milestone with evidence;
 * later milestones are never written ("not-reached").
 *
 * Durability: the whole tracker (buckets, seal count, chain head, entries)
 * is persisted on the run's terminal job at every seal and inside endRun's
 * durable enqueue. At boot a terminal job whose close never ran is closed
 * from its persisted buckets; pending own writes are re-driven (idempotent
 * per reference + digest in the adapter). A non-terminal run lost to a
 * restart is "interrupted": its sealed entries are still written.
 */
import type { AnchorWrite, ContractAnchor } from "./anchor.js";
import { createHash } from "node:crypto";

import { canonicalDigest } from "./canonical.js";
import type { ServerReceipt } from "./receipts.js";
import type { AnchorRunState, ContractRun } from "./service.js";
import type { TerminalAnchorJob, TerminalJob } from "./terminal-jobs.js";

export const MILESTONE_LOG_SCHEMA = "ac.milestone-log/v1" as const;
export const MILESTONES = ["discover", "proposal", "negotiation", "agreement", "execution", "settlement"] as const;
export type Milestone = (typeof MILESTONES)[number];

/** Tools whose receipts belong to a fixed milestone. */
export const MILESTONE_TOOL_CLASS: Readonly<Record<string, Milestone>> = Object.freeze({
  contract_bind: "discover",
  mandate_prepare: "proposal",
  mandate_submit: "proposal",
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

/** Stage-agnostic reads: never members, counted as the open milestone's pollCount. */
export const MILESTONE_POLL_TOOLS: ReadonlySet<string> = new Set([
  "contract_status", "settlement_status", "agreement_get", "rendezvous_inbox", "contract_get_brief",
]);

/** An `ok` receipt of these tools completes every milestone through the named one. */
const CLOSERS: Readonly<Record<string, Milestone>> = Object.freeze({
  offer_submit: "proposal",
  offer_accept_submit: "agreement",
  verification_submit: "execution",
});

/**
 * Review L6: the runId is the handshake session id, so it never goes on the
 * public ledger. The reference carries the first 32 hex of sha256(runId);
 * the runId itself is only inside the hashed payload, which is not published.
 */
export const milestoneRunRef = (runId: string): string =>
  createHash("sha256").update(runId, "utf8").digest("hex").slice(0, 32);
export const milestoneReferenceId = (runId: string, m: Milestone): string =>
  `ac-milestone:${milestoneRunRef(runId)}:${MILESTONES.indexOf(m) + 1}-${m}`;
/** Plain text only — the gateway strips punctuation from additional_info. */
export const milestoneAdditionalInfo = (m: Milestone): string => `agent contract milestone ${m}`;

export type AnchorKind = "terms" | "brief" | "briefBuyer" | "briefProvider" | "agreement" | "final";
/** A server anchor the milestone is indexed to; `digest` is its subject (final: null until it fires). */
export interface AnchorRef { kind: AnchorKind; digest: string | null }

export interface MilestonePayload {
  schema: typeof MILESTONE_LOG_SCHEMA;
  runId: string;
  milestone: Milestone;
  index: number;
  firstTs: string | null;
  lastTs: string | null;
  receiptIds: string[];
  approvalDigests: string[];
  pollCount: number;
  anchorRef: AnchorRef | null;
  prevEntryDigest: string | null;
}

export type EntrySource = "own-write" | "track-b-anchor" | "own-write (fallback)";
const writes = (e: { source: EntrySource }): boolean => e.source !== "track-b-anchor";

export interface MilestoneEntryState {
  index: number;
  milestone: Milestone;
  referenceId: string;
  /** sha256(canonicalJson(payload)). Own write: the anchored asset hash. */
  digest: string;
  payload: MilestonePayload;
  source: EntrySource;
  /** ISO time the entry was sealed (server clock). */
  sealedAt: string;
  /** Own write state; "referenced" = the state is the referenced anchor's. */
  status: "anchoring" | "pending" | "anchored" | "failed" | "referenced";
  anchorId?: string;
  eventHash?: string;
  ledger?: AnchorWrite["anchor"];
  error?: string;
}

export interface MilestoneBucket {
  receiptIds: string[];
  approvalDigests: string[];
  firstTs: number | null;
  lastTs: number | null;
  pollCount: number;
}

/** Per-run attribution state — JSON-serializable; the same object is persisted on the terminal job. */
export interface MilestoneTracker {
  buckets: MilestoneBucket[];
  /** How many milestones are sealed (0..6) — the first open one is MILESTONES[sealed]. */
  sealed: number;
  /** The terminal close ran: nothing more is attributed or sealed. */
  closed: boolean;
  /** The run was lost (restart / dropped) before it ended: unsealed milestones never complete. */
  interrupted?: boolean;
  /** run.approvalRecords already attributed. */
  approvalsSeen: number;
  prevDigest: string | null;
  entries: MilestoneEntryState[];
}

export function createMilestoneTracker(): MilestoneTracker {
  return {
    buckets: MILESTONES.map(() => ({ receiptIds: [], approvalDigests: [], firstTs: null, lastTs: null, pollCount: 0 })),
    sealed: 0, closed: false, approvalsSeen: 0, prevDigest: null, entries: [],
  };
}

type AnchorStates = Partial<Record<string, { digest: string } | undefined>>;

/** The server anchor a milestone is indexed to, from the anchors recorded so far. */
export function anchorRefFor(m: Milestone, anchors: AnchorStates | undefined, finalAnchors: boolean): AnchorRef | null {
  const a = anchors ?? {};
  if (m === "discover") {
    for (const kind of ["terms", "brief", "briefBuyer", "briefProvider"] as const) {
      const s = a[kind];
      if (s !== undefined) return { kind, digest: s.digest };
    }
    return null;
  }
  if (m === "agreement") return a.agreement !== undefined ? { kind: "agreement", digest: a.agreement.digest } : null;
  if (m === "settlement" && finalAnchors) return { kind: "final", digest: a.final?.digest ?? null };
  return null;
}

export interface SealContext {
  runId: string;
  /** ms clock for sealedAt. */
  now: number;
  anchors: AnchorStates | undefined;
  /** CONTRACT_SERVER_ANCHORS: a final anchor will cover settlement. */
  finalAnchors: boolean;
}

const iso = (ms: number | null): string | null => (ms === null ? null : new Date(ms).toISOString());

/** Seal every open milestone up to and including index `k` (0-based), in order. */
function sealThrough(t: MilestoneTracker, ctx: SealContext, k: number): MilestoneEntryState[] {
  const out: MilestoneEntryState[] = [];
  while (t.sealed <= k && t.sealed < MILESTONES.length) {
    const i = t.sealed;
    const m = MILESTONES[i]!;
    const b = t.buckets[i]!;
    const anchorRef = anchorRefFor(m, ctx.anchors, ctx.finalAnchors);
    const payload: MilestonePayload = {
      schema: MILESTONE_LOG_SCHEMA,
      runId: ctx.runId,
      milestone: m,
      index: i + 1,
      firstTs: iso(b.firstTs),
      lastTs: iso(b.lastTs),
      receiptIds: [...b.receiptIds].sort(),
      approvalDigests: [...b.approvalDigests],
      pollCount: b.pollCount,
      anchorRef,
      prevEntryDigest: t.prevDigest,
    };
    const digest = canonicalDigest(payload);
    t.prevDigest = digest;
    t.sealed += 1;
    const entry: MilestoneEntryState = {
      index: i + 1, milestone: m, referenceId: milestoneReferenceId(ctx.runId, m), digest, payload,
      // Settlement is always written too: the chain head's payload goes on chain.
      source: anchorRef === null || m === "settlement" ? "own-write" : "track-b-anchor",
      sealedAt: new Date(ctx.now).toISOString(),
      status: anchorRef === null || m === "settlement" ? "anchoring" : "referenced",
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
export function closeMilestones(t: MilestoneTracker, ctx: SealContext): MilestoneEntryState[] {
  if (t.closed) return [];
  t.closed = true;
  let last = t.sealed - 1;
  t.buckets.forEach((b, i) => {
    if (b.receiptIds.length > 0 || b.approvalDigests.length > 0) last = Math.max(last, i);
  });
  const sealed = sealThrough(t, ctx, last);
  // Review M2: the chain tail is always on Clockchain. A tail indexed to a
  // server anchor is ALSO written as its own record (anchorRef unchanged).
  const tail = t.entries.at(-1);
  if (tail !== undefined && tail.source === "track-b-anchor") {
    const own: MilestoneEntryState = { ...tail, source: "own-write", status: "anchoring" };
    t.entries[t.entries.length - 1] = own;
    const i = sealed.findIndex((e) => e.index === own.index);
    if (i >= 0) sealed[i] = own;
    else sealed.push(own);
  }
  return sealed;
}

/**
 * Pure attribution step for one appended run-chain receipt. `approvals` are
 * the approval digests verified during this call; `bothBound` is the run's
 * binding state after it. Returns the entries this receipt sealed, in order.
 */
export function observeMilestoneReceipt(
  t: MilestoneTracker,
  receipt: Pick<ServerReceipt, "receiptId" | "tool" | "surface" | "outcome" | "ts">,
  approvals: readonly string[],
  run: { bothBound: boolean; terminal: boolean },
  ctx: SealContext,
): MilestoneEntryState[] {
  if (t.closed || receipt.surface === "anchoring") return [];
  const sealed: MilestoneEntryState[] = [];
  if (t.sealed < MILESTONES.length) {
    const open = t.buckets[t.sealed]!;
    if (MILESTONE_POLL_TOOLS.has(receipt.tool)) {
      open.pollCount += 1;
    } else {
      const cls = MILESTONE_TOOL_CLASS[receipt.tool];
      const i = Math.max(cls === undefined ? 0 : MILESTONES.indexOf(cls), t.sealed);
      const b = t.buckets[i]!;
      b.receiptIds.push(receipt.receiptId);
      b.firstTs ??= receipt.ts;
      b.lastTs = receipt.ts;
    }
    // Approvals ride the call that verified them (polls verify none).
    if (approvals.length > 0) {
      const cls = MILESTONE_TOOL_CLASS[receipt.tool];
      t.buckets[Math.max(cls === undefined ? 0 : MILESTONES.indexOf(cls), t.sealed)]!.approvalDigests.push(...approvals);
    }
    if (receipt.outcome === "ok") {
      if (receipt.tool === "contract_bind" && run.bothBound) {
        sealed.push(...sealThrough(t, ctx, MILESTONES.indexOf("discover")));
      } else {
        const closer = CLOSERS[receipt.tool];
        if (closer !== undefined) sealed.push(...sealThrough(t, ctx, MILESTONES.indexOf(closer)));
      }
    }
  }
  if (run.terminal) sealed.push(...closeMilestones(t, ctx));
  return sealed;
}

/** One contract_status row per milestone (always six, in order) — what the UI shows per logging event. */
export interface RenderedMilestone {
  index: number;
  milestone: Milestone;
  assetReferenceId: string;
  /**
   * own-write: our ac-milestone record · track-b-anchor: the referenced server anchor ·
   * own-write (fallback): the referenced anchor failed, so we wrote our own. Null until sealed.
   */
  source: EntrySource | null;
  /**
   * open: not complete · not-reached: the run ended before it · interrupted: the run was lost before it completed ·
   * awaiting-anchor: indexed to a server anchor that has not fired yet · anchoring/pending/anchored/failed.
   */
  status: "open" | "not-reached" | "interrupted" | "awaiting-anchor" | "anchoring" | "pending" | "anchored" | "failed";
  /** sha256(canonicalJson(payload)) — the entry's chain digest. */
  digest: string | null;
  /** The hash actually on the ledger: own write = digest; track-b = the referenced anchor's event hash. */
  assetHash: string | null;
  /**
   * Review L4: the referenced anchor as it stands NOW (final's digest filled in once it fires). NOT hashed —
   * verifiers recompute the digest from `payload` (whose `anchorRef` is the hashed one).
   */
  anchorRefLive: AnchorRef | null;
  anchorId: string | null;
  ledgerId: string | null;
  blockHeight: string | null;
  sealedAt: string | null;
  anchoredAt: string | null;
  error: string | null;
  payload: MilestonePayload | null;
}

export function renderMilestones(
  runId: string,
  t: MilestoneTracker | undefined,
  anchors: Partial<Record<string, AnchorRunState | TerminalAnchorJob | undefined>> | undefined,
  /** Review L1: the run already ended — without a tracker every row is not-reached, never "open". */
  ended = false,
): RenderedMilestone[] {
  return MILESTONES.map((m, i) => {
    const e = t?.entries.find((x) => x.index === i + 1);
    const base = { index: i + 1, milestone: m, assetReferenceId: milestoneReferenceId(runId, m) };
    if (e === undefined) {
      return {
        ...base, source: null,
        status: t?.interrupted === true ? "interrupted" : t?.closed === true || (t === undefined && ended) ? "not-reached" : "open",
        digest: null, assetHash: null, anchorRefLive: null, anchorId: null, ledgerId: null, blockHeight: null,
        sealedAt: null, anchoredAt: null, error: null, payload: null,
      };
    }
    let state: { status: RenderedMilestone["status"]; ledger?: AnchorWrite["anchor"]; anchorId?: string; assetHash?: string; error?: string };
    if (e.source === "track-b-anchor") {
      const a = anchors?.[e.payload.anchorRef!.kind];
      state = a === undefined
        ? { status: "awaiting-anchor" }
        : { status: a.status, ledger: a.ledger, anchorId: a.anchorId, assetHash: a.eventHash, error: a.error };
    } else {
      state = {
        status: e.status as RenderedMilestone["status"], ledger: e.ledger, anchorId: e.anchorId,
        assetHash: e.eventHash ?? e.digest, error: e.error,
      };
    }
    return {
      ...base, assetReferenceId: e.referenceId, source: e.source, status: state.status,
      digest: e.digest, assetHash: state.assetHash ?? null,
      anchorRefLive: e.payload.anchorRef?.kind === "final" && e.payload.anchorRef.digest === null && anchors?.final !== undefined
        ? { kind: "final", digest: anchors.final.digest }
        : e.payload.anchorRef,
      anchorId: state.anchorId ?? null,
      ledgerId: state.ledger?.ledgerId || null,
      blockHeight: state.ledger?.blockHeight ?? null,
      sealedAt: e.sealedAt,
      anchoredAt: state.status === "anchored" ? state.ledger?.time ?? null : null,
      error: state.error ?? null,
      payload: e.payload,
    };
  });
}

export interface MilestoneLog {
  /** After a receipt was appended to `run`'s chain (bind included). */
  observe(run: ContractRun, receipt: ServerReceipt): void;
  /** At the terminal transition (endRun): close on the next macrotask if no receipt closed it first. */
  terminal(run: ContractRun): void;
  /** endRun, inside the durable enqueue: the run's tracker for its job. */
  snapshot(run: ContractRun): MilestoneTracker | undefined;
  /** A live run dropped before it ended: its unsealed milestones are interrupted. */
  dropped(run: ContractRun): void;
  /** Boot: close a terminal job never closed, interrupt a lost live run, re-drive pending own writes. */
  recover(job: TerminalJob): void;
  /** A run anchor reached `failed`: referenced entries indexed to a failed anchor fall back to own writes. */
  anchorFailed(runId: string): void;
  /**
   * QA F-6: the agreement anchor is about to be sent (offer_accept_submit).
   * Seal everything before `agreement` NOW (the agreement has formed, so
   * negotiation is complete), queue its own write, and run `send` on this
   * run's write queue after it — so Negotiation reaches the ledger before
   * Agreement, and later milestone writes wait for the agreement anchor.
   * `send` must not reject (its failure is the anchor path's to record).
   */
  beforeAgreementAnchor(run: ContractRun, send: () => Promise<void>): void;
}

export function createMilestoneLog(deps: {
  anchor: ContractAnchor & Required<Pick<ContractAnchor, "log">>;
  getRun(runId: string): ContractRun | undefined;
  getJob(runId: string): TerminalJob | undefined;
  /** Get-or-create + mutate + persist; a persist failure is swallowed (entry-state updates). */
  updateJob(runId: string, mutate: (job: TerminalJob) => void): void;
  /**
   * Review L3: the fail-closed variant (outbox.updateDurable) — THROWS when the
   * durable write fails, leaving the job as it was. Seals use it.
   */
  updateJobDurable(runId: string, mutate: (job: TerminalJob) => void): void;
  track(p: Promise<void>): void;
  sleep(ms: number): Promise<void>;
  confirmDelayMs: number;
  confirmMaxAttempts: number;
  /** CONTRACT_SERVER_ANCHORS: the final anchor covers settlement. */
  finalAnchors: boolean;
  now(): number;
}): MilestoneLog {
  const anchor = deps.anchor;
  /** Per-run write queue: own writes are issued strictly in index order. */
  const queues = new Map<string, Promise<void>>();
  /** `runId|index` of own writes queued or in flight (never queued twice at once). */
  const queued = new Set<string>();

  const ctxFor = (runId: string, anchors: AnchorStates | undefined): SealContext =>
    ({ runId, now: deps.now(), anchors, finalAnchors: deps.finalAnchors });

  /**
   * Durably persist the run's whole tracker on its job (creating the job if
   * needed). Review L3: false when the durable write failed — then NOTHING is
   * queued, so no ledger write can ever precede its seal on disk.
   */
  function persistTracker(runId: string, t: MilestoneTracker): boolean {
    try {
      deps.updateJobDurable(runId, (job) => { job.milestoneLog = structuredClone(t); });
      return true;
    } catch {
      return false;
    }
  }

  /** After a durable save: queue every own write sealed but not yet queued (in index order). */
  function queueSaved(runId: string, t: MilestoneTracker): void {
    enqueue(runId, t.entries.filter((e) => writes(e) && e.status === "anchoring"));
  }

  /** Record an own-write state on the live tracker and on the job. */
  function record(runId: string, next: MilestoneEntryState): void {
    const t = deps.getRun(runId)?.milestoneLog;
    if (t !== undefined) {
      const i = t.entries.findIndex((x) => x.index === next.index);
      if (i >= 0) t.entries[i] = { ...next };
    }
    if (deps.getJob(runId)?.milestoneLog === undefined) return;
    deps.updateJob(runId, (job) => {
      const ml = job.milestoneLog!;
      const i = ml.entries.findIndex((x) => x.index === next.index);
      if (i >= 0) ml.entries[i] = structuredClone(next);
    });
  }

  const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));

  /**
   * Re-check a pending own write: read its record by ledger id, or — when no
   * write ever landed — re-issue it (idempotent: searchAsset first). Bounded
   * by the confirm budget; past it the entry rests `pending` and the next
   * boot re-drives it. Review M1: an error never makes it permanent.
   */
  function confirm(runId: string, prior: MilestoneEntryState, attempt: number): void {
    if (deps.confirmDelayMs <= 0 || attempt > deps.confirmMaxAttempts) return;
    const ledgerId = prior.ledger?.ledgerId;
    deps.track(deps.sleep(deps.confirmDelayMs)
      .then(() => anchor.confirmLog !== undefined && ledgerId !== undefined && ledgerId !== ""
        ? anchor.confirmLog(ledgerId).then((ledger) => ({ ledger } as Partial<AnchorWrite> & { ledger: AnchorWrite["anchor"] }))
        : anchor.log({
            referenceId: prior.referenceId, digestHex: prior.digest,
            additionalInfo: milestoneAdditionalInfo(prior.milestone), runId,
          }).then((w) => ({ ledger: w.anchor, anchorId: w.anchorId, eventHash: w.eventHash })))
      .then((r) => {
        const confirmed = r.ledger.status === "anchored" && r.ledger.blockHeight !== null && r.ledger.time !== null;
        const next: MilestoneEntryState = {
          ...prior, status: confirmed ? "anchored" : "pending", ledger: r.ledger,
          ...(r.anchorId !== undefined ? { anchorId: r.anchorId, eventHash: r.eventHash } : {}),
        };
        delete next.error;
        record(runId, next);
        if (!confirmed) confirm(runId, next, attempt + 1);
      })
      .catch((err) => {
        const next: MilestoneEntryState = { ...prior, status: "pending", error: message(err) };
        record(runId, next);
        confirm(runId, next, attempt + 1);
      }));
  }

  /** Issue one own write (idempotent in the adapter); record every state. */
  function write(runId: string, entry: MilestoneEntryState): Promise<void> {
    return Promise.resolve()
      .then(() => anchor.log({
        referenceId: entry.referenceId,
        digestHex: entry.digest,
        additionalInfo: milestoneAdditionalInfo(entry.milestone),
        runId,
      }))
      .then((w) => {
        const confirmed = w.anchor.status === "anchored" && w.anchor.blockHeight !== null && w.anchor.time !== null;
        const next: MilestoneEntryState = {
          ...entry, status: confirmed ? "anchored" : "pending",
          anchorId: w.anchorId, eventHash: w.eventHash, ledger: w.anchor,
        };
        delete next.error;
        record(runId, next);
        if (!confirmed) confirm(runId, next, 1);
      })
      .catch((err) => {
        // Review M1: pending with its error, retried within the confirm budget.
        const next: MilestoneEntryState = { ...entry, status: "pending", error: message(err) };
        record(runId, next);
        confirm(runId, next, 1);
      });
  }

  function enqueue(runId: string, entries: readonly MilestoneEntryState[]): void {
    for (const entry of entries) {
      if (!writes(entry)) continue;
      const key = `${runId}|${entry.index}`;
      if (queued.has(key)) continue;
      queued.add(key);
      const prev = queues.get(runId) ?? Promise.resolve();
      const op = prev.then(() => write(runId, entry));
      queues.set(runId, op);
      deps.track(op);
      void op.finally(() => {
        queued.delete(key);
        if (queues.get(runId) === op) queues.delete(runId);
      });
    }
  }

  function afterSeal(runId: string, t: MilestoneTracker, sealed: readonly MilestoneEntryState[], closedNow: boolean): void {
    if (sealed.length === 0 && !closedNow) return;
    // L3: the seal is on disk before any of its writes is queued.
    if (persistTracker(runId, t)) queueSaved(runId, t);
    // A referenced anchor that already failed before the seal: fall back now.
    if (sealed.some((e) => e.source === "track-b-anchor")) fallback(runId);
  }

  /**
   * Founder rule: a referenced entry whose anchor FAILED is written as its
   * own ac-milestone record — same payload and digest (anchorRef still names
   * the failed anchor), source "own-write (fallback)".
   */
  function fallback(runId: string): void {
    const run = deps.getRun(runId);
    const job = deps.getJob(runId);
    const t = run?.milestoneLog ?? (job?.milestoneLog !== undefined ? structuredClone(job.milestoneLog) : undefined);
    if (t === undefined) return;
    const anchors = (run?.anchors ?? job?.anchors) as Partial<Record<string, { status: string }>> | undefined;
    const switched: MilestoneEntryState[] = [];
    t.entries.forEach((e, i) => {
      if (e.source !== "track-b-anchor") return;
      if (anchors?.[e.payload.anchorRef!.kind]?.status !== "failed") return;
      const next: MilestoneEntryState = { ...e, source: "own-write (fallback)", status: "anchoring" };
      t.entries[i] = next;
      switched.push(next);
    });
    if (switched.length === 0) return;
    if (persistTracker(runId, t)) queueSaved(runId, t);
  }

  return {
    observe(run, receipt) {
      const t = (run.milestoneLog ??= createMilestoneTracker());
      if (t.closed) return;
      const recs = run.approvalRecords ?? [];
      const approvals = recs.slice(t.approvalsSeen).map(({ record: r, boundDigest }) => boundDigest ?? r.digest);
      t.approvalsSeen = recs.length;
      const terminal = run.terminalState !== null;
      const sealed = observeMilestoneReceipt(
        t, receipt, approvals,
        { bothBound: run.bound.buyer !== undefined && run.bound.provider !== undefined, terminal },
        ctxFor(run.runId, run.anchors),
      );
      afterSeal(run.runId, t, sealed, terminal);
    },
    terminal(run) {
      run.milestoneLog ??= createMilestoneTracker();
      // The terminal call's own receipt is appended after endRun returns;
      // observe() closes on it. This deferred close covers sweeps (TTL,
      // half-bound release) where no receipt follows.
      setImmediate(() => {
        try {
          const t = run.milestoneLog!;
          if (t.closed) return;
          afterSeal(run.runId, t, closeMilestones(t, ctxFor(run.runId, run.anchors)), true);
        } catch { /* a milestone bug must never fault the terminal path */ }
      });
    },
    anchorFailed(runId) {
      fallback(runId);
    },
    beforeAgreementAnchor(run, send) {
      const t = (run.milestoneLog ??= createMilestoneTracker());
      if (!t.closed) {
        try {
          const sealed = sealThrough(t, ctxFor(run.runId, run.anchors), MILESTONES.indexOf("agreement") - 1);
          afterSeal(run.runId, t, sealed, false);
        } catch { /* a milestone bug must never hold the agreement anchor */ }
      }
      const prev = queues.get(run.runId) ?? Promise.resolve();
      const op = prev.then(send).catch(() => { /* recorded by the anchor path */ });
      queues.set(run.runId, op);
      deps.track(op);
      void op.finally(() => {
        if (queues.get(run.runId) === op) queues.delete(run.runId);
      });
    },
    snapshot(run) {
      return run.milestoneLog === undefined ? undefined : structuredClone(run.milestoneLog);
    },
    dropped(run) {
      const t = run.milestoneLog;
      if (t === undefined || t.closed || run.terminalState !== null) return;
      t.closed = true;
      t.interrupted = true;
      if (deps.getJob(run.runId)?.milestoneLog !== undefined) persistTracker(run.runId, t);
    },
    recover(job) {
      const ml = job.milestoneLog;
      if (ml === undefined) return;
      if (!ml.closed) {
        const t = structuredClone(ml);
        if (job.terminalState !== null) {
          // Crash between the terminal transition and the close: seal from the persisted buckets.
          closeMilestones(t, ctxFor(job.runId, job.anchors as AnchorStates | undefined));
          if (persistTracker(job.runId, t)) queueSaved(job.runId, t);
        } else {
          // The live run died with the process: what it reached stays sealed; nothing more can complete.
          t.closed = true;
          t.interrupted = true;
          persistTracker(job.runId, t);
        }
      }
      // Re-issue: the adapter finds an existing record under the same reference + hash (no second write).
      // Entries the close just sealed were enqueued above; these are the older pending ones.
      // Review M1: a legacy `failed` own write is re-driven too (searchAsset first, so never twice).
      enqueue(job.runId, ml.entries.filter((e) => writes(e) && (e.status === "anchoring" || e.status === "pending" || e.status === "failed")));
      // A referenced anchor that failed while we were down.
      fallback(job.runId);
    },
  };
}
