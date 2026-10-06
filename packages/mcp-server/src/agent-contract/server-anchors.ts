/**
 * Server-side anchors (mcp-coordination-design.md, "Anchoring"): the terms,
 * brief and final-head subjects, anchored IN-PROCESS through the same
 * ContractAnchor as agreement/terminal (anchor.ts; config.ts wires the
 * tsa_issue backing behind CONTRACT_ANCHOR_ENABLED=1). No client credential.
 *
 * - terms: the certificate's signed `statementDigest` (the published terms),
 *   anchored when the run is created at its first bind (the design's
 *   fallback for "at invitation accept": the handshake coordinator holds no
 *   ContractAnchor).
 * - brief: a frozen, digest-pinned brief template (CONTRACT_BRIEFS) served
 *   by `contract_get_brief`; the first serve per scope (the run, or the
 *   caller's pre-bind chain) anchors its digest before the result returns.
 * - final: once the terminal job is finished (close delivered/failed/absent,
 *   every other anchor of the run resolved), the run chain head AT THAT
 *   MOMENT — covering the close and anchor evidence receipts that chain on
 *   after the terminal anchor.
 *
 * None of these outcomes is chained as a receipt: they are recorded on the
 * run and the durable terminal job (contract_status reports them). A
 * chained final outcome would always leave one more uncovered receipt.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import type { ContractAnchor } from "./anchor.js";
import { canonicalDigest } from "./canonical.js";
import { chainHead } from "./receipts.js";
import type { TerminalAnchorJob, TerminalJob } from "./terminal-jobs.js";
import type { AnchorRunState, ContractRun } from "./service.js";

export type ServerAnchorKind = "terms" | "brief" | "final";

/** A frozen brief template: its text and the pinned sha256 digest (0x hex). */
export interface ContractBrief {
  digest: string;
  text: string;
}

const BRIEF_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const DIGEST = /^0x[0-9a-f]{64}$/;
const MAX_BRIEFS = 32;
const MAX_BRIEF_BYTES = 64 * 1024;

/** sha256 over the brief file's exact bytes, `0x` + lower hex. */
export function briefDigest(bytes: Uint8Array): string {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

/**
 * `CONTRACT_BRIEFS=<name>:<0x digest>,…` with each text at
 * `<dir>/<name>.md`. Every file must exist and hash to its pin — a missing
 * file or a digest mismatch THROWS (the config layer turns it into a
 * startup misconfiguration; a drifted brief is never served).
 */
export function parseContractBriefs(raw: string, dir: string): ReadonlyMap<string, ContractBrief> {
  const out = new Map<string, ContractBrief>();
  for (const entry of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [name, digest, ...extra] = entry.split(":");
    if (name === undefined || !BRIEF_NAME.test(name) || digest === undefined || !DIGEST.test(digest) || extra.length > 0) {
      throw new Error("malformed CONTRACT_BRIEFS entry (want name:0x<64 lower hex>)");
    }
    if (out.has(name)) throw new Error(`CONTRACT_BRIEFS lists ${name} more than once`);
    const file = path.join(dir, `${name}.md`);
    if (!existsSync(file)) throw new Error(`CONTRACT_BRIEFS: no brief file for ${name}`);
    const bytes = readFileSync(file);
    if (bytes.length > MAX_BRIEF_BYTES) throw new Error(`CONTRACT_BRIEFS: ${name} exceeds ${MAX_BRIEF_BYTES} bytes`);
    if (briefDigest(bytes) !== digest) throw new Error(`CONTRACT_BRIEFS: ${name} does not match its pinned digest`);
    out.set(name, { digest, text: bytes.toString("utf8") });
  }
  if (out.size > MAX_BRIEFS) throw new Error(`CONTRACT_BRIEFS: more than ${MAX_BRIEFS} briefs`);
  return out;
}

/**
 * The terms subject for a verified certificate: its signed
 * `statementDigest` (bare or 0x 64 hex), else the result digest.
 */
export function termsDigestOf(result: Readonly<Record<string, unknown>>, resultDigest: string): string {
  const sd = result.statementDigest;
  if (typeof sd === "string") {
    const bare = sd.startsWith("0x") ? sd.slice(2) : sd;
    if (/^[0-9a-fA-F]{64}$/.test(bare)) return `0x${bare.toLowerCase()}`;
  }
  return resultDigest;
}

/** contract_status / brief-result rendering of one server-side anchor state. */
export function renderServerAnchor(s: (AnchorRunState | TerminalAnchorJob) | undefined) {
  if (s === undefined) return null;
  return {
    status: s.status,
    digest: s.digest,
    anchorId: s.anchorId ?? null,
    eventHash: s.eventHash ?? null,
    ledger: s.ledger ?? null,
    error: s.error ?? null,
  };
}

export function renderFinalAnchor(s: (AnchorRunState | TerminalAnchorJob) | undefined) {
  const base = renderServerAnchor(s);
  return base === null ? null : { ...base, receiptCount: s?.receiptCount ?? null };
}

const isOpen = (a: { status: string } | undefined): boolean =>
  a !== undefined && (a.status === "anchoring" || a.status === "pending");

export interface ServerAnchors {
  /** Anchor the run's terms digest (write-once per run). */
  fireTerms(run: ContractRun, digest: string): void;
  /** Serve a brief; anchors its digest the first time per scope, awaited (bounded). */
  getBrief(
    name: string,
    scope: { run?: ContractRun; preBindScope: string },
  ): Promise<
    | { ok: true; result: { name: string; digest: string; text: string; anchor: ReturnType<typeof renderServerAnchor> } }
    | { ok: false; code: "NOT_FOUND" }
  >;
  /** At bind: a brief anchored on the seat's pre-bind scope becomes the run's brief anchor. */
  carryBrief(run: ContractRun, preBindScope: string): void;
  /** Re-check whether the run's final anchor can fire (deferred one macrotask). */
  scheduleFinal(runId: string): void;
  /** Bounded wait for an issued-but-unsettled (or about-to-fire) final anchor. */
  awaitFinal(runId: string): Promise<void>;
  /** Boot recovery for a persisted terms/brief/final job left anchoring/pending. */
  recover(job: TerminalJob, aj: TerminalAnchorJob): void;
}

export function createServerAnchors(deps: {
  anchor: ContractAnchor | undefined;
  getRun(runId: string): ContractRun | undefined;
  getJob(runId: string): TerminalJob | undefined;
  updateJob(runId: string, mutate: (job: TerminalJob) => void): void;
  track(p: Promise<void>): void;
  sleep(ms: number): Promise<void>;
  confirmDelayMs: number;
  confirmMaxAttempts: number;
  briefs?: ReadonlyMap<string, ContractBrief>;
  /** Max wait for the brief anchor before the brief result returns (default 10s). */
  briefAnchorAwaitMs?: number;
  /** Max wait contract_status gives an issued final anchor (default 5s). */
  finalAnchorAwaitMs?: number;
}): ServerAnchors {
  const briefAwaitMs = deps.briefAnchorAwaitMs ?? 10_000;
  const finalAwaitMs = deps.finalAnchorAwaitMs ?? 5_000;
  /** Brief anchors per scope (`run:<id>` or the pre-bind scope) and name. */
  const briefStates = new Map<string, Map<string, AnchorRunState>>();
  const briefOps = new Map<string, Promise<void>>();
  const finalOps = new Map<string, Promise<void>>();
  /** Real timer for bounded waits — never the injectable confirm sleep. */
  const wait = (ms: number): Promise<void> => new Promise((r) => {
    const t = setTimeout(r, ms);
    t.unref?.();
  });

  /**
   * One unchained anchor: issue, record every state through `onState`,
   * re-confirm a pending write under the same budget as agreement/terminal
   * (N4b-9 F13). Resolves once the FIRST issue settled.
   */
  function run(
    kind: ServerAnchorKind,
    scopeId: string,
    digest: string,
    onState: (s: AnchorRunState) => void,
    extra: Partial<AnchorRunState> = {},
  ): Promise<void> {
    const anchor = deps.anchor!;
    const record = onState;
    // A settled terms/brief state may make the run's final anchor eligible.
    onState = (s) => {
      record(s);
      if (kind !== "final" && s.status !== "anchoring") scheduleFinal(scopeId);
    };
    const confirm = (anchorId: string, attempt: number, prior: AnchorRunState): void => {
      if (deps.confirmDelayMs <= 0 || attempt > deps.confirmMaxAttempts) return;
      deps.track(deps.sleep(deps.confirmDelayMs)
        .then(() => anchor.confirm !== undefined
          ? anchor.confirm(anchorId)
          : anchor.anchor({ kind, runId: scopeId, digestHex: digest }).then((w) => w.anchor))
        .then((ledger) => {
          const confirmed = ledger.status === "anchored" && ledger.blockHeight !== null && ledger.time !== null;
          const next: AnchorRunState = { ...prior, status: confirmed ? "anchored" : "pending", ledger };
          onState(next);
          if (!confirmed) confirm(anchorId, attempt + 1, next);
        })
        .catch(() => confirm(anchorId, attempt + 1, prior)));
    };
    onState({ status: "anchoring", digest, ...extra });
    const op = Promise.resolve()
      .then(() => anchor.anchor({ kind, runId: scopeId, digestHex: digest }))
      .then((write) => {
        const confirmed = write.anchor.status === "anchored" &&
          write.anchor.blockHeight !== null && write.anchor.time !== null;
        const next: AnchorRunState = {
          status: confirmed ? "anchored" : "pending", digest, ...extra,
          anchorId: write.anchorId, eventHash: write.eventHash, ledger: write.anchor,
        };
        onState(next);
        if (!confirmed) confirm(write.anchorId, 1, next);
      })
      .catch((err) => {
        onState({ status: "failed", digest, ...extra, error: err instanceof Error ? err.message : String(err) });
      });
    deps.track(op);
    return op;
  }

  /**
   * Record a run-scoped state on the live run, and on its durable terminal
   * job when one exists. A live run has no job before its terminal
   * transition (endRun copies terms/brief in); this never creates one.
   */
  const recordOn = (runId: string, kind: ServerAnchorKind) => (s: AnchorRunState): void => {
    const live = deps.getRun(runId);
    if (live !== undefined) (live.anchors ??= {})[kind] = s;
    if (deps.getJob(runId) === undefined) return;
    deps.updateJob(runId, (job) => {
      job.anchors = { ...job.anchors, [kind]: { kind, ...s } };
    });
  };

  function scheduleFinal(runId: string): void {
    if (deps.anchor === undefined) return;
    setImmediate(() => maybeFireFinal(runId));
  }

  function finalEligible(job: TerminalJob): boolean {
    if (job.terminalState === null || job.anchors?.final !== undefined) return false;
    if (job.close !== undefined && job.close.status === "delivering") return false;
    const a = job.anchors;
    return a === undefined || ![a.agreement, a.terminal, a.terms, a.brief].some(isOpen);
  }

  function maybeFireFinal(runId: string): void {
    if (deps.anchor === undefined) return;
    const job = deps.getJob(runId);
    if (job === undefined || !finalEligible(job)) return;
    const live = deps.getRun(runId);
    // Live run: the in-memory chain head right now. After a restart the run
    // is gone; the job's own evidence chain (its tip, else the recorded
    // transition tip) is the head this process can still prove.
    const digest = live !== undefined
      ? chainHead(live.receipts)
      : (() => {
          const tip = job.evidence.at(-1) ?? job.prevReceipt ?? null;
          return tip === null ? null : canonicalDigest(tip);
        })();
    if (digest === null) return;
    const receiptCount = live !== undefined ? live.receipts.length : null;
    const op = run("final", runId, digest, recordOn(runId, "final"), { receiptCount });
    finalOps.set(runId, op);
    void op.finally(() => finalOps.delete(runId));
  }

  return {
    fireTerms(r, digest) {
      if (deps.anchor === undefined || r.anchors?.terms !== undefined) return;
      void run("terms", r.runId, digest, recordOn(r.runId, "terms"));
    },

    async getBrief(name, scope) {
      const brief = deps.briefs?.get(name);
      if (brief === undefined) return { ok: false, code: "NOT_FOUND" };
      const render = (s: AnchorRunState | undefined) => renderServerAnchor(s);
      if (deps.anchor === undefined) {
        return { ok: true, result: { name, digest: brief.digest, text: brief.text, anchor: null } };
      }
      const scopeKey = scope.run !== undefined ? `run:${scope.run.runId}` : scope.preBindScope;
      let states = briefStates.get(scopeKey);
      if (states === undefined) {
        states = new Map();
        briefStates.set(scopeKey, states);
      }
      const opKey = `${scopeKey}\u0000${name}`;
      const existing = states.get(name);
      // Write-once per scope and name; a FAILED anchor may be retried.
      if (existing === undefined || existing.status === "failed") {
        const runRef = scope.run;
        const scopeStates = states;
        const op = run(
          "brief",
          runRef !== undefined ? runRef.runId : scope.preBindScope,
          brief.digest,
          (s) => {
            scopeStates.set(name, s);
            // The run's brief anchor is the first brief anchored in it.
            if (runRef !== undefined) {
              const cur = runRef.anchors?.brief;
              if (cur === undefined || cur.digest === s.digest) recordOn(runRef.runId, "brief")(s);
            }
          },
        );
        briefOps.set(opKey, op);
        void op.finally(() => briefOps.delete(opKey));
      }
      const inflight = briefOps.get(opKey);
      if (inflight !== undefined) await Promise.race([inflight, wait(briefAwaitMs)]);
      return { ok: true, result: { name, digest: brief.digest, text: brief.text, anchor: render(states.get(name)) } };
    },

    carryBrief(r, preBindScope) {
      if (r.anchors?.brief !== undefined) return;
      const states = briefStates.get(preBindScope);
      if (states === undefined) return;
      const first = [...states.values()].find((s) => s.status !== "failed");
      if (first !== undefined) recordOn(r.runId, "brief")(first);
    },

    scheduleFinal,

    async awaitFinal(runId) {
      if (deps.anchor === undefined || finalAwaitMs <= 0) return;
      const deadline = Date.now() + finalAwaitMs;
      for (;;) {
        const job = deps.getJob(runId);
        if (job === undefined || job.terminalState === null) return;
        if (job.anchors?.final === undefined && !finalOps.has(runId)) {
          // Not issued and prerequisites (close delivery, other anchors)
          // still open: report what is known now. Eligible: issue it here
          // rather than wait for the deferred trigger (also covers a job
          // recovered after a restart that never got its final).
          if (!finalEligible(job)) return;
          maybeFireFinal(runId);
        }
        const fin = job.anchors?.final ?? deps.getJob(runId)?.anchors?.final;
        const inflight = finalOps.get(runId);
        if (fin === undefined || (fin.status !== "anchoring" && inflight === undefined)) return;
        const left = deadline - Date.now();
        if (left <= 0) return;
        await Promise.race([inflight ?? wait(Math.min(left, 20)), wait(left)]);
      }
    },

    recover(job, aj) {
      if (deps.anchor === undefined) return;
      if (aj.kind !== "terms" && aj.kind !== "brief" && aj.kind !== "final") return;
      const extra = aj.kind === "final" ? { receiptCount: aj.receiptCount ?? null } : {};
      // Re-issue: the deterministic commitmentId resolves the same object
      // with its current confirmation state. Still unchained.
      void run(aj.kind, job.runId, aj.digest, recordOn(job.runId, aj.kind), extra);
    },
  };
}
