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
 *   by `contract_get_brief`. CDT-SEC M4: ONE anchor per brief digest, shared
 *   by every scope (run or pre-bind session) — the first serve in the process
 *   issues it (awaited, bounded) and every later scope refers to it; a failed
 *   anchor is retried no sooner than 60 s later. CDT-SEC L6: its ledger
 *   subject is the constant `agent-contract:brief` (BRIEF_ANCHOR_SUBJECT) —
 *   no keyId, session id or run id goes on the ledger. The commitmentId is
 *   deterministic, so a restart re-resolves the same ledger object.
 * - final: once the terminal job is finished (close delivered/failed/absent,
 *   every other anchor of the run resolved), the run chain head AT THAT
 *   MOMENT — covering the close and anchor evidence receipts that chain on
 *   after the terminal anchor.
 *
 * - per-role brief (CDT-GAPS gap 1, CONTRACT_ROLE_BRIEFS — default off): each
 *   role's brief is recorded in its own slot (`briefBuyer` / `briefProvider`)
 *   and bound by that role's contract_bind (result `briefDigest`, covered by
 *   the bind receipt's responseDigest). A configured role brief's shared
 *   anchor is issued at service start, so it precedes every role's first
 *   event without any client calling contract_get_brief.
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
/** CDT-GAPS gap 1: the per-role brief slots on run.anchors / job.anchors. */
export type RoleBriefSlot = "briefBuyer" | "briefProvider";
export type ServerAnchorSlot = ServerAnchorKind | RoleBriefSlot;
export const roleBriefSlot = (role: "buyer" | "provider"): RoleBriefSlot =>
  role === "buyer" ? "briefBuyer" : "briefProvider";

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

/** CDT-SEC L6: the brief anchor's ledger subject (`agent-contract:<this>`) — scope-free. */
export const BRIEF_ANCHOR_SUBJECT = "brief";
/** CDT-SEC M4: minimum wait before a failed brief anchor is re-issued. */
export const BRIEF_ANCHOR_RETRY_MS = 60_000;
/** CDT-SEC M4: backstop on remembered scopes (each is evicted when it ends). */
const MAX_BRIEF_SCOPES = 4096;

const isOpen = (a: { status: string } | undefined): boolean =>
  a !== undefined && (a.status === "anchoring" || a.status === "pending");

export interface ServerAnchors {
  /** Anchor the run's terms digest (write-once per run). */
  fireTerms(run: ContractRun, digest: string): void;
  /** Serve a brief; its digest's one shared anchor is issued on first need, awaited (bounded). */
  getBrief(
    name: string,
    scope: { run?: ContractRun; preBindScope: string; role?: "buyer" | "provider" },
  ): Promise<
    | { ok: true; result: { name: string; digest: string; text: string; anchor: ReturnType<typeof renderServerAnchor> } }
    | { ok: false; code: "NOT_FOUND" }
  >;
  /** At bind: a brief anchored on the seat's pre-bind scope becomes the run's brief anchor. */
  carryBrief(run: ContractRun, preBindScope: string): void;
  /** CDT-GAPS gap 1: role-brief mode is on (CONTRACT_ROLE_BRIEFS). */
  readonly roleBriefs: boolean;
  /**
   * CDT-GAPS gap 1, at bind BEFORE the result is built: the binding role's
   * brief digest — the configured role brief, else the first non-failed
   * brief served in this seat's pre-bind scope, else null.
   */
  roleBriefFor(role: "buyer" | "provider", preBindScope: string): string | null;
  /** CDT-GAPS gap 1, after the bind committed: record `digest`'s shared anchor in the role's slot. */
  attachRoleBrief(run: ContractRun, role: "buyer" | "provider", digest: string): void;
  /** CDT-SEC M4: forget an ended scope (`run:<id>` or a pre-bind scope). */
  dropScope(scope: string): void;
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
  /** M4: minimum wait before a failed brief anchor is retried (default 60 s). */
  briefRetryMs?: number;
  /**
   * CDT-GAPS gap 1 (CONTRACT_ROLE_BRIEFS): role → configured brief digest.
   * Present (even empty) = role-brief mode; each digest's shared anchor is
   * issued at construction.
   */
  roleBriefs?: Partial<Record<"buyer" | "provider", string>>;
  now?: () => number;
}): ServerAnchors {
  const briefAwaitMs = deps.briefAnchorAwaitMs ?? 10_000;
  const finalAwaitMs = deps.finalAnchorAwaitMs ?? 5_000;
  const briefRetryMs = deps.briefRetryMs ?? BRIEF_ANCHOR_RETRY_MS;
  const now = deps.now ?? Date.now;
  /**
   * M4: one anchor per brief digest. `runs` are the runs whose brief anchor
   * IS this one — every state change is copied onto them (and their jobs).
   */
  interface SharedBrief {
    state: AnchorRunState | undefined;
    op: Promise<void> | undefined;
    retryAtMs: number;
    /** Targets: `runId` (the run's single brief slot) or `runId|buyer` / `runId|provider` (role slots). */
    runs: Set<string>;
  }
  const roleMode = deps.roleBriefs !== undefined;
  /** A shared-brief target → the run and the slot its state is copied into. */
  const targetOf = (target: string): { runId: string; slot: "brief" | RoleBriefSlot } => {
    const i = target.lastIndexOf("|");
    if (i < 0) return { runId: target, slot: "brief" };
    const role = target.slice(i + 1);
    return { runId: target.slice(0, i), slot: role === "buyer" ? "briefBuyer" : "briefProvider" };
  };
  const sharedBriefs = new Map<string, SharedBrief>();
  /** M4: the brief digests served per scope, in serve order (for carryBrief). */
  const scopeBriefs = new Map<string, string[]>();
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
  const recordOn = (runId: string, kind: ServerAnchorSlot) => (s: AnchorRunState): void => {
    const live = deps.getRun(runId);
    if (live !== undefined) (live.anchors ??= {})[kind] = s;
    if (deps.getJob(runId) === undefined) return;
    deps.updateJob(runId, (job) => {
      job.anchors = { ...job.anchors, [kind]: { kind, ...s } };
    });
  };

  /** M4: remember which brief a scope was served (bounded; evicted at scope end). */
  function noteScopeBrief(scopeKey: string, digest: string): void {
    let list = scopeBriefs.get(scopeKey);
    if (list === undefined) {
      if (scopeBriefs.size >= MAX_BRIEF_SCOPES) scopeBriefs.delete(scopeBriefs.keys().next().value!);
      list = [];
      scopeBriefs.set(scopeKey, list);
    }
    if (!list.includes(digest)) list.push(digest);
  }

  /**
   * M4: the one anchor for `digest` — issued on first need; re-issued after
   * a failure only once the backoff has passed and nothing is in flight.
   */
  function ensureBriefAnchor(digest: string): SharedBrief {
    let shared = sharedBriefs.get(digest);
    if (shared === undefined) {
      shared = { state: undefined, op: undefined, retryAtMs: 0, runs: new Set() };
      sharedBriefs.set(digest, shared);
    }
    const sb = shared;
    const due = sb.state === undefined || (sb.state.status === "failed" && now() >= sb.retryAtMs);
    if (due && sb.op === undefined) {
      const op = run("brief", BRIEF_ANCHOR_SUBJECT, digest, (s) => {
        sb.state = s;
        if (s.status === "failed") sb.retryAtMs = now() + briefRetryMs;
        for (const target of [...sb.runs]) {
          // A run whose live state and job are both gone needs no copy.
          const { runId } = targetOf(target);
          if (deps.getRun(runId) === undefined && deps.getJob(runId) === undefined) {
            sb.runs.delete(target);
            continue;
          }
          copyToRun(target, s);
        }
      });
      sb.op = op;
      void op.finally(() => { if (sb.op === op) sb.op = undefined; });
    }
    return sb;
  }

  /**
   * M4: make the shared anchor this run's brief anchor (state copied now and
   * on every change). `target` is a runId, or `runId|role` for a role slot.
   */
  function attachRun(sb: SharedBrief, target: string): void {
    sb.runs.add(target);
    if (sb.state !== undefined) copyToRun(target, sb.state);
  }

  function copyToRun(target: string, s: AnchorRunState): void {
    const { runId, slot } = targetOf(target);
    recordOn(runId, slot)(s);
    if (s.status !== "anchoring") scheduleFinal(runId);
  }

  function scheduleFinal(runId: string): void {
    if (deps.anchor === undefined) return;
    setImmediate(() => maybeFireFinal(runId));
  }

  function finalEligible(job: TerminalJob): boolean {
    if (job.terminalState === null || job.anchors?.final !== undefined) return false;
    if (job.close !== undefined && job.close.status === "delivering") return false;
    const a = job.anchors;
    return a === undefined || ![a.agreement, a.terminal, a.terms, a.brief, a.briefBuyer, a.briefProvider].some(isOpen);
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

  // CDT-GAPS gap 1: configured role briefs are anchored at start-up, so the
  // anchor's ledger time precedes every role's first event.
  if (deps.anchor !== undefined) {
    for (const digest of new Set(Object.values(deps.roleBriefs ?? {}))) {
      if (digest !== undefined) ensureBriefAnchor(digest);
    }
  }

  return {
    fireTerms(r, digest) {
      if (deps.anchor === undefined || r.anchors?.terms !== undefined) return;
      void run("terms", r.runId, digest, recordOn(r.runId, "terms"));
    },

    async getBrief(name, scope) {
      const brief = deps.briefs?.get(name);
      if (brief === undefined) return { ok: false, code: "NOT_FOUND" };
      if (deps.anchor === undefined) {
        return { ok: true, result: { name, digest: brief.digest, text: brief.text, anchor: null } };
      }
      const scopeKey = scope.run !== undefined ? `run:${scope.run.runId}` : scope.preBindScope;
      noteScopeBrief(scopeKey, brief.digest);
      const shared = ensureBriefAnchor(brief.digest);
      // The run's brief anchor is the first brief served in it.
      if (scope.run !== undefined) {
        if (roleMode) {
          // CDT-GAPS gap 1: the bound caller's own role slot, when it has none yet.
          if (scope.role !== undefined) {
            const cur = scope.run.anchors?.[roleBriefSlot(scope.role)];
            if (cur === undefined || cur.digest === brief.digest) {
              attachRun(shared, `${scope.run.runId}|${scope.role}`);
            }
          }
        } else {
          const cur = scope.run.anchors?.brief;
          if (cur === undefined || cur.digest === brief.digest) attachRun(shared, scope.run.runId);
        }
      }
      // Bounded wait for an in-flight issue only — never during the backoff.
      if (shared.op !== undefined) await Promise.race([shared.op, wait(briefAwaitMs)]);
      return {
        ok: true,
        result: { name, digest: brief.digest, text: brief.text, anchor: renderServerAnchor(shared.state) },
      };
    },

    roleBriefs: roleMode,

    roleBriefFor(role, preBindScope) {
      const configured = deps.roleBriefs?.[role];
      if (configured !== undefined) {
        // Re-issue only if the start-up issue failed and its backoff passed.
        if (deps.anchor !== undefined) ensureBriefAnchor(configured);
        return configured;
      }
      for (const digest of scopeBriefs.get(preBindScope) ?? []) {
        const shared = sharedBriefs.get(digest);
        if (shared?.state !== undefined && shared.state.status !== "failed") return digest;
      }
      return null;
    },

    attachRoleBrief(r, role, digest) {
      if (deps.anchor === undefined) return;
      const cur = r.anchors?.[roleBriefSlot(role)];
      if (cur !== undefined && cur.digest !== digest) return;
      attachRun(ensureBriefAnchor(digest), `${r.runId}|${role}`);
    },

    carryBrief(r, preBindScope) {
      if (roleMode || r.anchors?.brief !== undefined || deps.anchor === undefined) return;
      for (const digest of scopeBriefs.get(preBindScope) ?? []) {
        const shared = sharedBriefs.get(digest);
        if (shared?.state !== undefined && shared.state.status !== "failed") {
          attachRun(shared, r.runId);
          return;
        }
      }
    },

    dropScope(scope) {
      scopeBriefs.delete(scope);
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
      if (aj.kind === "brief") {
        // M4: the shared per-digest anchor (deterministic commitment).
        attachRun(ensureBriefAnchor(aj.digest), job.runId);
        return;
      }
      if (aj.kind === "briefBuyer" || aj.kind === "briefProvider") {
        attachRun(ensureBriefAnchor(aj.digest), `${job.runId}|${aj.kind === "briefBuyer" ? "buyer" : "provider"}`);
        return;
      }
      if (aj.kind !== "terms" && aj.kind !== "final") return;
      const extra = aj.kind === "final" ? { receiptCount: aj.receiptCount ?? null } : {};
      // Re-issue: the deterministic commitmentId resolves the same object
      // with its current confirmation state. Still unchained.
      void run(aj.kind, job.runId, aj.digest, recordOn(job.runId, aj.kind), extra);
    },
  };
}
