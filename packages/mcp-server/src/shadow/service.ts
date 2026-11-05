// Hosted Shadow: the record kept on the Clockchain MCP server for agents that have no machine of their own.
//
// One owner (the authenticated caller) holds sessions; each session is the library's hash chain of steps, signed
// checkpoints, and Clockchain anchors. Everything is bounded for a small box (V8 capped at 384 MB): per-owner open and
// total sessions, steps and bytes per session, the whole state directory, and anchors per owner per day. Only one
// session's events are ever in memory (the `heavy` gate), and they are read only when a checkpoint, packet, view or
// verification needs them. Logs carry counts and session ids only: never content, keys, link capabilities or tokens.
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, statfsSync } from "node:fs";
import { dirname } from "node:path";
import { getSharedLogBudget, type LogBudget } from "../budget.js";
import { clip, parseStrict } from "./lib/profile.js";
import { verifyPacket } from "./lib/verify.js";
import { summarize } from "./lib/summary.js";
import { redactSecrets, redactText } from "./redact.js";
import { windows, type Window } from "./lib/windows.js";
import type { Checkpoint, Network, ShadowEvent } from "./lib/types.js";
import { META_MAX_BYTES, ShadowStore, isSessionId, ownerKeyOf, type AnchorInfo, type OutboxRow, type SessionMeta } from "./store.js";
import {
  ANCHOR_LABEL, RECORD_KINDS, RecordError, START_LABEL, VERSION, LIBRARY, advance, buildEvent, buildPacket, buildPin,
  checkpointOver, receiptPayload, referenceId, startHashOf, stepFor, type RecordKind,
} from "./recorder.js";
import { AnchorLimitError, anchorHash, prefetchOnline, type AnchorOutcome, type ShadowLedger } from "./ledger.js";

export class ShadowError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ShadowError";
    this.code = code;
  }
}

export type ShadowLimits = {
  maxOpenSessionsPerOwner: number;
  maxSessionsPerOwner: number;
  /** Steps an agent records with shadow_record; the collector's own steps (receipts, gaps, close) ride on top. */
  maxStepsPerSession: number;
  /** Events plus metadata (and its backup) on disk. */
  maxSessionBytes: number;
  /** The whole SHADOW_STATE_DIR: new sessions are refused past it, and new steps past 125% of it. */
  maxStateBytes: number;
  maxAnchorsPerOwnerPerDay: number;
  maxContentBytes: number;
  maxAgents: number;
  maxOpenRuns: number;
  maxAnchorsPerSession: number;
  retentionMs: number;
  sweepIntervalMs: number;
  /** Online verification is skipped (offline verdict, with a note) for sessions with more receipts than this. */
  onlineVerifyMaxReceipts: number;
  anchorWaitMs: number;
  /** Bytes one owner's sessions may hold on disk; new steps and sessions are refused past it. */
  maxBytesPerOwner: number;
  maxSessionStartsPerOwnerPerDay: number;
  /** Built link bodies (packets and summaries) kept in memory and shared by every reader, in bytes. */
  linkCacheBytes: number;
};

export const DEFAULT_SHADOW_LIMITS: ShadowLimits = {
  maxOpenSessionsPerOwner: 20,
  maxSessionsPerOwner: 200,
  maxStepsPerSession: 2_000,
  maxSessionBytes: 8 * 1024 * 1024,
  maxStateBytes: 200 * 1024 * 1024,
  maxAnchorsPerOwnerPerDay: 60,
  maxContentBytes: 32 * 1024,
  maxAgents: 16,
  maxOpenRuns: 50,
  maxAnchorsPerSession: 100,
  retentionMs: 30 * 24 * 60 * 60_000,
  sweepIntervalMs: 60 * 60_000,
  onlineVerifyMaxReceipts: 12,
  anchorWaitMs: 12_000,
  maxBytesPerOwner: 40 * 1024 * 1024,
  maxSessionStartsPerOwnerPerDay: 30,
  linkCacheBytes: 48 * 1024 * 1024,
};

const RUN_STATUSES = ["succeeded", "failed", "cancelled", "timed_out", "unknown"] as const;
const AGENT_KINDS = new Set(["task.assigned", "agent.prompt", "agent.message", "agent.tool.call", "agent.tool.result", "artifact.created"]);
const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$/;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const MAX_OUTBOX = 20;
const MAX_PASSES = 10;
const COLLECTOR_STEP_HEADROOM = 500;
const ONLINE_TIMEOUT_MS = 20_000;
const LINKS_NOTE = "Anyone with these links can read the whole record until it is deleted, 30 days after the session started; links cannot be revoked.";
/** How long one call may spend anchoring before it reports what is still pending. */
const ANCHOR_BUDGET_MS = 25_000;
/** Readers at once when checking a session's receipts online. */
const ONLINE_CONCURRENCY = 8;
/** shadow_log_turn, the fallback: steps and bytes per call (a request's body is capped at about 1 MB). */
const MAX_TURN_STEPS = 100;
const MAX_TURN_BYTES = 900 * 1024;
const CREDENTIAL_AGENT = "An agent id can't hold a key or token, and nothing was recorded. Use a plain name, or leave agent out.";
const START_NEW = "Call again without session_id to start a new session; keep logging there.";
const NEW_SESSION_NOTE = "This session_id goes with every later step in this conversation. The viewer reads \"indeterminate\" until the session is closed; shadow_close_session and shadow_verify are for when the person asks to finish or verify.";
/** shadow_close_session's person_messages: well beyond any conversation, and small enough to read as a count. */
export const MAX_PERSON_MESSAGES = 10_000;

export type ShadowConfig =
  | { enabled: false }
  | {
      enabled: true;
      stateDir: string;
      network: Network;
      /** The env-tunable caps (security review follow-up, finding 2); the rest keep DEFAULT_SHADOW_LIMITS. */
      limits: Pick<ShadowLimits, "maxStateBytes" | "maxBytesPerOwner" | "maxSessionStartsPerOwnerPerDay"> &
        Partial<Pick<ShadowLimits, "maxAnchorsPerOwnerPerDay" | "maxAnchorsPerSession" | "onlineVerifyMaxReceipts">>;
      linkConcurrency: number;
      /** SHADOW_AUTO_LOG=1: logging is on by default for every connected account (shadow_log_step and friends). */
      autoLog?: true;
      /** SHADOW_LOG_STEPS_PER_MIN: shadow_log_step calls per account per minute, apart from MCP_RATE_PER_MIN. */
      logStepsPerMinute?: number;
      /** Set when a cap setting is malformed: Shadow then refuses to start (every /shadow path answers 503). */
      problem?: string;
    };

/**
 * Production defaults for the caps an operator can set through the environment. A free account is cheap to make, so
 * one account may keep only 10 MB, and all of Shadow 1 GB (and never more than half the state filesystem's free space,
 * checked at boot by {@link diskBudgetProblem}).
 */
export const SHADOW_ENV_DEFAULTS = {
  maxStateBytes: 1024 * 1024 * 1024, // SHADOW_MAX_BYTES
  maxBytesPerOwner: 10 * 1024 * 1024, // SHADOW_ACCOUNT_MAX_BYTES
  maxSessionStartsPerOwnerPerDay: 30, // SHADOW_SESSION_STARTS_PER_DAY
  linkConcurrency: 32, // SHADOW_LINK_CONCURRENCY
} as const;

/**
 * Defaults when SHADOW_AUTO_LOG=1: an anchor per step has to fit tasks of 50 steps and more. At 300 anchors a session's
 * metadata stays under the 256 KB limit of the build before this flag, so a rollback can still read it.
 */
export const AUTO_LOG_DEFAULTS = { anchorsPerDay: 400, anchorsPerSession: 300, logStepsPerMinute: 90, accountBytes: 5 * 1024 * 1024 } as const;
/** meta.anchors keeps about 260 bytes per anchor, and the metadata file holds at most META_MAX_BYTES. */
const MAX_ANCHORS_PER_SESSION = 1500;

/**
 * SHADOW_ENABLED=1 turns hosted Shadow on; SHADOW_STATE_DIR (default /app/state/shadow) is where it keeps records.
 * SHADOW_MAX_BYTES, SHADOW_ACCOUNT_MAX_BYTES, SHADOW_SESSION_STARTS_PER_DAY and SHADOW_LINK_CONCURRENCY set the caps
 * ("" or unset = SHADOW_ENV_DEFAULTS); anything but a positive whole number is a `problem`.
 *
 * SHADOW_AUTO_LOG=1 turns on automatic logging, which anchors every step. Its defaults are AUTO_LOG_DEFAULTS: anchors per
 * account per day and per session (SHADOW_ANCHORS_PER_DAY, SHADOW_ANCHORS_PER_SESSION; without the flag, 60 and 100 unless
 * set), shadow_log_step calls per account per minute (SHADOW_LOG_STEPS_PER_MIN), and a smaller SHADOW_ACCOUNT_MAX_BYTES.
 * Without the flag and those settings the result is exactly what it was before them.
 */
export function loadShadowConfig(env: NodeJS.ProcessEnv): ShadowConfig {
  if ((env.SHADOW_ENABLED ?? "").trim() !== "1") return { enabled: false };
  const problems: string[] = [];
  const whole = (name: string, fallback: number): number => {
    const raw = (env[name] ?? "").trim();
    if (raw === "") return fallback;
    if (!/^[1-9][0-9]{0,15}$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
      problems.push(`${name} must be a positive whole number`);
      return fallback;
    }
    return Number(raw);
  };
  const autoLog = (env.SHADOW_AUTO_LOG ?? "").trim() === "1";
  const anchorsPerDay = whole("SHADOW_ANCHORS_PER_DAY", autoLog ? AUTO_LOG_DEFAULTS.anchorsPerDay : DEFAULT_SHADOW_LIMITS.maxAnchorsPerOwnerPerDay);
  const anchorsPerSession = whole("SHADOW_ANCHORS_PER_SESSION", autoLog ? AUTO_LOG_DEFAULTS.anchorsPerSession : DEFAULT_SHADOW_LIMITS.maxAnchorsPerSession);
  if (anchorsPerSession > MAX_ANCHORS_PER_SESSION) problems.push(`SHADOW_ANCHORS_PER_SESSION must be at most ${MAX_ANCHORS_PER_SESSION}`);
  const logStepsPerMinute = autoLog ? whole("SHADOW_LOG_STEPS_PER_MIN", AUTO_LOG_DEFAULTS.logStepsPerMinute) : undefined;
  return {
    enabled: true,
    stateDir: (env.SHADOW_STATE_DIR ?? "").trim() || "/app/state/shadow",
    network: (env.SHADOW_NETWORK ?? "").trim() === "mainnet" ? "clockchain-mainnet" : "clockchain-testnet",
    limits: {
      maxStateBytes: whole("SHADOW_MAX_BYTES", SHADOW_ENV_DEFAULTS.maxStateBytes),
      maxBytesPerOwner: whole("SHADOW_ACCOUNT_MAX_BYTES", autoLog ? AUTO_LOG_DEFAULTS.accountBytes : SHADOW_ENV_DEFAULTS.maxBytesPerOwner),
      maxSessionStartsPerOwnerPerDay: whole("SHADOW_SESSION_STARTS_PER_DAY", SHADOW_ENV_DEFAULTS.maxSessionStartsPerOwnerPerDay),
      ...(anchorsPerDay !== DEFAULT_SHADOW_LIMITS.maxAnchorsPerOwnerPerDay ? { maxAnchorsPerOwnerPerDay: anchorsPerDay } : {}),
      ...(anchorsPerSession !== DEFAULT_SHADOW_LIMITS.maxAnchorsPerSession ? { maxAnchorsPerSession: anchorsPerSession } : {}),
      // Every receipt is checked online, however many a session has (a start marker plus the session's anchors).
      ...(autoLog ? { onlineVerifyMaxReceipts: anchorsPerSession + 1 } : {}),
    },
    linkConcurrency: whole("SHADOW_LINK_CONCURRENCY", SHADOW_ENV_DEFAULTS.linkConcurrency),
    ...(autoLog ? { autoLog: true as const, logStepsPerMinute } : {}),
    ...(problems.length ? { problem: problems.join("; ") } : {}),
  };
}

/**
 * At boot: refuses a global cap larger than half the free space on the state directory's filesystem, so a full
 * Shadow can never fill the disk the rest of the server (handshake state, accounts) lives on. Undefined when fine.
 */
export function diskBudgetProblem(stateDir: string, maxStateBytes: number, statfs: (p: string) => { bavail: number | bigint; bsize: number | bigint } = statfsSync): string | undefined {
  // The state directory may not exist yet on a fresh volume: measure the filesystem it will be created on.
  let probe = stateDir;
  while (!existsSync(probe) && dirname(probe) !== probe) probe = dirname(probe);
  const s = statfs(probe);
  const free = Number(s.bavail) * Number(s.bsize);
  return maxStateBytes > free / 2
    ? `SHADOW_MAX_BYTES (${maxStateBytes} bytes) is more than half the ${free} bytes free on the state directory's filesystem`
    : undefined;
}

// ---- small concurrency helpers --------------------------------------------------------------------------------------

class KeyedMutex {
  private readonly tails = new Map<string, Promise<void>>();
  async run<T>(key: string, fn: () => Promise<T> | T): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => (release = r));
    const tail = prev.then(() => next);
    this.tails.set(key, tail);
    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (this.tails.get(key) === tail) this.tails.delete(key);
    }
  }
  busy(key: string): boolean {
    return this.tails.has(key);
  }
}

/** One holder at a time, with a bounded queue: this is what keeps at most one session's events in memory. */
class Gate {
  private tail: Promise<void> = Promise.resolve();
  private waiting = 0;
  constructor(private readonly maxWaiting: number) {}
  async run<T>(fn: () => Promise<T> | T): Promise<T> {
    if (this.waiting >= this.maxWaiting) throw new ShadowError("SHADOW_BUSY", "Shadow is busy; try again in a few seconds.");
    this.waiting++;
    const prev = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((r) => (release = r));
    try {
      await prev;
    } finally {
      this.waiting--;
    }
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

/** A least-recently-used map of Buffers bounded by their total size. */
class ByteLru {
  private readonly items = new Map<string, Buffer>();
  private bytes = 0;
  constructor(private readonly maxBytes: number) {}
  get(key: string): Buffer | undefined {
    const v = this.items.get(key);
    if (v) {
      this.items.delete(key);
      this.items.set(key, v);
    }
    return v;
  }
  set(key: string, value: Buffer): void {
    if (value.length > this.maxBytes / 2) return;
    const prior = this.items.get(key);
    if (prior) {
      this.items.delete(key);
      this.bytes -= prior.length;
    }
    this.items.set(key, value);
    this.bytes += value.length;
    for (const [k, v] of this.items) {
      if (this.bytes <= this.maxBytes) break;
      this.items.delete(k);
      this.bytes -= v.length;
    }
  }
  get size(): number {
    return this.bytes;
  }
}

/** What a link body depends on: the steps (append-only, so the count), the checkpoint, and the queued checkpoints. */
type LinkKind = "packet" | "summary" | "log" | "log-json";

function linkKey(kind: LinkKind, meta: SessionMeta): string {
  const cp = meta.checkpoint;
  const queued = meta.outbox.filter((r) => r.kind === "checkpoint").map((r) => r.hash).join(",");
  return `${kind}:${meta.sessionId}:${meta.seq}:${cp?.hash ?? "-"}:${cp?.body.count ?? -1}:${queued}`;
}

// ---- input checks -----------------------------------------------------------------------------------------------------

const notFound = () => new ShadowError("SHADOW_NOT_FOUND", "No session with that id belongs to you. Call shadow_list_sessions to see yours.");
const bad = (message: string) => new ShadowError("SHADOW_BAD_INPUT", message);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function cleanText(v: unknown, max: number): string {
  return String(v).replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max).toWellFormed();
}

function depthWithin(v: unknown, max: number): boolean {
  const stack: [unknown, number][] = [[v, 0]];
  while (stack.length) {
    const [x, d] = stack.pop()!;
    if (d > max) return false;
    if (x && typeof x === "object") for (const y of Object.values(x)) stack.push([y, d + 1]);
  }
  return true;
}

function sessionIdOf(v: unknown): string {
  if (!isSessionId(v)) throw notFound();
  return v;
}

const loggingOff = () => new ShadowError("LOGGING_OFF", "Logging is off for this Clockchain account, because the person turned it off. Nothing was recorded. Do not log this step and do not show a logging footer. If the person asks to turn logging back on, call clockchain_logging {enabled: true}.");

// ---- automatic logging: results ----------------------------------------------------------------------------------

type LogStepInput = { agent?: unknown; kind?: unknown; content?: unknown };
type LoggedStep = { seq: number; hash: string; kind: RecordKind; runId: string | null; summary: string };
type LogAnchor = {
  block_height: string | null; ledger_id: string | null; block_time: string | null; anchored_hash: string | null; covers_steps: number | null;
  anchor_status: "anchored" | "pending" | "failed" | "over_limit" | "not_anchored"; anchor_reason?: string;
};

/** A short clip of a step for its result: what a person would recognise it by. */
function stepSummary(kind: RecordKind, content: unknown): string {
  const flat = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v) ?? "").replace(/\s+/g, " ").trim();
  const c = isObj(content) ? content : null;
  const name = c ? c.tool ?? c.name ?? c.path ?? c.filename : undefined;
  const body = !c ? flat(content) : kind === "file" ? "" : flat(c.args ?? c.arguments ?? c.input ?? c.result ?? c.output ?? c.content ?? content);
  const text = (typeof name === "string" ? `${name} ${body}` : body).trim();
  const chars = Array.from(text);
  return (chars.length > 80 ? chars.slice(0, 79).join("") + "…" : text).toWellFormed();
}

/** One step as the tables and summaries show it: its kind and a short title, never its content. */
type StepRow = { seq: number; kind: string; title: string; hash: string };

const MAX_TURN_ROWS = 30;
const MAX_SUMMARY_ROWS = 50;
const LEDGER_HASH_NOTE = "The ledger hash is the anchored checkpoint's hash, which is what a ledger lookup returns. It covers every step up to and including that one.";

const CREDENTIAL_PREFIX = /(?:^|[-_.])(?:glpat|npm|hf|dop|whsec|sk|ghp|gho|github_pat|xox[a-z])[-_]/i;

/**
 * A tool or file name to show, in backticks so it reads as a name and not as text from the server. Anything that could be
 * a credential or an identifier shows as `otherwise`: a session may predate redaction, and redaction can't know every
 * format. So no long run of letters and digits, and no more digits than a version or a year.
 */
function shownName(v: unknown, otherwise: string): string {
  if (typeof v !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/.test(v)) return otherwise;
  if (/[A-Za-z0-9]{20,}/.test(v) || (v.match(/\d/g)?.length ?? 0) > 6 || CREDENTIAL_PREFIX.test(v) || redactText(v) !== v) return otherwise;
  return `\`${v}\``;
}

function stepRow(e: ShadowEvent): StepRow {
  const p = (e.body.payload ?? {}) as { tool?: unknown; path?: unknown; isError?: unknown; note?: unknown; capture?: unknown };
  const [kind, title] =
    e.body.kind === "task.assigned" ? ["task", "the person's request"]
      : e.body.kind === "agent.prompt" ? ["prompt", "the person's message"]
        : e.body.kind === "agent.message" ? (p.capture ? ["note", "count of the person's messages"] : p.note === true ? ["note", "agent's note"] : ["message", "message shown"])
          : e.body.kind === "agent.tool.call" ? ["tool_call", shownName(p.tool, "a tool")]
            : e.body.kind === "agent.tool.result" ? ["tool_result", `${shownName(p.tool, "a tool")}${p.isError === true ? " (error)" : ""}`]
              : ["file", shownName(typeof p.path === "string" ? p.path.split(/[\\/]/).pop() : undefined, "a file")];
  return { seq: e.body.seq, kind, title, hash: e.hash };
}

/**
 * The steps since the latest prompt or task, that step included: at most the last MAX_TURN_ROWS. `earlier` counts those
 * cut off by the cap, and those in this call (from seq `callFrom` on) before the boundary: a table never drops one unsaid.
 */
function turnRows(events: ShadowEvent[], callFrom: number): { rows: StepRow[]; earlier: number } {
  const steps = events.filter((e) => AGENT_KINDS.has(e.body.kind));
  let from = steps.length - 1;
  while (from > 0 && steps[from].body.kind !== "agent.prompt" && steps[from].body.kind !== "task.assigned") from--;
  const turn = steps.slice(Math.max(from, 0));
  const cut = steps.slice(0, Math.max(from, 0)).filter((e) => e.body.seq >= callFrom).length;
  return { rows: turn.slice(-MAX_TURN_ROWS).map(stepRow), earlier: cut + Math.max(0, turn.length - MAX_TURN_ROWS) };
}

/**
 * For rows in order: the first anchored checkpoint covering each one. Without one, a step is pending only if a checkpoint
 * still queued for Clockchain covers it; otherwise nothing is on its way, and it is not anchored.
 */
function coverage(meta: SessionMeta): (seq: number) => { anchor?: SessionMeta["anchors"][number]; status: "anchored" | "pending" | "not_anchored" } {
  const anchors = meta.anchors.filter((a) => a.marker === "checkpoint" && a.count !== null).sort((a, b) => a.count! - b.count!);
  const queued = Math.max(-1, ...meta.outbox.filter((r) => r.kind === "checkpoint" && r.state !== "failed").map((r) => r.body?.count ?? -1));
  let i = 0;
  return (seq) => {
    while (i < anchors.length && anchors[i].count! < seq) i++;
    return anchors[i] ? { anchor: anchors[i], status: "anchored" } : { status: seq <= queued ? "pending" : "not_anchored" };
  };
}

/** First and last block by number, since anchors can land out of order. */
function blockSpan(anchors: { blockHeight: string }[]): { first: string | null; last: string | null } {
  const heights = anchors.map((a) => a.blockHeight).filter((h) => /^\d+$/.test(h)).sort((a, b) => Number(a) - Number(b));
  return { first: heights[0] ?? null, last: heights.at(-1) ?? null };
}

const bareHash = (h: string) => h.replace(/^sha256:/, "");
/** A value from the ledger, in a table cell or inline code: what it says, without anything that would break the markup. */
const cell = (v: unknown) => String(v).replace(/[\u0000-\u001f`|]/g, "");

function turnTable(meta: SessionMeta, turn: { rows: StepRow[]; earlier: number }): string {
  const cover = coverage(meta);
  const rows = turn.rows.map((r) => {
    const { anchor: a, status } = cover(r.seq);
    const anchored = a ? `\`${cell(bareHash(a.hash).slice(0, 12))}\` | ${cell(a.blockHeight)} | \`${cell(a.ledgerId)}\`` : status === "pending" ? "pending | pending | pending" : "not anchored | not anchored | not anchored";
    return `| ${r.kind}: ${r.title} | \`${bareHash(r.hash).slice(0, 12)}\` | ${anchored} |`;
  });
  const n = turn.earlier;
  return [
    ...(n ? [`${n} earlier ${n === 1 ? "step is" : "steps are"} at the viewer link below.`, ""] : []),
    "| What happened | Step hash | Ledger hash | Block | Ledger ID |", "|---|---|---|---|---|", ...rows,
    "", LEDGER_HASH_NOTE,
  ].join("\n");
}

/**
 * What can be said about turns missing from a session. A blocked call never reaches this server, so the only evidence
 * is the assistant's own count at close. A pass from the verifier is about integrity and doesn't touch this.
 */
function captureNote(meta: SessionMeta): string {
  if (meta.state === "open") return "This session is still open, so it can't yet say whether any turn is missing.";
  const c = meta.capture;
  if (!c) return "No count of the person's messages was given when this session closed, so this record can't say whether any turn is missing.";
  const reported = `${c.person_messages_reported} ${c.person_messages_reported === 1 ? "message" : "messages"} from the person`;
  const own = "That is the assistant's own count, and this server can't see a call that was blocked before it arrived.";
  if (c.missing > 0) return `${reported}, ${c.person_messages_logged} logged: at least ${c.missing} ${c.missing === 1 ? "turn is" : "turns are"} missing from this record. ${own}`;
  const closing = c.person_messages_logged > c.person_messages_reported ? " (the closing request can be one of them)" : "";
  return `${reported}, ${c.person_messages_logged} logged${closing}: no turn shows as missing. ${own} It also doesn't show that every step within a turn was logged.`;
}

/** The whole session as hashes and metadata, from its own record. No step content, and nothing a caller can supply. */
function sessionLog(meta: SessionMeta, events: ShadowEvent[]) {
  const cover = coverage(meta);
  const steps = events.filter((e) => AGENT_KINDS.has(e.body.kind)).map(stepRow).map((r) => {
    const { anchor: a, status } = cover(r.seq);
    return { seq: r.seq, kind: r.kind, title: r.title, step_hash: r.hash, status, ledger_hash: a?.hash ?? null, block: a?.blockHeight ?? null, ledger_id: a?.ledgerId ?? null };
  });
  const anchored = steps.filter((s) => s.status === "anchored");
  // Every record this session has on the ledger, as the footer counts them: its start and closing anchors too.
  const onLedger = meta.anchors.filter((a) => a.blockHeight);
  const blocks = blockSpan(onLedger);
  return {
    session_id: meta.sessionId,
    status: meta.state,
    expires_at: meta.expiresAt,
    totals: {
      steps: steps.length, anchored: anchored.length, pending: steps.filter((s) => s.status === "pending").length, not_anchored: steps.filter((s) => s.status === "not_anchored").length,
      ledger_records: onLedger.length,
      first_block: blocks.first, last_block: blocks.last,
    },
    capture: meta.capture ?? null,
    capture_note: captureNote(meta),
    steps,
    ledger_hash_note: LEDGER_HASH_NOTE,
  };
}

/** The log as text: a list of steps in order, with totals. `max` and `rest` cap the list in a tool result. */
function sessionLogText(log: ReturnType<typeof sessionLog>, cap?: { max: number; rest: string }): string {
  const t = log.totals;
  const shown = cap ? log.steps.slice(0, cap.max) : log.steps;
  const lines = shown.map((s, i) => {
    const ledger = s.status === "anchored" ? `Ledger hash \`${cell(s.ledger_hash)}\`. Block ${cell(s.block)}. Ledger ID \`${cell(s.ledger_id)}\`.` : s.status === "pending" ? "Ledger hash pending. Block pending. Ledger ID pending." : "Not anchored, so no ledger hash, block or ledger ID.";
    return `${i + 1}. ${s.kind}: ${s.title}. Step hash \`${s.step_hash}\`. ${ledger}`;
  });
  const blocks = t.first_block === null ? "Nothing on Clockchain yet." : `On Clockchain: first block ${cell(t.first_block)}, last block ${cell(t.last_block)}, ${t.ledger_records} ledger ${t.ledger_records === 1 ? "record" : "records"}, counting any start or closing anchor.`;
  return [
    "**Clockchain Shadow: everything logged in this session**",
    log.capture_note,
    `Session \`${log.session_id}\`, ${log.status}. ${t.steps} ${t.steps === 1 ? "step" : "steps"}: ${t.anchored} anchored, ${t.pending} pending${t.not_anchored ? `, ${t.not_anchored} not anchored` : ""}. ${blocks}`,
    lines.join("\n"),
    ...(cap && log.steps.length > shown.length ? [`Showing the first ${shown.length} of ${log.steps.length} steps. The rest are at ${cap.rest}`] : []),
    LEDGER_HASH_NOTE,
  ].filter(Boolean).join("\n\n") + "\n";
}

/** The footer to end a reply with: only what the record really holds, in server-made values (no step content). */
function logFooter(meta: { agentSteps: number; anchors: { blockHeight: string; ledgerId: string }[] }, anchor: LogAnchor, viewer: string, table: string, turnSteps?: number): string {
  const count = (n: number) => `${n} ${n === 1 ? "step" : "steps"}`;
  const span = blockSpan(meta.anchors);
  const latest = meta.anchors.at(-1);
  const parts: string[] = [];
  if (turnSteps !== undefined) {
    parts.push(`**Clockchain Shadow:** ${count(turnSteps)} logged in this reply under one shared anchor, not one per step (${count(meta.agentSteps)} so far).`);
    if (anchor.anchor_status === "anchored") parts.push(`Shared anchor: block ${anchor.block_height}, ledger ID \`${anchor.ledger_id}\`.`);
  } else {
    parts.push(`**Clockchain Shadow:** ${count(meta.agentSteps)} logged so far.`);
    if (span.first !== null) parts.push(`First block ${span.first}, last block ${span.last}.`);
    if (latest) parts.push(`Latest ledger ID: \`${latest.ledgerId}\`.`);
  }
  parts.push(`Viewer: ${viewer}`);
  const lines = ["---", ...(table ? [table] : []), parts.join(" ")];
  if (anchor.anchor_status !== "anchored") {
    const one = turnSteps === undefined;
    const said = {
      pending: one ? "its anchor is still pending" : "their anchor is still pending",
      over_limit: "an anchoring limit has been reached",
      failed: one ? "its anchor failed" : "their anchor failed",
      not_anchored: one ? "it has no anchor yet" : "they have no anchor yet",
    }[anchor.anchor_status];
    lines.push(`${one ? "The latest step is" : "These steps are"} recorded, but ${said}, so ${one ? "it has" : "they have"} no block or ledger ID. ${anchor.anchor_reason ?? ""}`.trim());
  }
  lines.push("Logging is on. Saying 'stop logging' turns it off.");
  return lines.join("\n\n");
}

/**
 * The hosted viewer checks a packet against the pin this same server made, so its checks aren't independent. The
 * library's summary, which is vendored and unchanged, is written for a pin that reached the reader separately: here the
 * report says whose pin it was, and {@link hostedViewer} replaces its "Proven" tag.
 */
function ownPinReport<T extends { summary: string; checks: { name: string; status: string; reason: string }[] }>(report: T): T {
  return {
    ...report,
    // "Captured" would claim more than the verifier can see: it knows the runs in the record, not the work outside it.
    summary: report.summary.replace("the supplied pin", "this server's own pin").replace("every run was captured", "every recorded run has an ending"),
    checks: report.checks.map((c) =>
      c.name === "trust" && c.status === "pass" ? { ...c, reason: "Matches the pin from this server. That pin isn't independent: it shows the record is what this server signed, not that this server is honest." }
        : c.name === "time" ? { ...c, reason: c.reason.replace("with a single validator they are only as good as its clock", "with a single-operator gateway they are only as good as its clock") }
          : c),
  };
}

const OWN_PIN_NOTE = `<p class="meta">The pin behind this page came from this server, so these checks aren't independent. For an independent check, run the command at the end of this page with a pin you received separately.</p>`;

/** The summary page with "Proven" (which step content can't produce: it is escaped) saying what was really checked. */
function hostedViewer(html: string): string {
  return html
    .replaceAll("<b>Proven:</b>", "<b>Matches what the server signed:</b>")
    .replaceAll('<td class="tag">Proven</td>', '<td class="tag">Matches what the server signed</td>')
    .replace("and that the validators keep good time.</li>", "and that the single-operator gateway keeps good time.</li>")
    .replace("<h2>What this record shows</h2>", `<h2>What this record shows</h2>${OWN_PIN_NOTE}`);
}

const escHtml = (s: unknown) => String(s ?? "").replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);

/**
 * The viewer's per-step table, added to the library's summary page (which is vendored, and lists receipts only by the
 * step that carries them): each step's own hash, and the block and ledger id of the first anchor that covers it.
 */
function withStepAnchors(html: string, events: ShadowEvent[], cap: string): string {
  const anchors = events.filter((e) => e.body.kind === "clockchain.anchored" && (e.body.payload as any)?.marker === "checkpoint")
    .sort((a, b) => Number((a.body.payload as any).checkpoint?.count) - Number((b.body.payload as any).checkpoint?.count));
  let i = 0;
  const rows = events.filter((e) => AGENT_KINDS.has(e.body.kind)).map((e) => {
    while (i < anchors.length && Number((anchors[i].body.payload as any).checkpoint?.count) < e.body.seq) i++;
    const p = anchors[i]?.body.payload as any;
    return `<tr><td>${escHtml(e.body.seq)}</td><td>${escHtml(e.body.kind)}</td><td><code>${escHtml(e.hash)}</code></td><td>${p ? `<code>${escHtml(p.checkpointHash)}</code>` : "not anchored yet"}</td><td>${p ? escHtml(p.blockHeight) : "not anchored yet"}</td><td>${p ? `<code>${escHtml(p.ledgerId)}</code>` : "none"}</td></tr>`;
  }).join("");
  const table = `<h2>Steps and their anchors</h2><p class="meta">Each anchor is a checkpoint over every step up to it. Steps with the same ledger ID were logged in one call and share that anchor. A ledger lookup returns the ledger hash, not the step's own. <a href="${cap}/summary">Summary of every step</a> (<a href="${cap}/summary?format=json">JSON</a>).</p><div class="scroll"><table><tr><th>#</th><th>Step</th><th>Hash</th><th>Ledger hash</th><th>Block</th><th>Ledger ID</th></tr>${rows}</table></div>\n`;
  // Step content is escaped on the page, so this heading can only be the library's own.
  const at = html.indexOf("<h2>Clockchain receipts");
  return at < 0 ? html : html.slice(0, at) + table + html.slice(at);
}

// ---- the service ------------------------------------------------------------------------------------------------------

export type ServiceOptions = {
  stateDir: string;
  network?: Network;
  ledger?: () => ShadowLedger;
  budget?: () => LogBudget;
  limits?: Partial<ShadowLimits>;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  log?: (event: string, fields: Record<string, string | number | boolean | null>) => void;
  /** SHADOW_AUTO_LOG=1: the viewer's per-step table of hash, block and ledger id, and verify's receipt counts. */
  autoLog?: boolean;
};

type Links = { viewer: string; packet: string; summary?: string };

export class ShadowService {
  readonly store: ShadowStore;
  readonly limits: ShadowLimits;
  readonly network: Network;
  private readonly now: () => Date;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly ledger: () => ShadowLedger;
  private readonly budget: () => LogBudget;
  private readonly log: NonNullable<ServiceOptions["log"]>;
  private readonly autoLog: boolean;
  private readonly locks = new KeyedMutex();
  private readonly heavy = new Gate(32);
  private readonly drains = new Map<string, Promise<void>>();
  private readonly eventsMax: number;
  private readonly agentEventsMax: number;
  private readonly maxEvents: number;
  private usageBytes = 0;
  /** Bytes per owner, computed on first use and kept current by appends; the sweep starts it afresh. */
  private readonly ownerUsage = new Map<string, number>();
  private readonly linkCache: ByteLru;
  private readonly linkBuilds = new Map<string, Promise<Buffer | undefined>>();
  /** Link bodies built (not served from the cache), for tests and logs. */
  linkBuildCount = 0;
  private timer: NodeJS.Timeout | undefined;

  constructor(o: ServiceOptions) {
    this.store = new ShadowStore(o.stateDir);
    this.limits = { ...DEFAULT_SHADOW_LIMITS, ...(o.limits ?? {}) };
    this.network = o.network ?? "clockchain-testnet";
    this.now = o.now ?? (() => new Date());
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.ledger = o.ledger ?? (() => { throw new Error("no ledger"); });
    this.budget = o.budget ?? (() => getSharedLogBudget());
    this.log = o.log ?? ((event, fields) => console.error(JSON.stringify({ event, ...fields })));
    this.autoLog = o.autoLog === true;
    // The session budget covers events.jsonl plus meta.json and its .bak. Metadata stays small with few anchors.
    const metaBytes = this.limits.maxAnchorsPerSession > DEFAULT_SHADOW_LIMITS.maxAnchorsPerSession ? META_MAX_BYTES : 256 * 1024;
    const metaBudget = Math.min(2 * metaBytes, Math.floor(this.limits.maxSessionBytes / 4));
    this.eventsMax = this.limits.maxSessionBytes - metaBudget;
    this.agentEventsMax = this.eventsMax - Math.min(256 * 1024, Math.floor(this.eventsMax / 4));
    this.maxEvents = this.limits.maxStepsPerSession + COLLECTOR_STEP_HEADROOM;
    this.linkCache = new ByteLru(this.limits.linkCacheBytes);
  }

  private ownerBytes(ownerKey: string): number {
    let n = this.ownerUsage.get(ownerKey);
    if (n === undefined) {
      n = this.store.ownerBytes(ownerKey);
      if (this.ownerUsage.size >= 10_000) this.ownerUsage.clear();
      this.ownerUsage.set(ownerKey, n);
    }
    return n;
  }

  private accountFull(ownerKey: string, extra: number): ShadowError | null {
    const used = this.ownerBytes(ownerKey);
    if (used + extra <= this.limits.maxBytesPerOwner) return null;
    const mb = (x: number) => (x >= 10 * 1048576 ? String(Math.round(x / 1048576)) : (x / 1048576).toFixed(1));
    return new ShadowError(
      "SHADOW_LIMIT_ACCOUNT_STORAGE",
      `Your account's Shadow records use ${mb(used)} MB of the ${mb(this.limits.maxBytesPerOwner)} MB it may keep. Close open sessions; space comes back as sessions expire ${Math.round(this.limits.retentionMs / 86_400_000)} days after they start.`,
    );
  }

  /** The start-up retention sweep, then one every sweepIntervalMs. */
  start(): void {
    this.sweep();
    this.timer = setInterval(() => {
      try {
        this.sweep();
      } catch (e) {
        this.log("shadow_sweep_failed", { error: (e as Error).name });
      }
    }, this.limits.sweepIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  sweep(): { removed: number; bytes: number } {
    const r = this.store.sweep(this.now().getTime(), this.limits.retentionMs, (o, s) => this.locks.busy(`${o}/${s}`));
    this.usageBytes = r.bytes;
    this.ownerUsage.clear();
    this.log("shadow_sweep", { removed: r.removed, bytes: r.bytes });
    return r;
  }

  // ---- session access --------------------------------------------------------------------------------------------------

  /** Runs fn under the session's lock with its metadata loaded (repairing it first if a crash left it behind). */
  private session<T>(ownerKey: string, sessionId: string, fn: (meta: SessionMeta) => Promise<T> | T, opening = false): Promise<T> {
    return this.locks.run(`${ownerKey}/${sessionId}`, async () => {
      let meta: SessionMeta | undefined;
      try {
        meta = this.store.readMeta(ownerKey, sessionId);
      } catch {
        this.log("shadow_session_unreadable", { sessionId });
        throw new ShadowError("SHADOW_UNAVAILABLE", "This session's files could not be read. Try again later.");
      }
      if (!meta || Date.parse(meta.expiresAt) <= this.now().getTime()) throw notFound();
      if (this.store.eventsFileBytes(meta) !== meta.eventsBytes) meta = await this.reconcile(meta);
      if (meta.seq === 0 && !opening) this.openUnanchored(meta);
      return fn(meta);
    });
  }

  /**
   * Rebuilds the metadata from the event log after a crash between an event append and the metadata write (a torn
   * last line, which the client was never told succeeded, is dropped). A log shorter than its metadata is refused.
   */
  private async reconcile(meta: SessionMeta): Promise<SessionMeta> {
    return this.heavy.run(() => {
      const { events, bytes } = this.store.readAndRepairEvents(meta);
      if (events.length < meta.seq) {
        this.log("shadow_session_inconsistent", { sessionId: meta.sessionId, steps: events.length, expected: meta.seq });
        throw new ShadowError("SHADOW_UNAVAILABLE", "This session's record is shorter than its index; it is kept as it is for inspection.");
      }
      const m: SessionMeta = { ...meta, seq: 0, head: null, eventsBytes: 0, agentSteps: 0, runs: [], state: "open", anchors: [] };
      for (const e of events) {
        advance(m, e, 0);
        if (AGENT_KINDS.has(e.body.kind)) m.agentSteps++;
        if (e.body.kind === "session.closed") m.closedAt ??= e.body.collectedAt;
        const a = anchorFrom(e);
        if (a) m.anchors.push(a);
      }
      m.eventsBytes = bytes;
      const landed = new Set(m.anchors.map((a) => a.hash));
      m.outbox = meta.outbox.filter((r) => !landed.has(r.hash));
      this.store.writeMeta(m);
      this.log("shadow_session_reconciled", { sessionId: m.sessionId, steps: m.seq });
      return m;
    });
  }

  /** A session whose start was interrupted before session.opened: open it now and queue the start marker. */
  private openUnanchored(meta: SessionMeta): void {
    this.appendStep(meta, "session.opened", "collector", this.openedPayload(meta, null, { errorKind: "Transient", errorCode: "interrupted" }), {}, false);
    if (!meta.outbox.some((r) => r.kind === "start")) meta.outbox.push(this.row("start", meta.startHash, null));
    this.store.writeMeta(meta);
  }

  private openedPayload(meta: SessionMeta, receipt: Record<string, unknown> | null, error: { errorKind: string; errorCode: string } | null) {
    return {
      nonce: meta.nonce, startHash: meta.startHash, network: meta.network, agents: meta.agents.map((a) => a.id),
      library: { name: LIBRARY, version: VERSION }, receipt, ...(error ? { error } : {}),
    };
  }

  private row(kind: "start" | "checkpoint", hash: string, cp: Checkpoint | null, extra: Partial<OutboxRow> = {}): OutboxRow {
    return {
      id: randomUUID(), kind, hash, body: cp?.body ?? null, state: "queued", attempts: 0, ledgerId: null, submittedAt: null,
      lastErrorKind: null, lastErrorCode: null, createdAt: this.now().toISOString(), ...extra,
    };
  }

  /** Session.append() plus the hosted bounds; advances the metadata (the caller writes it). */
  private appendStep(meta: SessionMeta, kind: string, actor: string, payload: Record<string, unknown>, source: Parameters<typeof buildEvent>[4], agent: boolean): ShadowEvent {
    if (meta.seq >= this.maxEvents) throw new ShadowError("SHADOW_LIMIT_STEPS", "This session has reached its step limit.");
    let event: ShadowEvent;
    try {
      event = buildEvent(meta, kind, actor, payload, source, this.now());
    } catch (e) {
      if (e instanceof RecordError) throw new ShadowError(e.code, e.message);
      throw bad(`${(e as Error).message}.`);
    }
    const line = JSON.stringify(event);
    const bytes = Buffer.byteLength(line) + 1;
    if (meta.eventsBytes + bytes > (agent ? this.agentEventsMax : this.eventsMax))
      throw new ShadowError("SHADOW_LIMIT_SESSION_SIZE", `This session is full (${Math.round(this.limits.maxSessionBytes / 1048576)} MB on disk). Close it and start a new one.`);
    this.store.appendLine(meta, line, this.eventsMax);
    this.usageBytes += bytes;
    const owned = this.ownerUsage.get(meta.ownerKey);
    if (owned !== undefined) this.ownerUsage.set(meta.ownerKey, owned + bytes);
    advance(meta, event, bytes);
    if (agent) meta.agentSteps++;
    return event;
  }

  private withEvents<T>(meta: SessionMeta, fn: (events: ShadowEvent[]) => Promise<T> | T): Promise<T> {
    return this.heavy.run(() => fn(this.store.readEvents(meta)));
  }

  /** latestCheckpoint(): a fresh, signed, unanchored checkpoint when steps were added since the last one. */
  private latest(meta: SessionMeta, events: ShadowEvent[]): Checkpoint {
    const cp = checkpointOver(meta, events, this.store.operator(meta.ownerKey, this.now()).keys, this.now());
    if (cp !== meta.checkpoint) {
      meta.checkpoint = cp;
      this.store.writeMeta(meta);
    }
    return cp;
  }

  /** Queues `cp` for Clockchain unless it already is, or the session's anchor allowance is used up. */
  private queueCheckpoint(meta: SessionMeta, cp: Checkpoint): { code: string; message: string } | null {
    if (meta.anchors.some((a) => a.hash === cp.hash) || meta.outbox.some((r) => r.hash === cp.hash)) return null;
    if (meta.anchors.length + meta.outbox.length >= this.limits.maxAnchorsPerSession)
      return { code: "SHADOW_LIMIT_SESSION_ANCHORS", message: `This session has used its ${this.limits.maxAnchorsPerSession} anchors; the checkpoint is signed but not sent to Clockchain.` };
    if (meta.outbox.length >= MAX_OUTBOX)
      return { code: "SHADOW_ANCHOR_BACKLOG", message: "Too many anchors are still waiting for Clockchain; the checkpoint is signed but not queued. Try again later." };
    meta.outbox.push(this.row("checkpoint", cp.hash, cp));
    return null;
  }

  private links(meta: SessionMeta, base: string): Links {
    return { viewer: `${base}/shadow/s/${meta.cap}`, packet: `${base}/shadow/p/${meta.cap}.json`, ...(this.autoLog ? { summary: `${base}/shadow/s/${meta.cap}/summary` } : {}) };
  }

  // ---- tools ---------------------------------------------------------------------------------------------------------

  async startSession(ownerId: string, input: { title?: unknown; agents?: unknown }, base: string) {
    if (typeof input.title !== "string" || !cleanText(input.title, 200)) throw bad("Give the session a title (up to 200 characters).");
    const title = this.autoLog ? cleanText(redactText(input.title.slice(0, 1000)), 200) : cleanText(input.title, 200);
    const agents = this.agentsOf(input.agents);
    const ownerKey = ownerKeyOf(ownerId);
    return this.locks.run(`owner:${ownerKey}`, async () => {
      const now = this.now();
      const ids = this.store.sessionIds(ownerKey);
      if (ids.length >= this.limits.maxSessionsPerOwner)
        throw new ShadowError("SHADOW_LIMIT_SESSIONS", `You have ${ids.length} sessions, the most kept per owner. Old ones are removed ${Math.round(this.limits.retentionMs / 86_400_000)} days after they start.`);
      let open = 0;
      for (const id of ids) {
        try {
          const m = this.store.readMeta(ownerKey, id);
          if (m && m.state === "open" && Date.parse(m.expiresAt) > now.getTime()) open++;
        } catch {
          // Unreadable sessions do not count as open.
        }
      }
      if (open >= this.limits.maxOpenSessionsPerOwner)
        throw new ShadowError("SHADOW_LIMIT_OPEN_SESSIONS", `You have ${open} open sessions, the most allowed. Close one with shadow_close_session first.`);
      if (this.usageBytes >= this.limits.maxStateBytes)
        throw new ShadowError("SHADOW_STORAGE_FULL", "Shadow's storage is full right now, so no new session can start. Try again later.");
      const full = this.accountFull(ownerKey, 4096);
      if (full) throw full;
      if (this.store.bump(ownerKey, "starts", this.today(), 1, this.limits.maxSessionStartsPerOwnerPerDay) === null)
        throw new ShadowError("SHADOW_LIMIT_SESSION_STARTS", `Your account has started ${this.limits.maxSessionStartsPerOwnerPerDay} sessions today, the most allowed per day. Try again tomorrow (UTC).`);
      const op = this.store.operator(ownerKey, now);
      const sessionId = randomUUID(), nonce = randomUUID();
      const meta: SessionMeta = {
        v: 1, sessionId, ownerKey, operatorId: op.operatorId, title, agents, network: this.network, state: "open",
        createdAt: now.toISOString(), closedAt: null, expiresAt: new Date(now.getTime() + this.limits.retentionMs).toISOString(),
        cap: randomBytes(16).toString("base64url"), nonce, startHash: startHashOf(op.operatorId, sessionId, nonce),
        seq: 0, head: null, eventsBytes: 0, agentSteps: 0, runs: [], checkpoint: null, outbox: [], anchors: [],
      };
      this.store.createSession(meta);
      this.usageBytes += 4096;
      const owned = this.ownerUsage.get(ownerKey);
      if (owned !== undefined) this.ownerUsage.set(ownerKey, owned + 4096);
      // Openers wait for the start marker, as the library's openSession does: its receipt goes into session.opened.
      return this.session(ownerKey, sessionId, async (m) => {
        const outcome = await this.anchorNetwork(ownerKey, m.sessionId, this.row("start", m.startHash, null), Date.now() + ANCHOR_BUDGET_MS);
        let receipt: Record<string, unknown> | null = null;
        let error: { errorKind: string; errorCode: string } | null = null;
        if (outcome.kind === "anchored") receipt = receiptPayload(m.sessionId, outcome.receipt);
        else if (outcome.kind === "pending") m.outbox.push(this.row("start", m.startHash, null, { state: "pending", ledgerId: outcome.ledgerId, submittedAt: outcome.submittedAt, attempts: 1 }));
        else {
          error = { errorKind: outcome.failure.kind, errorCode: outcome.failure.code };
          const ours = outcome.failure.code === "anchor_limit" || outcome.failure.code === "log_budget";
          m.outbox.push(this.row("start", m.startHash, null, { attempts: ours ? 0 : 1, lastErrorKind: outcome.failure.kind, lastErrorCode: outcome.failure.code }));
        }
        const opened = this.appendStep(m, "session.opened", "collector", this.openedPayload(m, receipt, error), {}, false);
        if (outcome.kind === "anchored") m.anchors.push({ marker: "start", seq: opened.body.seq, hash: m.startHash, count: null, ...anchorFields(outcome.receipt) });
        this.store.writeMeta(m);
        this.log("shadow_session_started", { sessionId: m.sessionId, agents: agents.length, startAnchor: outcome.kind });
        return {
          session_id: m.sessionId,
          title: m.title,
          status: "open",
          agents: m.agents,
          operator_id: m.operatorId,
          start_anchor: outcome.kind === "anchored"
            ? { status: "anchored", ledger_id: outcome.receipt.ledgerId, block: outcome.receipt.blockHeight, block_time: outcome.receipt.blockTime }
            : { status: "pending", note: "The start marker will be anchored with your next checkpoint." },
          expires_at: m.expiresAt,
          links: this.links(m, base),
          links_note: LINKS_NOTE,
          next: "Record each step with shadow_record, in order. Call shadow_close_session when the work is done.",
        };
      }, true);
    });
  }

  private agentsOf(v: unknown): { id: string; role: string | null }[] {
    if (v === undefined || v === null) return [{ id: "agent", role: null }];
    if (!Array.isArray(v) || v.length === 0) throw bad('agents must be a list like [{"id": "researcher", "role": "finds sources"}].');
    if (v.length > this.limits.maxAgents) throw new ShadowError("SHADOW_LIMIT_AGENTS", `A session declares at most ${this.limits.maxAgents} agents.`);
    const out: { id: string; role: string | null }[] = [];
    for (const a of v) {
      const id = isObj(a) ? a.id : a;
      if (typeof id !== "string" || !AGENT_ID.test(id) || id === "collector")
        throw bad('Each agent id is 1-64 letters, digits or . _ : @ -, starting with a letter or digit, and not "collector".');
      if (this.autoLog && redactText(id) !== id) throw bad(CREDENTIAL_AGENT);
      if (out.some((x) => x.id === id)) throw bad(`Agent "${id}" is listed twice.`);
      const roleText = isObj(a) && typeof a.role === "string" ? (this.autoLog ? redactText(a.role.slice(0, 1000)) : a.role) : "";
      const role = cleanText(roleText, 100) ? cleanText(roleText, 100) : null;
      out.push({ id, role });
    }
    return out;
  }

  async record(ownerId: string, input: { session_id?: unknown; agent?: unknown; kind?: unknown; content?: unknown; run_id?: unknown }) {
    const sessionId = sessionIdOf(input.session_id);
    if (typeof input.kind !== "string" || !(RECORD_KINDS as readonly string[]).includes(input.kind))
      throw bad(`kind must be one of ${RECORD_KINDS.join(", ")}.`);
    const kind = input.kind as RecordKind;
    if (typeof input.agent !== "string" || !input.agent) throw bad("Name the agent that took this step (one of the session's agents).");
    const agent = input.agent;
    let content = input.content;
    if (content === undefined) throw bad("content is required: a string, or JSON.");
    const size = Buffer.byteLength(typeof content === "string" ? content : JSON.stringify(content) ?? "");
    if (size > this.limits.maxContentBytes)
      throw new ShadowError("SHADOW_CONTENT_TOO_LARGE", `Content is ${size} bytes; the limit is ${this.limits.maxContentBytes}. Record a summary, or split it over several steps.`);
    if (!depthWithin(content, 48)) throw bad("Content is nested too deeply (more than 48 levels).");
    if (input.run_id !== undefined && input.run_id !== null && (typeof input.run_id !== "string" || !RUN_ID.test(input.run_id)))
      throw bad("run_id is 1-64 letters, digits or . _ : -, starting with a letter or digit.");
    const runInput = typeof input.run_id === "string" ? input.run_id : null;
    // With logging on by default, the same backstop as the log tools. Size and depth are checked above.
    if (this.autoLog) content = redactSecrets(content);
    return this.session(ownerKeyOf(ownerId), sessionId, (meta) => {
      if (meta.state === "closed") throw new ShadowError("SHADOW_SESSION_CLOSED", "This session is closed. Start a new session to record more.");
      if (!meta.agents.some((a) => a.id === agent))
        throw new ShadowError("SHADOW_UNKNOWN_AGENT", `"${agent}" is not one of this session's agents (${meta.agents.map((a) => a.id).join(", ")}).`);
      if (meta.agentSteps >= this.limits.maxStepsPerSession)
        throw new ShadowError("SHADOW_LIMIT_STEPS", `This session has ${meta.agentSteps} steps, the most allowed. Close it and start a new one.`);
      const full = this.accountFull(meta.ownerKey, size);
      if (full) throw full;
      // The disk brake: existing sessions can still close and anchor, but no longer grow.
      if (this.usageBytes >= this.limits.maxStateBytes * 1.25)
        throw new ShadowError("SHADOW_STORAGE_FULL", "Shadow's storage is full right now, so no more steps can be recorded. Close this session; its record is kept.");
      let spec;
      try {
        spec = stepFor(kind, content);
      } catch (e) {
        if (e instanceof RecordError) throw new ShadowError(e.code, e.message);
        throw bad(`${(e as Error).message}.`);
      }
      const runId = this.runFor(meta, kind, agent, runInput);
      const event = this.appendStep(meta, spec.kind, agent, spec.payload, { boundary: spec.boundary, agentRunId: runId }, true);
      this.store.writeMeta(meta);
      return { seq: event.body.seq, hash: event.hash, kind: spec.kind, run_id: runId };
    });
  }

  private runFor(meta: SessionMeta, kind: RecordKind, agent: string, runInput: string | null): string | null {
    if (kind === "task") {
      const runId = runInput ?? randomUUID();
      if (meta.runs.some((r) => r.id === runId)) throw new ShadowError("SHADOW_RUN_EXISTS", `Run ${runId} already exists in this session; use a new run_id.`);
      if (meta.runs.filter((r) => r.open).length >= this.limits.maxOpenRuns)
        throw new ShadowError("SHADOW_LIMIT_RUNS", `This session has ${this.limits.maxOpenRuns} open runs, the most allowed.`);
      return runId;
    }
    if (runInput) {
      const r = meta.runs.find((x) => x.id === runInput);
      if (!r || r.agent !== agent) throw new ShadowError("SHADOW_RUN_NOT_FOUND", `No run ${runInput} for "${agent}" in this session. A task step starts a run.`);
      if (!r.open) throw new ShadowError("SHADOW_RUN_ENDED", `Run ${runInput} has ended.`);
      return r.id;
    }
    // Without run_id, a step joins the agent's latest open run, if it has one.
    return [...meta.runs].reverse().find((r) => r.open && r.agent === agent)?.id ?? null;
  }

  // ---- automatic logging (SHADOW_AUTO_LOG) -------------------------------------------------------------------------

  /** The owner's logging setting; default on. A setting that cannot be read refuses logging rather than guessing. */
  loggingEnabled(ownerId: string): boolean {
    try {
      return !this.store.loggingOff(ownerKeyOf(ownerId));
    } catch {
      throw new ShadowError("SHADOW_UNAVAILABLE", "Clockchain can't read this account's logging setting right now, so nothing was logged. Do not show a logging footer.");
    }
  }

  setLogging(ownerId: string, enabled: boolean) {
    this.store.setLoggingOff(ownerKeyOf(ownerId), !enabled);
    this.log("shadow_logging_set", { enabled });
    return {
      logging: { enabled },
      message: enabled
        ? "Logging is on for this account. Steps are logged from now on, and a reply usually ends with show_user from the last result."
        : "Logging is off for this account. Do not log steps and do not show a logging footer until the person turns it back on.",
    };
  }

  /** Refuses shadow_record and the logging tools once the owner turned logging off. */
  assertLogging(ownerId: string): void {
    if (!this.loggingEnabled(ownerId)) throw loggingOff();
  }

  /** One step: appended and anchored in this call, with its own hash, and the block and ledger id of its own anchor. */
  async logStep(ownerId: string, input: { session_id?: unknown; title?: unknown; agent?: unknown; kind?: unknown; content?: unknown; run_id?: unknown }, base: string) {
    if (input.run_id !== undefined && input.run_id !== null && (typeof input.run_id !== "string" || !RUN_ID.test(input.run_id)))
      throw bad("run_id is 1-64 letters, digits or . _ : -, starting with a letter or digit.");
    const r = await this.logSteps(ownerId, { session_id: input.session_id, title: input.title, steps: [input], runInput: typeof input.run_id === "string" ? input.run_id : null, maxSteps: 1, table: input.kind === "message" || input.kind === "note" }, base);
    const step = r.steps[0];
    return {
      session_id: r.sessionId,
      seq: step.seq,
      hash: step.hash,
      kind: step.kind,
      ...(step.runId ? { run_id: step.runId } : {}),
      ...r.anchor,
      viewer: r.viewer,
      show_user: logFooter(r.meta, r.anchor, r.viewer, r.table),
      ...(r.started ? { note: NEW_SESSION_NOTE } : {}),
    };
  }

  /** The fallback: several steps in one call, sharing one anchor. */
  async logTurn(ownerId: string, input: { session_id?: unknown; title?: unknown; steps?: unknown }, base: string) {
    if (!Array.isArray(input.steps) || input.steps.length === 0) throw bad("steps must be a list of 1 or more steps.");
    const r = await this.logSteps(ownerId, { session_id: input.session_id, title: input.title, steps: input.steps as LogStepInput[], runInput: null, maxSteps: MAX_TURN_STEPS, table: true }, base);
    return {
      session_id: r.sessionId,
      shared_anchor: true,
      anchor_note: "These steps share one anchor: one block and one ledger record for the whole call, not one per step. shadow_log_step gives each step its own.",
      evidence: {
        logged: r.steps.map((s) => ({ seq: s.seq, kind: s.kind, hash: s.hash, summary: s.summary })),
        ...r.anchor,
        viewer: r.viewer,
      },
      show_user: logFooter(r.meta, r.anchor, r.viewer, r.table, r.steps.length),
      ...(r.started ? { note: NEW_SESSION_NOTE } : {}),
    };
  }

  private async logSteps(ownerId: string, input: { session_id?: unknown; title?: unknown; steps: LogStepInput[]; runInput: string | null; maxSteps: number; table: boolean }, base: string) {
    this.assertLogging(ownerId);
    if (input.steps.length > input.maxSteps)
      throw new ShadowError("SHADOW_LIMIT_TURN_STEPS", `One call logs at most ${input.maxSteps} steps; this one has ${input.steps.length}. Nothing was recorded. Split them over several calls.`);
    const many = input.maxSteps > 1;
    // Everything that can refuse a step's content comes first, so a refused call leaves no trace, not even a new session.
    const steps = input.steps.map((raw, i) => {
      try {
        return this.prepareStep(raw);
      } catch (e) {
        if (many && e instanceof ShadowError) throw new ShadowError(e.code, `Step ${i + 1}: ${e.message}`);
        throw e;
      }
    });
    const totalBytes = steps.reduce((n, s) => n + s.encodedBytes, 0);
    if (totalBytes > MAX_TURN_BYTES)
      throw new ShadowError("SHADOW_CONTENT_TOO_LARGE", `These steps hold ${totalBytes} bytes; one call takes at most ${MAX_TURN_BYTES}. Nothing was recorded. Split them over several calls.`);
    const ownerKey = ownerKeyOf(ownerId);
    const budgetEnd = Date.now() + ANCHOR_BUDGET_MS;
    let sessionId: string;
    let started = false;
    if (input.session_id === undefined || input.session_id === null || input.session_id === "") {
      const named = [...new Set(steps.map((s) => s.agent).filter((a): a is string => a !== null))];
      // Cut down before anything else looks at it: the title is the one field here with no other limit.
      const given = typeof input.title === "string" ? cleanText(redactText(input.title.slice(0, 1000)), 200) : "";
      const title = given || `Chat log, ${this.now().toISOString().slice(0, 16).replace("T", " ")} UTC`;
      sessionId = (await this.startSession(ownerId, { title, ...(named.length ? { agents: named.map((id) => ({ id })) } : {}) }, base)).session_id;
      started = true;
    } else {
      sessionId = sessionIdOf(input.session_id);
    }
    const made: { steps: LoggedStep[]; target: string | null; refused: { code: string; message: string } | null; turn: { rows: StepRow[]; earlier: number } } = { steps: [], target: null, refused: null, turn: { rows: [], earlier: 0 } };
    await this.session(ownerKey, sessionId, async (meta) => {
      if (meta.state === "closed") throw new ShadowError("SHADOW_SESSION_CLOSED", `This session is closed, so nothing was recorded. ${START_NEW}`);
      if (meta.agentSteps + steps.length > this.limits.maxStepsPerSession || meta.seq + steps.length + 3 > this.maxEvents)
        throw new ShadowError("SHADOW_LIMIT_STEPS", `This session has ${meta.agentSteps} steps and can't take ${steps.length} more, so nothing was recorded. ${START_NEW}`);
      // The last anchor is kept for shadow_close_session, so a full session can still anchor its final checkpoint.
      if (meta.anchors.length + meta.outbox.length >= this.limits.maxAnchorsPerSession - 1)
        throw new ShadowError("SHADOW_LIMIT_SESSION_ANCHORS", `This session has used its ${this.limits.maxAnchorsPerSession} anchors, so nothing was recorded. ${START_NEW}`);
      if (meta.eventsBytes + totalBytes + steps.length * 1024 + 8192 > this.agentEventsMax)
        throw new ShadowError("SHADOW_LIMIT_SESSION_SIZE", `This session is full (${Math.round(this.limits.maxSessionBytes / 1048576)} MB on disk), so nothing was recorded. ${START_NEW}`);
      const full = this.accountFull(meta.ownerKey, totalBytes);
      if (full) throw full;
      if (this.usageBytes >= this.limits.maxStateBytes * 1.25)
        throw new ShadowError("SHADOW_STORAGE_FULL", "Shadow's storage is full right now, so nothing was recorded. Say so in your reply; do not show a logging footer.");
      for (const s of steps) {
        const agent = s.agent ?? meta.agents[0].id;
        if (!meta.agents.some((a) => a.id === agent))
          throw new ShadowError("SHADOW_UNKNOWN_AGENT", `"${agent}" is not one of this session's agents (${meta.agents.map((a) => a.id).join(", ")}), so nothing was recorded. Use one of those, or leave agent out.`);
      }
      if (meta.runs.filter((r) => r.open).length + steps.filter((s) => s.kind === "task").length > this.limits.maxOpenRuns)
        throw new ShadowError("SHADOW_LIMIT_RUNS", `This session has too many open runs (${this.limits.maxOpenRuns} at most), so nothing was recorded. Use kind prompt for a later message from the person, or start a new session: ${START_NEW}`);
      try {
        for (const s of steps) {
          const agent = s.agent ?? meta.agents[0].id;
          const runId = this.runFor(meta, s.kind, agent, input.runInput);
          const event = this.appendStep(meta, s.spec.kind, agent, s.spec.payload, { boundary: s.spec.boundary, agentRunId: runId }, true);
          made.steps.push({ seq: event.body.seq, hash: event.hash, kind: s.kind, runId, summary: s.summary });
          // This call's own steps, in case the record can't be read back below.
          made.turn.rows = [...made.turn.rows, stepRow(event)].slice(-MAX_TURN_ROWS);
        }
      } finally {
        if (made.steps.length) this.store.writeMeta(meta);
      }
      // From here on the steps are recorded: whatever happens to the anchor is reported, never an error.
      try {
        const cp = await this.withEvents(meta, (events) => {
          if (input.table) made.turn = turnRows(events, made.steps[0].seq);
          return checkpointOver(meta, events, this.store.operator(ownerKey, this.now()).keys, this.now());
        });
        meta.checkpoint = cp;
        made.target = cp.hash;
        made.refused = this.queueCheckpoint(meta, cp);
        this.store.writeMeta(meta);
      } catch (e) {
        made.refused = { code: e instanceof ShadowError ? e.code : "SHADOW_INTERNAL", message: "The steps are recorded, but no checkpoint could be signed for them yet; the next call will cover them." };
      }
    });
    await this.drain(ownerKey, sessionId, { deadline: Math.max(budgetEnd, Date.now() + 2_000), stopOnFailure: true });
    return this.session(ownerKey, sessionId, (meta) => {
      const anchor = this.logAnchor(meta, made.target, made.refused);
      return { sessionId, started, steps: made.steps, anchor, table: input.table ? turnTable(meta, made.turn) : "", viewer: this.links(meta, base).viewer, meta: { agentSteps: meta.agentSteps, anchors: meta.anchors.map((a) => ({ blockHeight: a.blockHeight, ledgerId: a.ledgerId })) } };
    });
  }

  private prepareStep(raw: LogStepInput) {
    if (!isObj(raw)) throw bad("Each step is {kind, content} with an optional agent.");
    if (typeof raw.kind !== "string" || !(RECORD_KINDS as readonly string[]).includes(raw.kind)) throw bad(`kind must be one of ${RECORD_KINDS.join(", ")}.`);
    const kind = raw.kind as RecordKind;
    if (raw.content === undefined) throw bad("content is required: a string, or JSON.");
    const agent = raw.agent === undefined || raw.agent === null || raw.agent === "" ? null : raw.agent;
    if (agent !== null && (typeof agent !== "string" || !AGENT_ID.test(agent) || agent === "collector"))
      throw bad('agent is 1-64 letters, digits or . _ : @ -, starting with a letter or digit, and not "collector".');
    if (typeof agent === "string" && redactText(agent) !== agent) throw bad(CREDENTIAL_AGENT);
    const size = Buffer.byteLength(typeof raw.content === "string" ? raw.content : JSON.stringify(raw.content) ?? "");
    if (size > this.limits.maxContentBytes)
      throw new ShadowError("SHADOW_CONTENT_TOO_LARGE", `Content is ${size} bytes; the limit is ${this.limits.maxContentBytes}, and nothing was recorded. Record a summary, or split it over several steps.`);
    if (!depthWithin(raw.content, 48)) throw bad("Content is nested too deeply (more than 48 levels).");
    const content = redactSecrets(raw.content);
    let spec;
    try {
      spec = stepFor(kind, content);
    } catch (e) {
      if (e instanceof RecordError) throw new ShadowError(e.code, e.message);
      throw bad(`${(e as Error).message}.`);
    }
    return { kind, agent: agent as string | null, content, spec, encodedBytes: Buffer.byteLength(JSON.stringify(spec.payload) ?? ""), summary: stepSummary(kind, content) };
  }

  /** What became of the anchor for this call's checkpoint: a block and a ledger id only when they really exist. */
  private logAnchor(meta: SessionMeta, target: string | null, refused: { code: string; message: string } | null): LogAnchor {
    const none = { block_height: null, ledger_id: null, block_time: null, anchored_hash: null, covers_steps: null };
    const a = target ? meta.anchors.find((x) => x.hash === target) : undefined;
    if (a) return { block_height: a.blockHeight, ledger_id: a.ledgerId, block_time: a.blockTime, anchored_hash: a.hash, covers_steps: a.count, anchor_status: "anchored" };
    const row = target ? meta.outbox.find((x) => x.hash === target) : undefined;
    if (!row) return { ...none, anchor_status: "not_anchored", anchor_reason: refused?.message ?? "No anchor was sent for these steps." };
    if (row.state === "failed") return { ...none, anchor_status: "failed", anchor_reason: reasonOf(row) ?? "Clockchain did not accept it." };
    const limited = [row, ...meta.outbox].find((r) => r.lastErrorCode === "anchor_limit" || r.lastErrorCode === "log_budget");
    if (limited) return { ...none, anchor_status: "over_limit", anchor_reason: reasonOf(limited) ?? "An anchoring limit has been reached." };
    return { ...none, anchor_status: "pending", anchor_reason: reasonOf(row) ?? "Waiting to be sent to Clockchain." };
  }

  async checkpoint(ownerId: string, input: { session_id?: unknown }) {
    const sessionId = sessionIdOf(input.session_id);
    const ownerKey = ownerKeyOf(ownerId);
    const made: { target: string | null; refused: { code: string; message: string } | null } = { target: null, refused: null };
    await this.session(ownerKey, sessionId, async (meta) => {
      if (meta.state === "closed") return; // Only retries what is still owed.
      const cp = await this.withEvents(meta, (events) => checkpointOver(meta, events, this.store.operator(ownerKey, this.now()).keys, this.now()));
      meta.checkpoint = cp;
      made.target = cp.hash;
      made.refused = this.queueCheckpoint(meta, cp);
      this.store.writeMeta(meta);
    });
    await this.drain(ownerKey, sessionId);
    return this.session(ownerKey, sessionId, (meta) => ({
      session_id: sessionId,
      status: meta.state,
      ...(made.target ? { checkpoint: this.anchorView(meta, made.target, made.refused) } : { note: "The session is closed; anchors still owed were retried." }),
      pending_anchors: meta.outbox.map(pendingView),
      anchors_today: this.store.anchorsToday(ownerKey, this.today()),
      anchors_per_day: this.limits.maxAnchorsPerOwnerPerDay,
    }));
  }

  async close(ownerId: string, input: { session_id?: unknown; status?: unknown; person_messages?: unknown }, base: string) {
    const sessionId = sessionIdOf(input.session_id);
    const counted = this.autoLog && input.person_messages !== undefined && input.person_messages !== null ? input.person_messages : null;
    if (counted !== null && (typeof counted !== "number" || !Number.isSafeInteger(counted) || counted < 0 || counted > MAX_PERSON_MESSAGES))
      throw bad(`person_messages is a whole number from 0 to ${MAX_PERSON_MESSAGES}.`);
    if (input.status !== undefined && input.status !== null && !(RUN_STATUSES as readonly unknown[]).includes(input.status))
      throw bad(`status must be one of ${RUN_STATUSES.join(", ")}.`);
    const status = (input.status ?? null) as (typeof RUN_STATUSES)[number] | null;
    const ownerKey = ownerKeyOf(ownerId);
    const made: { target: string; refused: { code: string; message: string } | null } = { target: "", refused: null };
    await this.session(ownerKey, sessionId, async (meta) => {
      if (meta.state === "closed") throw new ShadowError("SHADOW_SESSION_CLOSED", "This session is already closed.");
      if (counted !== null) await this.recordCapture(meta, counted);
      // Session.close(): runs still open become gaps, unless the agent reports how they ended (status); then session.closed.
      for (const r of meta.runs.filter((x) => x.open)) {
        if (status) this.appendStep(meta, "execution.receipt", r.agent, { status, facts: {} }, { agentRunId: r.id }, false);
        else this.appendStep(meta, "coverage.gap", r.agent, { reason: clip("run still open when the session closed", 2000) }, { agentRunId: r.id }, false);
      }
      this.appendStep(meta, "session.closed", "collector", { events: meta.seq }, {}, false);
      meta.closedAt = this.now().toISOString();
      const cp = await this.withEvents(meta, (events) => checkpointOver(meta, events, this.store.operator(ownerKey, this.now()).keys, this.now()));
      meta.checkpoint = cp;
      made.target = cp.hash;
      made.refused = this.queueCheckpoint(meta, cp);
      this.store.writeMeta(meta);
    });
    await this.drain(ownerKey, sessionId);
    return this.session(ownerKey, sessionId, async (meta) => {
      const links = this.links(meta, base);
      const { pin, log } = await this.withEvents(meta, (events) => ({ pin: buildPin(meta, this.latest(meta, events)), log: this.autoLog ? sessionLog(meta, events) : null }));
      this.log("shadow_session_closed", { sessionId, steps: meta.seq, anchors: meta.anchors.length, pending: meta.outbox.length });
      return {
        ...(log ? { summary: sessionLogText(log, { max: MAX_SUMMARY_ROWS, rest: links.summary ?? links.viewer }), summary_note: "This summary is for the person, in full, as it is.", capture: meta.capture ?? null, capture_note: captureNote(meta) } : {}),
        session_id: sessionId,
        status: "closed",
        steps: meta.seq,
        final_checkpoint: this.anchorView(meta, made.target, made.refused),
        pin,
        links,
        links_note: LINKS_NOTE,
        share: "The viewer or packet link is for whoever should check this record; the pin goes by a different channel.",
      };
    });
  }

  /**
   * The assistant's count of the person's messages against the task and prompt steps logged, as a signed step, so the
   * comparison is inside the tamper-evident record. It joins no run, so it can't change whether a run counts as covered,
   * and so can't change the verifier's verdict. Its `capture` field can't come from a logged step: stepFor builds those.
   */
  private async recordCapture(meta: SessionMeta, reported: number): Promise<void> {
    const logged = await this.withEvents(meta, (events) => events.filter((e) => e.body.kind === "task.assigned" || e.body.kind === "agent.prompt").length);
    const capture = { person_messages_reported: reported, person_messages_logged: logged, missing: Math.max(0, reported - logged) };
    const { payload } = stepFor("note", `The assistant counted ${reported} messages from the person before the one asking to close; ${logged} are logged. This is the assistant's own count.`);
    this.appendStep(meta, "agent.message", meta.agents[0].id, { ...payload, capture }, { boundary: "transcript", agentRunId: null }, false);
    meta.agentSteps++;
    meta.capture = capture;
  }

  async getSession(ownerId: string, input: { session_id?: unknown }, base: string) {
    const sessionId = sessionIdOf(input.session_id);
    return this.session(ownerKeyOf(ownerId), sessionId, (meta) => this.withEvents(meta, (events) => {
      const pin = meta.state === "closed" ? buildPin(meta, this.latest(meta, events)) : null;
      return {
        session_id: meta.sessionId,
        title: meta.title,
        status: meta.state,
        agents: meta.agents,
        steps: meta.seq,
        recorded_steps: meta.agentSteps,
        open_runs: meta.state === "open" ? meta.runs.filter((r) => r.open).map((r) => ({ run_id: r.id, agent: r.agent })) : [],
        created_at: meta.createdAt,
        closed_at: meta.closedAt,
        expires_at: meta.expiresAt,
        anchors: meta.anchors.map(anchorView),
        pending_anchors: meta.outbox.map(pendingView),
        time_windows: windowsView(windows(events)),
        links: this.links(meta, base),
        links_note: LINKS_NOTE,
        ...(pin ? { pin } : { pin_note: "The pin is issued when the session is closed." }),
      };
    }));
  }

  async listSessions(ownerId: string) {
    const ownerKey = ownerKeyOf(ownerId);
    const now = this.now().getTime();
    const sessions: Record<string, unknown>[] = [];
    for (const id of this.store.sessionIds(ownerKey)) {
      try {
        const m = this.store.readMeta(ownerKey, id);
        if (m && Date.parse(m.expiresAt) > now)
          sessions.push({ session_id: m.sessionId, title: m.title, status: m.state, steps: m.seq, created_at: m.createdAt, expires_at: m.expiresAt });
      } catch {
        // Unreadable: left out.
      }
    }
    sessions.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    return { sessions, open: sessions.filter((s) => s.status === "open").length, limit_open: this.limits.maxOpenSessionsPerOwner, limit_total: this.limits.maxSessionsPerOwner };
  }

  async verify(ownerId: string, input: { session_id?: unknown }, base: string) {
    const sessionId = sessionIdOf(input.session_id);
    const ownerKey = ownerKeyOf(ownerId);
    // Online reads happen before the events are loaded, against what the metadata says landed.
    const ledgerIds = await this.session(ownerKey, sessionId, (meta) => meta.anchors.map((a) => a.ledgerId));
    let online: Awaited<ReturnType<typeof prefetchOnline>> | undefined;
    let onlineNote: string;
    let receipts: { checked: number; total: number } | undefined;
    if (ledgerIds.length > this.limits.onlineVerifyMaxReceipts) {
      onlineNote = `Checked offline: this session has ${ledgerIds.length} Clockchain receipts, more than the ${this.limits.onlineVerifyMaxReceipts} checked online here. Run shadow-verify packet.json --pin pin.json --online to confirm them all.`;
    } else {
      try {
        online = await prefetchOnline(this.ledger(), { network: this.network, referenceId: referenceId(sessionId), ledgerIds, timeoutMs: ONLINE_TIMEOUT_MS, concurrency: this.autoLog ? ONLINE_CONCURRENCY : 1 });
        onlineNote = "Checked online against the Clockchain ledger, from this server.";
        if (this.autoLog) {
          receipts = { checked: online.receiptsChecked, total: ledgerIds.length };
          if (receipts.checked < receipts.total) onlineNote = `Checked ${receipts.checked} of ${receipts.total} Clockchain receipts online in the time allowed; the rest were not checked, so witness stays indeterminate. Run shadow_verify again, or shadow-verify packet.json --pin pin.json --online.`;
        }
      } catch {
        onlineNote = "Checked offline: Clockchain could not be reached.";
      }
    }
    return this.session(ownerKey, sessionId, (meta) => this.withEvents(meta, async (events) => {
      const cp = this.latest(meta, events);
      const packet = buildPacket(meta, cp, events, this.network, this.now());
      const pin = buildPin(meta, cp);
      // Verified as a relying party would: strictly parsed from its JSON.
      // With logging on by default, a record that can't be confirmed on the ledger doesn't pass: witness decides too.
      const checked = await verifyPacket(parseStrict(JSON.stringify(packet)), { pin: parseStrict(JSON.stringify(pin)), online, ...(this.autoLog ? { requireOnline: true } : {}) });
      const report = this.autoLog ? ownPinReport(checked) : checked;
      return {
        session_id: sessionId,
        result: report.result,
        summary: report.summary,
        checks: report.checks,
        online: onlineNote,
        ...(receipts ? { receipts_checked_online: receipts.checked, receipts_total: receipts.total } : {}),
        interpretation: report.interpretation,
        ...(this.autoLog ? { capture: meta.capture ?? null, capture_note: captureNote(meta) } : {}),
        links: this.links(meta, base),
      };
    }));
  }

  // ---- public links (anyone with the capability) -------------------------------------------------------------------

  /**
   * A link's body, built at most once per (session, steps, checkpoint, queued checkpoints) and shared: every reader of
   * the same link gets the same Buffer, from a cache bounded in bytes, and concurrent first readers wait on one build.
   * So a crowd of readers costs one copy, not one per reader (security review: OOM from slow-reading link clients).
   */
  async linkBody(cap: string, kind: LinkKind): Promise<Buffer | undefined> {
    const target = this.store.resolveCap(cap);
    if (!target) return undefined;
    let meta: SessionMeta | undefined;
    try {
      meta = this.store.readMeta(target.ownerKey, target.sessionId);
    } catch {
      meta = undefined;
    }
    if (!meta || Date.parse(meta.expiresAt) <= this.now().getTime()) return undefined;
    const hit = this.linkCache.get(linkKey(kind, meta));
    if (hit) return hit;
    const flight = `${kind}:${meta.sessionId}:${meta.seq}`;
    const running = this.linkBuilds.get(flight);
    if (running) return running;
    const build = this.buildLink(target.ownerKey, target.sessionId, kind).finally(() => this.linkBuilds.delete(flight));
    this.linkBuilds.set(flight, build);
    return build;
  }

  private async buildLink(ownerKey: string, sessionId: string, kind: LinkKind): Promise<Buffer | undefined> {
    try {
      return await this.session(ownerKey, sessionId, (meta) => {
        const cached = this.linkCache.get(linkKey(kind, meta));
        if (cached) return cached;
        return this.withEvents(meta, async (events) => {
          if (kind === "log" || kind === "log-json") {
            const log = sessionLog(meta, events);
            // In JSON a title is a value, so without the backticks that mark a name in text.
            const body = Buffer.from(kind === "log" ? sessionLogText(log) : JSON.stringify({ ...log, steps: log.steps.map((s) => ({ ...s, title: s.title.replaceAll("`", "") })) }, null, 1));
            this.linkBuildCount++;
            this.linkCache.set(linkKey(kind, meta), body);
            return body;
          }
          const cp = this.latest(meta, events);
          const packet = buildPacket(meta, cp, events, this.network, this.now());
          const pin = buildPin(meta, cp);
          let body: Buffer;
          if (kind === "packet") {
            body = Buffer.from(JSON.stringify({
              packet, pin,
              verify: "Save packet and pin as packet.json and pin.json, then run: shadow-verify packet.json --pin pin.json --online. The pin is independent assurance only if it reached you separately from the packet.",
            }, null, 1));
          } else {
            const report = await verifyPacket(parseStrict(JSON.stringify(packet)), { pin });
            const html = hostedViewer(summarize(packet, ownPinReport(report), { packetFile: "packet.json", pinFile: "pin.json" }).html);
            body = Buffer.from(this.autoLog ? withStepAnchors(html.replace("<h2>What this record shows</h2>", () => `<h2>What this record shows</h2><p class="meta">${escHtml(captureNote(meta))}</p>`), events, meta.cap) : html);
          }
          this.linkBuildCount++;
          this.linkCache.set(linkKey(kind, meta), body);
          return body;
        });
      });
    } catch (e) {
      if (e instanceof ShadowError && e.code === "SHADOW_NOT_FOUND") return undefined;
      throw e;
    }
  }

  /** The evidence packet and its pin, as one JSON document. */
  async packetForCap(cap: string): Promise<string | undefined> {
    return (await this.linkBody(cap, "packet"))?.toString("utf8");
  }

  /** The library's static evidence summary (no scripts, no network), verified offline against its pin. */
  async summaryForCap(cap: string): Promise<string | undefined> {
    return (await this.linkBody(cap, "summary"))?.toString("utf8");
  }

  // ---- anchoring -----------------------------------------------------------------------------------------------------

  private today(): string {
    return this.now().toISOString().slice(0, 10);
  }

  private anchorNetwork(ownerKey: string, sessionId: string, row: OutboxRow, deadline: number): Promise<AnchorOutcome> {
    const day = this.today();
    const max = this.limits.maxAnchorsPerOwnerPerDay;
    let ledger: ShadowLedger;
    try {
      ledger = this.ledger();
    } catch {
      return Promise.resolve({ kind: "failed", failure: { kind: "Transient", code: "unavailable", retryAfterSeconds: null } });
    }
    return anchorHash({
      ledger, referenceId: referenceId(sessionId), hash: row.hash, label: row.kind === "start" ? START_LABEL : ANCHOR_LABEL,
      ledgerId: row.state === "pending" ? row.ledgerId : null, uncertain: row.attempts > 0, budget: this.budget(),
      reserve: () => {
        if (this.store.bumpAnchors(ownerKey, day, 1, max) === null) throw new AnchorLimitError();
      },
      refund: () => {
        this.store.bumpAnchors(ownerKey, day, -1, max);
      },
      waitMs: this.limits.anchorWaitMs, tries: 3, backoffMs: [500, 1500], sleep: this.sleep, deadline,
    });
  }

  /** Drains the session's outbox once; concurrent callers share the pass. Never holds the lock across the network. */
  private drain(ownerKey: string, sessionId: string, o: { deadline?: number; stopOnFailure?: boolean } = {}): Promise<void> {
    const key = `${ownerKey}/${sessionId}`;
    const running = this.drains.get(key);
    if (running) return running;
    const p = this.drainOnce(ownerKey, sessionId, o).finally(() => this.drains.delete(key));
    this.drains.set(key, p);
    return p;
  }

  private async drainOnce(ownerKey: string, sessionId: string, o: { deadline?: number; stopOnFailure?: boolean }): Promise<void> {
    const tried = new Set<string>();
    const deadline = o.deadline ?? Date.now() + ANCHOR_BUDGET_MS;
    for (;;) {
      if (Date.now() >= deadline) return; // What is left stays queued for the next call.
      const job = await this.session(ownerKey, sessionId, (meta) => {
        const row = meta.outbox.find((r) => r.state !== "failed" && !tried.has(r.id));
        if (!row) return null;
        // Never write to Clockchain a receipt the record has no room to keep.
        if (meta.seq + 2 > this.maxEvents || meta.eventsBytes + 64 * 1024 > this.eventsMax) {
          row.state = "failed";
          row.lastErrorKind = "Permanent";
          row.lastErrorCode = "session_full";
          this.store.writeMeta(meta);
          return null;
        }
        return { ...row };
      }).catch(() => null);
      if (!job) return;
      tried.add(job.id);
      const outcome = await this.anchorNetwork(ownerKey, sessionId, job, deadline);
      const halt = await this.session(ownerKey, sessionId, (meta) => this.applyOutcome(meta, job.id, outcome)).catch(() => true);
      // A step's call comes back quickly when Clockchain refuses: the rest stay queued for the next step.
      if (halt || (o.stopOnFailure && outcome.kind === "failed")) return;
    }
  }

  /** Records an anchoring outcome in the session (the library's drainOnce bookkeeping). Returns true to halt the pass. */
  private applyOutcome(meta: SessionMeta, rowId: string, outcome: AnchorOutcome): boolean {
    const row = meta.outbox.find((r) => r.id === rowId);
    if (!row) return false;
    let halt = false;
    if (outcome.kind === "anchored") {
      const receipt = receiptPayload(meta.sessionId, { ...outcome.receipt, submittedAt: outcome.receipt.submittedAt ?? row.submittedAt });
      const payload = row.kind === "start"
        ? { marker: "start", startHash: row.hash, ...receipt }
        : { marker: "checkpoint", checkpointHash: row.hash, checkpoint: row.body, ...receipt };
      const ev = this.appendStep(meta, "clockchain.anchored", "collector", payload, {}, false);
      meta.outbox = meta.outbox.filter((r) => r.id !== row.id);
      meta.anchors.push({ marker: row.kind, seq: ev.body.seq, hash: row.hash, count: row.body?.count ?? null, ...anchorFields({ ...outcome.receipt, submittedAt: receipt.submittedAt as string | null }) });
    } else if (outcome.kind === "pending") {
      row.state = "pending";
      row.ledgerId = outcome.ledgerId;
      row.submittedAt = outcome.submittedAt ?? row.submittedAt;
      row.attempts++;
    } else {
      const f = outcome.failure;
      row.lastErrorKind = f.kind;
      row.lastErrorCode = f.code;
      halt = f.kind === "Auth" || f.kind === "Credits";
      // Our own limits are not Clockchain failures: the row waits, and nothing goes into the record.
      if (f.code !== "anchor_limit" && f.code !== "log_budget") {
        row.attempts++;
        const failed = f.kind === "Permanent" || row.attempts >= MAX_PASSES;
        if (failed) row.state = "failed";
        if (meta.state === "open")
          this.appendStep(meta, "clockchain.error", "collector", {
            marker: row.kind, hash: row.hash, errorKind: f.kind, errorCode: f.code,
            outcome: failed ? "not anchored; later steps take their upper bound from the next anchor" : "will retry",
          }, {}, false);
      }
    }
    this.store.writeMeta(meta);
    this.log("shadow_anchor", { sessionId: meta.sessionId, marker: row.kind, outcome: outcome.kind, ...(outcome.kind === "failed" ? { code: outcome.failure.code } : {}) });
    return halt;
  }

  private anchorView(meta: SessionMeta, hash: string, refused: { code: string; message: string } | null) {
    const a = meta.anchors.find((x) => x.hash === hash);
    if (a) return { status: "anchored", checkpoint_hash: hash, covers_steps: a.count, ledger_id: a.ledgerId, block: a.blockHeight, block_time: a.blockTime, submitted_at: a.submittedAt };
    const r = meta.outbox.find((x) => x.hash === hash);
    if (r) return { status: r.state === "failed" ? "failed" : "pending", checkpoint_hash: hash, covers_steps: r.body?.count ?? null, ledger_id: r.ledgerId, reason: reasonOf(r), note: r.state === "failed" ? "Not anchored. The record is intact; later checkpoints still bound it." : "Signed and recorded; call shadow_checkpoint again later to anchor it." };
    if (refused) return { status: "not_anchored", checkpoint_hash: hash, covers_steps: meta.checkpoint?.body.count ?? null, code: refused.code, reason: refused.message };
    return { status: "not_anchored", checkpoint_hash: hash };
  }
}

// ---- views ------------------------------------------------------------------------------------------------------------

function anchorFields(r: { ledgerId: string; blockHeight: string | null; blockTime: string | null; submittedAt: string | null }) {
  return { ledgerId: r.ledgerId, blockHeight: r.blockHeight ?? "", blockTime: r.blockTime, submittedAt: r.submittedAt };
}

function anchorFrom(e: ShadowEvent): AnchorInfo | null {
  const p = e.body.payload as Record<string, any>;
  if (e.body.source.boundary !== "collector") return null;
  if (e.body.kind === "session.opened" && p.receipt?.ledgerId)
    return { marker: "start", seq: e.body.seq, hash: p.startHash, count: null, ledgerId: p.receipt.ledgerId, blockHeight: p.receipt.blockHeight ?? "", blockTime: p.receipt.blockTime ?? null, submittedAt: p.receipt.submittedAt ?? null };
  if (e.body.kind === "clockchain.anchored" && p.ledgerId)
    return {
      marker: p.marker === "start" ? "start" : "checkpoint", seq: e.body.seq, hash: p.marker === "start" ? p.startHash : p.checkpointHash,
      count: p.checkpoint?.count ?? null, ledgerId: p.ledgerId, blockHeight: p.blockHeight ?? "", blockTime: p.blockTime ?? null, submittedAt: p.submittedAt ?? null,
    };
  return null;
}

function reasonOf(r: OutboxRow): string | null {
  if (!r.lastErrorKind) return r.state === "pending" ? "Written to Clockchain; waiting for its block." : null;
  if (r.lastErrorCode === "anchor_limit") return "Today's anchor limit for your account is used up; it will be anchored on a later call.";
  if (r.lastErrorCode === "log_budget") return "The server's Clockchain write budget is used up; it will be anchored once it is raised.";
  return `Clockchain did not accept it (${r.lastErrorKind}, ${r.lastErrorCode}).`;
}

function anchorView(a: AnchorInfo) {
  return { marker: a.marker, step: a.seq, covers_steps: a.count, ledger_id: a.ledgerId, block: a.blockHeight, block_time: a.blockTime, submitted_at: a.submittedAt };
}

function pendingView(r: OutboxRow) {
  return { marker: r.kind, status: r.state, covers_steps: r.body?.count ?? null, attempts: r.attempts, ledger_id: r.ledgerId, reason: reasonOf(r) };
}

/** Time windows grouped into runs of consecutive steps that share their bounds. */
function windowsView(wins: Window[]) {
  const segments: { steps: string; after: string | null; before: string | null; before_block: string | null }[] = [];
  let start = 0;
  const key = (w: Window) => `${w.lower?.ledgerId ?? ""}|${w.lower?.time ?? ""}|${w.upper?.ledgerId ?? ""}|${w.upper?.time ?? ""}`;
  for (let i = 1; i <= wins.length; i++) {
    if (i < wins.length && key(wins[i]) === key(wins[start])) continue;
    const w = wins[start];
    segments.push({ steps: start === i - 1 ? `${w.seq}` : `${w.seq}-${wins[i - 1].seq}`, after: w.lower?.time ?? null, before: w.upper?.time ?? null, before_block: w.upper?.blockHeight ?? null });
    start = i;
  }
  return {
    total_steps: wins.length,
    steps_with_both_bounds: wins.filter((w) => w.lower && w.upper).length,
    segments: segments.slice(0, 50),
    ...(segments.length > 50 ? { more_segments: segments.length - 50 } : {}),
    note: "after = no earlier than a Clockchain receipt's submission time; before = existed by a checkpoint anchor's block time. Steps after the last anchor have no upper bound yet.",
  };
}
