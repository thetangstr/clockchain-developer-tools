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
import { declaredFields, declaredOf, declaredText, withDeclared, type DeclaredInput } from "./intent.js";
import { accountLevelNote, anchorsNow, deferredReason, effectiveLevel, finer, isLogLevel, levelNote, levelSetBy, recordedReason, type AnchorOutlook, type LevelSetBy, type LogLevel } from "./log-level.js";
import { windows, type Window } from "./lib/windows.js";
import type { Checkpoint, Network, Pin, ShadowEvent } from "./lib/types.js";
import { AgentKeyError, type AgentKeyBook } from "../agent-keys/book.js";
import { checkAgentKey, failedRecord, type KeyCheck } from "../agent-keys/check.js";
import { fileKey, StarterAnchors, type FilingLedger, type FilingResult } from "../agent-keys/filing.js";
import { META_MAX_BYTES, ShadowStore, isSessionId, ownerKeyOf, type AnchorBacklog, type AgentEntry, type AnchorInfo, type OutboxRow, type SessionMeta } from "./store.js";
import {
  ANCHOR_LABEL, RECORD_KINDS, RecordError, START_LABEL, VERSION, LIBRARY, advance, buildEvent, buildPacket, buildPin,
  agentOperatorId, checkpointBody, checkpointOver, receiptPayload, referenceId, refuseThinkTag, signingModeOf, startHashOf, stepFor, type RecordKind,
} from "./recorder.js";
import { fingerprint, verifySignature, type KeyProvider } from "./lib/keys.js";
import { AnchorLimitError, anchorHash, prefetchOnline, type AnchorOutcome, type Failure, type ShadowLedger } from "./ledger.js";

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
  /** An open session with no new step for this long closes by itself. 0: never. */
  idleCloseMs: number;
  /** The Starter allowance: anchors per UTC day shared by every agent-key owner (ak:), key filings included. Accounts never draw on it. */
  maxStarterAnchorsPerDay: number;
  /** Each address's share of the Starter allowance per UTC day: an agent's address is its root key's source (agent-keys/book.ts). */
  maxStarterAnchorsPerSourcePerDay: number;
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
  idleCloseMs: 0,
  maxStarterAnchorsPerDay: 2000,
  maxStarterAnchorsPerSourcePerDay: 200,
};

/** An agent key nobody used (agent-keys/book.ts forgetUnused) is removed this long after it was first seen. */
export const UNUSED_AGENT_KEY_MS = 30 * 24 * 60 * 60_000;

const RUN_STATUSES = ["succeeded", "failed", "cancelled", "timed_out", "unknown"] as const;
const AGENT_KINDS = new Set(["task.assigned", "agent.prompt", "agent.message", "agent.tool.call", "agent.tool.result", "artifact.created"]);
const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$/;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const MAX_OUTBOX = 20;
/** Rows the ledger won't confirm or deny, kept on purpose: each holds a checkpoint body, a few KB, in the metadata. */
const MAX_PARKED = 40;
/** The metadata stops taking rows this far below its limit, so a close and its reads always fit. */
const META_ROOM = 64 * 1024;
const MAX_PASSES = 10;
/** A closed session's row that keeps failing waits this many sweep intervals at most between tries. */
const MAX_RETRY_WAIT_INTERVALS = 6;
const COLLECTOR_STEP_HEADROOM = 500;
const ONLINE_TIMEOUT_MS = 20_000;
const LINKS_NOTE = "Anyone with these links can read the whole record until it is deleted, 30 days after the session started, unless the person deletes it sooner or revokes the links first (shadow_delete_session, shadow_revoke_links).";
const LINKS_REVOKED_NOTE = "The person revoked this session's links, so none exist. The record itself is still kept until it is deleted.";
const LEDGER_STAYS = "Its fingerprints (hashes) stay on the Clockchain ledger and can't be removed. They hold no content.";
const COPIES_STAY = "Anyone who already saved a copy keeps it.";
/** How long one call may spend anchoring before it reports what is still pending. */
const ANCHOR_BUDGET_MS = 25_000;
/** Readers at once when checking a session's receipts online. */
const ONLINE_CONCURRENCY = 8;
/** shadow_log_turn, the fallback: steps and bytes per call (a request's body is capped at about 1 MB). */
const MAX_TURN_STEPS = 100;
const MAX_TURN_BYTES = 900 * 1024;
const CREDENTIAL_AGENT = "An agent id can't hold a key or token, and nothing was recorded. Use a plain name, or leave agent out.";
const MAX_IDLE_CLOSES_PER_PASS = 200;
const IDLE_AT_LIMIT_MS = 60 * 60_000;
const START_NEW = "Call again without session_id to start a new session; keep logging there.";
const NEW_SESSION_NOTE = "This session_id goes with every later step in this conversation. The viewer reads \"indeterminate\" until the session is closed and its anchors land; shadow_close_session and shadow_verify are for when the person asks to finish or verify.";
/** Our own limits on anchors: a row they stop waits for a later call, unspent. */
const OWN_LIMITS = new Set(["anchor_limit", "log_budget", "starter_limit", "starter_source_limit"]);
/** Codes a row waits under without counting a try or writing an error into the record: our limits, and its agent key being filed first. */
const WAITING_CODES = new Set([...OWN_LIMITS, "key_filing"]);
/** What holds every row of an agent's session at once: its key not yet filed, or the Starter allowance (or its address's share) used up. */
const AGENT_HOLDS = new Set(["key_filing", "starter_limit", "starter_source_limit"]);
const STARTER_USED_UP = "Today's free allowance for new agents is used up. Try again tomorrow (UTC), or sign in to a Clockchain account.";
const STARTER_SHARE_USED_UP = "Agents from this address have used their share of today's Starter allowance. Try again tomorrow (UTC), or sign in to a Clockchain account.";
const FILING_FIRST = "Filing this agent's key on Clockchain first.";
/** What happens to an anchor held by the agent's key or the Starter allowance: the hourly pass sends it when it can. */
const HELD_NOTE = "Shadow anchors it by itself once the allowance has room again; you don't need to call again.";
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
        Partial<Pick<ShadowLimits, "maxAnchorsPerOwnerPerDay" | "maxAnchorsPerSession" | "onlineVerifyMaxReceipts" | "maxStarterAnchorsPerDay" | "maxStarterAnchorsPerSourcePerDay">>;
      linkConcurrency: number;
      /** Logging on by default is available on some endpoint (SHADOW_AUTO_LOG=1 or SHADOW_PREVIEW_AUTO_LOG=1): its limits and viewer table apply. */
      autoLog?: true;
      /** SHADOW_AUTO_LOG=1: /shadow/mcp and /shadow/chat/mcp log by default. Never on a listed server. */
      autoLogOnMainPaths?: true;
      /** SHADOW_PREVIEW_AUTO_LOG=1: the hand-added /shadow/preview/* endpoints exist, and log by default. */
      previewAutoLog?: true;
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
export const AUTO_LOG_DEFAULTS = { idleCloseHours: 24, anchorsPerDay: 400, anchorsPerSession: 300, logStepsPerMinute: 90, accountBytes: 5 * 1024 * 1024 } as const;
/** meta.anchors keeps about 260 bytes per anchor, and the metadata file holds at most META_MAX_BYTES. */
const MAX_ANCHORS_PER_SESSION = 1500;

/**
 * SHADOW_ENABLED=1 turns hosted Shadow on; SHADOW_STATE_DIR (default /app/state/shadow) is where it keeps records.
 * SHADOW_MAX_BYTES, SHADOW_ACCOUNT_MAX_BYTES, SHADOW_SESSION_STARTS_PER_DAY and SHADOW_LINK_CONCURRENCY set the caps
 * ("" or unset = SHADOW_ENV_DEFAULTS); anything but a positive whole number is a `problem`.
 *
 * Either logging flag below turns on automatic logging, which anchors every step. Its defaults are AUTO_LOG_DEFAULTS: anchors
 * per account per day and per session (SHADOW_ANCHORS_PER_DAY, SHADOW_ANCHORS_PER_SESSION; without a flag, 60 and 100 unless
 * set), shadow_log_step calls per account per minute (SHADOW_LOG_STEPS_PER_MIN), and a smaller SHADOW_ACCOUNT_MAX_BYTES.
 * Without a flag and those settings the result is exactly what it was before them. SHADOW_STARTER_ANCHORS_PER_DAY (default
 * 2000) is the Starter allowance every agent-key owner shares, and SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY (default 200) is
 * each address's share of it.
 *
 * Automatic logging is per endpoint. SHADOW_AUTO_LOG=1 puts it on /shadow/mcp and /shadow/chat/mcp, the paths directories
 * list, so a listed server must not set it. SHADOW_PREVIEW_AUTO_LOG=1 adds /shadow/preview/mcp and /shadow/preview/chat/mcp,
 * for people who add the URL by hand, and leaves the other two alone: there the person asks, chat by chat. What is per
 * account or per server follows either flag on every endpoint, since one account's sessions are reachable from all of them:
 * the limits above, redaction in shadow_record and session starts, and shadow_verify needing the ledger for a pass.
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
  if (!["", "testnet", "mainnet"].includes((env.SHADOW_NETWORK ?? "").trim())) problems.push("SHADOW_NETWORK must be testnet or mainnet");
  // The delegated writer is an email address today, and a ledger entry can't be taken back.
  if ((env.SHADOW_NETWORK ?? "").trim() === "mainnet" && !((env.SHADOW_LEDGER_CLIENT_ID ?? "").trim() && (env.SHADOW_LEDGER_WALLET_ID ?? "").trim())) problems.push("SHADOW_NETWORK=mainnet needs SHADOW_LEDGER_CLIENT_ID and SHADOW_LEDGER_WALLET_ID");
  const autoLogOnMainPaths = (env.SHADOW_AUTO_LOG ?? "").trim() === "1";
  const previewAutoLog = (env.SHADOW_PREVIEW_AUTO_LOG ?? "").trim() === "1";
  const autoLog = autoLogOnMainPaths || previewAutoLog;
  const anchorsPerDay = whole("SHADOW_ANCHORS_PER_DAY", autoLog ? AUTO_LOG_DEFAULTS.anchorsPerDay : DEFAULT_SHADOW_LIMITS.maxAnchorsPerOwnerPerDay);
  const anchorsPerSession = whole("SHADOW_ANCHORS_PER_SESSION", autoLog ? AUTO_LOG_DEFAULTS.anchorsPerSession : DEFAULT_SHADOW_LIMITS.maxAnchorsPerSession);
  if (anchorsPerSession > MAX_ANCHORS_PER_SESSION) problems.push(`SHADOW_ANCHORS_PER_SESSION must be at most ${MAX_ANCHORS_PER_SESSION}`);
  const starterPerDay = whole("SHADOW_STARTER_ANCHORS_PER_DAY", DEFAULT_SHADOW_LIMITS.maxStarterAnchorsPerDay);
  const starterPerSource = whole("SHADOW_STARTER_ANCHORS_PER_SOURCE_PER_DAY", DEFAULT_SHADOW_LIMITS.maxStarterAnchorsPerSourcePerDay);
  // Shadow's own writer on the ledger. Unset: the delegated CLOCKCHAIN_CLIENT_ID, as before. It goes on a public ledger, so
  // no email; and it must differ from the delegated one, or /mcp's writes would land under it.
  const ledgerClient = (env.SHADOW_LEDGER_CLIENT_ID ?? "").trim();
  const ledgerWallet = (env.SHADOW_LEDGER_WALLET_ID ?? "").trim();
  if (Boolean(ledgerClient) !== Boolean(ledgerWallet)) problems.push("SHADOW_LEDGER_CLIENT_ID and SHADOW_LEDGER_WALLET_ID must be set together");
  for (const [name, value, delegated] of [["SHADOW_LEDGER_CLIENT_ID", ledgerClient, env.CLOCKCHAIN_CLIENT_ID], ["SHADOW_LEDGER_WALLET_ID", ledgerWallet, env.CLOCKCHAIN_WALLET_ID]] as const) {
    if (!value) continue;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) problems.push(`${name} must be letters, digits and . _ - (it goes on a public ledger, so not an email address)`);
    if (value.toLowerCase() === (delegated ?? "").trim().toLowerCase()) problems.push(`${name} must differ from the delegated client and wallet`);
  }
  // With logging on by default nobody asks to close, so sessions would pile up open: viewers stuck on "indeterminate", and
  // the account refused at its open-session limit. "off" or 0 keeps them open until they expire.
  const idleRaw = (env.SHADOW_IDLE_CLOSE_HOURS ?? "").trim();
  const idleHours = idleRaw === "off" || idleRaw === "0" ? 0 : whole("SHADOW_IDLE_CLOSE_HOURS", autoLog ? AUTO_LOG_DEFAULTS.idleCloseHours : 0);
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
      ...(starterPerDay !== DEFAULT_SHADOW_LIMITS.maxStarterAnchorsPerDay ? { maxStarterAnchorsPerDay: starterPerDay } : {}),
      ...(starterPerSource !== DEFAULT_SHADOW_LIMITS.maxStarterAnchorsPerSourcePerDay ? { maxStarterAnchorsPerSourcePerDay: starterPerSource } : {}),
      // Every receipt is checked online, however many a session has (a start marker plus the session's anchors).
      ...(autoLog ? { onlineVerifyMaxReceipts: anchorsPerSession + 1 } : {}),
      ...(idleHours ? { idleCloseMs: idleHours * 3_600_000 } : {}),
    },
    linkConcurrency: whole("SHADOW_LINK_CONCURRENCY", SHADOW_ENV_DEFAULTS.linkConcurrency),
    ...(autoLog ? { autoLog: true as const, logStepsPerMinute } : {}),
    ...(autoLogOnMainPaths ? { autoLogOnMainPaths: true as const } : {}),
    ...(previewAutoLog ? { previewAutoLog: true as const } : {}),
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
  /** Drops every body whose key matches: a deleted record must not stay in memory, even unreachable. */
  deleteWhere(match: (key: string) => boolean): void {
    for (const [k, v] of this.items) {
      if (!match(k)) continue;
      this.items.delete(k);
      this.bytes -= v.length;
    }
  }
  get size(): number {
    return this.bytes;
  }
}

/**
 * What a link body depends on: the steps (append-only, so the count), the checkpoint, the queued checkpoints and how they
 * stand, and for an agent the book's entry for its signing key (`keyStamp`), so a filing or cancellation that lands later shows.
 */
type LinkKind = "packet" | "summary" | "log" | "log-json";

function linkKey(kind: LinkKind, meta: SessionMeta, keyStamp: string): string {
  const cp = meta.checkpoint;
  const queued = meta.outbox.filter((r) => r.kind === "checkpoint").map((r) => `${r.hash}/${r.state}/${r.lastErrorCode ?? ""}`).join(",");
  return `${kind}:${meta.sessionId}:${meta.seq}:${cp?.hash ?? "-"}:${cp?.body.count ?? -1}:${queued}:${keyStamp}`;
}

// ---- input checks -----------------------------------------------------------------------------------------------------

const notFound = () => new ShadowError("SHADOW_NOT_FOUND", "No session with that id belongs to you. Call shadow_list_sessions to see yours.");
const bad = (message: string) => new ShadowError("SHADOW_BAD_INPUT", message);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** The level a caller asked for: null when none was given, refused when it isn't one. */
function levelInput(v: unknown): LogLevel | null {
  if (v === undefined || v === null || v === "") return null;
  if (!isLogLevel(v)) throw bad("log_level must be step, turn or milestone.");
  return v;
}

/** An agent's own short claim about itself: redacted and cleaned, and empty when it isn't text. */
const reported = (v: unknown, max: number): string => (typeof v === "string" ? cleanText(redactText(v.slice(0, 1000)), max) : "");

/** Refuses hidden reasoning in a field an agent fills in, on its whole text: fields are cut to length only after this. */
function refuseHidden(v: unknown, field: string): void {
  if (typeof v !== "string") return;
  try {
    refuseThinkTag(v, field);
  } catch (e) {
    if (e instanceof RecordError) throw new ShadowError(e.code, e.message);
    throw e;
  }
}

/** A note step, with the same refusals as any recorded step. */
function noteSpec(text: string) {
  try {
    return stepFor("note", text);
  } catch (e) {
    if (e instanceof RecordError) throw new ShadowError(e.code, e.message);
    throw bad(`${(e as Error).message}.`);
  }
}

/** The purpose and accountable owner given for a session's agents, for the hashed record. Null when none was given. */
function agentProfileNote(agents: AgentEntry[]): string | null {
  const lines = agents.filter((a) => a.purpose || a.accountableOwner).map((a) =>
    `Agent ${a.id}: purpose ${a.purpose ?? NOT_PROVIDED}; accountable owner ${a.accountableOwner ?? NOT_PROVIDED}.`);
  return lines.length ? `As reported by the agent. ${lines.join(" ")}` : null;
}

/**
 * A server note's facts, in the step's hashed payload. stepFor builds every agent step's payload from fixed keys, and nothing
 * an agent sends becomes a top-level key, so no step kind can carry this field: that is what tells a server note from an
 * agent's note with the same words. Readers take the session's level and each agent's purpose and owner from here, never
 * from the metadata. All of it stays on this server: only hashes go to the ledger.
 */
type ReportedAgent = { agent: string; purpose?: string; accountable_owner?: string };
type ServerNote = {
  kind: "session_start" | "level_change";
  log_level: LogLevel;
  set_by?: LevelSetBy;
  account_level?: LogLevel | null;
  previous_account_level?: LogLevel | null;
  agents?: ReportedAgent[];
};

/** The note that opens a session, when it has anything to say. Built from the metadata only before the first step is shown. */
function startNote(meta: Pick<SessionMeta, "agents" | "logLevel" | "logLevelBy">): { text: string; note: ServerNote } | null {
  const level = meta.logLevel ?? "step";
  const by = meta.logLevelBy ?? null;
  const profile = agentProfileNote(meta.agents);
  if (level === "step" && !profile) return null;
  const agents = meta.agents.filter((a) => a.purpose || a.accountableOwner).map((a) => ({ agent: a.id, ...(a.purpose ? { purpose: a.purpose } : {}), ...(a.accountableOwner ? { accountable_owner: a.accountableOwner } : {}) }));
  return {
    text: [level !== "step" && by ? levelNote(level, by) : "", profile ?? ""].filter(Boolean).join(" "),
    note: { kind: "session_start", log_level: level, ...(level !== "step" && by ? { set_by: by } : {}), ...(agents.length ? { agents } : {}) },
  };
}

/** A step's server note, or null for anything an agent or the collector wrote. */
function serverNoteOf(e: ShadowEvent): Record<string, unknown> | null {
  const p = e.body.payload as { note?: unknown; server_note?: unknown } | null | undefined;
  return e.body.kind === "agent.message" && e.body.source.boundary === "transcript" && p?.note === true && isObj(p.server_note) ? p.server_note : null;
}

/** A step an agent recorded: not the server's own notes, and not the count it writes at close. */
const isRecordedStep = (e: ShadowEvent) => AGENT_KINDS.has(e.body.kind) && !serverNoteOf(e) && !(e.body.payload as { capture?: unknown }).capture;

type LevelChange = { seq: number; from: LogLevel; to: LogLevel; set_by: LevelSetBy | null; account_level: LogLevel | null };

/** What the hashed record says about a session's level and agents. A record with no server notes is at step, with nothing reported. */
function sessionFacts(events: ShadowEvent[]) {
  let level: LogLevel = "step";
  let setBy: LevelSetBy | null = null;
  let accountLevel: LogLevel | null | undefined;
  const changes: LevelChange[] = [];
  const agents = new Map<string, ReportedAgent>();
  for (const e of events) {
    const note = serverNoteOf(e);
    if (!note) continue;
    const next: LogLevel = isLogLevel(note.log_level) ? note.log_level : level;
    setBy = levelSetBy(note.set_by) ?? setBy;
    if ("account_level" in note) accountLevel = isLogLevel(note.account_level) ? note.account_level : null;
    if (note.kind === "level_change") changes.push({ seq: e.body.seq, from: level, to: next, set_by: setBy, account_level: accountLevel ?? null });
    level = next;
    for (const a of Array.isArray(note.agents) ? note.agents : []) if (isObj(a) && typeof a.agent === "string") agents.set(a.agent, a as ReportedAgent);
  }
  return { level, setBy, accountLevel, changes, agents };
}
type SessionFacts = ReturnType<typeof sessionFacts>;

/** One change, in server-made words. */
const changeText = (c: LevelChange) => c.from === c.to
  ? `at step ${c.seq} the account's level became ${c.account_level ?? "none"}, and this session stayed at ${c.to}`
  : `at step ${c.seq} this session moved from ${c.from} to ${c.to}${c.set_by ? `, set by the ${c.set_by}` : ""}`;
const changesText = (changes: LevelChange[]) => (changes.length ? ` During this session: ${changes.map(changeText).join("; ")}.` : "");

/** The steps that say how a session ended. An agent didn't record them, but "every run ended and it closed" rests on them. */
const CLOSING_KINDS = new Set(["execution.receipt", "coverage.gap", "session.closed"]);

export type Anchoring = { recorded_steps: number; anchored_steps: number; unanchored_steps: number; closing_steps: number; closing_unanchored: number; reason: string };
const anchoredOf = (a: Anchoring) => `${a.anchored_steps} of ${a.recorded_steps} recorded steps ${a.anchored_steps === 1 ? "has" : "have"} a checkpoint with a Clockchain receipt`;
const anchoringCounts = (a: Anchoring) => `${anchoredOf(a)}${a.unanchored_steps ? `, and ${a.unanchored_steps} ${a.unanchored_steps === 1 ? "does" : "do"} not` : ""}.${a.closing_unanchored ? " The session's ending has no such checkpoint, so how it ended isn't anchored." : ""}`;

/**
 * How many steps an agent recorded, and how many of those a checkpoint with a Clockchain receipt covers, from the record;
 * and the same for the steps that say how it ended. Server notes and receipts aren't counted. The vendored verifier sees none
 * of this, because its checks are about the record's integrity, so a record can pass them with most of it never anchored.
 */
function anchoringOf(meta: SessionMeta, events: ShadowEvent[]): Anchoring {
  const steps = events.filter(isRecordedStep);
  let covered = 0;
  for (const e of events) {
    const p = e.body.payload as { marker?: unknown; blockHeight?: unknown; checkpoint?: { count?: unknown } | null };
    if (e.body.kind !== "clockchain.anchored" || e.body.source.boundary !== "collector" || p.marker !== "checkpoint" || !p.blockHeight) continue;
    const count = p.checkpoint?.count;
    if (typeof count === "number" && Number.isSafeInteger(count)) covered = Math.max(covered, count);
  }
  const left = steps.filter((e) => e.body.seq > covered);
  const closing = events.filter((e) => CLOSING_KINDS.has(e.body.kind));
  const ending = closing.filter((e) => e.body.seq > covered);
  const counts = { recorded_steps: steps.length, anchored_steps: steps.length - left.length, unanchored_steps: left.length, closing_steps: closing.length, closing_unanchored: ending.length };
  if (!left.length && !ending.length) {
    const what = steps.length ? `All ${steps.length} recorded ${steps.length === 1 ? "step is" : "steps are"}` : closing.length ? "No steps were recorded, and the session's ending is" : "";
    return { ...counts, reason: what ? `${what}${steps.length && closing.length ? ", with the session's ending," : ""} covered by a checkpoint with a Clockchain receipt.` : "No steps have been recorded." };
  }
  // Only what is true of these steps: a waiting checkpoint can reach some of them and not the rest.
  const owed = [...left, ...ending];
  const rows = meta.outbox.filter((r) => r.kind === "checkpoint" && (r.body?.count ?? 0) > covered);
  const reach = (list: OutboxRow[]) => Math.max(0, ...list.map((r) => r.body?.count ?? 0));
  const live = rows.filter((r) => r.state !== "failed"), lost = rows.filter((r) => r.state === "failed");
  const waiting = owed.filter((e) => e.body.seq <= reach(live)).length;
  const failed = owed.filter((e) => e.body.seq > reach(live) && e.body.seq <= reach(lost)).length;
  const nothing = owed.length - waiting - failed;
  const liveRow = live.find((r) => (r.body?.count ?? 0) === reach(live)), lostRow = lost.find((r) => (r.body?.count ?? 0) === reach(lost));
  return {
    ...counts,
    reason: [
      left.length ? `${left.length} of ${steps.length} recorded ${steps.length === 1 ? "step has" : "steps have"} no checkpoint with a Clockchain receipt.` : "",
      ending.length ? `The session's ending (${ending.length} ${ending.length === 1 ? "step" : "steps"}: how runs ended, and the close) has none${left.length ? " either" : ""}.` : "",
      waiting && liveRow ? `A checkpoint still waiting covers ${waiting} of these ${owed.length}: ${reasonOf(liveRow) ?? "It is waiting to go to Clockchain."}` : "",
      failed && lostRow ? `A checkpoint that was not anchored covers ${failed} of these ${owed.length}: ${reasonOf(lostRow) ?? "Clockchain did not accept it."}` : "",
      nothing ? `${nothing} of these ${owed.length} ${nothing === 1 ? "has" : "have"} nothing on its way${meta.state === "open" ? " yet" : ", and this session is closed"}.` : "",
    ].filter(Boolean).join(" "),
  };
}

/** Whether a closed session's ending has no checkpoint at all: past the furthest one, anchored or queued, there is more than receipts. */
function finalOwed(meta: SessionMeta): boolean {
  if (meta.state !== "closed") return false;
  const top = Math.max(0, ...meta.anchors.map((a) => a.count ?? 0), ...meta.outbox.filter((r) => r.kind === "checkpoint").map((r) => r.body?.count ?? 0));
  return meta.seq - top > meta.anchors.filter((a) => a.seq > top).length;
}

/**
 * The next row to send. Oldest first, except on a closed session: there the close's row covers everything, so it goes first,
 * and older unpaid rows wait, because once it lands they aren't worth an anchor (see supersede). A row already written costs
 * nothing to follow up. A row backing off is passed over, so it holds up nothing behind it, unless `now` is null: a person asked.
 * `held` is the hourly pass on an open session that waits on its agent's key or the Starter allowance: it sends only the start
 * marker and the latest checkpoint, and only if a hold or nothing yet stopped them, so it can't use up a row's tries in an
 * outage nobody is watching, or spend a new day's allowance on checkpoints the latest one covers.
 */
function nextRow(meta: SessionMeta, tried: Set<string>, now: number | null, held = false): OutboxRow | undefined {
  const live = meta.outbox.filter((r) => r.state !== "failed");
  const due = (r: OutboxRow) => !tried.has(r.id) && (now === null || !r.nextTryAt || Date.parse(r.nextTryAt) <= now);
  if (held && meta.state !== "closed") {
    return live.find((r) => due(r) && heldSends(meta, r) && (r.lastErrorCode === null || AGENT_HOLDS.has(r.lastErrorCode)));
  }
  if (meta.state !== "closed") return live.find(due);
  const checkpoints = live.filter((r) => r.kind === "checkpoint").sort((a, b) => (b.body?.count ?? 0) - (a.body?.count ?? 0));
  return [...checkpoints.slice(0, 1), ...live.filter((r) => r.kind === "start"), ...checkpoints.slice(1).filter((r) => r.ledgerId)].find(due);
}

/**
 * Whether the hourly pass on an open session would send `r`: the start marker, or the checkpoint reaching furthest, anchored
 * ones included. Once that lands, older checkpoints aren't sent; it covers them.
 */
function heldSends(meta: SessionMeta, r: OutboxRow): boolean {
  if (r.kind === "start") return true;
  const top = Math.max(0, ...meta.anchors.map((x) => x.count ?? 0), ...meta.outbox.filter((x) => x.kind === "checkpoint" && x.state !== "failed").map((x) => x.body?.count ?? 0));
  return r.kind === "checkpoint" && (r.body?.count ?? 0) === top;
}

/**
 * Rows a person's retry of a closed session can bring back: gave up on anything but a permanent refusal, and reaching past what
 * is already anchored. One that reaches no further would cost an anchor to add nothing, and change a good pin.
 */
function revivable(meta: SessionMeta): OutboxRow[] {
  const covered = Math.max(0, ...meta.anchors.map((a) => a.count ?? 0));
  return meta.outbox.filter((r) => r.state === "failed" && r.lastErrorKind !== "Permanent" && (r.body?.count ?? 0) > covered);
}

function revive(meta: SessionMeta): boolean {
  const rows = revivable(meta);
  for (const r of rows) r.state = "queued";
  return rows.length > 0;
}

/**
 * The verifier's report with the anchoring counts in it. Its own checks stay as they are; a pass becomes indeterminate if any
 * recorded step, or the session's ending, has no anchored checkpoint, and fail and indeterminate keep their result and gain the counts.
 */
function withAnchoring<T extends { result: "pass" | "fail" | "indeterminate"; exitCode: 0 | 1 | 2; summary: string; indeterminate: string[]; checks: { name: string; status: string; reason: string }[] }>(report: T, a: Anchoring): T {
  if (!a.unanchored_steps && !a.closing_unanchored) return report;
  const counts = anchoringCounts(a);
  return {
    ...report,
    ...(report.result === "pass" ? { result: "indeterminate" as const, exitCode: 2 as const } : {}),
    summary: report.result === "pass" ? `No check failed, but not established: ${counts}` : `${report.summary} ${counts}`,
    indeterminate: [...report.indeterminate, "anchoring"],
    checks: [...report.checks, { name: "anchoring", status: "indeterminate", reason: a.reason }],
  };
}

/**
 * An agent's key verdict deciding the result: a record its key doesn't stand behind fails, saying why in the verdict's words,
 * and one whose key isn't filed yet, or can't be checked, is at most indeterminate. Every other verdict leaves it as is: record_failed
 * already fails, and witnessed and legacy are as computed.
 */
function withKeyVerdict<T extends { result: "pass" | "fail" | "indeterminate"; exitCode: 0 | 1 | 2; summary: string; failed: string[]; indeterminate: string[]; checks: { name: string; status: string; reason: string }[] }>(report: T, key: KeyCheck): T {
  if (key.verdict === "not_from_agent" || key.verdict === "key_revoked_before" || key.verdict === "key_filed_after")
    return { ...report, result: "fail", exitCode: 1, summary: key.text, failed: [...report.failed, "agent_key"], checks: [...report.checks, { name: "agent_key", status: "fail", reason: key.text }] };
  if (key.verdict === "key_not_filed" || key.verdict === "key_check_unavailable")
    return {
      ...report,
      ...(report.result === "pass" ? { result: "indeterminate" as const, exitCode: 2 as const, summary: key.text } : {}),
      indeterminate: [...report.indeterminate, "agent_key"],
      checks: [...report.checks, { name: "agent_key", status: "indeterminate", reason: key.text }],
    };
  return report;
}

/**
 * Whether the anchoring counts decide the result, not only sit beside it. With logging on by default they always do. On a listed
 * connection the person chooses when to anchor, so a partly anchored record keeps the verifier's result; but one with nothing
 * on the ledger at all doesn't pass, whether its close failed or hasn't landed yet: no receipt says anything about it.
 */
const anchoringDecides = (autoLog: boolean, a: Anchoring) => autoLog || (!a.anchored_steps && (a.unanchored_steps > 0 || a.closing_unanchored > 0));

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

const UNREADABLE_SETTING = "Clockchain can't read this account's logging setting right now, so nothing was logged. Do not show a logging footer. If it stays this way, ask the person whether to set the account's level, which resets the setting.";

const loggingOff = () => new ShadowError("LOGGING_OFF", "Logging is off for this Clockchain account. Nothing was recorded. Do not log this step and do not show a logging footer. If the person asks to turn logging back on, call clockchain_logging {enabled: true}.");

// ---- automatic logging: results ----------------------------------------------------------------------------------

type LogStepInput = { agent?: unknown; kind?: unknown; content?: unknown } & DeclaredInput;
type LoggedStep = { seq: number; hash: string; kind: RecordKind; runId: string | null; summary: string; declared: ReturnType<typeof declaredFields> };
type LogAnchor = {
  block_height: string | null; ledger_id: string | null; block_time: string | null; anchored_hash: string | null; covers_steps: number | null;
  anchor_status: "anchored" | "pending" | "failed" | "over_limit" | "not_anchored" | "deferred"; anchor_reason?: string;
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

/** One step as the tables and summaries show it: its kind, a short title and what it declares, never its content. */
type StepRow = { seq: number; kind: string; title: string; hash: string; declared: ReturnType<typeof declaredFields>; declaredNote: string };

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
  const server = serverNoteOf(e) !== null;
  const [kind, title] =
    e.body.kind === "task.assigned" ? ["task", "the person's request"]
      : e.body.kind === "agent.prompt" ? ["prompt", "the person's message"]
        : e.body.kind === "agent.message" ? (p.capture ? ["note", "count of the person's messages"] : server ? ["note", "server's note"] : p.note === true ? ["note", "agent's note"] : ["message", "message shown"])
          : e.body.kind === "agent.tool.call" ? ["tool_call", shownName(p.tool, "a tool")]
            : e.body.kind === "agent.tool.result" ? ["tool_result", `${shownName(p.tool, "a tool")}${p.isError === true ? " (error)" : ""}`]
              : ["file", shownName(typeof p.path === "string" ? p.path.split(/[\\/]/).pop() : undefined, "a file")];
  const declared = declaredOf(e.body.payload);
  return { seq: e.body.seq, kind, title, hash: e.hash, declared: declaredFields(declared), declaredNote: declaredText(declared) };
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
    return `| ${r.kind}: ${r.title}${r.declaredNote ? ` (${r.declaredNote})` : ""} | \`${bareHash(r.hash).slice(0, 12)}\` | ${anchored} |`;
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
  if (meta.closedIdle) return "This session closed by itself after no new steps, so nobody counted the person's messages, and this record can't say whether any turn is missing.";
  if (!c) return "No count of the person's messages was given when this session closed, so this record can't say whether any turn is missing.";
  const reported = `${c.person_messages_reported} ${c.person_messages_reported === 1 ? "message" : "messages"} from the person`;
  const own = "That is the assistant's own count, and this server can't see a call that was blocked before it arrived.";
  if (c.missing > 0) return `${reported}, ${c.person_messages_logged} logged: at least ${c.missing} ${c.missing === 1 ? "turn is" : "turns are"} missing from this record. ${own}`;
  const closing = c.person_messages_logged > c.person_messages_reported ? " (the closing request can be one of them)" : "";
  return `${reported}, ${c.person_messages_logged} logged${closing}: no turn shows as missing. ${own} It also doesn't show that every step within a turn was logged.`;
}

/** The whole session as hashes and metadata, from its own record. No step content; the only values a caller supplies are the declared types, which are checked. */
function sessionLog(meta: SessionMeta, events: ShadowEvent[]) {
  const cover = coverage(meta);
  const facts = sessionFacts(events);
  const agentStep = new Set(events.filter(isRecordedStep).map((e) => e.body.seq));
  const steps = events.filter((e) => AGENT_KINDS.has(e.body.kind)).map(stepRow).map((r) => {
    const { anchor: a, status } = cover(r.seq);
    return { seq: r.seq, kind: r.kind, title: r.title, ...r.declared, ...(r.declaredNote ? { declared_note: r.declaredNote } : {}), step_hash: r.hash, status, ledger_hash: a?.hash ?? null, block: a?.blockHeight ?? null, ledger_id: a?.ledgerId ?? null };
  });
  // The list shows the server's notes too; the totals count what agents recorded.
  const recorded = steps.filter((s) => agentStep.has(s.seq));
  const anchored = recorded.filter((s) => s.status === "anchored");
  // Every record this session has on the ledger, as the footer counts them: its start and closing anchors too.
  const onLedger = meta.anchors.filter((a) => a.blockHeight);
  const blocks = blockSpan(onLedger);
  return {
    session_id: meta.sessionId,
    status: meta.state,
    log_level: facts.level,
    log_level_changes: facts.changes,
    anchoring: anchoringOf(meta, events),
    expires_at: meta.expiresAt,
    totals: {
      steps: recorded.length, anchored: anchored.length, pending: recorded.filter((s) => s.status === "pending").length, not_anchored: recorded.filter((s) => s.status === "not_anchored").length,
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
function sessionLogText(log: ReturnType<typeof sessionLog>, cap?: { max: number; rest: string | null }): string {
  const t = log.totals;
  const shown = cap ? log.steps.slice(0, cap.max) : log.steps;
  const lines = shown.map((s, i) => {
    const ledger = s.status === "anchored" ? `Ledger hash \`${cell(s.ledger_hash)}\`. Block ${cell(s.block)}. Ledger ID \`${cell(s.ledger_id)}\`.` : s.status === "pending" ? "Ledger hash pending. Block pending. Ledger ID pending." : "Not anchored, so no ledger hash, block or ledger ID.";
    return `${i + 1}. ${s.kind}: ${s.title}${s.declared_note ? ` (${s.declared_note})` : ""}. Step hash \`${s.step_hash}\`. ${ledger}`;
  });
  const blocks = t.first_block === null ? "Nothing on Clockchain yet." : `On Clockchain: first block ${cell(t.first_block)}, last block ${cell(t.last_block)}, ${t.ledger_records} ledger ${t.ledger_records === 1 ? "record" : "records"}, counting any start or closing anchor.`;
  return [
    "**Clockchain Shadow: everything logged in this session**",
    log.capture_note,
    log.log_level === "step" && !log.log_level_changes.length ? "" : `Logging level: ${log.log_level}. Each anchor covers every step up to it.${changesText(log.log_level_changes)}`,
    `Session \`${log.session_id}\`, ${log.status}. ${t.steps} ${t.steps === 1 ? "step" : "steps"}: ${t.anchored} anchored, ${t.pending} pending${t.not_anchored ? `, ${t.not_anchored} not anchored` : ""}. ${blocks}`,
    log.anchoring.unanchored_steps || log.anchoring.closing_unanchored ? log.anchoring.reason : "",
    lines.join("\n"),
    ...(cap && log.steps.length > shown.length ? [`Showing the first ${shown.length} of ${log.steps.length} steps. ${cap.rest ? `The rest are at ${cap.rest}` : "This session's links were revoked, so the rest have no link."}`] : []),
    LEDGER_HASH_NOTE,
  ].filter(Boolean).join("\n\n") + "\n";
}

/** The footer to end a reply with: only what the record really holds, in server-made values (no step content). */
function logFooter(meta: { agentSteps: number; anchors: { blockHeight: string; ledgerId: string }[]; logLevel: LogLevel | null; levelChanged: boolean }, anchor: LogAnchor, viewer: string | null, table: string, turnSteps?: number): string {
  const count = (n: number) => `${n} ${n === 1 ? "step" : "steps"}`;
  const span = blockSpan(meta.anchors);
  const latest = meta.anchors.at(-1);
  const parts: string[] = [];
  if (turnSteps !== undefined) {
    parts.push(anchor.anchor_status === "anchored" || anchor.anchor_status === "pending"
      ? `**Clockchain Shadow:** ${count(turnSteps)} logged in this reply under one shared anchor, not one per step (${count(meta.agentSteps)} so far).`
      : `**Clockchain Shadow:** ${count(turnSteps)} logged in this reply, not anchored so far (${count(meta.agentSteps)} so far).`);
    if (anchor.anchor_status === "anchored") parts.push(`Shared anchor: block ${anchor.block_height}, ledger ID \`${anchor.ledger_id}\`.`);
  } else {
    parts.push(`**Clockchain Shadow:** ${count(meta.agentSteps)} logged so far.`);
    if (span.first !== null) parts.push(`First block ${span.first}, last block ${span.last}.`);
    if (latest) parts.push(`Latest ledger ID: \`${latest.ledgerId}\`.`);
  }
  if (meta.logLevel && (meta.logLevel !== "step" || meta.levelChanged)) parts.push(`Logging level: ${meta.logLevel}.`);
  parts.push(viewer ? `Viewer: ${viewer}` : "Viewer link revoked.");
  const lines = ["---", ...(table ? [table] : []), parts.join(" ")];
  if (anchor.anchor_status !== "anchored") {
    const one = turnSteps === undefined;
    const said = {
      pending: one ? "its anchor is still pending" : "their anchor is still pending",
      over_limit: "an anchoring limit has been reached",
      failed: one ? "its anchor failed" : "their anchor failed",
      not_anchored: one ? "it has no anchor so far" : "they have no anchor so far",
      deferred: one ? "it has no anchor so far" : "they have no anchor so far",
    }[anchor.anchor_status];
    lines.push(`${one ? "The latest step is" : "These steps are"} recorded, but ${said}, so ${one ? "it has" : "they have"} no block or ledger ID. ${anchor.anchor_reason ?? ""}`.trim());
  }
  lines.push("Logging is on. Saying 'stop logging' turns it off.");
  return lines.join("\n\n");
}

/**
 * The hosted viewer checks a packet against the pin this same server made, so its checks aren't independent. The
 * library's summary, which is vendored and unchanged, is written for a pin that reached the reader separately: here the
 * report says whose pin it was, and {@link hostedViewer} replaces its "Proven" tag. An agent's checkpoint isn't the
 * server's to sign, so for an agent (`agentLine` not undefined) a passing trust check reads its key verdict when that
 * verdict agrees with a pass (a string), and otherwise {@link AGENT_PIN} (null): this server built that pin too.
 */
function ownPinReport<T extends { summary: string; checks: { name: string; status: string; reason: string }[] }>(report: T, agentLine?: string | null): T {
  return {
    ...report,
    // "Captured" would claim more than the verifier can see: it knows the runs in the record, not the work outside it.
    summary: report.summary.replace("the supplied pin", "this server's own pin").replace("every run was captured", "every recorded run has an ending"),
    checks: report.checks.map((c) =>
      c.name === "trust" && c.status === "pass" ? { ...c, reason: agentLine === null ? AGENT_PIN : agentLine ?? "Matches the pin from this server. That pin isn't independent: it shows the record is what this server signed, not that this server is honest." }
        : c.name === "time" ? { ...c, reason: c.reason.replace("with a single validator they are only as good as its clock", "with a single-operator gateway they are only as good as its clock") }
          : c),
  };
}

const AGENT_PIN = "Matches the pin from this server for the agent's checkpoint; that pin isn't independent.";

const OWN_PIN_NOTE = `<p class="meta">The pin behind this page came from this server, so these checks aren't independent. For an independent check, run the command at the end of this page with a pin you received separately.</p>`;

/**
 * The summary page with "Proven" (which step content can't produce: it is escaped) saying what was really checked: what
 * the server signed, or for an agent's checkpoint, which the server didn't sign, the signing key. `keyLine` (an agent's
 * or a witnessed record's key verdict) is the first line under the title; a legacy record's page is as before.
 */
function hostedViewer(html: string, keyLine: KeyCheck | null, agent: boolean): string {
  const tag = agent ? "Matches the signing key" : "Matches what the server signed";
  return html
    .replace("<h1>Shadow evidence summary</h1>\n", (h) => (keyLine ? `${h}<p><b>${escHtml(keyLine.text)}</b></p>` : h))
    .replaceAll("<b>Proven:</b>", `<b>${tag}:</b>`)
    .replaceAll('<td class="tag">Proven</td>', `<td class="tag">${tag}</td>`)
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
    return `<tr><td>${escHtml(e.body.seq)}</td><td>${escHtml(e.body.kind)}</td><td><code>${escHtml(e.hash)}</code></td><td>${p ? `<code>${escHtml(p.checkpointHash)}</code>` : "not anchored"}</td><td>${p ? escHtml(p.blockHeight) : "not anchored"}</td><td>${p ? `<code>${escHtml(p.ledgerId)}</code>` : "none"}</td></tr>`;
  }).join("");
  const table = `<h2>Steps and their anchors</h2><p class="meta">Each anchor is a checkpoint over every step up to it. Steps with the same ledger ID share that anchor, whether or not they were logged in one call. A ledger lookup returns the ledger hash, not the step's own. <a href="${cap}/summary">Summary of every step</a> (<a href="${cap}/summary?format=json">JSON</a>).</p><div class="scroll"><table><tr><th>#</th><th>Step</th><th>Hash</th><th>Ledger hash</th><th>Block</th><th>Ledger ID</th></tr>${rows}</table></div>\n`;
  // Step content is escaped on the page, so this heading can only be the library's own.
  const at = html.indexOf("<h2>Clockchain receipts");
  return at < 0 ? html : html.slice(0, at) + table + html.slice(at);
}

const anchoringCaveat = (a: Anchoring) => `This command doesn't check anchoring, offline or online, so it can pass a record with steps no anchored checkpoint covers. This record: ${anchoringCounts(a)}`;
const ANCHORING_FIELD_NOTE = "The anchoring field beside the packet is this server's own count and isn't signed. It can be recounted from the packet's events: the clockchain.anchored steps say how many steps each receipt covers.";

const NOT_PROVIDED = "Not provided";
/** An agent as a reader sees it. Its purpose and owner come from the hashed record, so `reported` is what `facts.agents` holds. */
const agentView = (a: AgentEntry, reported: Pick<ReportedAgent, "purpose" | "accountable_owner"> | undefined) => ({ id: a.id, role: a.role, purpose: reported?.purpose ?? NOT_PROVIDED, accountable_owner: reported?.accountable_owner ?? NOT_PROVIDED });

/** The session's logging level and who acts in it, as reported, above what the record shows. Every value is escaped. */
function withSessionDetails(html: string, meta: SessionMeta, facts: SessionFacts, anchoring: Anchoring, pinNote: string | null): string {
  const rows = meta.agents.map((a) => agentView(a, facts.agents.get(a.id))).map((a) => `<tr><td>${escHtml(a.id)}</td><td>${escHtml(a.purpose)}</td><td>${escHtml(a.accountable_owner)}</td></tr>`).join("");
  const details = `<h2>Session details</h2><p class="meta">Logging level: ${escHtml(facts.level)}.${escHtml(changesText(facts.changes))} Purpose and accountable owner are what the agent reported; this record doesn't show they are true.</p><p class="meta">Anchoring: ${escHtml(anchoredOf(anchoring))}. ${escHtml(anchoring.reason)}</p>${pinNote ? `<p class="meta">${escHtml(pinNote)}</p>` : ""}<table><tr><th>Agent ID</th><th>Purpose</th><th>Accountable owner</th></tr>${rows}</table>`;
  return html.replace("<h2>What this record shows</h2>", () => `${details}<h2>What this record shows</h2>`);
}

/** Says beside the verify command what it can't see. Step content is escaped on the page, so this sentence can only be the library's. */
function withAnchoringCaveat(html: string, a: Anchoring): string {
  return html.replace("Exit code 0 is pass, 2 indeterminate, 1 fail.</p>", () => `Exit code 0 is pass, 2 indeterminate, 1 fail.</p><p class="meta">${escHtml(anchoringCaveat(a))}</p>`);
}

const NOTHING_SIGNED = "The agent has not signed a checkpoint of this record yet, so none of its steps are signed by the agent and there is nothing to verify. The agent calls shadow_checkpoint for the hash to sign, then shadow_sign_checkpoint.";

/**
 * Steps recorded after an agent's last signed checkpoint, which are in no checkpoint. Clockchain's receipts are left out of
 * the count: one for the checkpoint itself always lands after it.
 */
const unsignedCount = (after: ShadowEvent[]) => after.filter((e) => !e.body.kind.startsWith("clockchain.")).length;

/** The sentence for those steps, ending with where they are missing from ("on this page", "in what was verified"). */
const unsignedText = (n: number, missingFrom: string) =>
  `${n} ${n === 1 ? "step was" : "steps were"} recorded after the last checkpoint the agent signed. ${n === 1 ? "It is" : "They are"} not signed by the agent, so ${n === 1 ? "it is" : "they are"} not ${missingFrom}.`;

/** Says on the viewer what an agent's signed checkpoint leaves out. */
function withUnsignedTail(html: string, after: ShadowEvent[]): string {
  const n = unsignedCount(after);
  if (!n) return html;
  return html.replace("<h2>What this record shows</h2>", () => `<p class="meta">${escHtml(unsignedText(n, "on this page"))}</p><h2>What this record shows</h2>`);
}

/**
 * Marks the server's own steps in the library's timeline, which prints every note alike. The mark is markup, and step content
 * is escaped on the page, so an agent's note can use the same words and still not read as one.
 */
function withServerSteps(html: string, events: ShadowEvent[]): string {
  const from = html.indexOf("<h2>Timeline</h2>"), to = html.indexOf("<h2>Clockchain receipts");
  if (from < 0 || to < from) return html;
  let timeline = html.slice(from, to);
  for (const e of events) {
    if (!AGENT_KINDS.has(e.body.kind) || isRecordedStep(e)) continue;
    const row = `<tr><td>${e.body.seq}</td><td>${escHtml(e.body.actor)}</td><td>`;
    timeline = timeline.replace(row, () => `${row}<b>Server's note.</b> `);
  }
  return html.slice(0, from) + timeline + html.slice(to);
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
  /** SHADOW_WITNESS_KEY_FILE: Clockchain's single published key, which signs signed-in accounts' checkpoints. Unset: a key per owner, as before. */
  witness?: KeyProvider;
  /** MCP_AGENT_KEYS=1: the public book of agents' keys (the one the token endpoint uses), which checks an agent's own checkpoint signatures. */
  agentKeys?: AgentKeyBook;
};

type Links = { viewer: string | null; packet: string | null; summary?: string };
type Refusal = { code: string; message: string };
/** A close's final checkpoint: the one queued for Clockchain, or for an agent the hash it is to sign (`sign`, also the target). */
type FinalCheckpoint = { target: string; refused: Refusal | null; sign?: string };

const SIGN_NOTE = "Sign this hash with your key and call shadow_sign_checkpoint.";
/**
 * The hash for the agent to sign, with the step count and head (the last step's hash) it covers, so the agent can compare
 * them with the steps it recorded before it signs. A step someone else appended with its token changes them.
 */
const signView = (meta: SessionMeta, hash: string) => {
  const body = meta.awaitingSignature?.hash === hash ? meta.awaitingSignature.body : undefined;
  return { hash, ...(body ? { count: body.count, head: body.head } : {}), note: SIGN_NOTE };
};
const AGENT_SIGNS = "The steps are recorded. This agent signs its own checkpoints, so none was made here: call shadow_checkpoint for the hash to sign, then shadow_sign_checkpoint.";
const NOT_AGENT_OWNER = () => new ShadowError("not_agent_owner", "Only the agent that owns this session can sign its checkpoints, with an active key of its own. Sign in again with your current key.");
const AGENT_OWNER = /^ak:([0-9a-f]{64})$/;

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
  private readonly witness: boolean;
  /** The fingerprint of Clockchain's published witness key, when there is one. */
  private readonly witnessKey: string | undefined;
  private readonly agentKeys: AgentKeyBook | undefined;
  /** The Starter allowance agent-key owners share; only with the book. */
  private readonly starterAnchors: StarterAnchors | undefined;
  private readonly locks = new KeyedMutex();
  private readonly heavy = new Gate(32);
  private readonly drains = new Map<string, Promise<void>>();
  private readonly eventsMax: number;
  private readonly agentEventsMax: number;
  private readonly maxEvents: number;
  private usageBytes = 0;
  private lastSweepMs: number | undefined;
  /** Bytes per owner, computed on first use and kept current by appends; the sweep starts it afresh. */
  private readonly ownerUsage = new Map<string, number>();
  private readonly linkCache: ByteLru;
  private readonly linkBuilds = new Map<string, Promise<Buffer | undefined>>();
  /** Link bodies built (not served from the cache), for tests and logs. */
  linkBuildCount = 0;
  private timer: NodeJS.Timeout | undefined;
  private idlePassRunning = false;
  /** Accounts being deleted, or deleted since this process started: nothing new starts under them. Their tokens stop at the end of the delete. */
  private readonly deletedOwners = new Set<string>();

  constructor(o: ServiceOptions) {
    this.store = new ShadowStore(o.stateDir, o.witness);
    this.witness = o.witness !== undefined;
    this.witnessKey = o.witness ? fingerprint(o.witness.publicKey()) : undefined;
    this.agentKeys = o.agentKeys;
    this.limits = { ...DEFAULT_SHADOW_LIMITS, ...(o.limits ?? {}) };
    this.starterAnchors = o.agentKeys ? new StarterAnchors({ stateDir: o.stateDir, max: this.limits.maxStarterAnchorsPerDay, perSource: this.limits.maxStarterAnchorsPerSourcePerDay, today: () => this.today() }) : undefined;
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

  /** The start-up retention sweep, then one every sweepIntervalMs. With the witness key, first every owner's held key moves out. */
  start(): void {
    try {
      const held = this.store.migrateHeldKeys(this.now());
      if (held.migrated || held.failed || held.damaged) this.log("shadow_held_keys_migrated", { owners: held.migrated, failed: held.failed, damaged: held.damaged });
    } catch (e) {
      this.log("shadow_held_keys_migrate_failed", { error: (e as Error).name });
    }
    this.sweep();
    this.timer = setInterval(() => {
      try {
        this.sweep();
      } catch (e) {
        this.log("shadow_sweep_failed", { error: (e as Error).name });
      }
      void this.closeIdle();
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
    this.lastSweepMs = this.now().getTime();
    this.ownerUsage.clear();
    this.log("shadow_sweep", { removed: r.removed, bytes: r.bytes });
    if (this.agentKeys) {
      try {
        const keys = this.agentKeys.forgetUnused({
          firstSeenBefore: new Date(this.now().getTime() - UNUSED_AGENT_KEY_MS),
          inUse: (fp) => this.store.hasOwner(ownerKeyOf(`ak:${fp}`)),
        });
        if (keys > 0) this.log("agent_keys_forgotten", { keys });
      } catch (e) {
        this.log("agent_keys_forget_failed", { error: (e as Error).name });
      }
    }
    return r;
  }

  /**
   * Closes open sessions with no new step for idleCloseMs: a final checkpoint, anchored, as if the person had closed them.
   * Capped per pass, so a backlog after a long stop can't spend a day's anchors at once; the next pass takes the rest.
   * Not at start-up, so a restart can't close a session someone is coming back to before they can reach it. Nobody returns
   * to a closed session, so the pass also retries the anchors closed sessions still owe, within the same limits, and those of
   * open agent sessions held by the Starter allowance or a key filing once there is room (see heldWithRoom and nextRow).
   */
  async closeIdle(): Promise<number> {
    if (this.idlePassRunning) return 0;
    this.idlePassRunning = true;
    let closed = 0;
    try {
      const now = this.now().getTime();
      // Without idle closing the pass still retries what closed sessions owe: nobody comes back to a closed session.
      const cutoff = this.limits.idleCloseMs ? now - this.limits.idleCloseMs : -Infinity;
      const { idle, owed, held } = await this.store.idleScan(cutoff, now, MAX_IDLE_CLOSES_PER_PASS, this.heldWithRoom());
      for (const s of owed) await this.drain(s.ownerKey, s.sessionId, { stopOnFailure: true }).catch((e) => this.log("shadow_idle_close_failed", { sessionId: s.sessionId, error: (e as Error).name }));
      for (const s of held) await this.drain(s.ownerKey, s.sessionId, { stopOnFailure: true, held: true }).catch((e) => this.log("shadow_idle_close_failed", { sessionId: s.sessionId, error: (e as Error).name }));
      for (const s of idle) {
        try {
          if (!(await this.finishIdle(s.ownerKey, s.sessionId, cutoff))) continue;
          closed++;
          await this.drain(s.ownerKey, s.sessionId);
        } catch (e) {
          this.log("shadow_idle_close_failed", { sessionId: s.sessionId, error: (e as Error).name });
        }
      }
    } catch (e) {
      this.log("shadow_idle_close_failed", { error: (e as Error).name });
    } finally {
      this.idlePassRunning = false;
    }
    if (closed) this.log("shadow_idle_closed", { closed });
    return closed;
  }

  /**
   * For the hourly pass: whether an open session waits only on its agent's key or the Starter allowance, and the allowance
   * (its address's share included) has room now, so a session can't take a turn just to be refused. Asks once per address.
   */
  private heldWithRoom(): (meta: SessionMeta) => boolean {
    const room = new Map<string, boolean>();
    return (meta) => {
      const rows = meta.outbox.filter((r) => r.state === "queued" && r.lastErrorCode !== null && AGENT_HOLDS.has(r.lastErrorCode));
      // Only when the held pass would send something: older checkpoints the latest anchor covers stay queued, and never count.
      if (!rows.length || !this.starterAnchors || !nextRow(meta, new Set(), this.now().getTime(), true)) return false;
      const source = this.sourceOf(meta.agentRoot);
      const k = source ?? "";
      if (!room.has(k)) {
        try {
          this.starterAnchors.check(source);
          room.set(k, true);
        } catch {
          room.set(k, false);
        }
      }
      return room.get(k)!;
    };
  }

  /** Closes one session, unless a step has landed since the cutoff. Its open runs become gaps that say why. */
  private finishIdle(ownerKey: string, sessionId: string, cutoff: number): Promise<boolean> {
    return this.session(ownerKey, sessionId, async (meta) => {
      if (meta.state !== "open" || (meta.lastStepAt && Date.parse(meta.lastStepAt) > cutoff)) return false;
      await this.sealClose(meta, () => {
        for (const r of meta.runs.filter((x) => x.open)) this.appendStep(meta, "coverage.gap", r.agent, { reason: "run still open when the session closed by itself, after no new steps" }, { agentRunId: r.id }, false);
        this.appendStep(meta, "session.closed", "collector", { events: meta.seq }, {}, false);
        meta.closedAt = this.now().toISOString();
        meta.closedIdle = true;
      });
      return true;
    });
  }

  /**
   * Writes a session's ending and queues its final checkpoint under one hold of the heavy gate (for an agent, keeps it for the
   * agent to sign). Being busy can only refuse this before anything is written: once session.closed is on disk, nothing here
   * waits for the gate.
   */
  private sealClose(meta: SessionMeta, ending: () => void): Promise<FinalCheckpoint> {
    return this.heavy.run(() => {
      ending();
      const r = this.queueFinal(meta, this.store.readEvents(meta));
      this.store.writeMeta(meta);
      return r;
    });
  }

  /**
   * Queues the final checkpoint of a closed session that has none, which a crash in the middle of a close leaves. For an agent
   * there is nothing to queue until it signs: the body waits for its signature, and `sign` is the hash to sign. The caller
   * writes the metadata.
   */
  private queueFinal(meta: SessionMeta, events: ShadowEvent[]): FinalCheckpoint {
    if (this.agentSigns(meta)) {
      const sign = this.awaitSignature(meta, events, true);
      if (sign) return { target: sign, refused: null, sign };
      // The agent's last signed checkpoint covers every step: queued, unless that was refused before.
      const cp = meta.checkpoint!;
      return { target: cp.hash, refused: this.queueCheckpoint(meta, cp, true) };
    }
    const cp = this.signed(meta, events);
    meta.checkpoint = cp;
    return { target: cp.hash, refused: this.queueCheckpoint(meta, cp, true) };
  }

  /** Whether this session's checkpoints are its agent's to sign (an agent-key owner): the server builds them, and never signs. */
  private agentSigns(meta: SessionMeta): boolean {
    return signingModeOf(meta, this.witness) === "agent";
  }

  /**
   * An agent session's checkpoint over every step, kept for the agent to sign, and its hash; null when its last signed
   * checkpoint already covers them. Asked again over the same steps, it is the same body, so a signature in flight stays good.
   * The caller writes the metadata.
   */
  private awaitSignature(meta: SessionMeta, events: ShadowEvent[], final: boolean): string | null {
    const waiting = meta.awaitingSignature;
    if (waiting && waiting.body.count === events.length) {
      if (final) waiting.final = true;
      return waiting.hash;
    }
    const r = checkpointBody(meta, events, this.now(), "agent");
    if ("unchanged" in r) {
      delete meta.awaitingSignature;
      return null;
    }
    meta.awaitingSignature = { hash: r.hash, body: r.body, final };
    return r.hash;
  }

  /** For /metrics: totals only, and read from memory, so a scrape never walks the disk. */
  stats(): { stateBytes: number; maxStateBytes: number; anchors: AnchorBacklog; lastSweepMs: number | undefined } {
    return { stateBytes: this.usageBytes, maxStateBytes: this.limits.maxStateBytes, anchors: this.store.anchorBacklog(), lastSweepMs: this.lastSweepMs };
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
        if (isRecordedStep(e)) m.agentSteps++;
        if (e.body.kind === "session.closed") m.closedAt ??= e.body.collectedAt;
        const { capture } = e.body.payload as { capture?: unknown };
        if (e.body.kind === "agent.message" && isObj(capture)) m.capture = capture as SessionMeta["capture"];
        const a = anchorFrom(e);
        if (a) m.anchors.push(a);
      }
      m.eventsBytes = bytes;
      const landed = new Set(m.anchors.map((a) => a.hash));
      m.outbox = meta.outbox.filter((r) => !landed.has(r.hash));
      // The log wins over the metadata: a crash can land after a level note and before its metadata write.
      if (m.accountLevelSeen !== undefined) {
        const facts = sessionFacts(events);
        if (facts.accountLevel !== undefined) m.accountLevelSeen = facts.accountLevel;
        if (facts.changes.length) {
          m.logLevel = facts.level;
          if (facts.setBy) m.logLevelBy = facts.setBy;
        }
      }
      // What a crash in the middle of a start leaves undone: the start note, and the start marker's place in the queue.
      if (events.length) {
        const start = m.state === "open" && m.accountLevelSeen !== undefined && !events.some((e) => serverNoteOf(e)?.kind === "session_start") ? startNote(m) : null;
        if (start) this.appendNote(m, start.text, start.note);
        if (!m.anchors.some((a) => a.marker === "start") && !m.outbox.some((r) => r.kind === "start")) m.outbox.push(this.row("start", m.startHash, null, { sendStarted: true }));
      }
      // And in the middle of a close: session.closed landed, its checkpoint didn't.
      if (finalOwed(m)) this.queueFinal(m, this.store.readEvents(m));
      this.store.writeMeta(m);
      this.log("shadow_session_reconciled", { sessionId: m.sessionId, steps: m.seq });
      return m;
    });
  }

  /** A session whose start was interrupted before session.opened: open it now and queue the start marker. */
  private openUnanchored(meta: SessionMeta): void {
    this.appendStep(meta, "session.opened", "collector", this.openedPayload(meta, null, { errorKind: "Transient", errorCode: "interrupted" }), {}, false);
    const start = startNote(meta);
    if (start) this.appendNote(meta, start.text, start.note);
    // The start may have been sent before the interruption, so the ledger is asked before this is paid for.
    if (!meta.outbox.some((r) => r.kind === "start")) meta.outbox.push(this.row("start", meta.startHash, null, { sendStarted: true }));
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
      lastErrorKind: null, lastErrorCode: null, createdAt: this.now().toISOString(), sendStarted: false, ...extra,
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
    meta.lastStepAt = this.now().toISOString();
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

  /**
   * checkpointOver() with the session's signing mode: the witness key, or a legacy owner's key. An agent-key session's
   * checkpoints are the agent's to sign, and the server has no key for it: asking is a bug, never a fallback to another key.
   */
  private signed(meta: SessionMeta, events: ShadowEvent[]): Checkpoint {
    const mode = signingModeOf(meta, this.witness);
    if (mode === "agent") throw new Error("An agent signs its own checkpoints; the server holds no key for it");
    return checkpointOver(meta, events, this.store.operator(meta.ownerKey, this.now()).keys, this.now(), mode);
  }

  /**
   * latestCheckpoint(): a fresh, signed, unanchored checkpoint when steps were added since the last one. For an agent, the
   * last checkpoint it signed (null before its first), which can cover fewer steps than the record holds: the server never signs.
   */
  private latest(meta: SessionMeta, events: ShadowEvent[]): Checkpoint | null {
    if (this.agentSigns(meta)) return meta.checkpoint;
    const cp = this.signed(meta, events);
    if (cp !== meta.checkpoint) {
      meta.checkpoint = cp;
      this.store.writeMeta(meta);
    }
    return cp;
  }

  /** The book's entry for an agent checkpoint's signing key; null for any other checkpoint, or a key the book doesn't have. */
  private keyEntry(meta: SessionMeta, cp: Checkpoint): ReturnType<AgentKeyBook["get"]> {
    if (!this.agentSigns(meta) || !this.agentKeys) return null;
    try {
      return this.agentKeys.get(fingerprint(cp.publicKey));
    } catch {
      this.log("shadow_agent_key_unreadable", { sessionId: meta.sessionId });
      throw new ShadowError("SHADOW_UNAVAILABLE", "Clockchain can't read this agent's key right now. Try again later.");
    }
  }

  /** What the link cache keys on for the key verdict: the agent's key entry as it stands, which a filing or cancellation changes. */
  private keyStamp(meta: SessionMeta): string {
    const cp = meta.checkpoint;
    if (!cp || !this.agentSigns(meta) || !this.agentKeys) return "-";
    let e: ReturnType<AgentKeyBook["get"]>;
    try {
      e = this.agentKeys.get(fingerprint(cp.publicKey));
    } catch {
      return "?"; // The build reads it again, and says it can't.
    }
    return e ? `${e.status}/${e.filing.state}/${e.filing.block ?? ""}/${e.filing.filedAt ?? ""}/${e.revokedAt ?? ""}` : "none";
  }

  /**
   * Who made `cp`, from the public key lists: an agent's key in the book (checked against the anchor of `cp`, when its
   * receipt has landed), or Clockchain's witness key. `lookup` is where a reader finds that key. `failed`: the record
   * failed its checks for another reason, so it is never called unchanged.
   */
  private keyCheck(meta: SessionMeta, cp: Checkpoint, failed: boolean): KeyCheck & { lookup: string | null } {
    const anchor = meta.anchors.find((a) => a.marker === "checkpoint" && a.hash === cp.hash);
    // A block is known only as digits: an anchor whose height hasn't come back holds "".
    const block = anchor && /^\d+$/.test(anchor.blockHeight) ? Number(anchor.blockHeight) : null;
    const checked = checkAgentKey(this.keyEntry(meta, cp), cp, block !== null && Number.isSafeInteger(block) ? block : null, {
      anchoredAt: anchor?.blockTime ?? null,
      ...(this.witnessKey ? { witness: this.witnessKey } : {}),
      ...(this.agentSigns(meta) && !this.agentKeys ? { noBook: true } : {}),
    });
    const r = failed ? failedRecord(checked, cp) : checked;
    // Where the signing key is listed, as checked: a failed witnessed record's key is still the witness key.
    const lookup = checked.verdict === "legacy" || checked.verdict === "key_check_unavailable" ? null : checked.verdict === "witnessed" ? "/.well-known/clockchain-witness-key.json" : `/agent-keys/${fingerprint(cp.publicKey)}.json`;
    return { ...r, lookup };
  }

  /**
   * What a passing trust check says, for ownPinReport: the server's own-pin text (undefined) unless the agent signed; then
   * its key verdict when that agrees with a pass (made_by_agent or key_not_filed, on a record that didn't fail), else
   * AGENT_PIN (null).
   */
  private trustLine(meta: SessionMeta, key: KeyCheck, result: string): string | null | undefined {
    if (!this.agentSigns(meta)) return undefined;
    return result !== "fail" && (key.verdict === "made_by_agent" || key.verdict === "key_not_filed") ? key.text : null;
  }

  /** A closed session's pin. For an agent, of the last checkpoint it signed, and none while its final checkpoint waits for its signature. */
  private pinOf(meta: SessionMeta, events: ShadowEvent[]): Pin | null {
    if (meta.awaitingSignature?.final) return null;
    const cp = this.latest(meta, events);
    return cp ? buildPin(meta, cp) : null;
  }

  /**
   * Queues `cp` for Clockchain unless it already is, or the session's anchor allowance is used up. The last anchor is kept
   * for the close (`closing`), which also doesn't wait behind a backlog: it comes once, and it is the one anchor that covers
   * everything recorded.
   */
  private queueCheckpoint(meta: SessionMeta, cp: Checkpoint, closing = false): { code: string; message: string } | null {
    if (meta.network !== this.network) return { code: "SHADOW_OTHER_NETWORK", message: `This session is on ${meta.network}, and this server now writes to ${this.network}, so the checkpoint is signed but not anchored.` };
    if (meta.anchors.some((a) => a.hash === cp.hash) || meta.outbox.some((r) => r.hash === cp.hash)) return null;
    const used = meta.anchors.length + meta.outbox.length, max = this.limits.maxAnchorsPerSession;
    if (used >= (closing ? max : max - 1))
      return {
        code: "SHADOW_LIMIT_SESSION_ANCHORS",
        message: used >= max
          ? `This session has used all ${max} of its anchors, so the checkpoint is signed but not sent to Clockchain.`
          : `This session has used the ${max - 1} anchors it can spend before the close, so the checkpoint is signed but not sent to Clockchain. The last anchor is kept for the close.`,
      };
    if (!closing && this.parked(meta) >= MAX_PARKED)
      return { code: "SHADOW_ANCHORS_UNCONFIRMED", message: `${this.parked(meta)} earlier anchors may be on Clockchain and can't be confirmed, so no more are sent until they can be. This checkpoint is signed but not sent. The close still has its anchor, and nothing already queued is dropped.` };
    if (!closing && Buffer.byteLength(JSON.stringify(meta)) + META_ROOM > META_MAX_BYTES)
      return { code: "SHADOW_ANCHOR_BACKLOG", message: "This session's index is nearly full, so the checkpoint is signed but not queued. The close still has its anchor." };
    // A parked row isn't waiting its turn, so it holds no place in the queue.
    if (!closing && meta.outbox.length - this.parked(meta) >= MAX_OUTBOX)
      return { code: "SHADOW_ANCHOR_BACKLOG", message: "Too many anchors are still waiting for Clockchain; the checkpoint is signed but not queued. Try again later." };
    meta.outbox.push(this.row("checkpoint", cp.hash, cp, this.agentSigns(meta) ? { signer: fingerprint(cp.publicKey) } : {}));
    return null;
  }

  private parked(meta: SessionMeta): number {
    return meta.outbox.filter((r) => r.lastErrorCode === "search_refused").length;
  }

  /** What can still anchor this session's later steps. A failed row older than the latest anchor is history, not an outage. */
  private outlook(meta: SessionMeta): AnchorOutlook {
    const used = meta.anchors.length + meta.outbox.length, max = this.limits.maxAnchorsPerSession;
    const latest = Math.max(0, ...meta.anchors.map((a) => a.count ?? 0));
    const trouble = meta.outbox.filter((r) => r.lastErrorKind && r.lastErrorCode !== "search_refused" && (r.body?.count ?? 0) >= latest);
    const has = (code: string) => trouble.some((r) => r.lastErrorCode === code);
    return {
      canAnchor: used < max - 1,
      closeCanAnchor: used < max,
      blocked: has("anchor_limit") ? "day_limit" : has("starter_limit") ? "starter_limit" : has("starter_source_limit") ? "starter_source" : has("log_budget") ? "budget" : has("key_filing") ? "key_filing" : trouble.length ? "outage" : this.parked(meta) >= MAX_PARKED ? "unconfirmed" : null,
    };
  }

  /**
   * Said wherever a closed session's pin is given, while its pin can still change: each receipt that lands is a step, and the
   * pin names the record's head. That covers a row in the queue, one a retry can bring back, and a final checkpoint still owed.
   */
  private pinNote(meta: SessionMeta): string | null {
    // An agent's pin is over the checkpoint it signed: receipts landing after it don't change it.
    if (meta.state !== "closed" || this.agentSigns(meta)) return null;
    const coming = meta.outbox.some((r) => r.state !== "failed") || revivable(meta).length > 0 || (finalOwed(meta) && meta.network === this.network && this.outlook(meta).closeCanAnchor);
    if (!coming) return null;
    return `This pin is for the record as it stands now. A Clockchain receipt may still land. Each one adds a step, so the pin changes when it does, and this one will no longer match. ${meta.linksRevoked ? "shadow_get_session gives" : "shadow_get_session and the packet link give"} the current one.`;
  }

  /** Steps a close may still need room for: the count, a receipt or gap per open run, session.closed, the receipts owed, and the rule that a receipt needs a spare place. */
  private closeRoom(meta: SessionMeta): number {
    return 4 + meta.runs.filter((r) => r.open).length + meta.outbox.length;
  }

  private links(meta: SessionMeta, base: string): Links {
    if (meta.linksRevoked) return { viewer: null, packet: null };
    return { viewer: `${base}/shadow/s/${meta.cap}`, packet: `${base}/shadow/p/${meta.cap}.json`, ...(this.autoLog ? { summary: `${base}/shadow/s/${meta.cap}/summary` } : {}) };
  }

  // ---- tools ---------------------------------------------------------------------------------------------------------

  async startSession(ownerId: string, input: { title?: unknown; agents?: unknown; log_level?: unknown }, base: string) {
    if (typeof input.title !== "string" || !cleanText(input.title, 200)) throw bad("Give the session a title (up to 200 characters).");
    refuseHidden(input.title, "title");
    const title = cleanText(redactText(input.title.slice(0, 1000)), 200);
    const agents = this.agentsOf(input.agents);
    const agentLevel = levelInput(input.log_level);
    const ownerKey = ownerKeyOf(ownerId);
    const accountLevelSeen = this.accountLevel(ownerKey);
    const { level, by } = effectiveLevel(accountLevelSeen, agentLevel);
    // Checked here, so a refused profile leaves no session behind.
    const profile = agentProfileNote(agents);
    if (profile) noteSpec(profile);
    return this.locks.run(`owner:${ownerKey}`, async () => {
      if (this.deletedOwners.has(ownerKey)) throw new ShadowError("SHADOW_ACCOUNT_DELETED", "This account was deleted, so no session can start.");
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
      // At the limit, the session idle longest makes room rather than turning the person away, once nothing else refuses.
      const atLimit = open >= this.limits.maxOpenSessionsPerOwner;
      const roomCutoff = now.getTime() - Math.min(this.limits.idleCloseMs, IDLE_AT_LIMIT_MS);
      const makeRoom = atLimit && this.limits.idleCloseMs ? this.store.idleOpenSessionsOf(ownerKey, roomCutoff, now.getTime())[0] : undefined;
      if (atLimit && !makeRoom)
        throw new ShadowError("SHADOW_LIMIT_OPEN_SESSIONS", `You have ${open} open sessions, the most allowed. Close one with shadow_close_session first.`);
      if (this.usageBytes >= this.limits.maxStateBytes)
        throw new ShadowError("SHADOW_STORAGE_FULL", "Shadow's storage is full right now, so no new session can start. Try again later.");
      const full = this.accountFull(ownerKey, 4096);
      if (full) throw full;
      if (this.store.bump(ownerKey, "starts", this.today(), 1, this.limits.maxSessionStartsPerOwnerPerDay) === null)
        throw new ShadowError("SHADOW_LIMIT_SESSION_STARTS", `Your account has started ${this.limits.maxSessionStartsPerOwnerPerDay} sessions today, the most allowed per day. Try again tomorrow (UTC).`);
      if (makeRoom) {
        const made = await this.finishIdle(ownerKey, makeRoom.sessionId, roomCutoff).catch(() => false);
        if (!made) throw new ShadowError("SHADOW_LIMIT_OPEN_SESSIONS", `You have ${open} open sessions, the most allowed. Close one with shadow_close_session first.`);
        void this.drain(ownerKey, makeRoom.sessionId).catch(() => undefined);
      }
      // An agent-key owner gets its operator id from its root and no key; every other owner's comes from the store.
      const operatorId = agentOperatorId(ownerId) ?? this.store.operator(ownerKey, now).operatorId;
      const agentRoot = AGENT_OWNER.exec(ownerId)?.[1];
      const sessionId = randomUUID(), nonce = randomUUID();
      const meta: SessionMeta = {
        v: 1, sessionId, ownerKey, operatorId, title, agents, network: this.network, state: "open",
        createdAt: now.toISOString(), closedAt: null, expiresAt: new Date(now.getTime() + this.limits.retentionMs).toISOString(),
        cap: randomBytes(16).toString("base64url"), nonce, startHash: startHashOf(operatorId, sessionId, nonce),
        seq: 0, head: null, eventsBytes: 0, agentSteps: 0, runs: [], checkpoint: null, outbox: [], anchors: [],
        ...(agentRoot ? { agentRoot } : {}),
        ...(level === "step" ? {} : { logLevel: level, logLevelBy: by }),
        accountLevelSeen,
      };
      this.store.createSession(meta);
      this.usageBytes += 4096;
      const owned = this.ownerUsage.get(ownerKey);
      if (owned !== undefined) this.ownerUsage.set(ownerKey, owned + 4096);
      return this.session(ownerKey, sessionId, async (m) => {
        const deadline = Date.now() + ANCHOR_BUDGET_MS;
        const start = startNote(m);
        let outcome: AnchorOutcome;
        if (start) {
          // A session with something to note writes it before waiting on Clockchain, so a crash in the wait can't lose it. The
          // start marker's receipt then goes in its own step rather than in session.opened. It commits to the session's start
          // hash, not to any step, so the verifier reads it the same way; only the steps before it have no lower time bound.
          const row = this.row("start", m.startHash, null, { sendStarted: true });
          this.appendStep(m, "session.opened", "collector", this.openedPayload(m, null, null), {}, false);
          this.appendNote(m, start.text, start.note);
          m.outbox.push(row);
          this.store.writeMeta(m);
          outcome = await this.anchorNetwork(ownerKey, m.sessionId, { ...row, sendStarted: false }, deadline, this.keysToFile(m, row));
          this.applyOutcome(m, row.id, outcome);
        } else {
          // Nothing to lose in the wait: openers wait for the start marker, as the library's openSession does.
          const row = this.row("start", m.startHash, null);
          outcome = await this.anchorNetwork(ownerKey, m.sessionId, row, deadline, this.keysToFile(m, row));
          let receipt: Record<string, unknown> | null = null;
          let error: { errorKind: string; errorCode: string } | null = null;
          if (outcome.kind === "anchored") receipt = receiptPayload(m.sessionId, outcome.receipt);
          else if (outcome.kind === "pending") m.outbox.push(this.row("start", m.startHash, null, { state: "pending", ledgerId: outcome.ledgerId, submittedAt: outcome.submittedAt, attempts: 1, sendStarted: true }));
          else {
            error = { errorKind: outcome.failure.kind, errorCode: outcome.failure.code };
            const ours = WAITING_CODES.has(outcome.failure.code);
            const unconfirmed = outcome.kind === "unconfirmed";
            m.outbox.push(this.row("start", m.startHash, null, { attempts: ours ? 0 : 1, lastErrorKind: outcome.failure.kind, lastErrorCode: unconfirmed ? "search_refused" : outcome.failure.code, sendStarted: outcome.kind === "unconfirmed" || outcome.maybeWritten }));
          }
          const opened = this.appendStep(m, "session.opened", "collector", this.openedPayload(m, receipt, error), {}, false);
          if (outcome.kind === "anchored") m.anchors.push({ marker: "start", seq: opened.body.seq, hash: m.startHash, count: null, ...anchorFields(outcome.receipt) });
          this.store.writeMeta(m);
        }
        this.log("shadow_session_started", { sessionId: m.sessionId, agents: agents.length, startAnchor: outcome.kind });
        return {
          session_id: m.sessionId,
          title: m.title,
          status: "open",
          agents: m.agents.map((a) => agentView(a, { purpose: a.purpose, accountable_owner: a.accountableOwner })),
          ...(level === "step" ? {} : { log_level: level, log_level_set_by: by }),
          operator_id: m.operatorId,
          start_anchor: outcome.kind === "anchored"
            ? { status: "anchored", ledger_id: outcome.receipt.ledgerId, block: outcome.receipt.blockHeight, block_time: outcome.receipt.blockTime }
            : { status: "pending", note: heldByAgent(m) ? HELD_NOTE : "The start marker will be anchored with your next checkpoint.", ...startHeld(m) },
          expires_at: m.expiresAt,
          links: this.links(m, base),
          links_note: LINKS_NOTE,
          next: "Record each step with shadow_record, in order. Call shadow_close_session when the work is done.",
        };
      }, true);
    });
  }

  private agentsOf(v: unknown): AgentEntry[] {
    if (v === undefined || v === null) return [{ id: "agent", role: null }];
    if (!Array.isArray(v) || v.length === 0) throw bad('agents must be a list like [{"id": "researcher", "role": "finds sources"}].');
    if (v.length > this.limits.maxAgents) throw new ShadowError("SHADOW_LIMIT_AGENTS", `A session declares at most ${this.limits.maxAgents} agents.`);
    const out: AgentEntry[] = [];
    for (const a of v) {
      const id = isObj(a) ? a.id : a;
      if (typeof id !== "string" || !AGENT_ID.test(id) || id === "collector")
        throw bad('Each agent id is 1-64 letters, digits or . _ : @ -, starting with a letter or digit, and not "collector".');
      if (redactText(id) !== id) throw bad(CREDENTIAL_AGENT);
      if (out.some((x) => x.id === id)) throw bad(`Agent "${id}" is listed twice.`);
      if (isObj(a)) for (const field of ["role", "purpose", "accountable_owner"]) refuseHidden(a[field], field);
      const roleText = isObj(a) && typeof a.role === "string" ? redactText(a.role.slice(0, 1000)) : "";
      const role = cleanText(roleText, 100) ? cleanText(roleText, 100) : null;
      const purpose = isObj(a) ? reported(a.purpose, 200) : "";
      const accountableOwner = isObj(a) ? reported(a.accountable_owner, 100) : "";
      out.push({ id, role, ...(purpose ? { purpose } : {}), ...(accountableOwner ? { accountableOwner } : {}) });
    }
    return out;
  }

  /** `logs`: whether this endpoint has the logging tools. Anywhere else the result is what it always was, whatever the server's flags. */
  async record(ownerId: string, input: { session_id?: unknown; agent?: unknown; kind?: unknown; content?: unknown; run_id?: unknown } & DeclaredInput, logs: boolean = this.autoLog) {
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
    // The same backstop as the log tools, on every endpoint: a record can be read by anyone with its link. Size and depth
    // are checked above.
    content = redactSecrets(content);
    return this.session(ownerKeyOf(ownerId), sessionId, (meta) => {
      if (meta.state === "closed") throw new ShadowError("SHADOW_SESSION_CLOSED", "This session is closed. Start a new session to record more.");
      if (meta.network !== this.network) throw new ShadowError("SHADOW_OTHER_NETWORK", `This session is on ${meta.network}, and this server now writes to ${this.network}, so nothing was recorded. Start a new session to record more.`);
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
        spec = withDeclared(stepFor(kind, content), input);
      } catch (e) {
        if (e instanceof RecordError) throw new ShadowError(e.code, e.message);
        throw bad(`${(e as Error).message}.`);
      }
      const runId = this.runFor(meta, kind, agent, runInput);
      const session = this.sessionLevel(meta);
      // Server notes aren't counted as steps, so they can't use up the agent's: the whole session's room is what they share.
      if (meta.seq + 1 + (kind === "task" ? 1 : 0) + (session.noteDue ? 1 : 0) + this.closeRoom(meta) > this.maxEvents)
        throw new ShadowError("SHADOW_LIMIT_STEPS", `This session has ${meta.agentSteps} steps and no room for more. Close it and start a new one.`);
      if (session.noteDue) this.noteAccountLevel(meta, session);
      const event = this.appendStep(meta, spec.kind, agent, spec.payload, { boundary: spec.boundary, agentRunId: runId }, true);
      this.store.writeMeta(meta);
      return {
        seq: event.body.seq, hash: event.hash, kind: spec.kind, run_id: runId, ...declaredFields(declaredOf(event.body.payload)),
        ...(logs ? { anchor_status: "deferred" as const, anchor_reason: recordedReason(session.level, this.outlook(meta)) } : {}),
      };
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
      throw new ShadowError("SHADOW_UNAVAILABLE", UNREADABLE_SETTING);
    }
  }

  setLogging(ownerId: string, enabled: boolean) {
    const ownerKey = ownerKeyOf(ownerId);
    try {
      this.store.setLoggingOff(ownerKey, !enabled);
    } catch {
      throw new ShadowError("SHADOW_UNAVAILABLE", "Clockchain can't change this account's logging setting right now, so it stays as it was.");
    }
    this.log("shadow_logging_set", { enabled });
    let levelReadable = true;
    try {
      this.store.logLevel(ownerKey);
    } catch {
      levelReadable = false;
    }
    return {
      logging: { enabled, ...(levelReadable ? {} : { level_readable: false }) },
      message: !enabled
        ? "Logging is off for this account. Do not log steps and do not show a logging footer until the person turns it back on."
        : levelReadable
          ? "Logging is on for this account. Steps are logged from now on, and a reply usually ends with show_user from the last result."
          : "Logging is on for this account, but its logging level can't be read, so steps are still refused. Ask the person whether to set the account's level, which ends that.",
    };
  }

  /** This account's level, or null. A setting that cannot be read refuses rather than guessing. */
  accountLevel(ownerKey: string): LogLevel | null {
    try {
      return this.store.logLevel(ownerKey);
    } catch {
      throw new ShadowError("SHADOW_UNAVAILABLE", UNREADABLE_SETTING);
    }
  }

  /** This account's level, by account id, for clockchain_whoami. */
  logLevelOf(ownerId: string): LogLevel | null {
    return this.accountLevel(ownerKeyOf(ownerId));
  }

  /** `logs`: whether this endpoint has the logging tools, which is the only place a level changes when anchors happen. */
  setLogLevel(ownerId: string, input: unknown, logs: boolean = this.autoLog) {
    const level = levelInput(input);
    if (!level) throw bad("level must be step, turn or milestone.");
    const ownerKey = ownerKeyOf(ownerId);
    if (this.deletedOwners.has(ownerKey)) throw new ShadowError("SHADOW_ACCOUNT_DELETED", "This account was deleted, so nothing was changed.");
    let reset = false;
    try {
      ({ reset } = this.store.setLogLevel(ownerKey, level));
    } catch {
      throw new ShadowError("SHADOW_UNAVAILABLE", "Clockchain can't change this account's logging setting right now, so it stays as it was.");
    }
    this.log("shadow_log_level_set", { level });
    const after = !reset ? "" : logs
      ? " This account's settings couldn't be read, so they were reset: this level is kept, and logging is off until clockchain_logging turns it back on."
      : " This account's settings couldn't be read, so they were reset, and sessions can start again.";
    return {
      log_level: level,
      ...(reset ? { settings_reset: true } : {}),
      message: (logs
        ? `The logging level for this account is ${level}. It applies to sessions on this account: a new session runs at this level or a finer one chosen when it starts, and an open session at a coarser level moves to it on its next step. Each open session notes the change in its record on its next step.`
        : `The logging level for this account is ${level}. It is saved, and it doesn't change when anchors happen on this connection: anchors happen at the start, at shadow_checkpoint and at the close.`) + after,
    };
  }

  /**
   * This session's level, and whether the account's level has changed since the session last looked. A session from before
   * hashed notes has no such note and reads as step, so it runs as step too: what it shows is what it does.
   */
  private sessionLevel(meta: SessionMeta): { level: LogLevel; account: LogLevel | null; noteDue: boolean } {
    const account = this.accountLevel(meta.ownerKey);
    if (meta.accountLevelSeen === undefined) return { level: "step", account, noteDue: false };
    const current = meta.logLevel ?? "step";
    const level = account ? finer(current, account) : current;
    return { level, account, noteDue: level !== current || account !== meta.accountLevelSeen };
  }

  /** The account's level changed: says so in the record, in either direction, and moves the session if that makes it finer. Saved at once: the note is on disk. */
  private noteAccountLevel(meta: SessionMeta, { level, account }: { level: LogLevel; account: LogLevel | null }): void {
    const moved = level !== (meta.logLevel ?? "step");
    const previous = meta.accountLevelSeen ?? null;
    const setBy = moved ? "account" : meta.logLevelBy;
    this.appendNote(meta, accountLevelNote(previous, account, level, moved), {
      kind: "level_change", log_level: level, ...(setBy ? { set_by: setBy } : {}), account_level: account, previous_account_level: previous,
    });
    meta.accountLevelSeen = account;
    if (moved) {
      meta.logLevel = level;
      meta.logLevelBy = "account";
    }
    this.store.writeMeta(meta);
  }

  /** A server-made line in the record, as a step: hashed like any other, and in no run, so it can't change coverage. Not one of the agent's steps. */
  private appendNote(meta: SessionMeta, text: string, note: ServerNote): void {
    const { kind, boundary, payload } = noteSpec(text);
    this.appendStep(meta, kind, meta.agents[0].id, { ...payload, server_note: note }, { boundary, agentRunId: null }, false);
  }

  /** Refuses shadow_record and the logging tools once the owner turned logging off. */
  assertLogging(ownerId: string): void {
    if (!this.loggingEnabled(ownerId)) throw loggingOff();
  }

  /** One step, with its own hash. Whether this call anchors it, with a block and ledger id of its own, is the session's level's to say. */
  async logStep(ownerId: string, input: { session_id?: unknown; title?: unknown; log_level?: unknown; agent?: unknown; kind?: unknown; content?: unknown; run_id?: unknown } & DeclaredInput, base: string) {
    if (input.run_id !== undefined && input.run_id !== null && (typeof input.run_id !== "string" || !RUN_ID.test(input.run_id)))
      throw bad("run_id is 1-64 letters, digits or . _ : -, starting with a letter or digit.");
    const r = await this.logSteps(ownerId, { session_id: input.session_id, title: input.title, log_level: input.log_level, steps: [input], runInput: typeof input.run_id === "string" ? input.run_id : null, maxSteps: 1, table: input.kind === "message" || input.kind === "note" }, base);
    const step = r.steps[0];
    return {
      session_id: r.sessionId,
      seq: step.seq,
      hash: step.hash,
      kind: step.kind,
      ...step.declared,
      ...(step.runId ? { run_id: step.runId } : {}),
      ...r.anchor,
      ...(r.level && r.level !== "step" ? { log_level: r.level } : {}),
      ...(r.levelNote ? { log_level_note: r.levelNote } : {}),
      viewer: r.viewer,
      show_user: logFooter(r.meta, r.anchor, r.viewer, r.table),
      ...(r.started ? { note: NEW_SESSION_NOTE } : {}),
    };
  }

  /** The fallback: several steps in one call, sharing one anchor. */
  async logTurn(ownerId: string, input: { session_id?: unknown; title?: unknown; log_level?: unknown; steps?: unknown }, base: string) {
    if (!Array.isArray(input.steps) || input.steps.length === 0) throw bad("steps must be a list of 1 or more steps.");
    const r = await this.logSteps(ownerId, { session_id: input.session_id, title: input.title, log_level: input.log_level, steps: input.steps as LogStepInput[], runInput: null, maxSteps: MAX_TURN_STEPS, table: true }, base);
    return {
      session_id: r.sessionId,
      shared_anchor: r.anchor.anchor_status === "anchored" || r.anchor.anchor_status === "pending",
      anchor_note: r.anchor.anchor_status === "anchored" || r.anchor.anchor_status === "pending"
        ? "These steps share one anchor: one block and one ledger record for the whole call, not one per step. At the step level, shadow_log_step gives each call its own."
        : "These steps are recorded and have no anchor so far.",
      ...(r.level && r.level !== "step" ? { log_level: r.level } : {}),
      ...(r.levelNote ? { log_level_note: r.levelNote } : {}),
      evidence: {
        logged: r.steps.map((s) => ({ seq: s.seq, kind: s.kind, hash: s.hash, summary: s.summary, ...s.declared })),
        ...r.anchor,
        viewer: r.viewer,
      },
      show_user: logFooter(r.meta, r.anchor, r.viewer, r.table, r.steps.length),
      ...(r.started ? { note: NEW_SESSION_NOTE } : {}),
    };
  }

  private async logSteps(ownerId: string, input: { session_id?: unknown; title?: unknown; log_level?: unknown; steps: LogStepInput[]; runInput: string | null; maxSteps: number; table: boolean }, base: string) {
    this.assertLogging(ownerId);
    if (input.steps.length > input.maxSteps)
      throw new ShadowError("SHADOW_LIMIT_TURN_STEPS", `One call logs at most ${input.maxSteps} steps; this one has ${input.steps.length}. Nothing was recorded. Split them over several calls.`);
    const many = input.maxSteps > 1;
    const agentLevel = levelInput(input.log_level);
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
      refuseHidden(input.title, "title");
      sessionId = (await this.startSession(ownerId, { title, ...(named.length ? { agents: named.map((id) => ({ id })) } : {}), ...(agentLevel ? { log_level: agentLevel } : {}) }, base)).session_id;
      started = true;
    } else {
      sessionId = sessionIdOf(input.session_id);
    }
    const made: { steps: LoggedStep[]; target: string | null; refused: { code: string; message: string } | null; deferred: LogLevel | null; turn: { rows: StepRow[]; earlier: number } } = { steps: [], deferred: null, target: null, refused: null, turn: { rows: [], earlier: 0 } };
    await this.session(ownerKey, sessionId, async (meta) => {
      if (meta.state === "closed") throw new ShadowError("SHADOW_SESSION_CLOSED", `This session is closed, so nothing was recorded. ${START_NEW}`);
      if (meta.network !== this.network) throw new ShadowError("SHADOW_OTHER_NETWORK", `This session is on ${meta.network}, and this server now writes to ${this.network}, so nothing was recorded. ${START_NEW}`);
      const session = this.sessionLevel(meta);
      const { level } = session;
      const anchoring = anchorsNow(level, many, steps.map((s) => s.kind));
      const extra = session.noteDue ? 1 : 0;
      const tasks = steps.filter((s) => s.kind === "task").length;
      if (meta.agentSteps + steps.length > this.limits.maxStepsPerSession || meta.seq + steps.length + tasks + extra + this.closeRoom(meta) > this.maxEvents)
        throw new ShadowError("SHADOW_LIMIT_STEPS", `This session has ${meta.agentSteps} steps and can't take ${steps.length} more, so nothing was recorded. ${START_NEW}`);
      // The last anchor is kept for shadow_close_session, so a full session can still anchor its final checkpoint. At the step
      // level the session is over, since every step wants an anchor. At turn and milestone, steps were recorded on the
      // promise of a later anchor, and refusing the reply would leave actions with no answer: it is recorded, and says it has no anchor.
      if (anchoring && level === "step" && !this.outlook(meta).canAnchor)
        throw new ShadowError("SHADOW_LIMIT_SESSION_ANCHORS", `This session has used the ${this.limits.maxAnchorsPerSession - 1} anchors it can spend before the close, so nothing was recorded. ${START_NEW}`);
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
      if (session.noteDue) this.noteAccountLevel(meta, session);
      try {
        for (const s of steps) {
          const agent = s.agent ?? meta.agents[0].id;
          const runId = this.runFor(meta, s.kind, agent, input.runInput);
          const event = this.appendStep(meta, s.spec.kind, agent, s.spec.payload, { boundary: s.spec.boundary, agentRunId: runId }, true);
          made.steps.push({ seq: event.body.seq, hash: event.hash, kind: s.kind, runId, summary: s.summary, declared: declaredFields(declaredOf(event.body.payload)) });
          // This call's own steps, in case the record can't be read back below.
          made.turn.rows = [...made.turn.rows, stepRow(event)].slice(-MAX_TURN_ROWS);
        }
      } finally {
        if (made.steps.length) this.store.writeMeta(meta);
      }
      // Not this call's turn to anchor, or an agent's, which signs its own: nothing is signed or sent, so no anchor allowance is spent.
      if (!anchoring || this.agentSigns(meta)) {
        if (anchoring) made.refused = { code: "SHADOW_AGENT_SIGNS", message: AGENT_SIGNS };
        else made.deferred = level;
        if (input.table) made.turn = await this.withEvents(meta, (events) => turnRows(events, made.steps[0].seq)).catch(() => made.turn);
        return;
      }
      // From here on the steps are recorded: whatever happens to the anchor is reported, never an error.
      try {
        const cp = await this.withEvents(meta, (events) => {
          if (input.table) made.turn = turnRows(events, made.steps[0].seq);
          return this.signed(meta, events);
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
    return this.session(ownerKey, sessionId, async (meta) => {
      const anchor: LogAnchor = made.deferred
        ? { block_height: null, ledger_id: null, block_time: null, anchored_hash: null, covers_steps: null, anchor_status: "deferred", anchor_reason: deferredReason(made.deferred, this.outlook(meta)) }
        : this.logAnchor(meta, made.target, made.refused);
      // From the hashed record. The steps are recorded by now, so if it can't be read back the result leaves the level out.
      const facts = await this.withEvents(meta, (events) => sessionFacts(events)).catch(() => null);
      const level = facts?.level ?? null;
      const levelNote = !started && agentLevel ? "log_level applies when a session starts, so it had no effect on this open session." : null;
      return { sessionId, started, steps: made.steps, anchor, level, levelNote, table: input.table ? turnTable(meta, made.turn) : "", viewer: this.links(meta, base).viewer, meta: { agentSteps: meta.agentSteps, logLevel: level, levelChanged: (facts?.changes.length ?? 0) > 0, anchors: meta.anchors.map((a) => ({ blockHeight: a.blockHeight, ledgerId: a.ledgerId })) } };
    });
  }

  private prepareStep(raw: LogStepInput) {
    if (!isObj(raw)) throw bad("Each step is {kind, content} with an optional agent, action_type and intent_type.");
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
      spec = withDeclared(stepFor(kind, content), raw);
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
    const limited = [row, ...meta.outbox].find((r) => r.lastErrorCode !== null && OWN_LIMITS.has(r.lastErrorCode));
    if (limited) return { ...none, anchor_status: "over_limit", anchor_reason: reasonOf(limited) ?? "An anchoring limit has been reached." };
    return { ...none, anchor_status: "pending", anchor_reason: reasonOf(row) ?? "Waiting to be sent to Clockchain." };
  }

  async checkpoint(ownerId: string, input: { session_id?: unknown }) {
    const sessionId = sessionIdOf(input.session_id);
    const ownerKey = ownerKeyOf(ownerId);
    const made: { target: string | null; refused: Refusal | null; sign?: string } = { target: null, refused: null };
    await this.session(ownerKey, sessionId, async (meta) => {
      if (meta.state === "closed") { // Only retries what is still owed.
        const revived = revive(meta);
        // An agent's final checkpoint still unsigned: the hash to sign.
        if (finalOwed(meta)) {
          const final = await this.withEvents(meta, (events) => this.queueFinal(meta, events));
          if (final.sign) {
            Object.assign(made, final);
            this.store.writeMeta(meta);
            return;
          }
        }
        if (revived || meta.outbox.length) this.store.writeMeta(meta);
        return;
      }
      if (this.agentSigns(meta)) {
        // The body waits for the agent's signature, on disk, so a restart keeps the hash it was given. Nothing is queued.
        const sign = await this.withEvents(meta, (events) => {
          const hash = this.awaitSignature(meta, events, false);
          this.store.writeMeta(meta);
          return hash;
        });
        if (sign) {
          made.target = made.sign = sign;
          return;
        }
      }
      const cp = this.agentSigns(meta) ? meta.checkpoint! : await this.withEvents(meta, (events) => this.signed(meta, events));
      meta.checkpoint = cp;
      made.target = cp.hash;
      made.refused = this.queueCheckpoint(meta, cp);
      this.store.writeMeta(meta);
    });
    if (!made.sign) await this.drain(ownerKey, sessionId, { asked: true });
    return this.session(ownerKey, sessionId, (meta) => ({
      session_id: sessionId,
      status: meta.state,
      ...(made.target ? { checkpoint: this.anchorView(meta, made.target, made.refused) } : { note: "The session is closed; anchors still owed were retried." }),
      ...(made.sign ? { sign: signView(meta, made.sign) } : {}),
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
    const made: FinalCheckpoint = { target: "", refused: null };
    await this.session(ownerKey, sessionId, async (meta) => {
      if (meta.state === "closed") {
        // A retry finishes what an earlier close left: a final checkpoint never queued, or one still waiting. Otherwise it is over.
        const revived = revive(meta);
        if (finalOwed(meta)) {
          Object.assign(made, await this.withEvents(meta, (events) => this.queueFinal(meta, events)));
          this.store.writeMeta(meta);
          return;
        }
        const waiting = nextRow(meta, new Set(), null);
        if (waiting?.kind !== "checkpoint") throw new ShadowError("SHADOW_SESSION_CLOSED", "This session is already closed.");
        made.target = waiting.hash;
        if (revived) this.store.writeMeta(meta);
        return;
      }
      Object.assign(made, await this.sealClose(meta, () => {
        if (counted !== null) this.recordCapture(meta, counted);
        // Session.close(): runs still open become gaps, unless the agent reports how they ended (status); then session.closed.
        for (const r of meta.runs.filter((x) => x.open)) {
          if (status) this.appendStep(meta, "execution.receipt", r.agent, { status, facts: {} }, { agentRunId: r.id }, false);
          else this.appendStep(meta, "coverage.gap", r.agent, { reason: clip("run still open when the session closed", 2000) }, { agentRunId: r.id }, false);
        }
        this.appendStep(meta, "session.closed", "collector", { events: meta.seq }, {}, false);
        meta.closedAt = this.now().toISOString();
      }));
    });
    await this.drain(ownerKey, sessionId, { asked: true });
    return this.session(ownerKey, sessionId, async (meta) => {
      const links = this.links(meta, base);
      const { pin, log, anchoring } = await this.withEvents(meta, (events) => ({ pin: this.pinOf(meta, events), log: this.autoLog ? sessionLog(meta, events) : null, anchoring: anchoringOf(meta, events) }));
      this.log("shadow_session_closed", { sessionId, steps: meta.seq, anchors: meta.anchors.length, pending: meta.outbox.length });
      return {
        ...(log ? { summary: sessionLogText(log, { max: MAX_SUMMARY_ROWS, rest: links.summary ?? links.viewer }), summary_note: "This summary is for the person, in full, as it is.", capture: meta.capture ?? null, capture_note: captureNote(meta) } : {}),
        session_id: sessionId,
        status: "closed",
        steps: meta.seq,
        final_checkpoint: this.anchorView(meta, made.target, made.refused),
        ...(made.sign ? { sign: signView(meta, made.sign) } : {}),
        anchoring,
        pin,
        ...(this.pinNote(meta) ? { pin_note: this.pinNote(meta) } : {}),
        links,
        links_note: meta.linksRevoked ? LINKS_REVOKED_NOTE : LINKS_NOTE,
        share: meta.linksRevoked ? "This session's links were revoked, so there is nothing to share." : "The viewer or packet link is for whoever should check this record; the pin goes by a different channel.",
      };
    });
  }

  /** Whether agents' keys are on: then an agent-key owner signs its own checkpoints with shadow_sign_checkpoint. */
  get agentKeysOn(): boolean {
    return this.agentKeys !== undefined;
  }

  /**
   * shadow_sign_checkpoint: the agent's own signature over the checkpoint hash it was given. `agentKey` is the fingerprint
   * of the key its token was issued for (akf). The key must be active in the book and belong to the session owner's root,
   * and its signature must verify over the hash waiting in the session. Then the checkpoint is the agent's, under its key,
   * and is queued and anchored as shadow_checkpoint queues the server's.
   */
  async signCheckpoint(ownerId: string, agentKey: string | undefined, input: { session_id?: unknown; hash?: unknown; signature?: unknown }) {
    const sessionId = sessionIdOf(input.session_id);
    const root = AGENT_OWNER.exec(ownerId)?.[1];
    if (!root || !this.agentKeys || typeof agentKey !== "string") throw NOT_AGENT_OWNER();
    const book = this.agentKeys;
    const ownerKey = ownerKeyOf(ownerId);
    const made: { target: string; refused: Refusal | null } = { target: "", refused: null };
    await this.session(ownerKey, sessionId, (meta) => {
      // The key is read under the lock, and nothing awaits from here to writeMeta, so a key replaced or revoked while this
      // call waited for the lock signs nothing.
      let entry: ReturnType<AgentKeyBook["get"]>;
      try {
        entry = book.get(agentKey);
      } catch {
        this.log("shadow_agent_key_unreadable", { sessionId });
        throw new ShadowError("SHADOW_UNAVAILABLE", "Clockchain can't read this agent's key right now. Try again later.");
      }
      if (!entry || entry.status !== "active" || entry.root !== root) throw NOT_AGENT_OWNER();
      const key = entry.publicKeyPem;
      if (!this.agentSigns(meta)) throw NOT_AGENT_OWNER();
      const waiting = meta.awaitingSignature;
      // The same signature over the latest signed checkpoint, resent because the reply was lost: write and queue nothing,
      // and answer from what is already recorded.
      if (!waiting && meta.checkpoint && meta.checkpoint.hash === input.hash && meta.checkpoint.signature === input.signature && meta.checkpoint.publicKey === key) {
        made.target = meta.checkpoint.hash;
        return;
      }
      if (!waiting) throw new ShadowError("hash_mismatch", "No checkpoint of this session is waiting to be signed. Call shadow_checkpoint for the hash to sign.");
      if (input.hash !== waiting.hash) throw new ShadowError("hash_mismatch", `That is not the hash waiting to be signed. The current hash is ${waiting.hash}: sign it and call shadow_sign_checkpoint again.`);
      if (!verifySignature(key, waiting.hash, input.signature))
        throw new ShadowError("bad_signature", "The signature does not verify over that hash under your key. Sign the 32 bytes of the hash (its hex decoded) with Ed25519, and send the 64-byte signature in base64.");
      const cp: Checkpoint = { body: waiting.body, hash: waiting.hash, publicKey: key, signature: input.signature as string };
      meta.checkpoint = cp;
      delete meta.awaitingSignature;
      made.target = cp.hash;
      made.refused = this.queueCheckpoint(meta, cp, waiting.final);
      this.store.writeMeta(meta);
    });
    await this.drain(ownerKey, sessionId, { asked: true });
    return this.session(ownerKey, sessionId, async (meta) => {
      const pin = meta.state === "closed" ? await this.withEvents(meta, (events) => this.pinOf(meta, events)) : null;
      return {
        session_id: sessionId,
        status: meta.state,
        checkpoint: this.anchorView(meta, made.target, made.refused),
        ...(pin ? { pin } : {}),
        pending_anchors: meta.outbox.map(pendingView),
        anchors_today: this.store.anchorsToday(ownerKey, this.today()),
        anchors_per_day: this.limits.maxAnchorsPerOwnerPerDay,
      };
    });
  }

  /**
   * The assistant's count of the person's messages against the task and prompt steps logged, as a signed step, so the
   * comparison is inside the tamper-evident record. It joins no run, so it can't change whether a run counts as covered,
   * and so can't change the verifier's verdict. Its `capture` field can't come from a logged step: stepFor builds those.
   */
  private recordCapture(meta: SessionMeta, reported: number): void {
    const logged = this.store.readEvents(meta).filter((e) => e.body.kind === "task.assigned" || e.body.kind === "agent.prompt").length;
    const capture = { person_messages_reported: reported, person_messages_logged: logged, missing: Math.max(0, reported - logged) };
    const { payload } = stepFor("note", `The assistant counted ${reported} messages from the person before the one asking to close; ${logged} are logged. This is the assistant's own count.`);
    this.appendStep(meta, "agent.message", meta.agents[0].id, { ...payload, capture }, { boundary: "transcript", agentRunId: null }, false);
    meta.capture = capture;
  }

  async getSession(ownerId: string, input: { session_id?: unknown }, base: string) {
    const sessionId = sessionIdOf(input.session_id);
    return this.session(ownerKeyOf(ownerId), sessionId, (meta) => this.withEvents(meta, (events) => {
      const pin = meta.state === "closed" ? this.pinOf(meta, events) : null;
      const facts = sessionFacts(events);
      // A session from before hashed notes has only its metadata to say who set it, and it reads as step whatever that says.
      const setBy = facts.setBy ?? (meta.accountLevelSeen === undefined ? meta.logLevelBy : null);
      return {
        session_id: meta.sessionId,
        title: meta.title,
        status: meta.state,
        agents: meta.agents.map((a) => agentView(a, facts.agents.get(a.id))),
        log_level: facts.level,
        ...(setBy ? { log_level_set_by: setBy } : {}),
        ...(facts.changes.length ? { log_level_changes: facts.changes } : {}),
        steps: meta.seq,
        recorded_steps: meta.agentSteps,
        anchoring: anchoringOf(meta, events),
        open_runs: meta.state === "open" ? meta.runs.filter((r) => r.open).map((r) => ({ run_id: r.id, agent: r.agent })) : [],
        created_at: meta.createdAt,
        closed_at: meta.closedAt,
        expires_at: meta.expiresAt,
        anchors: meta.anchors.map(anchorView),
        pending_anchors: meta.outbox.map(pendingView),
        time_windows: windowsView(windows(events)),
        links: this.links(meta, base),
        links_note: meta.linksRevoked ? LINKS_REVOKED_NOTE : LINKS_NOTE,
        ...(pin ? { pin, ...(this.pinNote(meta) ? { pin_note: this.pinNote(meta) } : {}) } : { pin_note: meta.state === "closed" ? "The pin is issued when the agent signs the final checkpoint (shadow_checkpoint gives the hash, shadow_sign_checkpoint takes the signature)." : "The pin is issued when the session is closed." }),
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
    const { ledgerIds, other } = await this.session(ownerKey, sessionId, (meta) => ({ ledgerIds: meta.anchors.map((a) => a.ledgerId), other: meta.network === this.network ? null : meta.network }));
    let online: Awaited<ReturnType<typeof prefetchOnline>> | undefined;
    let onlineNote: string;
    let receipts: { checked: number; total: number } | undefined;
    if (ledgerIds.length > this.limits.onlineVerifyMaxReceipts) {
      onlineNote = `Checked offline: this session has ${ledgerIds.length} Clockchain receipts, more than the ${this.limits.onlineVerifyMaxReceipts} checked online here. Run shadow-verify packet.json --pin pin.json --online to confirm them all.`;
    } else {
      try {
        if (other) throw new Error("other network");
        online = await prefetchOnline(this.ledger(), { network: this.network, referenceId: referenceId(sessionId), ledgerIds, timeoutMs: ONLINE_TIMEOUT_MS, concurrency: this.autoLog ? ONLINE_CONCURRENCY : 1 });
        onlineNote = "Checked online against the Clockchain ledger, from this server.";
        if (this.autoLog) {
          receipts = { checked: online.receiptsChecked, total: ledgerIds.length };
          if (receipts.checked < receipts.total) onlineNote = `Checked ${receipts.checked} of ${receipts.total} Clockchain receipts online in the time allowed; the rest were not checked, so witness stays indeterminate. Run shadow_verify again, or shadow-verify packet.json --pin pin.json --online.`;
        }
      } catch {
        onlineNote = other ? `Checked offline: this session's receipts are on ${other}, which this server no longer reads.` : "Checked offline: Clockchain could not be reached.";
      }
    }
    return this.session(ownerKey, sessionId, (meta) => this.withEvents(meta, async (events) => {
      const cp = this.latest(meta, events);
      if (!cp) return { session_id: sessionId, result: "indeterminate" as const, summary: NOTHING_SIGNED, checks: [], anchoring: anchoringOf(meta, events), online: onlineNote, links: this.links(meta, base) };
      // An agent's checkpoint covers what it signed; the steps after it are in no checkpoint, so not in the packet.
      const packet = buildPacket(meta, cp, events.slice(0, cp.body.count), meta.network, this.now());
      const pin = buildPin(meta, cp);
      // Verified as a relying party would: strictly parsed from its JSON.
      // With logging on by default, a record that can't be confirmed on the ledger doesn't pass: witness decides too. So too
      // anywhere for a record with no receipts when the ledger gave no answer: nothing says what it holds for this session.
      const checked = await verifyPacket(parseStrict(JSON.stringify(packet)), { pin: parseStrict(JSON.stringify(pin)), online, ...(this.autoLog || online?.searchUnanswered ? { requireOnline: true } : {}) });
      const anchoring = anchoringOf(meta, events);
      const key = this.keyCheck(meta, cp, checked.result === "fail");
      // Where logging is on by default, a pass also needs every recorded step under an anchored checkpoint. Elsewhere it needs at least some of the record to be.
      const own = this.autoLog ? ownPinReport(checked, this.trustLine(meta, key, checked.result)) : checked;
      const report = withKeyVerdict(anchoringDecides(this.autoLog, anchoring) ? withAnchoring(own, anchoring) : own, key);
      // The result is about the signed prefix only, so steps the agent never signed are said beside it.
      const unsigned = unsignedCount(events.slice(cp.body.count));
      return {
        session_id: sessionId,
        result: report.result,
        summary: report.summary,
        ...(unsigned ? { unsigned_steps: unsigned, unsigned_note: unsignedText(unsigned, "in what was verified") } : {}),
        checks: report.checks,
        agent_key: key,
        anchoring,
        online: onlineNote,
        ...(receipts ? { receipts_checked_online: receipts.checked, receipts_total: receipts.total } : {}),
        interpretation: report.interpretation,
        ...(this.autoLog ? { capture: meta.capture ?? null, capture_note: captureNote(meta) } : {}),
        links: this.links(meta, base),
      };
    }));
  }

  // ---- delete and revoke, at the person's request --------------------------------------------------------------------

  /** A session deleted now: record, links and cached copies. Call under the session's lock. */
  private removeSession(ownerKey: string, sessionId: string): { steps: number | null; anchors: number } {
    let meta: SessionMeta | undefined;
    try {
      meta = this.store.readMeta(ownerKey, sessionId);
    } catch {
      meta = undefined; // Unreadable is no reason to keep it: the sweep drops a capability file left behind.
    }
    const bytes = (meta?.eventsBytes ?? 0) + 4096;
    this.store.deleteSession(ownerKey, sessionId, meta?.cap ?? null);
    this.usageBytes = Math.max(0, this.usageBytes - bytes);
    const owned = this.ownerUsage.get(ownerKey);
    if (owned !== undefined) this.ownerUsage.set(ownerKey, Math.max(0, owned - bytes));
    this.linkCache.deleteWhere((key) => key.includes(`:${sessionId}:`));
    // Those still owed count too if the ledger already holds them: a pending row has its ledger ID.
    return { steps: meta?.seq ?? null, anchors: (meta?.anchors.length ?? 0) + (meta?.outbox.filter((r) => r.ledgerId).length ?? 0) };
  }

  /** What deleting a session would remove. Changes nothing. */
  async deletePreview(ownerId: string, input: { session_id?: unknown }) {
    const sessionId = sessionIdOf(input.session_id);
    return this.session(ownerKeyOf(ownerId), sessionId, (meta) => ({
      status: "confirmation_needed",
      session_id: sessionId,
      title: meta.title,
      would_delete: { steps: meta.seq, links: "all of them" },
      message: `Nothing was deleted. This would delete this record and stop its links, and it can't be undone. ${LEDGER_STAYS} Ask the person; call again with confirm: true only if they clearly say yes.`,
    }));
  }

  /** Deletes one session for its owner, now. Its links stop at once. */
  async deleteSession(ownerId: string, input: { session_id?: unknown }) {
    const sessionId = sessionIdOf(input.session_id);
    const ownerKey = ownerKeyOf(ownerId);
    return this.locks.run(`${ownerKey}/${sessionId}`, () => {
      if (!this.store.sessionExists(ownerKey, sessionId)) throw notFound();
      const removed = this.removeSession(ownerKey, sessionId);
      this.log("shadow_session_deleted", { sessionId, anchors: removed.anchors });
      return {
        status: "deleted",
        session_id: sessionId,
        steps_deleted: removed.steps,
        links: "stopped",
        ledger: { kept: true, fingerprints: removed.anchors, note: LEDGER_STAYS },
        message: `Deleted. The record is gone from this server and its viewer and packet links have stopped working. ${LEDGER_STAYS} ${COPIES_STAY}`,
      };
    });
  }

  /** Stops a session's links without touching the record. The links can't be turned back on. */
  async revokeLinks(ownerId: string, input: { session_id?: unknown }) {
    const sessionId = sessionIdOf(input.session_id);
    return this.session(ownerKeyOf(ownerId), sessionId, (meta) => {
      const already = meta.linksRevoked === true;
      if (!already) {
        // Saved first: linkBody refuses a revoked session whatever its capability file says, so a crash here can't reopen it.
        meta.linksRevoked = true;
        this.store.writeMeta(meta);
        this.store.revokeCap(meta);
        this.linkCache.deleteWhere((key) => key.includes(`:${sessionId}:`));
        this.log("shadow_links_revoked", { sessionId });
      }
      return {
        status: already ? "already_revoked" : "revoked",
        session_id: sessionId,
        links: "stopped",
        record: "kept",
        message: `The viewer and packet links for this session have stopped working, and they can't be turned back on. The record is still kept until it is deleted, ${meta.expiresAt.slice(0, 10)} at the latest. ${COPIES_STAY}`,
      };
    });
  }

  /** What deleting an owner's data would take, for the confirmation. */
  ownerSummary(ownerId: string): { sessions: number; steps: number; fingerprints: number } {
    const ownerKey = ownerKeyOf(ownerId);
    const total = { sessions: 0, steps: 0, fingerprints: 0 };
    for (const id of this.store.sessionIds(ownerKey)) {
      total.sessions++;
      try {
        const m = this.store.readMeta(ownerKey, id);
        total.steps += m?.seq ?? 0;
        total.fingerprints += m?.anchors.length ?? 0;
      } catch {
        // Unreadable: counted as a session, and deleted like the rest.
      }
    }
    return total;
  }

  /**
   * Deletes everything Shadow keeps for an owner, each session under its own lock and no new session starting meanwhile,
   * then `finish` (which removes the account, so its tokens stop), then the owner's key and settings.
   */
  async deleteOwner(ownerId: string, finish: () => void): Promise<{ sessions: number; fingerprints: number }> {
    const ownerKey = ownerKeyOf(ownerId);
    this.deletedOwners.add(ownerKey);
    return this.locks.run(`owner:${ownerKey}`, async () => {
      let sessions = 0, fingerprints = 0;
      for (const id of this.store.sessionIds(ownerKey)) {
        const removed = await this.locks.run(`${ownerKey}/${id}`, () => this.removeSession(ownerKey, id));
        sessions++;
        fingerprints += removed.anchors;
      }
      finish();
      this.store.deleteOwner(ownerKey);
      this.ownerUsage.delete(ownerKey);
      this.log("shadow_owner_deleted", { sessions, anchors: fingerprints });
      return { sessions, fingerprints };
    }).catch((e) => {
      this.deletedOwners.delete(ownerKey); // Not deleted after all: the account still works.
      throw e;
    });
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
    if (!meta || meta.linksRevoked || Date.parse(meta.expiresAt) <= this.now().getTime()) return undefined;
    const stamp = this.keyStamp(meta);
    const hit = this.linkCache.get(linkKey(kind, meta, stamp));
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
        if (meta.linksRevoked) return undefined; // Revoked while this request waited for the lock.
        const stamp = this.keyStamp(meta);
        const cached = this.linkCache.get(linkKey(kind, meta, stamp));
        if (cached) return cached;
        return this.withEvents(meta, async (events) => {
          if (kind === "log" || kind === "log-json") {
            const log = sessionLog(meta, events);
            // In JSON a title is a value, so without the backticks that mark a name in text.
            const body = Buffer.from(kind === "log" ? sessionLogText(log) : JSON.stringify({ ...log, steps: log.steps.map((s) => ({ ...s, title: s.title.replaceAll("`", "") })) }, null, 1));
            this.linkBuildCount++;
            this.linkCache.set(linkKey(kind, meta, stamp), body);
            return body;
          }
          const cp = this.latest(meta, events);
          const anchoring = anchoringOf(meta, events);
          let body: Buffer;
          if (!cp) {
            body = Buffer.from(kind === "packet"
              ? JSON.stringify({ packet: null, pin: null, anchoring, note: NOTHING_SIGNED }, null, 1)
              : `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Clockchain Shadow</title></head><body><h1>${escHtml(meta.title)}</h1><p>${escHtml(NOTHING_SIGNED)}</p></body></html>\n`);
            this.linkBuildCount++;
            this.linkCache.set(linkKey(kind, meta, stamp), body);
            return body;
          }
          // An agent's checkpoint covers what it signed; the steps after it are in no checkpoint, so not in the packet.
          const packet = buildPacket(meta, cp, events.slice(0, cp.body.count), meta.network, this.now());
          const pin = buildPin(meta, cp);
          if (kind === "packet") {
            body = Buffer.from(JSON.stringify({
              packet, pin,
              anchoring,
              verify: `Save packet and pin as packet.json and pin.json, then run: shadow-verify packet.json --pin pin.json --online. The pin is independent assurance only if it reached you separately from the packet. ${anchoringCaveat(anchoring)} ${ANCHORING_FIELD_NOTE}`,
            }, null, 1));
          } else {
            const report = await verifyPacket(parseStrict(JSON.stringify(packet)), { pin });
            const agent = this.agentSigns(meta);
            const key = this.keyCheck(meta, cp, report.result === "fail");
            const own = ownPinReport(report, this.trustLine(meta, key, report.result));
            // A failed key verdict fails the page, so the library tags nothing as matching.
            const shown = withKeyVerdict(anchoringDecides(this.autoLog, anchoring) ? withAnchoring(own, anchoring) : own, key);
            const html = withServerSteps(withUnsignedTail(withAnchoringCaveat(withSessionDetails(hostedViewer(summarize(packet, shown, { packetFile: "packet.json", pinFile: "pin.json" }).html, key.verdict === "legacy" ? null : key, agent), meta, sessionFacts(events), anchoring, this.pinNote(meta)), anchoring), events.slice(cp.body.count)), events);
            body = Buffer.from(this.autoLog ? withStepAnchors(html.replace("<h2>What this record shows</h2>", () => `<h2>What this record shows</h2><p class="meta">${escHtml(captureNote(meta))}</p>`), events, meta.cap) : html);
          }
          this.linkBuildCount++;
          this.linkCache.set(linkKey(kind, meta, stamp), body);
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

  /**
   * The agent keys Clockchain must hold before this row is anchored: the session's root key and, for a checkpoint, the key
   * that signed it (a replacement key, say). Null for an account's session. A key it can't name is undefined, and the row waits.
   */
  private keysToFile(meta: SessionMeta, row: OutboxRow): (string | undefined)[] | null {
    if (!this.agentSigns(meta)) return null;
    return [...new Set([meta.agentRoot, ...(row.kind === "checkpoint" ? [row.signer] : [])])];
  }

  /**
   * Anchors one row. For an agent-key owner (`keys` set) each of its keys not yet filed is filed first, and the row is sent
   * only once they all are; every anchor, filings included, also draws on the Starter allowance. Filings count toward the
   * owner's daily anchors like any other.
   */
  private async anchorNetwork(ownerKey: string, sessionId: string, row: OutboxRow, deadline: number, keys: (string | undefined)[] | null): Promise<AnchorOutcome> {
    const day = this.today();
    let ledger: ShadowLedger;
    try {
      ledger = this.ledger();
    } catch {
      return { kind: "failed", failure: { kind: "Transient", code: "unavailable", retryAfterSeconds: null }, maybeWritten: row.sendStarted !== false };
    }
    // keysToFile names the session's root key first.
    const anchoring = this.anchoring(ledger, ownerKey, day, deadline, keys !== null, keys?.[0]);
    if (keys) {
      const held = await this.fileFirst(keys, anchoring, row);
      if (held) return held;
    }
    return anchorHash({
      ...anchoring, referenceId: referenceId(sessionId), hash: row.hash, label: row.kind === "start" ? START_LABEL : ANCHOR_LABEL,
      ledgerId: row.state === "pending" ? row.ledgerId : null, uncertain: row.sendStarted !== false,
    });
  }

  /**
   * What an anchor needs besides its own hash: the ledger, the budget (with the Starter allowance for an agent, and the share
   * of its root key's address), and the owner's daily anchors.
   */
  private anchoring(ledger: ShadowLedger, ownerKey: string, day: string, deadline: number, agent: boolean, root?: string): FilingLedger {
    const max = this.limits.maxAnchorsPerOwnerPerDay;
    const budget = this.budget();
    return {
      ledger, budget: agent && this.starterAnchors ? this.withStarter(budget, this.starterAnchors, this.sourceOf(root)) : budget,
      reserve: () => {
        if (this.store.bumpAnchors(ownerKey, day, 1, max) === null) throw new AnchorLimitError();
      },
      refund: () => {
        this.store.bumpAnchors(ownerKey, day, -1, max);
      },
      waitMs: this.limits.anchorWaitMs, tries: 3, backoffMs: [500, 1500], sleep: this.sleep, deadline,
    };
  }

  /**
   * Files a key's "replaced" or "revoked" event on Clockchain (agent-keys/routes.ts), as an anchor of the agent that owns
   * the key's root: it spends that owner's daily anchors and the Starter allowance like any agent anchor, and runs one filing
   * per key at a time. Recording the result in the book is the caller's job (fileKey leaves it so).
   */
  async fileAgentKeyEvent(fp: string, event: "replaced" | "revoked", extra: { newFp?: string } = {}): Promise<FilingResult> {
    const book = this.agentKeys;
    if (!book) throw new AgentKeyError("unavailable");
    const root = book.rootOf(fp);
    if (!root) throw new AgentKeyError("unknown_key");
    let ledger: ShadowLedger;
    try {
      ledger = this.ledger();
    } catch {
      return { state: "pending", failure: { kind: "Transient", code: "unavailable", retryAfterSeconds: null } };
    }
    const anchoring = this.anchoring(ledger, ownerKeyOf(`ak:${root}`), this.today(), Date.now() + ANCHOR_BUDGET_MS, true, root);
    return this.locks.run(`agent-key:${fp}`, () => fileKey(book, anchoring, fp, event, extra));
  }

  /** Files each of `keys` not yet filed, one filing per key at a time. Null when all are filed; else the outcome that holds the row. */
  private async fileFirst(keys: (string | undefined)[], anchoring: FilingLedger, row: OutboxRow): Promise<AnchorOutcome | null> {
    // The row wasn't sent, so whether it may have been is what it was before. A limit that stopped the filing is said as itself.
    const wait = (failure?: Failure): AnchorOutcome => ({
      kind: "failed", maybeWritten: row.sendStarted !== false,
      failure: failure && OWN_LIMITS.has(failure.code) ? failure : { kind: "Transient", code: "key_filing", retryAfterSeconds: null },
    });
    const book = this.agentKeys;
    if (!book) return wait();
    for (const fp of keys) {
      if (!fp) return wait();
      try {
        const filing = await this.locks.run(`agent-key:${fp}`, () => fileKey(book, anchoring, fp, "filed"));
        if (filing.state !== "filed") return wait(filing.failure);
      } catch {
        this.log("shadow_agent_key_filing_error", {});
        return wait();
      }
    }
    return null;
  }

  /**
   * The address an agent's root key first signed in from, as the book keeps it; none when the book can't say. Filing the
   * key fails closed on a book it can't read, so this needn't.
   */
  private sourceOf(root: string | undefined): string | undefined {
    if (!root) return undefined;
    try {
      return this.agentKeys?.get(root)?.source;
    } catch {
      return undefined;
    }
  }

  /**
   * The server's write budget with the Starter allowance on top, drawn on by `source`'s share too when there is one. A count
   * that can't be saved doesn't undo a write that landed.
   */
  private withStarter(budget: LogBudget, starter: StarterAnchors, source: string | undefined): LogBudget {
    return {
      check: () => {
        budget.check();
        starter.check(source);
      },
      record: () => {
        budget.record();
        try {
          starter.record(source);
        } catch {
          this.log("shadow_starter_count_unsaved", {});
        }
      },
      remaining: () => budget.remaining(),
      enabled: budget.enabled,
    };
  }

  /** Drains the session's outbox once; concurrent callers share the pass. Never holds the lock across the network. */
  private drain(ownerKey: string, sessionId: string, o: { deadline?: number; stopOnFailure?: boolean; asked?: boolean; held?: boolean } = {}): Promise<void> {
    const key = `${ownerKey}/${sessionId}`;
    const running = this.drains.get(key);
    if (running) return running;
    const p = this.drainOnce(ownerKey, sessionId, o).finally(() => this.drains.delete(key));
    this.drains.set(key, p);
    return p;
  }

  private async drainOnce(ownerKey: string, sessionId: string, o: { deadline?: number; stopOnFailure?: boolean; asked?: boolean; held?: boolean }): Promise<void> {
    const tried = new Set<string>();
    const deadline = o.deadline ?? Date.now() + ANCHOR_BUDGET_MS;
    for (;;) {
      if (Date.now() >= deadline) return; // What is left stays queued for the next call.
      const next = await this.session(ownerKey, sessionId, (meta) => {
        const row = nextRow(meta, tried, o.asked ? null : this.now().getTime(), o.held === true);
        if (!row) return null;
        // Owed on a network this server has left: never written to the new one.
        if (meta.network !== this.network) {
          for (const r of meta.outbox) if (r.state !== "failed") Object.assign(r, { state: "failed", lastErrorKind: "Permanent", lastErrorCode: "other_network" });
          this.store.writeMeta(meta);
          return null;
        }
        // Never write to Clockchain a receipt the record has no room to keep.
        if (meta.seq + 2 > this.maxEvents || meta.eventsBytes + 64 * 1024 > this.eventsMax) {
          row.state = "failed";
          row.lastErrorKind = "Permanent";
          row.lastErrorCode = "session_full";
          this.store.writeMeta(meta);
          return null;
        }
        const job = { ...row };
        const keys = this.keysToFile(meta, row);
        // On disk before the network call: a process that dies after the ledger write and before the receipt leaves this behind.
        if (row.sendStarted === false && !row.ledgerId) {
          row.sendStarted = true;
          this.store.writeMeta(meta);
        }
        return { job, keys };
      }).catch(() => null);
      if (!next) return;
      const { job, keys } = next;
      tried.add(job.id);
      const outcome = await this.anchorNetwork(ownerKey, sessionId, job, deadline, keys);
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
    // What held an agent's row (its key, or the Starter allowance) is over once the row is tried again; the outcome says what's next.
    if (row.lastErrorCode !== null && AGENT_HOLDS.has(row.lastErrorCode)) Object.assign(row, { lastErrorKind: null, lastErrorCode: null });
    if (outcome.kind === "anchored") {
      const receipt = receiptPayload(meta.sessionId, { ...outcome.receipt, submittedAt: outcome.receipt.submittedAt ?? row.submittedAt });
      const payload = row.kind === "start"
        ? { marker: "start", startHash: row.hash, ...receipt }
        : { marker: "checkpoint", checkpointHash: row.hash, checkpoint: row.body, ...receipt };
      const ev = this.appendStep(meta, "clockchain.anchored", "collector", payload, {}, false);
      meta.outbox = meta.outbox.filter((r) => r.id !== row.id);
      meta.anchors.push({ marker: row.kind, seq: ev.body.seq, hash: row.hash, count: row.body?.count ?? null, ...anchorFields({ ...outcome.receipt, submittedAt: receipt.submittedAt as string | null }) });
      if (meta.state === "closed" && row.body) this.supersede(meta, row.body.count);
    } else if (outcome.kind === "pending") {
      row.state = "pending";
      row.ledgerId = outcome.ledgerId;
      row.submittedAt = outcome.submittedAt ?? row.submittedAt;
      row.attempts++;
    } else if (outcome.kind === "unconfirmed") {
      // It may be on the ledger and the ledger won't say. It isn't paid for again, and it steps aside, so nothing queued behind it waits.
      row.lastErrorKind = outcome.failure.kind;
      row.lastErrorCode = "search_refused";
      row.attempts++;
      row.nextTryAt = this.retryAt(row);
    } else {
      const f = outcome.failure;
      row.lastErrorKind = f.kind;
      row.lastErrorCode = f.code;
      if (!outcome.maybeWritten) row.sendStarted = false;
      halt = f.kind === "Auth" || f.kind === "Credits" || f.code === "key_filing";
      // The session's other rows wait on the same key or allowance, so they say so too, unspent.
      if (AGENT_HOLDS.has(f.code))
        for (const r of meta.outbox)
          if (r !== row && r.state === "queued" && !r.ledgerId && (r.lastErrorCode === null || WAITING_CODES.has(r.lastErrorCode))) Object.assign(r, { lastErrorKind: f.kind, lastErrorCode: f.code });
      // A closed session has no later checkpoint to fall back on, so only a permanent refusal ends its rows; the rest back off.
      const closed = meta.state === "closed";
      if (closed) row.nextTryAt = this.retryAt(row);
      // Our own limits, and an agent's key still being filed, are not Clockchain failures: the row waits, and nothing goes into the record.
      if (!WAITING_CODES.has(f.code)) {
        row.attempts++;
        const failed = f.kind === "Permanent" || (!closed && row.attempts >= MAX_PASSES);
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

  /** When a failing row is next due: one sweep interval, doubling, up to the cap. A close's retry doesn't wait for it. */
  private retryAt(row: OutboxRow): string {
    const intervals = Math.min(2 ** Math.max(0, row.attempts - 1), MAX_RETRY_WAIT_INTERVALS);
    return new Date(this.now().getTime() + intervals * this.limits.sweepIntervalMs).toISOString();
  }

  /**
   * After a closed session's anchor lands, older checkpoints aren't worth an anchor: it covers all they cover, and the record
   * keeps every step's hash; what goes is the earlier block times they would have given those steps. A row no send ever
   * started for is dropped. A row that may have been written stays in the queue, marked and never sent again, because the
   * packet has to account for it: if that write did land, the ledger holds a record for this session, and the online check
   * fails on one the packet leaves out. A row with a ledger ID is already paid for, and is followed up.
   */
  private supersede(meta: SessionMeta, count: number): void {
    const older = (r: OutboxRow) => r.kind === "checkpoint" && (r.body?.count ?? 0) < count && !r.ledgerId;
    meta.outbox = meta.outbox.filter((r) => !(older(r) && r.sendStarted === false));
    for (const r of meta.outbox) if (older(r) && r.state !== "failed") Object.assign(r, { state: "failed", lastErrorKind: "Permanent", lastErrorCode: "superseded" });
  }

  private anchorView(meta: SessionMeta, hash: string, refused: { code: string; message: string } | null) {
    const a = meta.anchors.find((x) => x.hash === hash);
    if (a) return { status: "anchored", checkpoint_hash: hash, covers_steps: a.count, ledger_id: a.ledgerId, block: a.blockHeight, block_time: a.blockTime, submitted_at: a.submittedAt };
    const r = meta.outbox.find((x) => x.hash === hash);
    if (r) return { status: r.state === "failed" ? "failed" : r.lastErrorCode === "starter_limit" || r.lastErrorCode === "starter_source_limit" ? "over_limit" : "pending", checkpoint_hash: hash, covers_steps: r.body?.count ?? null, ledger_id: r.ledgerId, reason: reasonOf(r), note: r.state === "failed" ? `Not anchored. The record is intact${meta.state === "open" ? "; later checkpoints still bound it" : ""}.` : r.lastErrorCode === "search_refused" ? "Signed and recorded. Whether it reached Clockchain isn't known." : r.lastErrorCode !== null && AGENT_HOLDS.has(r.lastErrorCode) ? (heldSends(meta, r) ? `Signed and recorded. ${HELD_NOTE}` : "Signed and recorded. A later anchor covers these steps.") : "Signed and recorded; call shadow_checkpoint again later to anchor it." };
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

/** Whether a new session's start marker waits on its agent's key or the Starter allowance, which the hourly pass retries. */
function heldByAgent(meta: SessionMeta): boolean {
  return meta.outbox.some((r) => r.kind === "start" && r.lastErrorCode !== null && AGENT_HOLDS.has(r.lastErrorCode));
}

/** Why a new session's start marker waits, when one of our own limits or the agent's key holds it: added to start_anchor. */
function startHeld(meta: SessionMeta): { reason?: string } {
  const row = meta.outbox.find((r) => r.kind === "start" && r.lastErrorCode !== null && WAITING_CODES.has(r.lastErrorCode));
  const reason = row ? reasonOf(row) : null;
  return reason ? { reason } : {};
}

function reasonOf(r: OutboxRow): string | null {
  if (r.lastErrorCode === "search_refused") return "It may already be on Clockchain, and the ledger refused the search that would show it, so it hasn't been sent again.";
  if (r.lastErrorCode === "superseded") return "A later anchor covers these steps, so this one wasn't sent again.";
  if (!r.lastErrorKind && r.state !== "pending" && r.sendStarted === true) return "A send was started, and whether it reached Clockchain isn't known yet. The ledger is asked before it is sent again.";
  if (!r.lastErrorKind) return r.state === "pending" ? "Written to Clockchain; waiting for its block." : null;
  if (r.lastErrorCode === "anchor_limit") return "Today's anchor limit for your account is used up; it will be anchored on a later call.";
  if (r.lastErrorCode === "starter_limit") return STARTER_USED_UP;
  if (r.lastErrorCode === "starter_source_limit") return STARTER_SHARE_USED_UP;
  if (r.lastErrorCode === "key_filing") return FILING_FIRST;
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
