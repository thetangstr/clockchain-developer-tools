import { createHash } from "node:crypto";
import { existsSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";

import { createDurableJsonFile, DurableStateError, type DurableJsonFile } from "../handshake-core/durable-store.js";

import { nextDeadline, pendingTurn } from "./turns.js";

const STAGES = ["invited", "readiness_pending", "readiness_retry", "ready", "ready_failed", "consent_pending", "consented", "open", "closed", "revoked", "expired", "abandoned", "stalled"] as const;
const LEGAL: Record<string, readonly string[]> = {
  invited: ["readiness_pending"],
  readiness_pending: ["ready", "ready_failed", "readiness_retry"],
  readiness_retry: ["readiness_pending", "ready_failed"],
  ready: ["consent_pending"],
  consent_pending: ["consented"],
  consented: ["open"],
  open: ["closed", "revoked", "expired"],
};
const ROLES = ["initiator", "responder"];
const TERMINAL_STAGES = new Set(["ready_failed", "closed", "revoked", "expired", "abandoned", "stalled"]);
// Stages that end as "abandoned" when the session misses its open deadline. readiness_pending
// is excluded: it only lasts while a checklist evaluation is in flight.
const ABANDONABLE_STAGES = new Set(["invited", "readiness_retry", "ready", "consent_pending", "consented"]);
const TERMINAL_EVENTS = new Set(["ready_failed", "close", "revoke", "expire", "abandon", "turn_timeout"]);

// Terminal sessions are retained for post-hoc inspection up to this cap; the oldest
// are evicted (Map insertion order) so a long-lived process cannot grow unbounded.
export const TERMINAL_SESSION_RETENTION = 500;
// Non-terminal sessions that sit untouched longer than this are evicted — an
// abandoned invite must not pin store memory forever.
export const NON_TERMINAL_SESSION_TTL_MS = 24 * 60 * 60_000;
// Unclaimed invitations die after one hour; the secret is single-use anyway.
export const INVITATION_TTL_MS = 60 * 60_000;
// Bodies live in memory; a bounded channel still needs a bounded transcript.
export const MAX_MESSAGES_PER_SESSION = 10_000;
// After acceptance, both consents and channel_open must happen within this window, or
// the session ends as "abandoned". Before acceptance the deadline is the invitation TTL.
export const PRE_OPEN_TTL_MS = 60 * 60_000;
// Access tokens of evicted sessions are remembered (as digests, bounded FIFO) so a
// late caller learns SESSION_ENDED instead of a generic refusal.
export const ENDED_TOKEN_MEMORY = 10_000;
// A Responder whose readiness fails the checklist may correct it this many times in all
// (first claim included), within the invitation TTL.
export const READINESS_MAX_ATTEMPTS = 3;
// Timeline bounds: events per session (terminal events are always kept), and previews
// per session so an invitation holder cannot flood the timeline.
export const MAX_TIMELINE_EVENTS = 500;
export const MAX_PREVIEW_EVENTS = 20;
// Message bodies of an ended session are deleted this long after it ended; digests stay.
export const BODY_RETENTION_MS = 24 * 60 * 60_000;
// Bound on one session's durable file (a full channel is 10,000 messages of up to 16 KiB).
export const MAX_SESSION_FILE_BYTES = 192 * 1024 * 1024;
const SESSION_FILE_SCHEMA = "clockchain.standalone-handshake-session/v1";
const ENDED_TOKENS_SCHEMA = "clockchain.standalone-handshake-ended-tokens/v1";
const SESSION_ID_FILE = /^([0-9a-f-]{1,64})\.json$/;

function tokenDigest(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export class StandaloneIllegalTransitionError extends Error {
  constructor() {
    super("Standalone handshake illegal transition.");
    this.name = "StandaloneIllegalTransitionError";
  }
}

export class StandaloneAdmissionError extends Error {
  constructor(readonly reason: string) {
    super(`Standalone handshake admission refused: ${reason}`);
    this.name = "StandaloneAdmissionError";
  }
}

export function createStandaloneSessionStore(options: {
  now?: () => number;
  /** Cap on retained terminal-stage sessions; defaults to TERMINAL_SESSION_RETENTION. */
  terminalRetention?: number;
  /** Idle cap on non-terminal sessions; defaults to NON_TERMINAL_SESSION_TTL_MS. */
  sessionTtlMs?: number;
  /** Cap on unclaimed invitations; defaults to INVITATION_TTL_MS. */
  invitationTtlMs?: number;
  /** Cap on stored channel messages; defaults to MAX_MESSAGES_PER_SESSION. */
  maxMessagesPerSession?: number;
  /** Window from acceptance to channel_open; defaults to PRE_OPEN_TTL_MS. */
  preOpenTtlMs?: number;
  /**
   * Durable state directory (spec B2). Each session is one file under `sessions/`, the
   * source of truth for everything about it (stage, readiness, attempts, consents, turn
   * state, timeline, messages, anchors, closure pins, its unclaimed invitation and its
   * access-token digests); the in-memory indexes are rebuilt from those files at boot.
   * Memory-only when omitted.
   */
  stateDir?: string;
  coalesceMs?: number;
} = {}) {
  const now = options.now ?? Date.now;
  // Housekeeping (TTL eviction, invitation expiry) is resource management, not a
  // protocol time judgment — if the protocol clock is unavailable it degrades to
  // the wall clock rather than refusing to clean up.
  const housekeepingNow = () => {
    try {
      return now();
    } catch {
      return Date.now();
    }
  };
  const terminalRetention = options.terminalRetention ?? TERMINAL_SESSION_RETENTION;
  const sessionTtlMs = options.sessionTtlMs ?? NON_TERMINAL_SESSION_TTL_MS;
  const invitationTtlMs = options.invitationTtlMs ?? INVITATION_TTL_MS;
  const maxMessagesPerSession = options.maxMessagesPerSession ?? MAX_MESSAGES_PER_SESSION;
  const preOpenTtlMs = options.preOpenTtlMs ?? PRE_OPEN_TTL_MS;
  const sessions = new Map<string, any>();
  // Access-token digest -> session and role, so authenticating one caller never touches
  // (and never refreshes the idle timer of) any other session.
  const tokens = new Map<string, { sessionId: string; role: string }>();
  const endedTokens = new Set<string>();
  const invitations = new Map<string, { sessionId: string; expiresAtMs: number }>();
  // Pinned closure records: prepared before anchoring so retries produce the identical digest.
  // Kept beside (not on) the session objects, which stay read-only everywhere else.
  const pendingClosures = new Map<string, any>();

  // ---- Durability ---------------------------------------------------------------
  const stateDir = options.stateDir;
  const sessionDir = stateDir === undefined ? undefined : join(stateDir, "sessions");
  const sessionFiles = new Map<string, DurableJsonFile<any>>();

  function sessionFile(sessionId: string): DurableJsonFile<any> | undefined {
    if (sessionDir === undefined) return undefined;
    let file = sessionFiles.get(sessionId);
    if (file === undefined) {
      file = createDurableJsonFile({
        path: join(sessionDir, `${sessionId}.json`),
        schema: SESSION_FILE_SCHEMA,
        maxBytes: MAX_SESSION_FILE_BYTES,
        coalesceMs: options.coalesceMs,
        snapshot: () => serializeSession(sessions.get(sessionId)),
        validate: validateSessionRecord,
      });
      sessionFiles.set(sessionId, file);
    }
    return file;
  }

  // "now": the change was (or is about to be) reported to a client, so it is on disk
  // before the call returns. "soon": bookkeeping, coalesced to at most one write a second.
  function persist(session: any, kind: "now" | "soon" = "now"): void {
    if (session === undefined || !sessions.has(session.sessionId)) return;
    sessionFile(session.sessionId)?.save(kind);
  }

  const endedTokensFile: DurableJsonFile<string[]> | undefined = stateDir === undefined ? undefined : createDurableJsonFile({
    path: join(stateDir, "ended-tokens.json"),
    schema: ENDED_TOKENS_SCHEMA,
    maxBytes: 4 * 1024 * 1024,
    coalesceMs: options.coalesceMs,
    snapshot: () => [...endedTokens],
    validate: (value) => {
      if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !/^[0-9a-f]{64}$/.test(item))) throw new Error("bad ended tokens");
      return value as string[];
    },
  });

  function forgetSessionFile(sessionId: string): void {
    const file = sessionFiles.get(sessionId);
    file?.close();
    sessionFiles.delete(sessionId);
    if (sessionDir === undefined) return;
    for (const suffix of [".json", ".json.bak"]) {
      try { unlinkSync(join(sessionDir, `${sessionId}${suffix}`)); } catch { /* already gone */ }
    }
  }

  function requireSession(sessionId: string): any {
    const session = sessions.get(sessionId);
    if (!session) throw new StandaloneAdmissionError("NOT_OPEN");
    session.touchedAtMs = housekeepingNow();
    return session;
  }

  // Runs on createSession: drops stale invitations and idle non-terminal sessions,
  // then evicts the oldest terminal sessions while more than the retention cap are
  // terminal. An active session is never evicted to make room.
  function evictStaleSessions(): void {
    const current = housekeepingNow();
    for (const [secret, invitation] of invitations) {
      if (current >= invitation.expiresAtMs) invitations.delete(secret);
    }
    purgeEndedBodies(current);
    for (const [sessionId, session] of sessions) {
      if (!TERMINAL_STAGES.has(session.stage) && current - session.touchedAtMs > sessionTtlMs) dropSession(sessionId);
    }
    let terminal = 0;
    for (const session of sessions.values()) if (TERMINAL_STAGES.has(session.stage)) terminal += 1;
    for (const [sessionId, session] of sessions) {
      if (terminal <= terminalRetention) return;
      if (TERMINAL_STAGES.has(session.stage)) {
        dropSession(sessionId);
        terminal -= 1;
      }
    }
  }

  function isoNow(): string {
    return new Date(housekeepingNow()).toISOString();
  }

  // Append-only, bounded. Bodies never enter the timeline: callers pass digests only.
  function pushEvent(session: any, event: Record<string, unknown>): void {
    const type = String(event.type);
    const previews = type === "previewed" ? session.timeline.filter((item: any) => item.type === "previewed").length : 0;
    const full = session.timeline.length >= MAX_TIMELINE_EVENTS && !TERMINAL_EVENTS.has(type);
    if (full || previews >= MAX_PREVIEW_EVENTS) {
      session.timelineDropped += 1;
      return;
    }
    session.timeline.push(Object.freeze({ at: isoNow(), ...event }));
  }

  function dropSession(sessionId: string): void {
    const session = sessions.get(sessionId);
    for (const role of ROLES) {
      const digest = session?.auth[role];
      if (typeof digest !== "string") continue;
      tokens.delete(digest);
      endedTokens.add(digest);
      if (endedTokens.size > ENDED_TOKEN_MEMORY) endedTokens.delete(endedTokens.values().next().value as string);
    }
    if (session?.invitation !== undefined) invitations.delete(session.invitation.digest);
    sessions.delete(sessionId);
    pendingClosures.delete(sessionId);
    forgetSessionFile(sessionId);
    endedTokensFile?.save("soon");
  }

  function markEnded(session: any): void {
    if (session.endedAtMs === undefined) session.endedAtMs = housekeepingNow();
  }

  // Bodies are kept while a session can still show them, and deleted BODY_RETENTION_MS
  // after it ended. Digests, kinds and seqs stay, so the timeline and cursors still hold.
  function purgeEndedBodies(current: number): void {
    for (const session of sessions.values()) {
      if (session.bodiesPurged || session.endedAtMs === undefined || current - session.endedAtMs < BODY_RETENTION_MS) continue;
      session.messages = session.messages.map((message: any) => Object.freeze({ ...message, body: null }));
      session.bodiesPurged = true;
      persist(session, "now");
    }
  }

  // Applies the session's clocks through the single nextDeadline() rule (turns.ts): an open
  // channel expires, a session that never opened is abandoned, or a turn deadline passes
  // and the session ends as stalled. Only one of them can ever fire.
  // Sessions ended by a clock during this call; written by settle() below.
  const persistAfterSettle = new Set<any>();

  function expireIfDue(session: any): void {
    expireIfDueInner(session);
    for (const ended of persistAfterSettle) persist(ended, "now");
    persistAfterSettle.clear();
  }

  function expireIfDueInner(session: any): void {
    const deadline = nextDeadline(session);
    if (deadline === undefined) return;
    // Channel time is protocol time; pre-open deadlines are housekeeping time.
    const current = session.stage === "open" ? now() : housekeepingNow();
    if (current < deadline.atMs) return;
    // A closure pinned before the deadline wins: channel_close/revoke is mid-anchor, so the
    // session completes as closed/revoked and never also stalls (one closure anchor only).
    if (deadline.outcome === "stalled" && pendingClosures.has(session.sessionId)) return;
    const fromStage = session.stage;
    if (deadline.outcome === "abandoned" && !ABANDONABLE_STAGES.has(fromStage)) return;
    markEnded(session);
    persistAfterSettle.add(session);
    if (deadline.outcome === "expired") {
      session.stage = "expired";
      pushEvent(session, { type: "expire" });
    } else if (deadline.outcome === "abandoned") {
      session.abandonedFrom = fromStage;
      session.stage = "abandoned";
      pushEvent(session, { type: "abandon", fromStage });
    } else {
      session.stalled = Object.freeze({ reason: deadline.reason, role: deadline.stalledRole, atMs: deadline.atMs, fromStage });
      session.stage = "stalled";
      pushEvent(session, { type: "turn_timeout", reason: deadline.reason, stalledRole: deadline.stalledRole, fromStage });
    }
  }

  // A new turn: whose move it is (or what the move is) changed. Turns on an open channel
  // run on the channel's clock (protocol time), like its expiry; earlier turns on
  // housekeeping time, like abandonment.
  function startTurn(session: any): void {
    let current = housekeepingNow();
    if (session.stage === "open") {
      try {
        current = now();
      } catch {
        // Protocol clock unavailable: fall back to housekeeping time.
      }
    }
    session.turnStartedAtMs = current;
    session.turnSeq += 1;
  }

  function other(role: string): string {
    return role === "initiator" ? "responder" : "initiator";
  }

  // ---- Serialization ------------------------------------------------------------
  // Sets become arrays; the webhook signing secret is not written (it is re-derived from
  // the server secret when needed); access tokens and invitation secrets are digests only.
  function serializeSession(session: any): any {
    if (session === undefined) return undefined;
    const notify = Object.fromEntries(Object.entries(session.notify ?? {}).map(([role, value]: [string, any]) => [role, { webhookUrl: value.webhookUrl }]));
    return { ...session, prompted: [...session.prompted], noticeKeys: [...session.noticeKeys], notify };
  }

  function validateSessionRecord(value: unknown): any {
    const record = value as any;
    if (record === null || typeof record !== "object" || typeof record.sessionId !== "string" || !(STAGES as readonly string[]).includes(record.stage)) {
      throw new Error("not a session record");
    }
    for (const key of ["messages", "timeline", "attempts", "anchors", "prompted", "noticeKeys"]) {
      if (!Array.isArray(record[key])) throw new Error(`session.${key} must be an array`);
    }
    for (const key of ["terms", "consents", "auth", "lastSeenAtMs", "seenEventCount", "notify", "lastNoticeAtMs", "pendingNudge"]) {
      if (record[key] === null || typeof record[key] !== "object") throw new Error(`session.${key} must be an object`);
    }
    return record;
  }

  const rolledBack = new Set<string>();

  function restoreSession(record: any): void {
    const session = { ...record, prompted: new Set(record.prompted), noticeKeys: new Set(record.noticeKeys) };
    // A readiness attempt that was evaluating when the process stopped never completed:
    // roll it back and give back the invitation it claimed, so the retry just works.
    if (session.stage === "readiness_pending" && session.attemptInFlight !== undefined && session.attemptInFlight !== null) {
      const inFlight = session.attemptInFlight;
      session.stage = inFlight.previousStage;
      session.responderReadiness = inFlight.previousReadiness;
      if (inFlight.invitationDigest) session.invitation = { digest: inFlight.invitationDigest, expiresAtMs: inFlight.invitationExpiresAtMs };
      session.attemptInFlight = undefined;
      pushEvent(session, { type: "attempt_interrupted", resumedStage: session.stage });
      rolledBack.add(session.sessionId);
    }
    sessions.set(session.sessionId, session);
    for (const role of ROLES) if (typeof session.auth[role] === "string") tokens.set(session.auth[role], { sessionId: session.sessionId, role });
    if (session.invitation) invitations.set(session.invitation.digest, { sessionId: session.sessionId, expiresAtMs: session.invitation.expiresAtMs });
    if (session.pendingClosure) pendingClosures.set(session.sessionId, session.pendingClosure);
  }

  if (sessionDir !== undefined) {
    const ids = new Set<string>();
    if (existsSync(sessionDir)) {
      for (const name of readdirSync(sessionDir)) {
        const match = SESSION_ID_FILE.exec(name.replace(/\.bak$/, ""));
        if (match) ids.add(match[1]);
      }
    }
    for (const sessionId of ids) {
      try {
        const record = sessionFile(sessionId)!.load();
        if (record !== undefined && record.sessionId === sessionId) restoreSession(record);
      } catch (error) {
        // One unreadable session never takes the others down; it stays on disk for an operator.
        if (!(error instanceof DurableStateError)) throw error;
        sessionFiles.get(sessionId)?.close();
        sessionFiles.delete(sessionId);
        console.error(JSON.stringify({ event: "handshake_state_session_unreadable", sessionId }));
      }
    }
    for (const digest of endedTokensFile?.load() ?? []) endedTokens.add(digest);
    // Sessions rolled back at boot are written back at once; eviction and body retention
    // run as they would on the next new session.
    for (const sessionId of rolledBack) persist(sessions.get(sessionId));
    evictStaleSessions();
  }

  return {
    /** Writes coalesced changes now and stops timers (tests, shutdown). */
    close(): void {
      for (const file of sessionFiles.values()) {
        file.flush();
        file.close();
      }
      endedTokensFile?.flush();
      endedTokensFile?.close();
    },

    createSession(input: { sessionId: string; terms: any; termsDigest: string; initiatorReadiness: any }): void {
      const createdAtMs = housekeepingNow();
      const session = {
        sessionId: input.sessionId,
        terms: input.terms,
        termsDigest: input.termsDigest,
        initiatorReadiness: input.initiatorReadiness,
        responderReadiness: undefined,
        checklist: undefined,
        consents: {},
        auth: {},
        stage: "invited",
        openedAtMs: undefined,
        expiresAtMs: undefined,
        closedBy: undefined,
        messages: [],
        seq: 0,
        anchors: [],
        prompted: new Set<string>(),
        attempts: [] as any[],
        timeline: [] as any[],
        timelineDropped: 0,
        abandonedFrom: undefined,
        invitationExpiresAtMs: createdAtMs + invitationTtlMs,
        openDeadlineMs: createdAtMs + invitationTtlMs,
        touchedAtMs: createdAtMs,
        // Active facilitation (F1-F4).
        turnStartedAtMs: createdAtMs,
        turnSeq: 0,
        lastSeenAtMs: { initiator: createdAtMs } as Record<string, number>,
        seenEventCount: { initiator: 1 } as Record<string, number>,
        stallFlag: undefined as undefined | { role: string; turn: number },
        stalled: undefined,
        notify: {} as Record<string, { webhookUrl: string; secret: string }>,
        noticeKeys: new Set<string>(),
        lastNoticeAtMs: {} as Record<string, number>,
        pendingNudge: {} as Record<string, string>,
        // Durability (B2).
        invitation: undefined as undefined | { digest: string; expiresAtMs: number },
        pendingClosure: undefined,
        attemptInFlight: undefined,
        endedAtMs: undefined as undefined | number,
        bodiesPurged: false,
      };
      sessions.set(input.sessionId, session);
      pushEvent(session, { type: "invited", termsDigest: input.termsDigest });
      persist(session);
      evictStaleSessions();
    },

    // A restored invitation keeps its original expiry when one is given.
    // Invitations are held by digest of their secret, in memory and on disk.
    putInvitation(input: { secret: string; sessionId: string; expiresAtMs?: number }): void {
      const digest = tokenDigest(input.secret);
      const record = { sessionId: input.sessionId, expiresAtMs: input.expiresAtMs ?? housekeepingNow() + invitationTtlMs };
      invitations.set(digest, record);
      const session = sessions.get(input.sessionId);
      if (session !== undefined) {
        session.invitation = { digest, expiresAtMs: record.expiresAtMs };
        persist(session);
      }
    },

    // Reads an unclaimed, unexpired invitation without claiming it.
    peekInvitation(secret: string): { sessionId: string; expiresAtMs: number } | undefined {
      const invitation = invitations.get(tokenDigest(secret));
      if (invitation === undefined || housekeepingNow() >= invitation.expiresAtMs) return undefined;
      return { ...invitation };
    },

    claimInvitation(secret: string): string | undefined {
      const digest = tokenDigest(secret);
      const invitation = invitations.get(digest);
      if (invitation === undefined) return undefined;
      invitations.delete(digest);
      const session = sessions.get(invitation.sessionId);
      if (session?.invitation?.digest === digest) {
        session.invitation = undefined;
        // Coalesced on purpose: the accept path records its attempt (with this invitation's
        // digest, for rollback) in the same tick, and that write carries the claim with it.
        persist(session, "soon");
      }
      if (housekeepingNow() >= invitation.expiresAtMs) return undefined;
      return invitation.sessionId;
    },

    getSession(sessionId: string): any {
      const session = sessions.get(sessionId);
      if (!session) return undefined;
      expireIfDue(session);
      session.touchedAtMs = housekeepingNow();
      return session;
    },

    sessionIds(): string[] {
      return [...sessions.keys()];
    },

    requireSession,

    // Resolves an access token to its session and role through the digest index. Only the
    // matching session is read (and its idle timer refreshed). A token of a session that
    // was evicted refuses with SESSION_ENDED; an unknown token returns undefined.
    authenticateToken(token: string): { session: any; role: string } | undefined {
      const digest = tokenDigest(token);
      const entry = tokens.get(digest);
      if (entry === undefined) {
        if (endedTokens.has(digest)) throw new StandaloneAdmissionError("SESSION_ENDED");
        return undefined;
      }
      const session = this.getSession(entry.sessionId);
      if (!session || session.auth[entry.role] !== digest) return undefined;
      return { session, role: entry.role };
    },

    authenticate(sessionId: string, token: string): string | undefined {
      const session = this.getSession(sessionId);
      if (!session) return undefined;
      const digest = tokenDigest(token);
      for (const role of ROLES) if (session.auth[role] !== undefined && session.auth[role] === digest) return role;
      return undefined;
    },

    setAccessToken(sessionId: string, role: string, token: string): void {
      // Only digests of access tokens are kept, in memory and on disk.
      const session = requireSession(sessionId);
      if (typeof session.auth[role] === "string") tokens.delete(session.auth[role]);
      const digest = tokenDigest(token);
      session.auth[role] = digest;
      tokens.set(digest, { sessionId, role });
      persist(session);
    },

    setStage(sessionId: string, stage: string): void {
      const session = requireSession(sessionId);
      if (!(STAGES as readonly string[]).includes(stage) || !LEGAL[session.stage]?.includes(stage)) throw new StandaloneIllegalTransitionError();
      session.stage = stage;
      startTurn(session);
      // Accepted: consent and channel_open now have their own window.
      if (stage === "ready") session.openDeadlineMs = housekeepingNow() + preOpenTtlMs;
      if (TERMINAL_STAGES.has(stage)) markEnded(session);
      persist(session);
    },

    // Narrow escape hatch for the coordinator's accept path: when checklist
    // evaluation dies mid-flight (a transient infra error, never a completed
    // evaluation), the session is rolled back to "invited" so the responder can
    // claim the restored invitation again. A session that already holds a
    // checklist result can never go back — ready_failed stays terminal.
    resetToInvited(sessionId: string): void {
      const session = requireSession(sessionId);
      if (session.stage !== "readiness_pending" || session.checklist !== undefined) throw new StandaloneIllegalTransitionError();
      session.stage = "invited";
      session.responderReadiness = undefined;
      persist(session);
    },

    // Rolls an attempt whose checklist evaluation died mid-flight back to where it started
    // (invited, or readiness_retry with the previous readiness), without counting it.
    rollbackAttempt(sessionId: string, previous: { stage: string; readiness: any }): void {
      const session = requireSession(sessionId);
      if (session.stage !== "readiness_pending" || (previous.stage !== "invited" && previous.stage !== "readiness_retry")) throw new StandaloneIllegalTransitionError();
      session.stage = previous.stage;
      session.responderReadiness = previous.readiness;
      session.attemptInFlight = undefined;
      persist(session);
    },

    // Recorded before a readiness attempt starts, so a restart mid-evaluation can roll the
    // session back (and give back the invitation it claimed) instead of leaving it stuck in
    // readiness_pending: the client's interrupted call is then simply retryable.
    beginAttempt(sessionId: string, input: { previousStage: string; invitationSecret?: string }): void {
      const session = requireSession(sessionId);
      session.attemptInFlight = {
        previousStage: input.previousStage,
        previousReadiness: session.responderReadiness,
        invitationDigest: input.invitationSecret === undefined ? undefined : tokenDigest(input.invitationSecret),
        invitationExpiresAtMs: session.invitationExpiresAtMs,
      };
      persist(session);
    },

    // Records a completed checklist attempt and its timeline event.
    recordAttempt(sessionId: string, attempt: { passed: boolean; codes: readonly string[] }): number {
      const session = requireSession(sessionId);
      session.attempts.push(Object.freeze({ passed: attempt.passed, codes: Object.freeze([...attempt.codes]) }));
      pushEvent(session, { type: "attempt", attempt: session.attempts.length, passed: attempt.passed, codes: [...attempt.codes] });
      session.attemptInFlight = undefined;
      persist(session);
      return session.attempts.length;
    },

    appendEvent(sessionId: string, event: Record<string, unknown>): void {
      const session = requireSession(sessionId);
      pushEvent(session, event);
      persist(session, "soon");
    },

    // Timeline events from index `from` on (F2 catch-up).
    eventsSince(sessionId: string, from: number): readonly any[] {
      return requireSession(sessionId).timeline.slice(from);
    },

    timeline(sessionId: string): { events: readonly any[]; dropped: number } | undefined {
      const session = sessions.get(sessionId);
      if (!session) return undefined;
      expireIfDue(session);
      return Object.freeze({ events: Object.freeze([...session.timeline]), dropped: session.timelineDropped });
    },

    // Summaries of every retained session, for an operator view. Reads do not refresh idle timers.
    listSessions(): readonly any[] {
      return [...sessions.values()].map((session) => {
        expireIfDue(session);
        const events = session.timeline;
        return Object.freeze({
          sessionId: session.sessionId,
          stage: session.stage,
          termsDigest: session.termsDigest,
          createdAt: events[0]?.at,
          lastEventAt: events[events.length - 1]?.at,
          eventCount: events.length,
          attempts: session.attempts.length,
          messageCount: session.messages.length,
        });
      });
    },

    setResponderReadiness(sessionId: string, readiness: any): void {
      requireSession(sessionId).responderReadiness = readiness;
      persist(requireSession(sessionId), "soon");
    },

    setChecklist(sessionId: string, result: any): void {
      requireSession(sessionId).checklist = result;
      persist(requireSession(sessionId), "soon");
    },

    setConsent(sessionId: string, role: string, consentDigest: string): void {
      const session = requireSession(sessionId);
      session.consents[role] = consentDigest;
      startTurn(session);
      persist(session, "now");
    },

    bothConsented(sessionId: string): boolean {
      const session = requireSession(sessionId);
      return ROLES.every((role) => typeof session.consents[role] === "string" && session.consents[role].length === 64);
    },

    openChannel(sessionId: string, times: { openedAtMs: number; expiresAtMs: number }): void {
      const session = requireSession(sessionId);
      session.openedAtMs = times.openedAtMs;
      session.expiresAtMs = times.expiresAtMs;
      // The first open-channel turn starts when the channel's clock does.
      session.turnStartedAtMs = times.openedAtMs;
      persist(session, "now");
    },

    admitMessage(sessionId: string, role: string, kind: string, body: string): any {
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      if (session.stage === "expired") throw new StandaloneAdmissionError("EXPIRED");
      if (session.stage === "revoked") throw new StandaloneAdmissionError("REVOKED");
      if (session.stage !== "open") throw new StandaloneAdmissionError("NOT_OPEN");
      if (!session.terms.channelLimits.messageKinds.includes(kind)) throw new StandaloneAdmissionError("SCOPE_VIOLATION");
      if (typeof body !== "string" || body.length === 0) throw new StandaloneAdmissionError("MALFORMED");
      if (Buffer.byteLength(body, "utf8") > Number(session.terms.channelLimits.maxMessageBytes)) {
        throw new StandaloneAdmissionError("TOO_LARGE");
      }
      if (session.messages.length >= maxMessagesPerSession) throw new StandaloneAdmissionError("CHANNEL_FULL");
      session.seq += 1;
      const message = {
        sessionId,
        seq: session.seq,
        kind,
        fromRole: role,
        toRole: other(role),
        bodyDigest: createHash("sha256").update(body, "utf8").digest("hex"),
        sentAtMs: Math.floor(now()),
        body,
      };
      session.messages.push(message);
      startTurn(session);
      pushEvent(session, { type: "message", seq: message.seq, kind, fromRole: role, bodyDigest: message.bodyDigest });
      persist(session);
      return message;
    },

    // Messages addressed to `role`. With `afterSeq`, only those with seq > afterSeq, so a
    // caller holding a cursor (the highest seq it has seen) reads just what is new.
    readMessages(sessionId: string, role: string, afterSeq = 0): readonly any[] {
      if (!Number.isSafeInteger(afterSeq) || afterSeq < 0) throw new StandaloneAdmissionError("MALFORMED");
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      return session.messages
        .filter((message: any) => message.toRole === role && message.seq > afterSeq)
        .map((message: any) => Object.freeze({ ...message }));
    },

    // F1: any authenticated call by `role`. Returns when it was last seen before this call and
    // how long the timeline was then (F2 counts what happened after that point).
    // A role reported as stalled that comes back gets a "resumed" event.
    markSeen(sessionId: string, role: string): { atMs: number | undefined; eventCount: number } {
      const session = requireSession(sessionId);
      const previous = session.lastSeenAtMs[role];
      const eventCount = session.seenEventCount[role] ?? 0;
      session.lastSeenAtMs[role] = housekeepingNow();
      session.seenEventCount[role] = session.timeline.length;
      if (session.stallFlag?.role === role) {
        pushEvent(session, { type: "resumed", role, silentMs: session.lastSeenAtMs[role] - (previous ?? session.lastSeenAtMs[role]) });
        session.stallFlag = undefined;
      }
      persist(session, "soon");
      return { atMs: previous, eventCount };
    },

    // Records (once per turn) that `role` was reported stalled to its counterparty.
    flagStall(sessionId: string, role: string, turn: number, pendingAction: string): void {
      const session = requireSession(sessionId);
      if (session.stallFlag?.role === role && session.stallFlag.turn === turn) return;
      session.stallFlag = { role, turn };
      pushEvent(session, { type: "stalled", role, pendingAction });
      persist(session, "soon");
    },

    pendingTurn(sessionId: string) {
      return pendingTurn(requireSession(sessionId));
    },

    // F4: a role's own webhook. Never part of readiness, status, preview or the timeline.
    setNotify(sessionId: string, role: string, notify: { webhookUrl: string; secret: string }): void {
      requireSession(sessionId).notify[role] = Object.freeze({ ...notify });
      persist(requireSession(sessionId), "now");
    },

    getNotify(sessionId: string, role: string): { webhookUrl: string; secret: string } | undefined {
      return requireSession(sessionId).notify[role];
    },

    // Claims the right to send one notice of `kind` to `role` for the current turn. At most
    // once per (turn, kind), and never twice to one role within minIntervalMs.
    claimNotice(sessionId: string, role: string, kind: string, minIntervalMs: number): boolean {
      const session = requireSession(sessionId);
      const key = `${role}:${kind}:${session.turnSeq}`;
      const current = housekeepingNow();
      if (session.noticeKeys.has(key)) return false;
      if (session.lastNoticeAtMs[role] !== undefined && current - session.lastNoticeAtMs[role] < minIntervalMs) return false;
      session.noticeKeys.add(key);
      session.lastNoticeAtMs[role] = current;
      persist(session, "soon");
      return true;
    },

    // handshake_nudge: at most once per turn per nudging role.
    claimNudge(sessionId: string, byRole: string): boolean {
      const session = requireSession(sessionId);
      const key = `nudge:${byRole}:${session.turnSeq}`;
      if (session.noticeKeys.has(key)) return false;
      session.noticeKeys.add(key);
      persist(session, "soon");
      return true;
    },

    setPendingNudge(sessionId: string, toRole: string, fromRole: string): void {
      requireSession(sessionId).pendingNudge[toRole] = fromRole;
      persist(requireSession(sessionId), "soon");
    },

    takePendingNudge(sessionId: string, role: string): string | undefined {
      const session = requireSession(sessionId);
      const from = session.pendingNudge[role];
      if (from !== undefined) {
        delete session.pendingNudge[role];
        persist(session, "soon");
      }
      return from;
    },

    // An actionable prompt (e.g. the Initiator's "send first", or a fix_readiness for one
    // attempt) has been delivered once; handshake_next holds repeats of it.
    markPrompted(sessionId: string, key: string): void {
      requireSession(sessionId).prompted.add(key);
      persist(requireSession(sessionId), "soon");
    },

    wasPrompted(sessionId: string, key: string): boolean {
      return requireSession(sessionId).prompted.has(key);
    },

    // Highest seq admitted on the channel so far (0 before the first message).
    lastSeq(sessionId: string): number {
      return requireSession(sessionId).seq;
    },

    // Ledger anchors witnessed for this session (opening transitions, then closure),
    // kept so a terminal next-action can report them to either role.
    addAnchors(sessionId: string, anchors: readonly any[]): void {
      const session = requireSession(sessionId);
      session.anchors = [...session.anchors, ...anchors.map((anchor) => Object.freeze({ ...anchor }))];
      persist(session, "now");
    },

    anchors(sessionId: string): readonly any[] {
      return Object.freeze([...requireSession(sessionId).anchors]);
    },

    status(sessionId: string): any {
      const session = this.getSession(sessionId);
      if (!session) return undefined;
      return Object.freeze({
        sessionId: session.sessionId,
        reference: session.terms.reference,
        stage: session.stage,
        // Frozen copies: no live reference into the store's session state escapes.
        checklist: session.checklist === undefined ? undefined : Object.freeze({ ...session.checklist }),
        consented: { initiator: session.consents.initiator !== undefined, responder: session.consents.responder !== undefined },
        openedAtMs: session.openedAtMs,
        expiresAtMs: session.expiresAtMs,
        remainingMs: session.stage === "open" ? Math.max(0, Math.floor(session.expiresAtMs - now())) : 0,
        scope: Object.freeze({ ...session.terms.channelLimits }),
        messageCount: session.messages.length,
        closedBy: session.closedBy,
      });
    },

    closeChannel(sessionId: string, role: string): void {
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (session.stage !== "open") throw new StandaloneAdmissionError("NOT_OPEN");
      session.stage = "closed";
      session.closedBy = role;
      markEnded(session);
      persist(session);
    },

    pendingClosure(sessionId: string): Readonly<Record<string, any>> | undefined {
      return pendingClosures.get(sessionId);
    },

    // The pin is durable before anchoring starts, so a restart mid-anchor retries the
    // byte-identical record (same closedAtMs) and the ledger's idempotent lookup finds it.
    setPendingClosure(sessionId: string, record: Readonly<Record<string, any>>): void {
      const session = requireSession(sessionId);
      const existing = pendingClosures.get(sessionId);
      // A pin is only replaced by the same outcome+role (an idempotent retry). A different
      // outcome or role while a pin exists refuses rather than silently re-dating — and
      // re-anchoring — a different record under the same closure reference.
      if (existing !== undefined && (existing.outcome !== record.outcome || existing.byRole !== record.byRole)) {
        throw new StandaloneAdmissionError("CLOSURE_PENDING");
      }
      pendingClosures.set(sessionId, record);
      session.pendingClosure = record;
      persist(session);
    },

    clearPendingClosure(sessionId: string): void {
      pendingClosures.delete(sessionId);
      const session = sessions.get(sessionId);
      if (session !== undefined) session.pendingClosure = undefined;
      persist(sessions.get(sessionId), "now");
    },

    revokeChannel(sessionId: string, role: string): void {
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (session.stage !== "open") throw new StandaloneAdmissionError("NOT_OPEN");
      session.stage = "revoked";
      session.closedBy = role;
      markEnded(session);
      persist(session);
    },
  };
}
