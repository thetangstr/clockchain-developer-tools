import { createHash } from "node:crypto";

const STAGES = ["invited", "readiness_pending", "readiness_retry", "ready", "ready_failed", "consent_pending", "consented", "open", "closed", "revoked", "expired", "abandoned"] as const;
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
const TERMINAL_STAGES = new Set(["ready_failed", "closed", "revoked", "expired", "abandoned"]);
// Stages that end as "abandoned" when the session misses its open deadline. readiness_pending
// is excluded: it only lasts while a checklist evaluation is in flight.
const ABANDONABLE_STAGES = new Set(["invited", "readiness_retry", "ready", "consent_pending", "consented"]);
const TERMINAL_EVENTS = new Set(["ready_failed", "close", "revoke", "expire", "abandon"]);

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
      const token = session?.auth[role];
      if (typeof token !== "string") continue;
      const digest = tokenDigest(token);
      tokens.delete(digest);
      endedTokens.add(digest);
      if (endedTokens.size > ENDED_TOKEN_MEMORY) endedTokens.delete(endedTokens.values().next().value as string);
    }
    sessions.delete(sessionId);
    pendingClosures.delete(sessionId);
  }

  // Applies the session's clocks: an open channel expires at expiresAtMs, and a session
  // that never opened is abandoned at its open deadline.
  function expireIfDue(session: any): void {
    if (session.stage === "open" && now() >= session.expiresAtMs) {
      session.stage = "expired";
      pushEvent(session, { type: "expire" });
    } else if (ABANDONABLE_STAGES.has(session.stage) && housekeepingNow() >= session.openDeadlineMs) {
      session.abandonedFrom = session.stage;
      session.stage = "abandoned";
      pushEvent(session, { type: "abandon", fromStage: session.abandonedFrom });
    }
  }

  function other(role: string): string {
    return role === "initiator" ? "responder" : "initiator";
  }

  return {
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
      };
      sessions.set(input.sessionId, session);
      pushEvent(session, { type: "invited", termsDigest: input.termsDigest });
      evictStaleSessions();
    },

    // A restored invitation keeps its original expiry when one is given.
    putInvitation(input: { secret: string; sessionId: string; expiresAtMs?: number }): void {
      invitations.set(input.secret, { sessionId: input.sessionId, expiresAtMs: input.expiresAtMs ?? housekeepingNow() + invitationTtlMs });
    },

    // Reads an unclaimed, unexpired invitation without claiming it.
    peekInvitation(secret: string): { sessionId: string; expiresAtMs: number } | undefined {
      const invitation = invitations.get(secret);
      if (invitation === undefined || housekeepingNow() >= invitation.expiresAtMs) return undefined;
      return { ...invitation };
    },

    claimInvitation(secret: string): string | undefined {
      const invitation = invitations.get(secret);
      if (invitation === undefined) return undefined;
      invitations.delete(secret);
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
      if (!session || session.auth[entry.role] !== token) return undefined;
      return { session, role: entry.role };
    },

    authenticate(sessionId: string, token: string): string | undefined {
      const session = this.getSession(sessionId);
      if (!session) return undefined;
      for (const role of ROLES) if (session.auth[role] !== undefined && session.auth[role] === token) return role;
      return undefined;
    },

    setAccessToken(sessionId: string, role: string, token: string): void {
      const session = requireSession(sessionId);
      if (typeof session.auth[role] === "string") tokens.delete(tokenDigest(session.auth[role]));
      session.auth[role] = token;
      tokens.set(tokenDigest(token), { sessionId, role });
    },

    setStage(sessionId: string, stage: string): void {
      const session = requireSession(sessionId);
      if (!(STAGES as readonly string[]).includes(stage) || !LEGAL[session.stage]?.includes(stage)) throw new StandaloneIllegalTransitionError();
      session.stage = stage;
      // Accepted: consent and channel_open now have their own window.
      if (stage === "ready") session.openDeadlineMs = housekeepingNow() + preOpenTtlMs;
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
    },

    // Rolls an attempt whose checklist evaluation died mid-flight back to where it started
    // (invited, or readiness_retry with the previous readiness), without counting it.
    rollbackAttempt(sessionId: string, previous: { stage: string; readiness: any }): void {
      const session = requireSession(sessionId);
      if (session.stage !== "readiness_pending" || (previous.stage !== "invited" && previous.stage !== "readiness_retry")) throw new StandaloneIllegalTransitionError();
      session.stage = previous.stage;
      session.responderReadiness = previous.readiness;
    },

    // Records a completed checklist attempt and its timeline event.
    recordAttempt(sessionId: string, attempt: { passed: boolean; codes: readonly string[] }): number {
      const session = requireSession(sessionId);
      session.attempts.push(Object.freeze({ passed: attempt.passed, codes: Object.freeze([...attempt.codes]) }));
      pushEvent(session, { type: "attempt", attempt: session.attempts.length, passed: attempt.passed, codes: [...attempt.codes] });
      return session.attempts.length;
    },

    appendEvent(sessionId: string, event: Record<string, unknown>): void {
      pushEvent(requireSession(sessionId), event);
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
    },

    setChecklist(sessionId: string, result: any): void {
      requireSession(sessionId).checklist = result;
    },

    setConsent(sessionId: string, role: string, consentDigest: string): void {
      const session = requireSession(sessionId);
      session.consents[role] = consentDigest;
    },

    bothConsented(sessionId: string): boolean {
      const session = requireSession(sessionId);
      return ROLES.every((role) => typeof session.consents[role] === "string" && session.consents[role].length === 64);
    },

    openChannel(sessionId: string, times: { openedAtMs: number; expiresAtMs: number }): void {
      const session = requireSession(sessionId);
      session.openedAtMs = times.openedAtMs;
      session.expiresAtMs = times.expiresAtMs;
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
      pushEvent(session, { type: "message", seq: message.seq, kind, fromRole: role, bodyDigest: message.bodyDigest });
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

    // An actionable prompt (e.g. the Initiator's "send first", or a fix_readiness for one
    // attempt) has been delivered once; handshake_next holds repeats of it.
    markPrompted(sessionId: string, key: string): void {
      requireSession(sessionId).prompted.add(key);
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
    },

    pendingClosure(sessionId: string): Readonly<Record<string, any>> | undefined {
      return pendingClosures.get(sessionId);
    },

    setPendingClosure(sessionId: string, record: Readonly<Record<string, any>>): void {
      requireSession(sessionId);
      const existing = pendingClosures.get(sessionId);
      // A pin is only replaced by the same outcome+role (an idempotent retry). A different
      // outcome or role while a pin exists refuses rather than silently re-dating — and
      // re-anchoring — a different record under the same closure reference.
      if (existing !== undefined && (existing.outcome !== record.outcome || existing.byRole !== record.byRole)) {
        throw new StandaloneAdmissionError("CLOSURE_PENDING");
      }
      pendingClosures.set(sessionId, record);
    },

    clearPendingClosure(sessionId: string): void {
      pendingClosures.delete(sessionId);
    },

    revokeChannel(sessionId: string, role: string): void {
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (session.stage !== "open") throw new StandaloneAdmissionError("NOT_OPEN");
      session.stage = "revoked";
      session.closedBy = role;
    },
  };
}
