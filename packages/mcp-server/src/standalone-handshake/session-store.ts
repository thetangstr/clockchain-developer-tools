import { createHash } from "node:crypto";

const STAGES = ["invited", "readiness_pending", "ready", "ready_failed", "consent_pending", "consented", "open", "closed", "revoked", "expired"] as const;
const LEGAL: Record<string, readonly string[]> = {
  invited: ["readiness_pending"],
  readiness_pending: ["ready", "ready_failed"],
  ready: ["consent_pending"],
  consent_pending: ["consented"],
  consented: ["open"],
  open: ["closed", "revoked", "expired"],
};
const ROLES = ["initiator", "responder"];
const TERMINAL_STAGES = new Set(["ready_failed", "closed", "revoked", "expired"]);

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
  const sessions = new Map<string, any>();
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
      if (!TERMINAL_STAGES.has(session.stage) && current - session.touchedAtMs > sessionTtlMs) {
        sessions.delete(sessionId);
        pendingClosures.delete(sessionId);
      }
    }
    let terminal = 0;
    for (const session of sessions.values()) if (TERMINAL_STAGES.has(session.stage)) terminal += 1;
    for (const [sessionId, session] of sessions) {
      if (terminal <= terminalRetention) return;
      if (TERMINAL_STAGES.has(session.stage)) {
        sessions.delete(sessionId);
        pendingClosures.delete(sessionId);
        terminal -= 1;
      }
    }
  }

  function expireIfDue(session: any): void {
    if (session.stage === "open" && now() >= session.expiresAtMs) session.stage = "expired";
  }

  function other(role: string): string {
    return role === "initiator" ? "responder" : "initiator";
  }

  return {
    createSession(input: { sessionId: string; terms: any; termsDigest: string; initiatorReadiness: any }): void {
      sessions.set(input.sessionId, {
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
        touchedAtMs: housekeepingNow(),
      });
      evictStaleSessions();
    },

    putInvitation(input: { secret: string; sessionId: string }): void {
      invitations.set(input.secret, { sessionId: input.sessionId, expiresAtMs: housekeepingNow() + invitationTtlMs });
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

    authenticate(sessionId: string, token: string): string | undefined {
      const session = this.getSession(sessionId);
      if (!session) return undefined;
      for (const role of ROLES) if (session.auth[role] !== undefined && session.auth[role] === token) return role;
      return undefined;
    },

    setAccessToken(sessionId: string, role: string, token: string): void {
      requireSession(sessionId).auth[role] = token;
    },

    setStage(sessionId: string, stage: string): void {
      const session = requireSession(sessionId);
      if (!(STAGES as readonly string[]).includes(stage) || !LEGAL[session.stage]?.includes(stage)) throw new StandaloneIllegalTransitionError();
      session.stage = stage;
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
      return message;
    },

    readMessages(sessionId: string, role: string): readonly any[] {
      const session = requireSession(sessionId);
      expireIfDue(session);
      if (!ROLES.includes(role)) throw new StandaloneAdmissionError("UNKNOWN_PARTY");
      return session.messages.filter((message: any) => message.toRole === role).map((message: any) => Object.freeze({ ...message }));
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
