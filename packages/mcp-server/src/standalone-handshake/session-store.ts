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
} = {}) {
  const now = options.now ?? Date.now;
  const terminalRetention = options.terminalRetention ?? TERMINAL_SESSION_RETENTION;
  const sessions = new Map<string, any>();
  const invitations = new Map<string, string>();
  // Pinned closure records: prepared before anchoring so retries produce the identical digest.
  // Kept beside (not on) the session objects, which stay read-only everywhere else.
  const pendingClosures = new Map<string, any>();

  function requireSession(sessionId: string): any {
    const session = sessions.get(sessionId);
    if (!session) throw new StandaloneAdmissionError("NOT_OPEN");
    return session;
  }

  // Evicts the oldest terminal sessions while more than the retention cap are terminal.
  // Runs on createSession; an active session is never evicted to make room.
  function evictTerminalSessions(): void {
    let terminal = 0;
    for (const session of sessions.values()) if (TERMINAL_STAGES.has(session.stage)) terminal += 1;
    for (const [sessionId, session] of sessions) {
      if (terminal <= terminalRetention) return;
      if (TERMINAL_STAGES.has(session.stage)) {
        sessions.delete(sessionId);
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
      });
      evictTerminalSessions();
    },

    putInvitation(input: { secret: string; sessionId: string }): void {
      invitations.set(input.secret, input.sessionId);
    },

    claimInvitation(secret: string): string | undefined {
      const sessionId = invitations.get(secret);
      if (sessionId === undefined) return undefined;
      invitations.delete(secret);
      return sessionId;
    },

    getSession(sessionId: string): any {
      const session = sessions.get(sessionId);
      if (!session) return undefined;
      expireIfDue(session);
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
      session.seq += 1;
      const message = {
        sessionId,
        seq: session.seq,
        kind,
        fromRole: role,
        toRole: other(role),
        bodyDigest: createHash("sha256").update(body, "utf8").digest("hex"),
        sentAtMs: now(),
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
        remainingMs: session.stage === "open" ? Math.max(0, session.expiresAtMs - now()) : 0,
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
