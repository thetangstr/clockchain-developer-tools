// Turn tracking for active facilitation (F1-F3). Pure functions over a session record,
// shared by the store (deadlines) and handshake_next (stall reporting).

export type PendingOn = "initiator" | "responder" | "both";
export type PendingAction = "ACCEPT" | "FIX_READINESS" | "CONSENT" | "OPEN" | "SEND" | "REPLY";

export interface PendingTurn {
  pendingOn: PendingOn;
  action: PendingAction;
  /** When this turn began (ms). */
  sinceMs: number;
  /** Increments whenever the turn changes hands or action; keys once-per-turn limits. */
  turn: number;
}

// F3 defaults: consent and open within 10 minutes each; a reply within 10 minutes
// (never beyond channel expiry). Per-session overrides live in channelLimits.
export const TURN_DEADLINE_MS = 10 * 60_000;
export const REPLY_DEADLINE_MS = 10 * 60_000;
// F1: a pending party silent this long is reported to the waiting party as stalled.
export const STALL_AFTER_MS = 3 * 60_000;

type Session = Record<string, any>;

function other(role: string): "initiator" | "responder" {
  return role === "initiator" ? "responder" : "initiator";
}

/** Whose move it is, or undefined when nobody owes one (checklist running, terminal). */
export function pendingTurn(session: Session): PendingTurn | undefined {
  const base = { sinceMs: session.turnStartedAtMs as number, turn: session.turnSeq as number };
  switch (session.stage) {
    case "invited":
      return { pendingOn: "responder", action: "ACCEPT", ...base };
    case "readiness_retry":
      return { pendingOn: "responder", action: "FIX_READINESS", ...base };
    case "ready":
    case "consent_pending": {
      const missing = (["initiator", "responder"] as const).filter((role) => session.consents[role] === undefined);
      return { pendingOn: missing.length === 1 ? missing[0] : "both", action: "CONSENT", ...base };
    }
    case "consented":
      return { pendingOn: "both", action: "OPEN", ...base };
    case "open": {
      const last = session.messages[session.messages.length - 1];
      return last === undefined ? { pendingOn: "initiator", action: "SEND", ...base } : { pendingOn: other(last.fromRole), action: "REPLY", ...base };
    }
    default:
      return undefined;
  }
}

export function turnDeadlineMs(session: Session): number {
  const seconds = session.terms.channelLimits.turnDeadlineSeconds;
  return seconds === undefined ? TURN_DEADLINE_MS : Number(seconds) * 1000;
}

export function replyDeadlineMs(session: Session): number {
  const seconds = session.terms.channelLimits.replyDeadlineSeconds;
  return seconds === undefined ? REPLY_DEADLINE_MS : Number(seconds) * 1000;
}

export interface SessionDeadline {
  atMs: number;
  outcome: "expired" | "abandoned" | "stalled";
  /** For stalled: STALLED_<ACTION>_BY_<ROLE>. */
  reason?: string;
  /** For stalled: the role that failed to act (both roles for a shared action). */
  stalledRole?: PendingOn;
}

/**
 * The one deadline that ends this session next, if any. Every clock-driven terminal
 * outcome comes from here, so expiry, abandonment and turn stalls can never both fire:
 * - invited / readiness_retry: the invitation TTL -> abandoned.
 * - ready / consent_pending / consented: the turn deadline -> stalled, or the pre-open
 *   deadline -> abandoned, whichever is earlier (abandoned on an exact tie: the older
 *   whole-session rule keeps its meaning).
 * - open: the reply deadline -> stalled, unless the channel expires first (or at the
 *   same moment) -> expired. A reply window never extends past channel expiry.
 */
export function nextDeadline(session: Session): SessionDeadline | undefined {
  const stage = session.stage;
  if (stage === "invited" || stage === "readiness_retry") return { atMs: session.openDeadlineMs, outcome: "abandoned" };
  const turn = pendingTurn(session);
  if (turn === undefined) return undefined;
  const stalled = (atMs: number): SessionDeadline => ({
    atMs,
    outcome: "stalled",
    reason: `STALLED_${turn.action}_BY_${turn.pendingOn.toUpperCase()}`,
    stalledRole: turn.pendingOn,
  });
  if (stage === "ready" || stage === "consent_pending" || stage === "consented") {
    const turnAt = turn.sinceMs + turnDeadlineMs(session);
    return turnAt < session.openDeadlineMs ? stalled(turnAt) : { atMs: session.openDeadlineMs, outcome: "abandoned" };
  }
  if (stage === "open") {
    const replyAt = turn.sinceMs + replyDeadlineMs(session);
    return replyAt < session.expiresAtMs ? stalled(replyAt) : { atMs: session.expiresAtMs, outcome: "expired" };
  }
  return undefined;
}
