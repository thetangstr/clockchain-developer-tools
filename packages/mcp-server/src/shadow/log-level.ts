// How much detail Shadow anchors for a session. Steps are recorded on this server at every level; the level decides when
// the record's hash goes to Clockchain. An account can have a level, and an agent can choose one when a session starts: the
// session runs at the finer of the two. clockchain_log_level runs on the same token as the agent, so this server can't tell
// who called it, and the record says "account", never that a person chose it.
export const LOG_LEVELS = ["step", "turn", "milestone"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];
export type LevelSetBy = "account" | "agent";

/** What each level does where the logging tools exist. */
export const LEVELS_EXPLAINED = "step: each logging call gets its own anchor, and the steps in one shadow_log_turn call share it. turn: an anchor at each shadow_log_turn call and each task, message or note, and the steps between wait for it. milestone: an anchor at each task, shadow_checkpoint and the close, and the steps between wait for it.";

export const LOG_LEVEL_HELP = `Optional, for a new session: step, turn or milestone. ${LEVELS_EXPLAINED} If this account has a level, the session runs at the finer of the two.`;

/** Where the person asks, shadow_record writes nothing to the ledger, so a level changes nothing about anchoring. */
export const LOG_LEVEL_HELP_ASKED = "Optional: step, turn or milestone, saved with the session. It doesn't change when anchors happen here: steps are recorded on this server, and anchors happen at the start, at shadow_checkpoint and at the close.";

export const isLogLevel = (v: unknown): v is LogLevel => typeof v === "string" && (LOG_LEVELS as readonly string[]).includes(v);

/** Who a stored level is attributed to. Records from before this wording say "person", which meant the account's level. */
export const levelSetBy = (v: unknown): LevelSetBy | null => (v === "account" || v === "person" ? "account" : v === "agent" ? "agent" : null);

/** The more detailed of two levels. */
export const finer = (a: LogLevel, b: LogLevel): LogLevel => (LOG_LEVELS.indexOf(a) <= LOG_LEVELS.indexOf(b) ? a : b);

/** A session's level from the account's level and the agent's choice, and which of them it came from. Neither given is "step". */
export function effectiveLevel(account: LogLevel | null, agent: LogLevel | null): { level: LogLevel; by: LevelSetBy } {
  if (account && agent) return { level: finer(account, agent), by: finer(account, agent) === account ? "account" : "agent" };
  if (account) return { level: account, by: "account" };
  return { level: agent ?? "step", by: "agent" };
}

/** Whether this call's steps get an anchor now. Anything else waits: shadow_checkpoint and the close always try to anchor. */
export function anchorsNow(level: LogLevel, turnCall: boolean, kinds: readonly string[]): boolean {
  if (level === "step") return true;
  if (level === "turn") return turnCall || kinds.some((k) => k === "task" || k === "message" || k === "note");
  return kinds.includes("task");
}

export const levelNote = (level: LogLevel, by: LevelSetBy) => `Logging level: ${level} (set by the ${by}).`;

/** The note for a change to the account's level, whether or not it moved this session. */
export function accountLevelNote(previous: LogLevel | null, account: LogLevel | null, level: LogLevel, moved: boolean): string {
  const change = `The account's level changed from ${previous ?? "none"} to ${account ?? "none"}.`;
  return moved ? `${levelNote(level, "account")} ${change}` : `${change} This session stays at ${level}.`;
}

/** What can still anchor a session's later steps. */
export type AnchorOutlook = {
  /** A call before the close can still spend an anchor. */
  canAnchor: boolean;
  /** The close still has its anchor. */
  closeCanAnchor: boolean;
  /** Why anchors aren't landing just now, when they aren't. */
  blocked: "outage" | "day_limit" | "budget" | null;
};

const NEXT_ANCHOR: Record<LogLevel, string> = {
  step: "a logging call, a checkpoint or the close",
  turn: "the turn's reply, a task, a checkpoint or the close",
  milestone: "the next task, a checkpoint or the close",
};

/** What can still anchor this step: only what is possible now, so an outage or a limit is said, not papered over. */
function stillPossible(level: LogLevel, o: AnchorOutlook): string {
  if (!o.closeCanAnchor) return "This session has no anchors left, so this stays unanchored.";
  if (o.blocked === "outage") return "Clockchain isn't taking anchors right now, so this stays unanchored unless a later anchor lands.";
  if (o.blocked === "day_limit") return "This account's anchors for today are used up, so this stays unanchored unless a later anchor lands.";
  if (o.blocked === "budget") return "The server's Clockchain write budget is used up, so this stays unanchored unless a later anchor lands.";
  if (!o.canAnchor) return "This session has used the anchors it can spend before the close, so only the close can still anchor this.";
  return `A later anchor covers this: ${NEXT_ANCHOR[level]}.`;
}

/** Why a step has no anchor yet, for a result that says so. */
export const deferredReason = (level: LogLevel, o: AnchorOutlook) =>
  `This session logs at the ${level} level, so this is recorded now with no anchor. ${stillPossible(level, o)}`;

/** The same for shadow_record, which writes nothing to the ledger at any level. */
export const recordedReason = (level: LogLevel, o: AnchorOutlook) =>
  `shadow_record writes nothing to the ledger at any level, so this is recorded on this server with no anchor. ${stillPossible(level, o)}`;
