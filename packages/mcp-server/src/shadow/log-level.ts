// How much detail Shadow anchors for a session. Steps are recorded on this server at every level; the level decides when
// the record's hash goes to Clockchain. The person's level for the account is the least detail allowed: an agent can log
// in more detail, never less.
export const LOG_LEVELS = ["step", "turn", "milestone"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export const LOG_LEVEL_HELP = "Optional, for a new session: step, turn or milestone. step gives each step its own anchor, turn gives one anchor per turn, and milestone anchors at tasks, checkpoints and the close. The account's own level is the least detail allowed, so a coarser choice here has no effect.";

export const isLogLevel = (v: unknown): v is LogLevel => typeof v === "string" && (LOG_LEVELS as readonly string[]).includes(v);

/** The more detailed of two levels. */
export const finer = (a: LogLevel, b: LogLevel): LogLevel => (LOG_LEVELS.indexOf(a) <= LOG_LEVELS.indexOf(b) ? a : b);

/** A session's level from the person's level and the agent's choice, and who set it. Neither given is "step". */
export function effectiveLevel(person: LogLevel | null, agent: LogLevel | null): { level: LogLevel; by: "person" | "agent" } {
  if (person && agent) return { level: finer(person, agent), by: finer(person, agent) === person ? "person" : "agent" };
  if (person) return { level: person, by: "person" };
  return { level: agent ?? "step", by: "agent" };
}

/** Whether this call's steps get an anchor now. Anything else waits: shadow_checkpoint and the close always anchor. */
export function anchorsNow(level: LogLevel, turnCall: boolean, kinds: readonly string[]): boolean {
  if (level === "step") return true;
  if (level === "turn") return turnCall || kinds.includes("message");
  return kinds.includes("task");
}

export const levelNote = (level: LogLevel, by: "person" | "agent") => `Logging level: ${level} (set by the ${by}).`;

/** When a step at this level gets its anchor, for a result that says it hasn't one yet. */
export const deferredReason = (level: LogLevel) => level === "turn"
  ? "This session logs at the turn level, so this is recorded now and anchored with the turn's reply, a checkpoint or the close."
  : "This session logs at the milestone level, so this is recorded now and anchored with the next task, a checkpoint or the close.";
