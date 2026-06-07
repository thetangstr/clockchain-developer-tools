/**
 * Optional per-process logging budget cap (v2 safety).
 *
 * Prevents a runaway test session from draining Clockchain log credits by
 * limiting how many successful `log_action` writes one server process may make.
 *
 * DISABLED by default: when `MCP_LOG_BUDGET` is unset (or not a positive
 * integer) the cap is off and behavior is identical to v1. Only successful
 * writes count toward the budget; failed writes (rate limit, auth, etc.) do not
 * spend a credit, so they do not count.
 */

/** Thrown when a log write would exceed the configured budget. */
export class BudgetExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BudgetExceededError";
  }
}

export interface LogBudget {
  /** Throw {@link BudgetExceededError} if no budget remains; else no-op. */
  check(): void;
  /** Record one successful write against the budget. */
  record(): void;
  /** Remaining writes, or null when the cap is disabled (unlimited). */
  remaining(): number | null;
  /** Whether a cap is active. */
  readonly enabled: boolean;
}

export function createLogBudget(
  env: NodeJS.ProcessEnv = process.env,
): LogBudget {
  const raw = env.MCP_LOG_BUDGET;
  const parsed = raw != null && raw.trim() !== "" ? Number(raw) : NaN;
  const enabled = Number.isInteger(parsed) && parsed > 0;
  const cap = enabled ? parsed : 0;
  let used = 0;

  return {
    enabled,
    check() {
      if (!enabled) return;
      if (used >= cap) {
        throw new BudgetExceededError(
          `Logging budget exhausted (${cap} write(s) this session). ` +
            `Raise MCP_LOG_BUDGET or restart the server to reset.`,
        );
      }
    },
    record() {
      if (enabled) used++;
    },
    remaining() {
      return enabled ? Math.max(0, cap - used) : null;
    },
  };
}
