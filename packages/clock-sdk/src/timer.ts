/**
 * Timer — thin convenience over {@link ClockScheduler}: a one-shot alarm at
 * `clock.now() + durationMs`. Returns the job id so it can be cancelled or
 * inspected via the scheduler.
 */
import type { ClockScheduler, FireContext, JobMode } from "./scheduler.js";
import type { SchedulerClock } from "./scheduler.js";

export interface TimerOptions {
  /** "soft" (default) or "confirmed". */
  mode?: JobMode;
  /** Identity for the on-chain attestation. */
  agentId?: string;
  /** Optional explicit job id. */
  id?: string;
}

/**
 * Schedule `action` to run once after `durationMs`, relative to the scheduler's
 * disciplined clock. Requires the scheduler's clock so the fire time is computed
 * in the same (disciplined) frame the scheduler fires on.
 */
export function timer(
  scheduler: ClockScheduler,
  clock: SchedulerClock,
  durationMs: number,
  action: (ctx: FireContext) => unknown | Promise<unknown>,
  options: TimerOptions = {},
): string {
  const fireAt = clock.now().epochMs + durationMs;
  return scheduler.schedule({
    id: options.id,
    fireAt,
    action,
    mode: options.mode,
    agentId: options.agentId,
  });
}
