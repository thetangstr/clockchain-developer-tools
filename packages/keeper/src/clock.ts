/**
 * Disciplined-clock adapter for the keeper.
 *
 * Wraps clock-sdk's {@link ClockchainClock} (Cristian's-algorithm discipline over
 * the gateway's consensus time) into the tiny `nowMs` / `nowUncertaintyMs` shape
 * the {@link Keeper} consumes. The keeper compares trigger fire times against this
 * disciplined time — NOT the host's wall clock — so a fire happens at a
 * verified-time instant the receipt can later stand on.
 */
import { ClockchainClock, type TimestampSource } from "@clockchain/clock-sdk";

export interface DisciplinedClock {
  nowMs(): number;
  nowUncertaintyMs(): number;
  /** Re-discipline against consensus time. Call once on boot. */
  sync(): Promise<void>;
  /** Stop background auto-resync. */
  stop(): void;
}

/**
 * Build a disciplined clock from any timestamp source (a full ClockchainClient
 * satisfies {@link TimestampSource}). Auto-resyncs every `autoResyncMs` (default
 * 60s) so a long-running keeper does not drift between consensus reads.
 */
export function createDisciplinedClock(
  source: TimestampSource,
  opts: { autoResyncMs?: number } = {},
): DisciplinedClock {
  const clock = new ClockchainClock(source, {
    autoResyncMs: opts.autoResyncMs ?? 60_000,
  });
  return {
    nowMs: () => clock.now().epochMs,
    nowUncertaintyMs: () => clock.now().uncertaintyMs,
    sync: async () => {
      await clock.sync();
    },
    stop: () => clock.stopAutoResync(),
  };
}
