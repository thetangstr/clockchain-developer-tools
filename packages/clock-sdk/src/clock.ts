/**
 * ClockchainClock — a Clockchain-disciplined local clock.
 *
 * Discipline model (Cristian's algorithm / NTP-style):
 *   1. Read a monotonic clock `t0`.
 *   2. Call the gateway `getTimestamp()` (consensus time).
 *   3. Read the monotonic clock `t1`.
 *   4. rttMs = t1 - t0; the request's midpoint is at monotonic (t0 + t1) / 2.
 *   5. offsetMs = consensusEpochMs - monotonicMid  (add to a monotonic reading
 *      to get the disciplined wall-clock epoch).
 *   6. uncertaintyMs = rttMs / 2 + AbsTimeDifference  (one-way network delay
 *      bound plus the gateway's own reported time spread).
 *
 * `now()` is offline: monotonic reading + offset. No network call, so it is
 * cheap and safe to poll. An optional auto-resync interval re-runs `sync()`.
 */
import type { TimestampResponse } from "@clockchain/core";
import { parseGatewayTime } from "./time.js";

/**
 * The minimal slice of {@link ClockchainClient} the clock needs. A full
 * `ClockchainClient` satisfies this, and tests can inject a fake.
 */
export interface TimestampSource {
  getTimestamp(): Promise<TimestampResponse>;
}

/** A monotonic millisecond clock (e.g. `performance.now()`). Injectable for tests. */
export type MonotonicNow = () => number;

/** A `setInterval`/`clearInterval` pair, injectable so tests avoid real timers. */
export interface IntervalScheduler {
  set(handler: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

export interface ClockOptions {
  /** Monotonic clock source. Defaults to `performance.now()` (epoch-agnostic). */
  monotonic?: MonotonicNow;
  /** Auto-resync period in ms. <= 0 or omitted disables auto-resync. */
  autoResyncMs?: number;
  /** Interval scheduler used for auto-resync. Defaults to global setInterval. */
  intervalScheduler?: IntervalScheduler;
}

/** A disciplined-time reading. */
export interface ClockReading {
  /** Disciplined wall-clock time, epoch milliseconds (UTC). */
  epochMs: number;
  /** Half-width of the uncertainty band around `epochMs`, in ms. */
  uncertaintyMs: number;
}

/** Diagnostics captured by the last successful {@link ClockchainClock.sync}. */
export interface SyncResult {
  /** Disciplined epoch at the moment of sync (consensus midpoint). */
  epochMs: number;
  /** offset to add to a monotonic reading to obtain the disciplined epoch. */
  offsetMs: number;
  /** Round-trip time of the getTimestamp call, ms. */
  rttMs: number;
  /** Uncertainty half-width: rttMs/2 + AbsTimeDifference. */
  uncertaintyMs: number;
  /** Monotonic midpoint of the getTimestamp call. */
  monotonicMidMs: number;
  /** The gateway's reported AbsTimeDifference, ms. */
  absTimeDifferenceMs: number;
  /** The raw gateway madMarzulloTime string that was parsed. */
  madMarzulloTime: string;
  /** Block height at sync time (for traceability). */
  blockHeight: number;
}

const defaultMonotonic: MonotonicNow =
  typeof performance !== "undefined" && typeof performance.now === "function"
    ? () => performance.now()
    : () => Number(process.hrtime.bigint() / 1_000_000n);

const defaultIntervalScheduler: IntervalScheduler = {
  set: (handler, ms) => setInterval(handler, ms),
  clear: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
};

export class ClockchainClock {
  private readonly source: TimestampSource;
  private readonly monotonic: MonotonicNow;
  private readonly intervalScheduler: IntervalScheduler;
  private readonly autoResyncMs: number;

  private offsetMs = 0;
  private uncertaintyAtSyncMs = 0;
  private lastSyncResult: SyncResult | null = null;
  private resyncHandle: unknown = null;

  constructor(source: TimestampSource, options: ClockOptions = {}) {
    this.source = source;
    this.monotonic = options.monotonic ?? defaultMonotonic;
    this.intervalScheduler = options.intervalScheduler ?? defaultIntervalScheduler;
    this.autoResyncMs = options.autoResyncMs ?? 0;
    if (this.autoResyncMs > 0) this.startAutoResync();
  }

  /**
   * Discipline the local clock against one consensus read (Cristian's algorithm).
   * Returns the computed {@link SyncResult} and updates `lastSync`.
   */
  async sync(): Promise<SyncResult> {
    const t0 = this.monotonic();
    const ts = await this.source.getTimestamp();
    const t1 = this.monotonic();

    const rttMs = Math.max(0, t1 - t0);
    const monotonicMidMs = (t0 + t1) / 2;
    const consensusEpochMs = parseGatewayTime(ts.madMarzulloTime);
    if (Number.isNaN(consensusEpochMs)) {
      throw new Error(
        `ClockchainClock.sync: unparseable madMarzulloTime "${ts.madMarzulloTime}"`,
      );
    }
    const absTimeDifferenceMs = Math.abs(Number(ts.AbsTimeDifference) || 0);

    this.offsetMs = consensusEpochMs - monotonicMidMs;
    this.uncertaintyAtSyncMs = rttMs / 2 + absTimeDifferenceMs;

    const result: SyncResult = {
      epochMs: consensusEpochMs,
      offsetMs: this.offsetMs,
      rttMs,
      uncertaintyMs: this.uncertaintyAtSyncMs,
      monotonicMidMs,
      absTimeDifferenceMs,
      madMarzulloTime: String(ts.madMarzulloTime),
      blockHeight: Number(ts.blockHeight),
    };
    this.lastSyncResult = result;
    return result;
  }

  /**
   * Current disciplined time. Offline: monotonic + offset. Throws if called
   * before the first successful {@link sync}.
   *
   * The uncertainty band is the band captured at sync time. (It does not grow
   * with assumed drift here; callers needing drift bounds should resync.)
   */
  now(): ClockReading {
    if (this.lastSyncResult == null) {
      throw new Error("ClockchainClock.now: call sync() before now()");
    }
    return {
      epochMs: this.monotonic() + this.offsetMs,
      uncertaintyMs: this.uncertaintyAtSyncMs,
    };
  }

  /** True once at least one sync has succeeded. */
  get isSynced(): boolean {
    return this.lastSyncResult != null;
  }

  /** The most recent {@link SyncResult}, or null if never synced. */
  get lastSync(): SyncResult | null {
    return this.lastSyncResult;
  }

  /** Start periodic background resync (no-op if already running or disabled). */
  startAutoResync(periodMs: number = this.autoResyncMs): void {
    if (this.resyncHandle != null || periodMs <= 0) return;
    this.resyncHandle = this.intervalScheduler.set(() => {
      // Swallow errors: a failed resync keeps the last good offset.
      void this.sync().catch(() => undefined);
    }, periodMs);
  }

  /** Stop periodic background resync. */
  stopAutoResync(): void {
    if (this.resyncHandle != null) {
      this.intervalScheduler.clear(this.resyncHandle);
      this.resyncHandle = null;
    }
  }
}
