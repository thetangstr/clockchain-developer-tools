/**
 * ClockScheduler — a local cron/alarm engine driven by a disciplined clock.
 *
 * A job fires when `clock.now().epochMs >= fireAt`. In "confirmed" mode the
 * scheduler does one extra `getTimestamp()` at the boundary to re-confirm the
 * consensus time has actually crossed `fireAt` before firing (trading a network
 * round-trip for a tighter guarantee). On fire it runs the user `action` and,
 * when a core client is provided, anchors the fire via `attestAction`, attaching
 * the resulting receipt to the job status.
 *
 * Everything time-related is injectable (the clock, the boundary timestamp
 * source, and a setTimeout/clearTimeout-style timer), so tests drive it with a
 * fake clock + fake timer and never sleep on real time or hit the network.
 */
import type { AgentReceipt, TimestampResponse } from "@clockchain/core";
import { parseGatewayTime } from "./time.js";

/** The minimal clock surface the scheduler reads. {@link ClockchainClock} satisfies it. */
export interface SchedulerClock {
  now(): { epochMs: number; uncertaintyMs: number };
}

/** Boundary re-confirmation source for "confirmed" mode. */
export interface ConfirmSource {
  getTimestamp(): Promise<TimestampResponse>;
}

/** The core-client surface used to anchor a fire on-chain. */
export interface AttestSource {
  attestAction(input: {
    agentId: string;
    action: string;
    inputs?: unknown;
    outputs?: unknown;
  }): Promise<AgentReceipt>;
}

/** An abstract timer so tests can advance time deterministically. */
export interface Timer {
  set(handler: () => void, delayMs: number): unknown;
  clear(handle: unknown): void;
}

export type JobMode = "soft" | "confirmed";

export interface ScheduleInput {
  /** Optional stable id. A unique id is generated when omitted. */
  id?: string;
  /** Absolute fire time, epoch ms (UTC). Mutually exclusive with `everyMs`. */
  fireAt?: number;
  /** Recurring period, ms. The first fire is `clock.now() + everyMs`. */
  everyMs?: number;
  /** The action to run on fire. May be async; its return is captured. */
  action: (ctx: FireContext) => unknown | Promise<unknown>;
  /** "soft" (default) fires off the disciplined clock; "confirmed" re-checks consensus. */
  mode?: JobMode;
  /** Identity for the on-chain attestation. Defaults to "clock-scheduler". */
  agentId?: string;
}

/** Context passed to a job's action when it fires. */
export interface FireContext {
  id: string;
  /** Disciplined epoch (ms) at which the job fired. */
  firedAt: number;
  /**
   * The fired consensus epoch (ms) from the disciplined clock at fire time.
   * Same reading as {@link FireContext.firedAt}; named `epochMs` to mirror
   * {@link ClockReading} so callers can format `new Date(ctx.epochMs)`.
   */
  epochMs: number;
  /** The clock's uncertainty half-width (ms) at fire time (the `±` band). */
  uncertaintyMs: number;
  /** The scheduled fire time, epoch ms. */
  fireAt: number;
}

export type JobState =
  | "scheduled"
  | "firing"
  | "fired"
  | "error"
  | "cancelled";

export interface JobStatus {
  id: string;
  mode: JobMode;
  state: JobState;
  /** Next fire time, epoch ms. */
  fireAt: number;
  everyMs: number | null;
  /** Disciplined epoch at which the job last fired, or null. */
  firedAt: number | null;
  /** How many times the job has fired. */
  fireCount: number;
  /** The receipt anchoring the most recent fire (when a client is configured). */
  receipt: AgentReceipt | null;
  /** Whatever the action returned on its most recent fire. */
  result: unknown;
  /** Error from the most recent fire, if any. */
  error: string | null;
}

interface Job {
  status: JobStatus;
  action: (ctx: FireContext) => unknown | Promise<unknown>;
  agentId: string;
  handle: unknown;
}

const defaultTimer: Timer = {
  set: (handler, delayMs) => setTimeout(handler, delayMs),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/**
 * Node's setTimeout stores the delay as a signed 32-bit int; anything larger
 * (~24.8 days) overflows and fires almost immediately. We hop forward in chunks
 * no larger than this for far-future alarms.
 */
const MAX_TIMER_DELAY_MS = 2_147_483_647; // 2^31 - 1

/**
 * The next interval slot strictly after `now`. Normally `fireAt + intervalMs`;
 * but if that slot is already in the past (downtime / a long-blocked fire), jump
 * straight to the upcoming slot instead of replaying every missed slot in a
 * burst (the catch-up storm). Mirrors the keeper's `nextIntervalSlot`.
 */
export function nextIntervalSlot(
  fireAtMs: number,
  intervalMs: number,
  now: number,
): number {
  let next = fireAtMs + intervalMs;
  if (next <= now) {
    const missed = Math.ceil((now - fireAtMs) / intervalMs);
    next = fireAtMs + missed * intervalMs;
    if (next <= now) next += intervalMs;
  }
  return next;
}

export interface SchedulerOptions {
  /** Disciplined clock that drives fire decisions. Required. */
  clock: SchedulerClock;
  /** Timer abstraction (defaults to global setTimeout/clearTimeout). */
  timer?: Timer;
  /** Source for the extra boundary read in "confirmed" mode. */
  confirmSource?: ConfirmSource;
  /** Core client; when present, each fire is anchored via attestAction. */
  client?: AttestSource;
  /**
   * Re-check delay (ms) used by the timer when a job's fireAt has not yet been
   * crossed. A small value keeps the poll tight; tests inject 0. Default 250.
   */
  pollMs?: number;
  /**
   * Behaviour when a "confirmed" job cannot read consensus at the boundary
   * (the boundary `getTimestamp()` throws or returns an unparseable time).
   *
   * - `false` (default, fail-closed): do NOT fire; hold and retry on the next
   *   tick. This keeps "confirmed" honest — a gateway outage never silently
   *   downgrades the guarantee to a "soft" disciplined-clock-only fire.
   * - `true` (fail-open): fire on the disciplined clock alone when consensus is
   *   unavailable (availability over confirmation).
   *
   * Ignored for "soft" jobs (they never do a boundary read).
   */
  confirmFailOpen?: boolean;
}

export class ClockScheduler {
  private readonly clock: SchedulerClock;
  private readonly timer: Timer;
  private readonly confirmSource?: ConfirmSource;
  private readonly client?: AttestSource;
  private readonly pollMs: number;
  private readonly confirmFailOpen: boolean;
  private readonly jobs = new Map<string, Job>();
  private seq = 0;

  constructor(options: SchedulerOptions) {
    this.clock = options.clock;
    this.timer = options.timer ?? defaultTimer;
    this.confirmSource = options.confirmSource;
    this.client = options.client;
    this.pollMs = options.pollMs ?? 250;
    this.confirmFailOpen = options.confirmFailOpen ?? false;
  }

  /** Register a job and arm its timer. Returns the job id. */
  schedule(input: ScheduleInput): string {
    if (input.fireAt == null && input.everyMs == null) {
      throw new Error("schedule: provide either fireAt or everyMs");
    }
    if (input.fireAt != null && input.everyMs != null) {
      throw new Error("schedule: provide only one of fireAt or everyMs");
    }
    const id = input.id ?? `job_${Date.now()}_${++this.seq}`;
    if (this.jobs.has(id)) {
      throw new Error(`schedule: job id "${id}" already exists`);
    }
    const everyMs = input.everyMs ?? null;
    const fireAt =
      input.fireAt ?? this.clock.now().epochMs + (input.everyMs as number);

    const job: Job = {
      status: {
        id,
        mode: input.mode ?? "soft",
        state: "scheduled",
        fireAt,
        everyMs,
        firedAt: null,
        fireCount: 0,
        receipt: null,
        result: undefined,
        error: null,
      },
      action: input.action,
      agentId: input.agentId ?? "clock-scheduler",
      handle: null,
    };
    this.jobs.set(id, job);
    this.arm(job);
    return id;
  }

  /** List a snapshot of every job's status. */
  list(): JobStatus[] {
    return [...this.jobs.values()].map((j) => ({ ...j.status }));
  }

  /** A snapshot of one job's status, or null if unknown. */
  getStatus(id: string): JobStatus | null {
    const job = this.jobs.get(id);
    return job ? { ...job.status } : null;
  }

  /** Cancel a job (disarms its timer). Returns true if it existed and was active. */
  cancel(id: string): boolean {
    const job = this.jobs.get(id);
    if (!job) return false;
    if (job.handle != null) {
      this.timer.clear(job.handle);
      job.handle = null;
    }
    if (job.status.state === "scheduled" || job.status.state === "firing") {
      job.status.state = "cancelled";
    }
    return true;
  }

  /** Force a job to fire immediately, regardless of its fireAt. */
  async runNow(id: string): Promise<JobStatus> {
    const job = this.jobs.get(id);
    if (!job) throw new Error(`runNow: unknown job "${id}"`);
    if (job.handle != null) {
      this.timer.clear(job.handle);
      job.handle = null;
    }
    await this.fire(job);
    return { ...job.status };
  }

  /** Disarm every job. Call on shutdown to release pending timers. */
  clearAll(): void {
    for (const id of [...this.jobs.keys()]) this.cancel(id);
  }

  // --- internals ---

  private arm(job: Job): void {
    if (job.status.state === "cancelled") return;
    const remaining = job.status.fireAt - this.clock.now().epochMs;
    if (remaining > MAX_TIMER_DELAY_MS) {
      // Far-future alarm: a delay beyond Node's 32-bit setTimeout cap (~24.8
      // days) overflows and fires after ~1ms (then busy-polls). Hop forward in
      // <=cap chunks, re-arming each time, and only do the real fire-check once
      // the boundary is within range.
      job.handle = this.timer.set(() => {
        job.handle = null;
        this.arm(job);
      }, MAX_TIMER_DELAY_MS);
      return;
    }
    const delay = remaining > 0 ? remaining : this.pollMs > 0 ? this.pollMs : 0;
    job.handle = this.timer.set(() => {
      void this.onTick(job);
    }, delay);
  }

  private async onTick(job: Job): Promise<void> {
    job.handle = null;
    if (job.status.state === "cancelled" || job.status.state === "firing") return;
    if (this.clock.now().epochMs < job.status.fireAt) {
      // Not there yet (disciplined clock ran ahead of the timer estimate): re-arm.
      this.arm(job);
      return;
    }
    if (job.status.mode === "confirmed" && this.confirmSource) {
      const ts = await this.confirmSource.getTimestamp().catch(() => null);
      const consensusMs = ts ? parseGatewayTime(ts.madMarzulloTime) : NaN;
      if (!Number.isFinite(consensusMs)) {
        // Could not read consensus at the boundary (getTimestamp threw or
        // returned an unparseable time). Fail-closed by default: do NOT fire —
        // hold and retry on the next tick — so "confirmed" is never silently
        // downgraded to "soft". Opt into fail-open with `confirmFailOpen`.
        if (!this.confirmFailOpen) {
          this.arm(job);
          return;
        }
        // fail-open: fall through and fire on the disciplined clock alone.
      } else if (consensusMs < job.status.fireAt) {
        // Consensus hasn't crossed the boundary yet: wait and re-check.
        this.arm(job);
        return;
      }
    }
    await this.fire(job);
  }

  private async fire(job: Job): Promise<void> {
    job.status.state = "firing";
    const reading = this.clock.now();
    const firedAt = reading.epochMs;
    const ctx: FireContext = {
      id: job.status.id,
      firedAt,
      epochMs: reading.epochMs,
      uncertaintyMs: reading.uncertaintyMs,
      fireAt: job.status.fireAt,
    };
    try {
      const result = await job.action(ctx);
      job.status.result = result;
      job.status.firedAt = firedAt;
      job.status.fireCount += 1;
      job.status.error = null;

      if (this.client) {
        const receipt = await this.client.attestAction({
          agentId: job.agentId,
          action: "scheduler.fire",
          inputs: { id: job.status.id, fireAt: job.status.fireAt, mode: job.status.mode },
          outputs: { firedAt, fireCount: job.status.fireCount },
        });
        job.status.receipt = receipt;
      }
      job.status.state = "fired";
    } catch (err) {
      job.status.state = "error";
      job.status.error = err instanceof Error ? err.message : String(err);
    }

    // Recurring jobs re-schedule on the interval grid. Normally that is just the
    // next slot (prior fireAt + everyMs) which avoids drift; but after downtime
    // or a long-blocked fire the next slot may already be in the past, which
    // would replay EVERY missed slot in a burst. Fast-forward to the next slot
    // strictly in the future so a missed window resumes on the next real
    // boundary, firing at most once on catch-up. (State is "fired" | "error"
    // here; a synchronous cancel mid-fire is not possible.)
    if (job.status.everyMs != null) {
      job.status.fireAt = nextIntervalSlot(
        job.status.fireAt,
        job.status.everyMs,
        this.clock.now().epochMs,
      );
      if (job.status.state === "fired") job.status.state = "scheduled";
      this.arm(job);
    }
  }
}
