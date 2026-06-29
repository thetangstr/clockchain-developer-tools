/**
 * The Keeper: control plane (register / list / cancel) + data plane (the dispatch
 * loop that fires due triggers while the client is offline).
 *
 * Dependencies are injected ({@link KeeperDeps}) so the whole fire path is unit
 * testable without a network, real timers, or a real clock:
 *   - store    : durable {@link KeeperStore} (survives restart; re-armed on boot).
 *   - anchorer : {@link Anchorer} (real one wraps attest_action).
 *   - nowMs    : disciplined Clockchain time, epoch ms (from clock-sdk in prod).
 *   - fetchFn  : webhook transport (injectable).
 *
 * AGE-193 invariant: a due trigger is removed from the due set ONLY after its fire
 * is anchored. A pending/failed anchor leaves it armed, so a fire is never
 * silently dropped — it is retried on the next tick and re-armed after a restart.
 */
import { randomUUID } from "node:crypto";
import { type Anchorer } from "./anchor.js";
import { type SsrfOptions, assertSafeWebhookUrl } from "./ssrf.js";
import { type KeeperStore } from "./store.js";
import {
  type FetchLike,
  type RetryOptions,
  deliverWebhook,
  deliverWithRetry,
} from "./webhook.js";
import type { FireRecord, ScheduleInput, Trigger, TriggerStatus } from "./types.js";

export interface KeeperConfig {
  /** Keeper's acting identity used when anchoring fires (e.g. "agent:clockchain-keeper"). */
  agentId: string;
  /** Standard-Webhooks signing secret (raw or whsec_...). */
  webhookSecret: string;
  /** Delivery retry/backoff policy. */
  retry?: RetryOptions;
  /** SSRF guard policy for webhook targets. */
  ssrf?: SsrfOptions;
  /** Delay before re-attempting a pending/failed anchor on the next tick, ms. Default 1000. */
  anchorRetryDelayMs?: number;
}

export interface KeeperDeps {
  store: KeeperStore;
  anchorer: Anchorer;
  /** Disciplined wall-clock time, epoch ms. */
  nowMs: () => number;
  /** Uncertainty half-width of `nowMs`, ms. Default 0. */
  nowUncertaintyMs?: () => number;
  /** Webhook transport. Defaults to global fetch (via deliverWebhook). */
  fetchFn?: FetchLike;
  /** Id generator (override in tests for determinism). Default randomUUID. */
  idGen?: () => string;
  config: KeeperConfig;
}

/** Outcome of one dispatch tick. */
export interface TickSummary {
  examined: number;
  fired: number;
  delivered: number;
  anchored: number;
  pendingAnchor: number;
  deadLettered: number;
}

const TERMINAL: ReadonlySet<TriggerStatus> = new Set(["done", "cancelled", "dead"]);

export class Keeper {
  private readonly d: KeeperDeps;
  private loopHandle: ReturnType<typeof setInterval> | null = null;
  /** Guards against overlapping ticks if a tick outlasts the interval. */
  private ticking = false;

  constructor(deps: KeeperDeps) {
    this.d = deps;
  }

  // ===== control plane =====

  /** Register a new trigger. Validates the target against the SSRF guard. */
  async schedule(input: ScheduleInput): Promise<Trigger> {
    if (!Number.isFinite(input.fireAtMs)) {
      throw new Error("fireAtMs must be a finite epoch-ms number.");
    }
    if (!input.sub) throw new Error("sub (owner identity) is required.");
    const mode = input.mode ?? "once";
    if (mode === "interval" && !(input.intervalMs && input.intervalMs > 0)) {
      throw new Error('mode "interval" requires a positive intervalMs.');
    }
    // SSRF check at registration time (and again before each delivery).
    assertSafeWebhookUrl(input.target, this.d.config.ssrf);

    const now = this.d.nowMs();
    const id = (this.d.idGen ?? randomUUID)();
    const trigger: Trigger = {
      id,
      sub: input.sub,
      fireAtMs: input.fireAtMs,
      target: input.target,
      payload: input.payload ?? null,
      mode,
      intervalMs: input.intervalMs,
      status: "scheduled",
      createdAtMs: now,
      updatedAtMs: now,
      attempts: 0,
      nextAttemptAtMs: 0,
      lastError: null,
      fires: [],
    };
    await this.d.store.put(trigger);
    return trigger;
  }

  /** List triggers, optionally scoped to one owner (AGE-194 tenant isolation). */
  async list(sub?: string): Promise<Trigger[]> {
    const all = await this.d.store.all();
    const scoped = sub ? all.filter((t) => t.sub === sub) : all;
    return scoped.sort((a, b) => a.fireAtMs - b.fireAtMs);
  }

  /**
   * Cancel a trigger. When `sub` is given it must match the trigger's owner, so
   * one tenant cannot cancel another's. Returns the cancelled trigger or null if
   * not found / not owned.
   */
  async cancel(id: string, sub?: string): Promise<Trigger | null> {
    const t = await this.d.store.get(id);
    if (!t) return null;
    if (sub && t.sub !== sub) return null;
    if (TERMINAL.has(t.status)) return t; // already terminal; idempotent
    t.status = "cancelled";
    t.updatedAtMs = this.d.nowMs();
    await this.d.store.put(t);
    return t;
  }

  // ===== data plane =====

  /** Process every due trigger once. Safe to call repeatedly (idempotent fires). */
  async tick(): Promise<TickSummary> {
    const now = this.d.nowMs();
    const summary: TickSummary = {
      examined: 0,
      fired: 0,
      delivered: 0,
      anchored: 0,
      pendingAnchor: 0,
      deadLettered: 0,
    };
    const triggers = await this.d.store.all();
    for (const t of triggers) {
      summary.examined++;
      if (t.status !== "scheduled" && t.status !== "firing") continue;
      if (t.fireAtMs > now) continue; // not due yet
      if (t.nextAttemptAtMs > now) continue; // backing off a retry
      await this.fireOne(t, now, summary);
    }
    return summary;
  }

  /** Fire a single due trigger: deliver -> anchor -> finalize (AGE-193). */
  private async fireOne(
    trigger: Trigger,
    now: number,
    summary: TickSummary,
  ): Promise<void> {
    const uncertainty = this.d.nowUncertaintyMs?.() ?? 0;
    const cfg = this.d.config;

    // Mark firing and create (or reuse) the fire record for THIS instant. A crash
    // after this point re-arms here on reboot — the fire is never lost.
    trigger.status = "firing";
    trigger.updatedAtMs = now;
    let fire = trigger.fires.find((f) => f.scheduledForMs === trigger.fireAtMs);
    if (!fire) {
      fire = newFire(trigger.id, trigger.fireAtMs, now, uncertainty);
      trigger.fires.push(fire);
    }
    await this.d.store.put(trigger);
    summary.fired++;

    // SSRF re-check before delivery: a hard block dead-letters delivery, but we
    // STILL anchor the (blocked) fire so the attempt is on the record.
    if (fire.delivery.status === "pending") {
      try {
        assertSafeWebhookUrl(trigger.target, cfg.ssrf);
      } catch (err) {
        fire.delivery.status = "dead";
        fire.delivery.lastError = err instanceof Error ? err.message : String(err);
      }
    }

    // Deliver (Standard-Webhooks signed POST) with retry/backoff/dead-letter.
    if (fire.delivery.status === "pending") {
      const body = deliveryBody(trigger, fire);
      const res = await deliverWithRetry(
        () =>
          deliverWebhook({
            target: trigger.target,
            body,
            secret: cfg.webhookSecret,
            idempotencyKey: fire!.fireId, // stable across retries + restart
            nowSec: Math.floor(now / 1000),
            fetchFn: this.d.fetchFn,
          }),
        cfg.retry,
      );
      fire.delivery.attempts += res.attempts;
      fire.delivery.lastStatusCode = res.lastStatus;
      fire.delivery.lastError = res.lastError;
      fire.delivery.status = res.ok ? "delivered" : "dead";
      trigger.attempts = fire.delivery.attempts;
    }
    if (fire.delivery.status === "delivered") summary.delivered++;
    if (fire.delivery.status === "dead") summary.deadLettered++;
    await this.d.store.put(trigger); // persist delivery outcome before anchoring

    // Anchor the fire (AGE-193). Failure leaves it pending; we re-anchor next tick.
    if (fire.anchor.status !== "anchored") {
      try {
        const a = await this.d.anchorer.anchorFire({
          trigger,
          fire,
          agentId: cfg.agentId,
        });
        fire.anchor = {
          status: a.status,
          eventHash: a.eventHash,
          ledgerId: a.ledgerId,
          blockHeight: a.blockHeight,
          receiptSchema: a.receiptSchema,
        };
        trigger.lastError = null;
      } catch (err) {
        trigger.lastError = err instanceof Error ? err.message : String(err);
      }
    }

    // Finalize ONLY when anchored. Otherwise re-arm for a retry next tick.
    if (fire.anchor.status === "anchored") {
      summary.anchored++;
      this.finalize(trigger, fire, now);
    } else {
      summary.pendingAnchor++;
      trigger.nextAttemptAtMs = now + (cfg.anchorRetryDelayMs ?? 1000);
    }
    await this.d.store.put(trigger);
  }

  /** Retire or re-arm a trigger after its fire anchored. */
  private finalize(trigger: Trigger, fire: FireRecord, now: number): void {
    const reArmInterval =
      trigger.mode === "interval" &&
      trigger.intervalMs &&
      trigger.intervalMs > 0 &&
      fire.delivery.status !== "dead";
    if (reArmInterval) {
      trigger.fireAtMs = trigger.fireAtMs + (trigger.intervalMs as number);
      trigger.status = "scheduled";
      trigger.attempts = 0;
      trigger.nextAttemptAtMs = 0;
    } else {
      trigger.status = fire.delivery.status === "dead" ? "dead" : "done";
    }
    trigger.updatedAtMs = now;
  }

  // ===== loop lifecycle =====

  /**
   * Start the always-on dispatch loop. Runs an immediate tick (re-arming any
   * triggers that were due while the worker was down) then ticks every
   * `intervalMs`. Idempotent. `onError` receives any tick error.
   */
  start(intervalMs = 1000, onError?: (err: unknown) => void): void {
    if (this.loopHandle) return;
    const runTick = () => {
      if (this.ticking) return; // skip if the previous tick is still running
      this.ticking = true;
      this.tick()
        .catch((err) => onError?.(err))
        .finally(() => {
          this.ticking = false;
        });
    };
    runTick(); // immediate boot tick (re-arm)
    this.loopHandle = setInterval(runTick, intervalMs);
    // Don't keep the event loop alive solely for the timer in short-lived runs.
    if (typeof this.loopHandle.unref === "function") this.loopHandle.unref();
  }

  /** Stop the dispatch loop. */
  stop(): void {
    if (this.loopHandle) {
      clearInterval(this.loopHandle);
      this.loopHandle = null;
    }
  }
}

/** A fresh, un-delivered, un-anchored fire record. */
function newFire(
  triggerId: string,
  scheduledForMs: number,
  firedAtMs: number,
  uncertaintyMs: number,
): FireRecord {
  return {
    fireId: `${triggerId}#${scheduledForMs}`,
    scheduledForMs,
    firedAtMs,
    firedAtUncertaintyMs: uncertaintyMs,
    delivery: { status: "pending", attempts: 0, lastStatusCode: null, lastError: null },
    anchor: {
      status: "pending",
      eventHash: null,
      ledgerId: null,
      blockHeight: null,
      receiptSchema: null,
    },
  };
}

/** The JSON body delivered to the webhook target for a fire. */
function deliveryBody(trigger: Trigger, fire: FireRecord): unknown {
  return {
    type: "keeper.fire",
    triggerId: trigger.id,
    fireId: fire.fireId,
    scheduledForMs: fire.scheduledForMs,
    firedAtMs: fire.firedAtMs,
    firedAtUncertaintyMs: fire.firedAtUncertaintyMs,
    payload: trigger.payload,
  };
}
