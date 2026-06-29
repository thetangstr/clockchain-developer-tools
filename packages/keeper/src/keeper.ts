/**
 * The Keeper: control plane (register / list / cancel) + data plane (the dispatch
 * loop that fires due triggers while the client is offline).
 *
 * Dependencies are injected ({@link KeeperDeps}) so the whole fire path is unit
 * testable without a network, real timers, or a real clock:
 *   - store    : durable {@link KeeperStore} (survives restart; re-armed on boot).
 *   - anchorer : {@link Anchorer} (real one wraps attest_action ONCE then polls).
 *   - nowMs    : disciplined Clockchain time, epoch ms (from clock-sdk in prod).
 *   - fetchFn  : webhook transport (injectable).
 *
 * Tick discipline (HIGH-2): a tick never blocks. Each due trigger does at most ONE
 * delivery POST and ONE anchor step per tick; all backoff/wait is carried ACROSS
 * ticks via `nextAttemptAtMs` (no in-tick sleeps, no wait:true held connections).
 * Due triggers are processed by a bounded concurrency pool and capped per tick, so
 * one slow/large batch cannot starve the rest.
 *
 * Truthful anchoring invariant: a due trigger leaves the due set ONLY after its fire is
 * anchored. A pending/failed anchor leaves it armed, so a fire is never silently
 * dropped — it is retried next tick and re-armed after a restart. Credit-safety:
 * the chargeable anchor write happens once; later ticks poll read-only.
 */
import { randomUUID } from "node:crypto";
import { type Anchorer } from "./anchor.js";
import { type SsrfOptions, assertSafeWebhookUrl } from "./ssrf.js";
import { type KeeperStore } from "./store.js";
import { type FetchLike, backoffDelayMs, deliverWebhook } from "./webhook.js";
import type { FireRecord, ScheduleInput, Trigger, TriggerStatus } from "./types.js";

export interface KeeperConfig {
  /** Keeper's acting identity used when anchoring fires (e.g. "agent:clockchain-keeper"). */
  agentId: string;
  /** Standard-Webhooks signing secret (raw or whsec_...). */
  webhookSecret: string;
  /** SSRF guard policy for webhook targets. */
  ssrf?: SsrfOptions;
  /** Max delivery attempts before dead-lettering. Default 5. */
  maxAttempts?: number;
  /** Delivery backoff base, ms (delay = base * 2^(attempt-2), capped). Default 500. */
  baseDelayMs?: number;
  /** Delivery backoff cap, ms. Default 30000. */
  maxDelayMs?: number;
  /** Delay before re-attempting a pending/failed anchor on the next tick, ms. Default 1000. */
  anchorRetryDelayMs?: number;
  /** Max due triggers processed per tick. Default 100. */
  maxPerTick?: number;
  /** Max fires processed concurrently within a tick. Default 10. */
  concurrency?: number;
  /** Max fire records retained per trigger (ring buffer). Default 50. */
  maxRetainedFires?: number;
  /** Max serialized payload size, bytes. Default 65536. */
  maxPayloadBytes?: number;
  /** Max live (non-terminal) triggers per owner. Default 1000. */
  maxTriggersPerSub?: number;
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
  /** New fires created this tick (a fire being retried is not re-counted). */
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
    const cfg = this.d.config;
    if (!Number.isFinite(input.fireAtMs)) {
      throw new Error("fireAtMs must be a finite epoch-ms number.");
    }
    if (!input.sub) throw new Error("sub (owner identity) is required.");
    const mode = input.mode ?? "once";
    if (mode === "interval" && !(input.intervalMs && input.intervalMs > 0)) {
      throw new Error('mode "interval" requires a positive intervalMs.');
    }
    // Payload size cap (LOW): bound what a single trigger can store/deliver/hash.
    const maxBytes = cfg.maxPayloadBytes ?? 65536;
    const payloadBytes = Buffer.byteLength(JSON.stringify(input.payload ?? null));
    if (payloadBytes > maxBytes) {
      throw new Error(`payload too large (${payloadBytes} > ${maxBytes} bytes).`);
    }
    // Per-owner trigger-count cap (LOW): bound fan-out per tenant.
    const maxPerSub = cfg.maxTriggersPerSub ?? 1000;
    const live = (await this.d.store.all()).filter(
      (t) => t.sub === input.sub && !TERMINAL.has(t.status),
    );
    if (live.length >= maxPerSub) {
      throw new Error(`trigger limit reached for this owner (${maxPerSub}).`);
    }
    // SSRF check at registration time (and again before each delivery).
    assertSafeWebhookUrl(input.target, cfg.ssrf);

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

  /** List triggers, optionally scoped to one owner (per-user auth tenant isolation). */
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

  /**
   * Process every due trigger once, with bounded concurrency and a per-tick cap.
   * Safe to call repeatedly (idempotent fires). Never blocks on network waits.
   */
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
    const due: Trigger[] = [];
    for (const t of triggers) {
      summary.examined++;
      if (t.status !== "scheduled" && t.status !== "firing") continue;
      if (t.fireAtMs > now) continue; // not due yet
      if (t.nextAttemptAtMs > now) continue; // backing off a retry across ticks
      due.push(t);
    }
    // Oldest-due first so a backlog drains fairly; cap per-tick work.
    due.sort((a, b) => a.fireAtMs - b.fireAtMs);
    const slice = due.slice(0, this.d.config.maxPerTick ?? 100);
    const concurrency = Math.max(1, this.d.config.concurrency ?? 10);
    await runPool(slice, concurrency, (t) => this.fireOne(t, now, summary));
    return summary;
  }

  /**
   * Advance a single due trigger by ONE step (deliver + anchor), non-blocking.
   * Delivery and anchor each attempt at most once; remaining work is re-armed via
   * `nextAttemptAtMs` for a later tick.
   */
  private async fireOne(
    trigger: Trigger,
    now: number,
    summary: TickSummary,
  ): Promise<void> {
    const cfg = this.d.config;
    const uncertainty = this.d.nowUncertaintyMs?.() ?? 0;

    // Mark firing and create (or reuse) the fire record for THIS instant. A crash
    // after this point re-arms here on reboot — the fire is never lost.
    trigger.status = "firing";
    trigger.updatedAtMs = now;
    let fire = trigger.fires.find((f) => f.scheduledForMs === trigger.fireAtMs);
    if (!fire) {
      fire = newFire(trigger.id, trigger.fireAtMs, now, uncertainty);
      trigger.fires.push(fire);
      this.trimFires(trigger);
      summary.fired++;
    }
    await this.d.store.put(trigger);

    // The soonest delay (ms) any still-pending step needs before its next attempt.
    let retryDelay = Number.POSITIVE_INFINITY;

    // ---- delivery step: at most one POST per tick ----
    if (fire.delivery.status === "pending") {
      let ssrfError: string | null = null;
      try {
        assertSafeWebhookUrl(trigger.target, cfg.ssrf);
      } catch (err) {
        ssrfError = err instanceof Error ? err.message : String(err);
      }
      if (ssrfError) {
        // Hard block: dead-letter delivery, but still anchor the (blocked) fire.
        fire.delivery.status = "dead";
        fire.delivery.lastError = ssrfError;
        summary.deadLettered++;
      } else {
        const res = await deliverWebhook({
          target: trigger.target,
          body: deliveryBody(trigger, fire),
          secret: cfg.webhookSecret,
          idempotencyKey: fire.fireId, // stable across retries + restart re-fire
          nowSec: Math.floor(now / 1000),
          fetchFn: this.d.fetchFn,
        });
        fire.delivery.attempts++;
        fire.delivery.lastStatusCode = res.status;
        fire.delivery.lastError = res.error ?? (res.ok ? null : `HTTP ${res.status}`);
        trigger.attempts = fire.delivery.attempts;
        if (res.ok) {
          fire.delivery.status = "delivered";
          summary.delivered++;
        } else if (fire.delivery.attempts >= (cfg.maxAttempts ?? 5)) {
          fire.delivery.status = "dead"; // exhausted -> dead-letter
          summary.deadLettered++;
        } else {
          // Backoff carried ACROSS ticks (no in-tick sleep).
          retryDelay = Math.min(
            retryDelay,
            backoffDelayMs(fire.delivery.attempts + 1, cfg.baseDelayMs ?? 500, cfg.maxDelayMs ?? 30000),
          );
        }
      }
    }

    // ---- anchor step: charge ONCE, then poll read-only ----
    if (fire.anchor.status !== "anchored") {
      try {
        const outcome =
          fire.anchor.receipt == null
            ? await this.d.anchorer.anchorFire({ trigger, fire, agentId: cfg.agentId })
            : await this.d.anchorer.pollAnchor(fire.anchor.receipt);
        fire.anchor = {
          status: outcome.status,
          eventHash: outcome.eventHash,
          ledgerId: outcome.ledgerId,
          blockHeight: outcome.blockHeight,
          receiptSchema: outcome.receiptSchema,
          receipt: outcome.receipt,
        };
        trigger.lastError = null;
        if (outcome.status === "anchored") {
          summary.anchored++;
        } else {
          summary.pendingAnchor++;
          retryDelay = Math.min(retryDelay, cfg.anchorRetryDelayMs ?? 1000);
        }
      } catch (err) {
        // Leave the anchor pending; retry next tick. If the write itself failed
        // (no receipt persisted) the next tick re-issues anchorFire — a failed
        // gateway write spends no credit, so this does not drain credits.
        trigger.lastError = err instanceof Error ? err.message : String(err);
        retryDelay = Math.min(retryDelay, cfg.anchorRetryDelayMs ?? 1000);
      }
    }

    // ---- finalize ONLY when delivery is terminal AND the fire is anchored ----
    const deliveryTerminal =
      fire.delivery.status === "delivered" || fire.delivery.status === "dead";
    if (deliveryTerminal && fire.anchor.status === "anchored") {
      this.finalize(trigger, fire, now);
    } else {
      trigger.nextAttemptAtMs =
        now + (Number.isFinite(retryDelay) ? retryDelay : cfg.anchorRetryDelayMs ?? 1000);
    }
    await this.d.store.put(trigger);
  }

  /** Retire (once) or re-arm (interval) a trigger after its fire anchored. */
  private finalize(trigger: Trigger, fire: FireRecord, now: number): void {
    if (trigger.mode === "interval" && trigger.intervalMs && trigger.intervalMs > 0) {
      // Re-arm even through a dead-lettered delivery: the fire IS anchored, and a
      // single failed POST should not silently kill a recurring schedule. (A
      // permanently-broken endpoint keeps anchoring until the owner cancels — see
      // the keeper_schedule tool description.)
      trigger.fireAtMs = nextIntervalSlot(trigger.fireAtMs, trigger.intervalMs, now);
      trigger.status = "scheduled";
      trigger.attempts = 0;
      trigger.nextAttemptAtMs = 0;
      trigger.lastError = null;
    } else {
      trigger.status = fire.delivery.status === "dead" ? "dead" : "done";
    }
    trigger.updatedAtMs = now;
  }

  /** Cap retained fire history (ring buffer) — keeps the newest N (incl. current). */
  private trimFires(trigger: Trigger): void {
    const cap = this.d.config.maxRetainedFires ?? 50;
    if (trigger.fires.length > cap) {
      trigger.fires = trigger.fires.slice(trigger.fires.length - cap);
    }
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

/**
 * Next interval slot strictly after `now` (avoids a catch-up storm: after downtime
 * the trigger jumps to the upcoming slot instead of firing once per missed slot).
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
      receipt: null,
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

/** Run `fn` over `items` with at most `concurrency` in flight. */
async function runPool<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const workers: Promise<void>[] = [];
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]);
    }
  };
  for (let i = 0; i < Math.min(concurrency, items.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
}
