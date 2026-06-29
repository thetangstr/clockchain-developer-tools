/**
 * Domain model for the hosted keeper.
 *
 * A {@link Trigger} is a registered verified-time schedule. The dispatch worker
 * fires a trigger when Clockchain-disciplined time passes `fireAtMs`, even if the
 * agent that registered it is offline. Each fire produces a {@link FireRecord}.
 *
 * AGE-193 honesty: a fire is NOT "done" until it is anchored on-chain. The fire's
 * `anchor.status` is "pending" until a blockHeight lands, then "anchored". The
 * trigger is only retired (status "done") once its terminal fire is anchored, so
 * a crash between deliver and anchor re-arms the fire on reboot instead of losing
 * the proof.
 */

/** How a trigger repeats. "once" fires a single time; "interval" re-arms. */
export type TriggerMode = "once" | "interval";

/**
 * Lifecycle of a {@link Trigger}.
 * - scheduled: armed, waiting for `fireAtMs`.
 * - firing:    a fire is in progress (delivering and/or anchoring). Re-armed on
 *              reboot if the process died here, so the fire is never dropped.
 * - done:      a "once" trigger whose fire has fully anchored. Terminal.
 * - cancelled: cancelled by the owner via keeper_cancel. Terminal.
 * - dead:      delivery exhausted all retries (dead-letter). The fire is still
 *              anchored (the attempt is on the record); terminal for "once".
 */
export type TriggerStatus =
  | "scheduled"
  | "firing"
  | "done"
  | "cancelled"
  | "dead";

/** Delivery outcome of a single fire's webhook POST chain. */
export type DeliveryStatus = "pending" | "delivered" | "dead";

/** On-chain anchor status of a single fire (AGE-193). */
export type FireAnchorStatus = "pending" | "anchored";

/** One fire of a trigger: the verified-time instant + its delivery + its anchor. */
export interface FireRecord {
  /** Stable id for this fire: `${triggerId}#${fireAtMs}`. Also the idempotency key. */
  fireId: string;
  /** The scheduled instant this fire is for (epoch ms). */
  scheduledForMs: number;
  /** Disciplined Clockchain time the keeper actually fired at (epoch ms). */
  firedAtMs: number;
  /** Uncertainty half-width of `firedAtMs`, in ms (from the disciplined clock). */
  firedAtUncertaintyMs: number;
  delivery: {
    status: DeliveryStatus;
    attempts: number;
    lastStatusCode: number | null;
    lastError: string | null;
  };
  anchor: {
    status: FireAnchorStatus;
    eventHash: string | null;
    ledgerId: string | null;
    blockHeight: string | null;
    /** The full receipt schema id, for traceability. */
    receiptSchema: string | null;
  };
}

/** A registered verified-time trigger. */
export interface Trigger {
  id: string;
  /**
   * Owner identity (AGE-194). With bring-your-own-key, this is the caller's
   * Clockchain identity / key fingerprint; it scopes list/cancel so one tenant
   * cannot see or cancel another's triggers.
   */
  sub: string;
  /** When to fire, epoch ms (Clockchain-disciplined time is compared against this). */
  fireAtMs: number;
  /** Webhook URL the fire POSTs to. */
  target: string;
  /** Arbitrary JSON payload delivered (and hashed into the anchor). */
  payload: unknown;
  mode: TriggerMode;
  /** For mode "interval": gap between fires, ms. Ignored for "once". */
  intervalMs?: number;
  status: TriggerStatus;
  createdAtMs: number;
  updatedAtMs: number;
  /** Delivery attempts made for the in-flight fire (persisted for backoff/restart). */
  attempts: number;
  /** Earliest epoch ms the next delivery attempt may run (exponential backoff). */
  nextAttemptAtMs: number;
  /** Last error seen on this trigger, if any. */
  lastError: string | null;
  /** History of fires (most recent last). */
  fires: FireRecord[];
}

/** What keeper_schedule accepts to register a trigger. */
export interface ScheduleInput {
  sub: string;
  fireAtMs: number;
  target: string;
  payload?: unknown;
  mode?: TriggerMode;
  intervalMs?: number;
}
