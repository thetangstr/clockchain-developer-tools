/**
 * Anchoring: turn a keeper fire into a keyless-verifiable Clockchain receipt.
 *
 * Credit-safety (HIGH-1): a fire is anchored EXACTLY ONCE. `anchorFire` does the
 * single chargeable write via `ClockchainClient.attestAction({ wait: false })` —
 * it returns a (possibly pending) receipt immediately without holding the
 * connection. Later ticks call `pollAnchor`, which uses `completeReceipt` — a
 * READ-ONLY re-fetch that spends NO log credit — to see whether the block has
 * landed. Re-running `attestAction` would embed a fresh `Date.now()` in the
 * assetReferenceId and mint a brand-new ledger entry + burn a new credit on every
 * retry, so the keeper must never do that.
 *
 * The keeper depends only on the {@link Anchorer} interface, so tests inject a
 * fake. {@link ClockchainAnchorer} is the real implementation.
 */
import type { AgentReceipt, ClockchainClient } from "@clockchain/core";
import type { FireRecord, Trigger } from "./types.js";

/** What the anchorer returns for one fire. */
export interface AnchorOutcome {
  status: "anchored" | "pending";
  eventHash: string | null;
  ledgerId: string | null;
  blockHeight: string | null;
  receiptSchema: string | null;
  /** The receipt to persist + re-poll. Opaque to the keeper. */
  receipt: unknown;
}

export interface Anchorer {
  /**
   * Anchor a fire ONCE (chargeable). Returns immediately with a pending or
   * anchored receipt; the keeper persists `receipt` for later read-only polling.
   */
  anchorFire(args: {
    trigger: Trigger;
    fire: FireRecord;
    agentId: string;
  }): Promise<AnchorOutcome>;

  /**
   * Poll a previously-anchored fire's receipt for confirmation. READ-ONLY: spends
   * no credit, anchors nothing. Returns the (possibly now-anchored) outcome.
   */
  pollAnchor(receipt: unknown): Promise<AnchorOutcome>;
}

/** Real anchorer over a {@link ClockchainClient}. */
export class ClockchainAnchorer implements Anchorer {
  constructor(private readonly client: ClockchainClient) {}

  async anchorFire(args: {
    trigger: Trigger;
    fire: FireRecord;
    agentId: string;
  }): Promise<AnchorOutcome> {
    const { trigger, fire, agentId } = args;
    // wait:false — the ONE chargeable write. Returns a pending receipt at once
    // (no held connection, no head-of-line blocking of other due triggers).
    const receipt = await this.client.attestAction({
      agentId,
      action: "keeper.fire",
      inputs: {
        triggerId: trigger.id,
        fireId: fire.fireId,
        scheduledForMs: fire.scheduledForMs,
        target: trigger.target,
        payload: trigger.payload,
      },
      outputs: {
        firedAtMs: fire.firedAtMs,
        firedAtUncertaintyMs: fire.firedAtUncertaintyMs,
        delivery: fire.delivery,
      },
      wait: false,
    });
    return toOutcome(receipt);
  }

  async pollAnchor(receipt: unknown): Promise<AnchorOutcome> {
    // completeReceipt re-fetches the ledger entry (and enriches once anchored)
    // WITHOUT writing — no credit spent. Idempotent and safe to call every tick.
    const updated = await this.client.completeReceipt(receipt as AgentReceipt);
    return toOutcome(updated);
  }
}

/** Map an AgentReceipt into the keeper's {@link AnchorOutcome}. */
function toOutcome(receipt: AgentReceipt): AnchorOutcome {
  return {
    status: receipt.status === "anchored" ? "anchored" : "pending",
    eventHash: receipt.eventHash,
    ledgerId: receipt.anchor.ledgerId,
    blockHeight: receipt.anchor.blockHeight,
    receiptSchema: receipt.schema,
    receipt,
  };
}
