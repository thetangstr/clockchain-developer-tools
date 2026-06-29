/**
 * Anchoring: turn a keeper fire into a keyless-verifiable Clockchain receipt.
 *
 * The keeper depends only on the {@link Anchorer} interface so tests can inject a
 * fake. {@link ClockchainAnchorer} is the real implementation: it wraps
 * `@clockchain/core`'s `ClockchainClient.attestAction` (the same `attest_action`
 * the MCP server exposes), hashing the fire's identity + payload into an on-chain
 * event. AGE-193: the returned status is "anchored" only once a blockHeight has
 * landed; otherwise "pending" and the dispatcher will re-anchor.
 */
import type { ClockchainClient } from "@clockchain/core";
import type { FireRecord, Trigger } from "./types.js";

/** What the anchorer returns for one fire. */
export interface AnchorResult {
  status: "anchored" | "pending";
  eventHash: string | null;
  ledgerId: string | null;
  blockHeight: string | null;
  receiptSchema: string | null;
}

export interface Anchorer {
  /**
   * Anchor a fire. `agentId` is the keeper's acting identity; `fire` carries the
   * verified-time instant and delivery outcome that get hashed into the receipt.
   */
  anchorFire(args: {
    trigger: Trigger;
    fire: FireRecord;
    agentId: string;
  }): Promise<AnchorResult>;
}

/** Real anchorer over a {@link ClockchainClient}. */
export class ClockchainAnchorer implements Anchorer {
  constructor(private readonly client: ClockchainClient) {}

  async anchorFire(args: {
    trigger: Trigger;
    fire: FireRecord;
    agentId: string;
  }): Promise<AnchorResult> {
    const { trigger, fire, agentId } = args;
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
      // Wait briefly for the block; if it has not landed we record pending and the
      // dispatcher re-anchors next tick rather than blocking the loop.
      wait: true,
    });
    return {
      status: receipt.status === "anchored" ? "anchored" : "pending",
      eventHash: receipt.eventHash,
      ledgerId: receipt.anchor.ledgerId,
      blockHeight: receipt.anchor.blockHeight,
      receiptSchema: receipt.schema,
    };
  }
}
