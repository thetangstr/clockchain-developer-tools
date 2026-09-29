/**
 * N4b-8 (gap 4): the contract anchor. Anchors the agreement digest when it
 * is formed and the receipt-chain head at the terminal transition, so both
 * land on the anchoring substrate as neutral hash+time records (Clockchain's
 * "anchor a hash + neutral time, content never leaves" model).
 *
 * The production backing is the existing in-process `tsa_issue` lifecycle —
 * `tsaIssue(client, …)` from `@clockchain/core` (core/src/tsa.ts), the same
 * primitive the `tsa_issue` MCP tool serves (mcp-server/src/tools.ts). Each
 * anchor is a TSA issue over `agent-contract:<runId>` with the digested
 * subject as the commitment and a fixed far deadline, so the commitmentId —
 * and therefore the `tsa:<id>` reference — is deterministic per
 * (runId, kind, digest): re-anchoring the same subject resolves to the same
 * on-chain reference.
 *
 * Tests inject a fake ContractAnchor — no network.
 */
import { tsaIssue } from "@clockchain/core";

import type { ClockchainClient } from "@clockchain/core";

/** What one anchored subject produced — carried on the run and digested into the anchor receipt. */
export interface AnchorWrite {
  /** The shared on-chain reference, `tsa:<commitmentId>`. */
  anchorId: string;
  /** sha256 of the canonical event payload that went on-chain. */
  eventHash: string;
  /** The TSA receipt's anchor record (ledger id, block height, honest status). */
  anchor: {
    ledgerId: string;
    blockHeight: string | null;
    time: string | null;
    status: string;
  };
}

export interface ContractAnchor {
  /**
   * Anchor a digest under a kind ("agreement" | "terminal"). Resolves with
   * the AnchorWrite; REJECTS or throws on any failure — the caller records
   * the failure, it is never silently dropped.
   */
  anchor(input: {
    kind: "agreement" | "terminal";
    runId: string;
    digestHex: string;
  }): Promise<AnchorWrite>;
}

/**
 * The production anchor: `tsa_issue` against the in-process Clockchain
 * client. A fixed deadline keeps `commitmentId` deterministic — the deadline
 * semantics (kept/broken verdicts) are unused here; we never attest.
 */
export function createTsaContractAnchor(client: ClockchainClient): ContractAnchor {
  return {
    async anchor({ kind, runId, digestHex }) {
      const receipt = await tsaIssue(client, {
        agentId: `agent-contract:${runId}`,
        commitment: `${kind}:${digestHex}`,
        deadline: "2099-12-31T00:00:00.000Z",
        consequence: `agent-contract ${kind} anchor`,
      });
      return {
        anchorId: `tsa:${receipt.commitmentId}`,
        eventHash: receipt.eventHash,
        anchor: receipt.anchor,
      };
    },
  };
}
