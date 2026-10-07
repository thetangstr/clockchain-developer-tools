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
import { deriveAnchorStatus, tsaIssue, tsaStatus } from "@clockchain/core";

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
  /** log only: true when an existing record was found (no write was made). */
  reused?: boolean;
}

export interface ContractAnchor {
  /**
   * Anchor a digest under a kind ("agreement" | "terminal", or the
   * server-side "terms" | "brief" | "final" subjects). Resolves with
   * the AnchorWrite; REJECTS or throws on any failure — the caller records
   * the failure, it is never silently dropped.
   */
  anchor(input: {
    kind: "agreement" | "terminal" | "terms" | "brief" | "final";
    runId: string;
    digestHex: string;
  }): Promise<AnchorWrite>;
  /**
   * N4b-9 (F13): re-check an issued anchor's confirmation state. A resolved
   * anchor write whose `anchor.status` is `pending_confirmation` is NOT
   * anchored — the job stays pending and is re-confirmed via this call
   * (boot recovery, scheduled polls). Optional: a backing that cannot poll
   * simply omits it and the pending job is re-issued via `anchor` instead
   * (idempotent — deterministic commitmentId).
   */
  confirm?(anchorId: string): Promise<AnchorWrite["anchor"]>;
  /**
   * Milestone log (milestone-log.ts, CONTRACT_MILESTONE_LOG — default off):
   * anchor `digestHex` as the asset hash under the caller's own reference id
   * (`ac-milestone:<runId>:<n>-<milestone>`), not under a TSA commitment.
   * Idempotent per (referenceId, digest): an existing record with the same
   * hash under that reference is returned instead of a second write, so a
   * re-issue (confirm fallback, boot recovery) never spends twice. The
   * returned `anchorId` is the reference id. REJECTS on any failure.
   * Optional: a backing without it leaves the milestone log inert.
   */
  log?(input: { referenceId: string; digestHex: string; additionalInfo: string }): Promise<AnchorWrite>;
  /** Re-read a milestone log record's confirmation state by its ledger id. */
  confirmLog?(ledgerId: string): Promise<AnchorWrite["anchor"]>;
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
        // N4b-9 (F17): core emits a BARE 64-hex eventHash; the published
        // contract_status schema requires the 0x-prefixed digestHex form.
        // Normalization lives at this adapter boundary — the one place core
        // types cross into the contract vocabulary.
        eventHash: normalizeDigestHex(receipt.eventHash),
        anchor: receipt.anchor,
      };
    },
    // N4b-9 (F13): confirmation polling for pending anchors — reads the
    // on-chain trail so a restart/recheck can resolve block/time honestly.
    async confirm(anchorId) {
      const commitmentId = anchorId.startsWith("tsa:") ? anchorId.slice(4) : anchorId;
      const status = await tsaStatus(client, commitmentId);
      const latest = status.events.at(-1);
      return {
        ledgerId: latest?.ledgerId ?? "",
        blockHeight: latest?.blockHeight ?? null,
        time: latest?.time ?? null,
        status: deriveAnchorStatus(latest?.blockHeight ?? null),
      };
    },
    // Milestone log: a plain `/log` write of the entry digest under its own
    // reference. searchAsset first (exact-match on the reference) makes the
    // write idempotent across re-issues and restarts.
    async log({ referenceId, digestHex, additionalInfo }) {
      const eventHash = normalizeDigestHex(digestHex);
      const bare = eventHash.slice(2);
      const existing = (await client.searchAsset(referenceId))
        .find((r) => typeof r.assetHash === "string" && r.assetHash.toLowerCase().replace(/^0x/, "") === bare);
      const record = existing ?? await client.log({ assetHash: bare, assetReferenceId: referenceId, additionalInfo });
      return { anchorId: referenceId, eventHash, anchor: ledgerOf(record), reused: existing !== undefined };
    },
    async confirmLog(ledgerId) {
      return ledgerOf(await client.getLedgerEntry(ledgerId));
    },
  };
}

/** A gateway log record as the contract's ledger view (honest status from blockHeight). */
function ledgerOf(record: { ledgerId: string; blockHeight?: string | null; createdTimestamp?: string | null }): AnchorWrite["anchor"] {
  const blockHeight = record.blockHeight ?? null;
  return {
    ledgerId: record.ledgerId,
    blockHeight,
    time: record.createdTimestamp ?? null,
    status: deriveAnchorStatus(blockHeight),
  };
}

/**
 * Bare or prefixed hex (either case) normalizes to the published `0x`-lower
 * digestHex form. Anything else fails at the adapter boundary — a malformed
 * event hash must never reach `contract_status`.
 */
function normalizeDigestHex(hash: string): string {
  const raw = hash.startsWith("0x") || hash.startsWith("0X") ? hash.slice(2) : hash;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error(`anchor substrate returned a malformed eventHash (${hash.length} chars)`);
  }
  return `0x${raw.toLowerCase()}`;
}
