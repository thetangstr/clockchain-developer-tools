/**
 * Type definitions for the Clockchain gateway API.
 *
 * NOTE: The live API uses inconsistent response envelopes per endpoint.
 * These interfaces describe the UNWRAPPED data that {@link ClockchainClient}
 * returns to callers (the envelope handling lives in the client).
 */

/**
 * Anchor status for a write (truthful anchoring — "never report success on an un-anchored
 * fire"):
 *   - "anchored": the entry has a blockHeight (confirmed on-chain).
 *   - "pending":  submitted, no blockHeight yet (poll to confirm).
 *   - "degraded": not anchored AND the node pool is degraded (0% participation),
 *                 so anchoring is at risk — a stronger warning than plain pending.
 */
export type AnchorStatus = "anchored" | "pending" | "degraded";

/**
 * A snapshot of node-pool health, derived from {@link TimestampResponse}. Used
 * to guard writes (refuse at 0% participation) and to enrich receipts so a
 * caller can see WHY a write is degraded.
 */
export interface PoolHealth {
  totalNodes: number;
  /** The gateway's `nodeParticipation%`. 0 means the pool is degraded. */
  nodeParticipationPct: number;
  degraded: boolean;
}

/** GET /api/time/time -> data */
export interface TimeResponse {
  latestBlockTime: string;
  latestBlockHeight: number;
}

/**
 * GET /api/time/timestamp -> data
 * `nodeParticipation%` is kept as a quoted key on purpose: that is the exact
 * field name returned by the gateway.
 */
export interface TimestampResponse {
  consentedOffset: number;
  positiveVotesPercentage: number;
  blockHeight: number;
  madMarzulloTime: string;
  nodeStatus: string;
  systemTime: string;
  AbsTimeDifference: number;
  negativeVotesPercentage: number;
  "nodeParticipation%": number;
  totalNodes: number;
}

/** GET /api/time/block?height=N -> data */
export interface BlockResponse {
  blockHeight: number;
  proposerAddress: string;
  blockTime: string;
}

/**
 * GET /getValidationBlock/{h} -> validationBlockData
 * Field names with spaces are kept exactly as returned by the gateway.
 * Not all blocks have validation data; `faultHandling` is surfaced when present.
 */
export interface ValidationBlock {
  validationBlock?: unknown;
  blockHeight: number;
  positiveVotes: number;
  negativeVotes: number;
  "Trust value percentage": number;
  "Node participation percentage": number;
  /** Present only when the block went through fault handling. */
  faultHandling?: unknown;
  [key: string]: unknown;
}

/** Fields required to POST /log (and a subset of the response shape). */
export interface LogEntry {
  clientId: string;
  walletId: string;
  assetReferenceId: string;
  assetHash: string;
  hashType: string;
  versionNumber: number;
  /**
   * Plain-text-only. The gateway sanitizes this server-side to alphanumeric +
   * spaces (it strips punctuation/JSON). Do NOT store structured metadata here.
   */
  additionalInfo: string;
}

/**
 * POST /log response (and GET /ledger/{id}).
 * `blockHeight` is null on create and is populated ~0.6s later once the leader
 * writes the block; treat null as "pending".
 */
export interface LogResponse extends LogEntry {
  ledgerId: string;
  blockHeight: string | null;
  createdTimestamp: string;
  updatedTimestamp: string | null;
  assetName: string | null;
  type: string | null;
  /**
   * Anchor status derived from blockHeight by the client (truthful anchoring). Optional
   * because the raw gateway payload does not carry it — the client stamps it on
   * the way out so a caller never mistakes a pending write for success.
   */
  status?: AnchorStatus;
}

/** Result of an ERC-8004 agent resolution (read-only). */
export interface AgentIdentity {
  agentId: string;
  agentURI?: string;
  owner?: string;
  status: "active" | "unknown";
}

/** A bare ledger record as returned by /searchAsset and /ledger/{id}. */
export type LedgerRecord = LogResponse;

/** Input to {@link ClockchainClient.attestAction}. */
export interface AttestActionInput {
  /** Who acted (e.g. an ERC-8004 agentId or an internal agent label). */
  agentId: string;
  /** What they did (e.g. "execute_trade", "sign_contract"). */
  action: string;
  /** The exact inputs to the decision (hashed into the event fingerprint). */
  inputs?: unknown;
  /** The exact outputs of the decision (hashed into the event fingerprint). */
  outputs?: unknown;
  /** Wait for on-chain confirmation before returning. Default true. */
  wait?: boolean;
  /** Max wait for confirmation, ms. Default 15000. */
  waitMs?: number;
}

/**
 * An Agent Attested Receipt: independently verifiable proof of who acted, what
 * they did, and when. Fields are populated where the live network supports them;
 * multi-validator attestation is marked as mainnet-gated (the testnet runs a
 * single validator, so its vote/trust data is not yet a supermajority).
 */
export interface AgentReceipt {
  schema: "clockchain.receipt/v1";
  network: string;
  /**
   * Top-level anchor status (truthful anchoring). "anchored" only once the event has a
   * blockHeight; otherwise "pending" (or "degraded" when the pool is degraded
   * and the event is not yet anchored). A receipt is NOT a success claim until
   * this is "anchored".
   */
  status: AnchorStatus;
  agentId: string;
  action: string;
  /** SHA-256 of the canonical {agentId, action, inputs, outputs}. */
  eventHash: string;
  hashType: "SHA-256";
  /** The exact payload that was hashed, so the receipt is self-verifying. */
  payload: { inputs: unknown; outputs: unknown };
  anchor: {
    ledgerId: string;
    assetReferenceId: string;
    blockHeight: string | null;
    recordedAt: string;
    consensusTime: string | null;
    confirmed: boolean;
  };
  attestation: {
    validators: number;
    trustPct: number | null;
    status: "single-validator-testnet" | "multi-validator";
    note: string;
  };
  identity: {
    resolved: boolean;
    status: string;
    note: string;
  };
  verify: { how: string };
  /** Node-pool health at attest time (truthful anchoring). Present when it could be read. */
  poolHealth?: PoolHealth;
  disclaimer: string;
}

/** Result of {@link ClockchainClient.verifyReceipt}. */
export interface ReceiptVerification {
  match: boolean;
  eventHash: string;
  anchoredHash: string;
  blockHeight: string | null;
  ledgerId: string;
  /**
   * Where the anchored hash was read from: the IMMUTABLE on-chain block
   * ("on-chain block") or, when not yet anchored, the mutable record cache
   * ("record cache (not yet anchored on-chain)").
   */
  verifiedAgainst: string;
}

/**
 * A record read from the IMMUTABLE on-chain block (GET /searchAssetFromChain).
 * Unlike GET /ledger/{id} and /verifyAsset (which read a mutable convenience
 * cache an api-key holder can rewrite via PUT /ledger/{id}), the block cannot be
 * altered — this is the AUTHORITATIVE record.
 */
export interface ChainRecord {
  assetHash: string;
  assetReferenceId: string;
  blockHeight: string;
}

/**
 * Result of {@link ClockchainClient.verifyOnChain} — the authoritative,
 * keyless cross-party check against the immutable on-chain block.
 */
export interface OnChainVerification {
  verifiedAgainst: string;
  keyless?: boolean;
  ledgerId: string;
  blockHeight?: string;
  heightSource?: string;
  anchoredHash?: string;
  assetReferenceId?: string;
  note: string;
}

// ===== SCHEDULER (smart-contract /api/contract/*) =====

/**
 * Multipart form fields for {@link ClockchainClient.estimateContract} /
 * scheduleContract. These map to Spring `@RequestParam` values forwarded as
 * multipart/form-data alongside the Solidity source file. Required keys are
 * blockchain, contractType, contractName, deadline; additional per-ERC keys
 * (symbol, supply, …) are passed through as-is. The file part is named
 * `contractFile` for estimate and `solidityFile` for schedule (VERIFIED, Swagger).
 */
export type ContractParams = Record<string, string | number>;

/**
 * The "approve" half of propose-then-approve: the gas numbers from the chosen
 * estimate plus the caller's wallet signature + integer nonce. VERIFIED against
 * the gateway's Swagger (2026-06-11): nonce is an INTEGER and the signature is
 * an EVM wallet signature (personal_sign pattern; see {@link
 * ClockchainClient.scheduleContract}). NON-CUSTODIAL — caller-supplied.
 */
export interface ScheduleApproval {
  /** Gas fees from the chosen estimate (numbers, not strings). */
  gasFees: number;
  minGasFees?: number;
  maxGasFees?: number;
  totalPayablePrice: number;
  totalPayablePriceUnit?: string;
  /** INTEGER nonce per Swagger (NOT a string). */
  nonce: number;
  /** EVM wallet signature (personal_sign pattern) — caller-supplied. */
  signature: string;
  deadline?: number;
  trustPercentage?: number;
}

/**
 * Result of {@link ClockchainClient.estimateContract}. The gateway's estimate
 * shape is not strictly typed here (it varies by ERC); the raw object is
 * surfaced to the caller alongside the params that must be signed to schedule.
 */
export interface ContractEstimate {
  estimate: unknown;
  /** The exact params the caller must sign + forward to scheduleContract. */
  params: ContractParams;
}

/** Result of {@link ClockchainClient.scheduleContract} (non-custodial deploy). */
export interface ScheduledContract {
  result: unknown;
  params: ContractParams;
  approval: ScheduleApproval;
}

// ===== AUDIT (derivative — composes Time + Logging + Identity) =====

/** One assembled, attested event in an {@link AuditTrail}. Mints nothing new. */
export interface AuditEvent {
  ledgerId: string;
  assetReferenceId: string;
  assetHash: string;
  /** Clockchain consensus time for this event's block (null if pending). */
  time: string | null;
  blockHeight: string | null;
  additionalInfo: string;
}

/** Assembled view over events the free modules already attested. */
export interface AuditTrail {
  assetReferenceId: string;
  events: AuditEvent[];
  count: number;
  builtAt: string;
}

/** Supported compliance presets. Formats are PARAMETERS, never bespoke tools. */
export type ComplianceFormat = "eu_ai_act_art12" | "sec_17a4" | "iso_27001";

/** A rendered compliance report (the same trail in a regulator preset). */
export interface ComplianceReport {
  format: ComplianceFormat;
  assetReferenceId: string;
  reportHash: string;
  document: Record<string, unknown>;
  honestyNote: string;
}

/** A self-contained, offline-verifiable evidence packet for one ledger record. */
export interface EvidencePackage {
  packageId: string;
  pkgHash: string;
  record: LedgerRecord;
  block: BlockResponse | null;
  validation: ValidationBlock | null;
  plainEnglish: string;
  honestyNote: string;
}

/** Result of {@link ClockchainClient.verifyPackage}. */
export interface PackageVerification {
  valid: boolean;
  pkgHashMatch: boolean;
  anchorMatch: boolean;
  recomputedPkgHash: string;
  anchoredHash: string;
  note: string;
}

// ===== AGENT IDENTITY (writes via the /log hash-anchor convention) =====

/** Result of a mint / revoke / delegate identity write. */
export interface IdentityWrite {
  did: string;
  assetReferenceId: string;
  docHash: string;
  ledgerId: string;
  blockHeight: string | null;
  /** The identity lifecycle state this write records. */
  status: "active" | "revoked" | "delegated";
  /**
   * Anchor status derived from blockHeight (truthful anchoring) — distinct from the
   * lifecycle `status`. "anchored" only once the write has a blockHeight, so a
   * caller never treats an un-anchored mint/revoke/delegate as confirmed.
   */
  anchorStatus: AnchorStatus;
}

/** One entry in a DID's attested activity history. */
export interface IdentityEvent {
  type: "mint" | "revoke" | "delegate";
  assetReferenceId: string;
  ledgerId: string;
  assetHash: string;
  /** Clockchain consensus time for this event's block (null if pending). */
  time: string | null;
  blockHeight: string | null;
  /**
   * The gateway's record-creation timestamp (createdTimestamp). Used as the
   * fallback instant for valid-at-T when consensus `time` is not yet populated.
   * Gateway format is DD-MM-YYYY (e.g. "11-06-2026 16:10:48:544 UTC").
   */
  recordedAt: string;
}

/** Result of {@link ClockchainClient.getIdentityHistory}. */
export interface IdentityHistory {
  did: string;
  events: IdentityEvent[];
}

/**
 * Result of {@link ClockchainClient.verifyIdentityAt} — the valid-at-T query.
 * Authorized iff an attested mint exists at or before T and no revoke does.
 * This is identity VERIFICATION (was the binding valid at T?), not authentication.
 */
export interface IdentityVerification {
  did: string;
  /** The queried instant (RFC 3339, echoed back). */
  at: string;
  authorized: boolean;
  reason: string;
  mintedAt: string | null;
  revokedAt: string | null;
  evidence: { mintLedgerId?: string; revokeLedgerId?: string };
  note: string;
}
