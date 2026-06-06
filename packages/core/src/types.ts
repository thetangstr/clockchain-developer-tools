/**
 * Type definitions for the Clockchain gateway API.
 *
 * NOTE: The live API uses inconsistent response envelopes per endpoint.
 * These interfaces describe the UNWRAPPED data that {@link ClockchainClient}
 * returns to callers (the envelope handling lives in the client).
 */

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
