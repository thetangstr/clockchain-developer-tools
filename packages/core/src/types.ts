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
  disclaimer: string;
}

/** Result of {@link ClockchainClient.verifyReceipt}. */
export interface ReceiptVerification {
  match: boolean;
  eventHash: string;
  anchoredHash: string;
  blockHeight: string | null;
  ledgerId: string;
}
