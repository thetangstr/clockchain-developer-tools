// Vendored from clockchain-shadow/ts/src/types.ts (source sha256 e2fdb43a014bd598cdcfb8b80f57398feaf0b9dfd563b7a607e00a78c0b1f42d) by scripts/sync-shadow-lib.mjs.
// Do not edit here: change the library, then re-run the script.
// Record formats (spec/SPEC.md §3–§5). Field order here is documentation only; hashing sorts keys.
import type { Json, ProofStep } from './profile.js';

export type Network = 'clockchain-testnet' | 'clockchain-mainnet';
export type Boundary = 'collector' | 'transcript';

export type Source = { boundary: Boundary; agentRunId: string | null; taskId: string | null; transcriptId: string | null };

export type EventBody = {
  profile: string;
  operatorId: string;
  sessionId: string;
  streamId: 'collector';
  seq: number;
  previousHash: string | null;
  eventId: string;
  kind: string;
  actor: string;
  collectedAt: string;
  source: Source;
  payload: { [key: string]: Json };
};
export type ShadowEvent = { body: EventBody; hash: string };

export type Coverage = {
  agent: string;
  status: 'idle' | 'observed' | 'open' | 'partial';
  runs: number;
  observedEvents: number;
  gaps: number;
};

export type CheckpointBody = {
  profile: string;
  operatorId: string;
  sessionId: string;
  streamId: 'collector';
  count: number;
  head: string | null;
  merkleRoot: string;
  previousCheckpointHash: string | null;
  createdAt: string;
  network: Network;
  inventory: { profile: 'shadow-inventory-v1'; agents: string[] };
  coverage: Coverage[];
  knownLimits: string[];
};
export type Checkpoint = { body: CheckpointBody; hash: string; publicKey: string; signature: string };

// A Clockchain write receipt as recorded in session.opened and clockchain.anchored. blockHeight is a decimal string.
export type Receipt = {
  referenceId: string;
  ledgerId: string;
  blockHeight: string | null;
  blockTime: string | null;
  status: 'anchored' | 'pending';
};

// salt is the agent's random commitment salt (spec §6). It stays with the operator and travels only in packets, so a
// relying party can recompute the DID; it is never sent to Clockchain.
export type Identity = { agentId: string; did: string; document: Json; docHash: string | null; ledgerId: string | null; salt?: string };

// A checkpoint queued for Clockchain whose receipt is not among the packet's steps (spec §9). It lets an online verifier
// account for a ledger record that landed after the packet was made.
export type PendingCheckpoint = { hash: string; body: CheckpointBody };

export type Packet = {
  format: 'shadow-evidence-v2';
  profile: string;
  events: ShadowEvent[];
  checkpoint: Checkpoint;
  proofs: ProofStep[][];
  identities: Identity[];
  pendingCheckpoints?: PendingCheckpoint[];
  manifest: { library: string; version: string; network: Network; createdAt: string };
};

export type Pin = {
  format: 'shadow-trust-pin-v2';
  checkpointHash: string;
  publicKeyFingerprint: string;
  operatorId: string;
  sessionId: string;
};
