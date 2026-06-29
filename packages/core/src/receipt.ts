import { computeHash } from "./hash.js";
import type {
  AgentReceipt,
  AnchorStatus,
  AttestActionInput,
  BlockResponse,
  LogResponse,
  PoolHealth,
  ValidationBlock,
} from "./types.js";

/**
 * Deterministic JSON: object keys sorted recursively so the same logical value
 * always produces the same string (and therefore the same event hash). This is
 * what makes an Agent Attested Receipt independently reproducible.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortDeep(value) ?? null);
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortDeep((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

/** The event fingerprint: SHA-256 of the canonical {agentId, action, inputs, outputs}. */
export function eventHashOf(input: AttestActionInput): string {
  return computeHash(
    canonicalize({
      agentId: input.agentId,
      action: input.action,
      inputs: input.inputs ?? null,
      outputs: input.outputs ?? null,
    }),
  );
}

const TESTNET_NOTE =
  "Recorded on the current single-validator testnet. Multi-validator " +
  "supermajority signatures (GPS / atomic time sources) activate at mainnet.";

const DISCLAIMER =
  "Testnet receipt: the event hash, on-chain anchor, and consensus timestamp are " +
  "real and independently verifiable. Validator-signature attestation is " +
  "mainnet-gated. Not yet a court-of-law evidentiary claim.";

/**
 * Assemble an {@link AgentReceipt} from the pieces the client fetched. Pure: all
 * I/O happens in the caller, so this is fully unit-testable.
 */
export function buildReceipt(args: {
  input: AttestActionInput;
  eventHash: string;
  network: string;
  log: LogResponse;
  block?: BlockResponse | null;
  validation?: ValidationBlock | null;
  identity?: { resolved: boolean; status: string } | null;
  poolHealth?: PoolHealth | null;
}): AgentReceipt {
  const { input, eventHash, network, log, block, validation, identity, poolHealth } =
    args;
  const confirmed = log.blockHeight != null;
  // Truthful anchoring: never report an un-anchored fire as success. "anchored" only when
  // confirmed; otherwise "degraded" if the pool is degraded (0% participation),
  // else plain "pending".
  const status: AnchorStatus = confirmed
    ? "anchored"
    : poolHealth?.degraded
      ? "degraded"
      : "pending";
  const validators = validation
    ? (validation.positiveVotes ?? 0) + (validation.negativeVotes ?? 0)
    : 0;
  const trustPct = validation
    ? (validation["Trust value percentage"] as number | undefined) ?? null
    : null;

  return {
    schema: "clockchain.receipt/v1",
    network,
    status,
    agentId: input.agentId,
    action: input.action,
    eventHash,
    hashType: "SHA-256",
    payload: { inputs: input.inputs ?? null, outputs: input.outputs ?? null },
    anchor: {
      ledgerId: log.ledgerId,
      assetReferenceId: log.assetReferenceId,
      blockHeight: log.blockHeight,
      recordedAt: log.createdTimestamp,
      consensusTime: block?.blockTime ?? null,
      confirmed,
    },
    attestation: {
      validators,
      trustPct,
      status: "single-validator-testnet",
      note: TESTNET_NOTE,
    },
    identity: identity?.resolved
      ? { resolved: true, status: identity.status, note: "Resolved via ERC-8004." }
      : {
          resolved: false,
          status: identity?.status ?? "recorded-only",
          note:
            "agentId recorded but not independently resolved (set EVM_RPC_URL + " +
            "ERC8004_REGISTRY_ADDRESS to resolve via ERC-8004).",
        },
    verify: {
      how:
        "Recompute SHA-256 of the canonical {agentId, action, inputs, outputs} " +
        "and compare to the hash anchored at this ledgerId on the Clockchain ledger.",
    },
    ...(poolHealth ? { poolHealth } : {}),
    disclaimer: DISCLAIMER,
  };
}
