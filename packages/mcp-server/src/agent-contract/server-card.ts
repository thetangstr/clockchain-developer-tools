import { canonicalDigest } from "./canonical.js";
import { guidanceDigests } from "./tools-list.js";

/**
 * The machine-readable server card for `/.well-known/mcp/server-card.json`
 * (LLD §3 "Discovery"): the harness configures only the server's base URL;
 * agents read this card, learn which surfaces exist and their guidance
 * digests, and choose what to connect to. The published digests are exactly
 * what `tools/list` and the instructions serve, so R10(c) can compare what an
 * agent received against this card.
 */

export const MCP_HOST_ORIGIN = "https://mcp.clockchain.network";

/**
 * The ONE pinned handshake endpoint. `/next/handshake/mcp` is the URL the
 * server's own instructions advertise (`agent-handshake/v2/instructions.ts`)
 * and the route every ledgered travel invite used; `/handshake/mcp` happens
 * to reach the same build today but is the ACM4 lane's pin, not ours.
 */
export const HANDSHAKE_MCP_ENDPOINT = `${MCP_HOST_ORIGIN}/next/handshake/mcp`;

export const CONTRACT_MCP_ENDPOINT = `${MCP_HOST_ORIGIN}/contract/mcp`;
/** Staging comes free via the Caddy `/staging/*` path strip — no edge change. */
export const CONTRACT_MCP_STAGING_ENDPOINT = `${MCP_HOST_ORIGIN}/staging/contract/mcp`;
export const GENERAL_MCP_ENDPOINT = `${MCP_HOST_ORIGIN}/mcp`;

export const SERVER_CARD_SCHEMA_ID = "agent-contract.server-card/v1";
export const SERVER_CARD_PATH = "/.well-known/mcp/server-card.json";
export const SERVER_KEYS_SCHEMA_ID = "agent-contract.server-keys/v1";
export const SERVER_KEYS_PATH = "/contract/keys";

/**
 * A published receipt/envelope signing key (M3, LLD §3): agents pin the
 * keyId+publicKey BEFORE any run so receipt chains verify offline. Rotation
 * metadata (`validFrom`/`validUntil`, ISO-8601; `validUntil: null` = no
 * scheduled expiry) lets a verifier reject receipts signed outside the key's
 * window. `ephemeral: true` marks a disposable dev key — it must never
 * appear at production.
 */
export interface PublishedServerKey {
  keyId: string;
  alg: "Ed25519";
  /** 0x-prefixed hex of the raw 32-byte public key. */
  publicKeyHex: string;
  validFrom: string;
  validUntil: string | null;
  ephemeral?: true;
}

export interface ContractServerCard {
  schema: typeof SERVER_CARD_SCHEMA_ID;
  host: string;
  surfaces: {
    name: string;
    kind: "handshake" | "business" | "anchoring";
    endpoint: string;
    stagingEndpoint?: string;
  }[];
  guidance: {
    buyer: { toolsListDigest: string; instructionsDigest: string };
    provider: { toolsListDigest: string; instructionsDigest: string };
  };
  /** Published signing keys (M3) — empty only on a card built without a signer. */
  keys?: readonly PublishedServerKey[];
  /**
   * N4b-6 (H1 honesty): present and true only when the deployment allows
   * config-seeded sim faults (`CONTRACT_ALLOW_SIM_FAULTS=1`). Verifiers use
   * it to tell a fault-capable server from a strictly honest one; the field
   * is inside `cardDigest`'s coverage.
   */
  simFaultsEnabled?: true;
  cardDigest?: string;
}

/** The server card body; `cardDigest` covers the card minus itself. */
export function buildServerCard(
  keys: readonly PublishedServerKey[] = [],
  options: { simFaultsEnabled?: boolean } = {},
): ContractServerCard {
  const card: ContractServerCard = {
    schema: SERVER_CARD_SCHEMA_ID,
    host: MCP_HOST_ORIGIN,
    surfaces: [
      {
        name: "agent-handshake",
        kind: "handshake",
        endpoint: HANDSHAKE_MCP_ENDPOINT,
      },
      {
        name: "agent-contract",
        kind: "business",
        endpoint: CONTRACT_MCP_ENDPOINT,
        stagingEndpoint: CONTRACT_MCP_STAGING_ENDPOINT,
      },
      {
        name: "clockchain-anchoring",
        kind: "anchoring",
        endpoint: GENERAL_MCP_ENDPOINT,
      },
    ],
    guidance: {
      buyer: guidanceDigests("buyer"),
      provider: guidanceDigests("provider"),
    },
    keys,
    ...(options.simFaultsEnabled ? { simFaultsEnabled: true as const } : {}),
  };
  return { ...card, cardDigest: canonicalDigest(card) };
}

/** `GET /contract/keys` — the standalone key-discovery document (M3). */
export function buildServerKeysDoc(
  keys: readonly PublishedServerKey[],
  options: { simFaultsEnabled?: boolean } = {},
): {
  schema: typeof SERVER_KEYS_SCHEMA_ID;
  keys: readonly PublishedServerKey[];
  /** N4b-6: the same honesty flag as the card. */
  simFaultsEnabled?: true;
} {
  return {
    schema: SERVER_KEYS_SCHEMA_ID,
    keys,
    ...(options.simFaultsEnabled ? { simFaultsEnabled: true as const } : {}),
  };
}
