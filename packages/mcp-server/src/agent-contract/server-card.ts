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
  cardDigest?: string;
}

/** The server card body; `cardDigest` covers the card minus itself. */
export function buildServerCard(): ContractServerCard {
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
  };
  return { ...card, cardDigest: canonicalDigest(card) };
}
