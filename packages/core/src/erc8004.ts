import type { ClockchainConfig } from "./config.js";
import type { AgentIdentity } from "./types.js";

/**
 * Resolve an ERC-8004 agent identity (read-only).
 *
 * The ERC-8004 Identity Registry is an ERC-721: an agent is a tokenId (uint256),
 * its registration pointer is `tokenURI(agentId)`, and its holder is
 * `ownerOf(agentId)`. We read both via plain JSON-RPC `eth_call` and decode the
 * results by hand (no web3 dependency).
 *
 * Returns status "unknown" when resolution is not configured, the agentId is not
 * a numeric tokenId, or the token does not exist.
 */

const SELECTOR_TOKEN_URI = "0xc87b56dd"; // tokenURI(uint256)
const SELECTOR_OWNER_OF = "0x6352211e"; // ownerOf(uint256)

/** Encode a non-negative integer string as a 32-byte (64-hex) word. Throws if not numeric. */
function uint256Hex(value: string): string {
  const n = BigInt(value.trim()); // throws on non-numeric input
  if (n < 0n) throw new Error("agentId must be non-negative");
  return n.toString(16).padStart(64, "0");
}

/** Decode an ABI-encoded dynamic string from an eth_call result. */
export function decodeAbiString(hex: string): string {
  const b = hex.startsWith("0x") ? hex.slice(2) : hex;
  const offset = Number(BigInt("0x" + b.slice(0, 64))) * 2;
  const len = Number(BigInt("0x" + b.slice(offset, offset + 64))) * 2;
  const data = b.slice(offset + 64, offset + 64 + len);
  return Buffer.from(data, "hex").toString("utf8");
}

/** Decode a 32-byte ABI word into a 0x-address (last 20 bytes). */
export function decodeAbiAddress(hex: string): string {
  const b = hex.startsWith("0x") ? hex.slice(2) : hex;
  return "0x" + b.slice(-40);
}

async function ethCall(rpcUrl: string, to: string, data: string): Promise<string> {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] }),
  });
  const json = (await res.json()) as { result?: string; error?: { message?: string } };
  if (json.error) throw new Error(json.error.message ?? "eth_call error");
  if (!json.result || json.result === "0x") throw new Error("empty result (token may not exist)");
  return json.result;
}

export async function resolveAgent(
  config: ClockchainConfig,
  agentId: string,
): Promise<AgentIdentity> {
  const rpcUrl = config.evmRpcUrl;
  const registry = config.erc8004RegistryAddress;
  if (!rpcUrl || !registry) {
    console.warn(
      "[erc8004] resolution not configured (EVM_RPC_URL + ERC8004_REGISTRY_ADDRESS). Returning unknown.",
    );
    return { agentId, status: "unknown" };
  }

  let idHex: string;
  try {
    idHex = uint256Hex(agentId);
  } catch {
    // Not a numeric ERC-8004 tokenId (e.g. a label like "agent:treasury-bot").
    return { agentId, status: "unknown" };
  }

  try {
    const agentURI = decodeAbiString(await ethCall(rpcUrl, registry, SELECTOR_TOKEN_URI + idHex));
    let owner: string | undefined;
    try {
      owner = decodeAbiAddress(await ethCall(rpcUrl, registry, SELECTOR_OWNER_OF + idHex));
    } catch {
      // owner is best-effort
    }
    return { agentId, agentURI, owner, status: "active" };
  } catch (err) {
    console.warn(
      `[erc8004] resolve failed for agentId ${agentId}: ${err instanceof Error ? err.message : String(err)}`,
    );
    return { agentId, status: "unknown" };
  }
}

/**
 * Smart-contract scheduling stub.
 *
 * CORRECTION (2026-06-10): the scheduling API IS live — at `POST /api/contract/schedule`
 * (not `/schedule`, which 404s), and it takes a client-side `signature` + `nonce`
 * (NOT a private key in a URL), so it is non-custodial-friendly. The `/api/contract/*`
 * surface — `types`, `estimate`, `schedule`, list-by-client/wallet — is verified live.
 *
 * This still throws only because the core client does not wrap `/api/contract/*` yet.
 * When it does, deploy is a value-moving write, so wrap it propose-then-approve:
 * the server prepares + prices the deployment, a client-side signer approves.
 * See ROADMAP.md "Smart contracts".
 */
export function schedule(): never {
  throw new Error("smart-contract scheduling (POST /api/contract/schedule) is live but not yet wrapped in this client — see ROADMAP.md");
}
