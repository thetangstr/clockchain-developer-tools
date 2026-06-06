import type { ClockchainConfig } from "./config.js";
import type { AgentIdentity } from "./types.js";

/**
 * Resolve an ERC-8004 agent identity (read-only).
 *
 * If `evmRpcUrl` or `erc8004RegistryAddress` are not configured, this returns
 * a stub identity with status "unknown" and warns. When configured, it performs
 * a minimal JSON-RPC `eth_call` against the registry.
 *
 * TODO: Full ERC-8004 ABI encode/decode is out of scope for this POC. The call
 * below wires the transport but does not yet ABI-encode the agentId argument or
 * decode the returned tuple. Replacing the placeholder selector/decoding with
 * the real registry ABI is a follow-up.
 */
export async function resolveAgent(
  config: ClockchainConfig,
  agentId: string,
): Promise<AgentIdentity> {
  if (!config.evmRpcUrl || !config.erc8004RegistryAddress) {
    console.warn(
      "[erc8004] ERC-8004 resolution is not configured (set EVM_RPC_URL and " +
        "ERC8004_REGISTRY_ADDRESS). Returning unknown identity.",
    );
    return { agentId, status: "unknown" };
  }

  // Minimal read-only JSON-RPC eth_call placeholder.
  // TODO: ABI-encode `data` for the real registry getter and decode the result.
  const payload = {
    jsonrpc: "2.0",
    id: 1,
    method: "eth_call",
    params: [
      {
        to: config.erc8004RegistryAddress,
        // Placeholder: empty calldata. Replace with `selector + abiEncode(agentId)`.
        data: "0x",
      },
      "latest",
    ],
  };

  try {
    const res = await fetch(config.evmRpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = (await res.json()) as {
      result?: string;
      error?: { message?: string };
    };

    if (json.error) {
      console.warn(`[erc8004] eth_call error: ${json.error.message ?? "unknown"}`);
      return { agentId, status: "unknown" };
    }

    // TODO: decode json.result into agentURI/owner via the registry ABI.
    // Until decoding is implemented we mark the identity as resolved-but-opaque.
    return { agentId, status: "unknown" };
  } catch (err) {
    console.warn(
      `[erc8004] resolution failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return { agentId, status: "unknown" };
  }
}

/**
 * Smart-contract scheduling stub.
 *
 * The /schedule endpoint is NOT available on the gateway (returns 404), so this
 * intentionally throws rather than making a real call.
 */
export function schedule(): never {
  throw new Error(
    "smart-contract scheduling is not available on the gateway yet",
  );
}
