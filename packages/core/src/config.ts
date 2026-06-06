/** Runtime configuration for {@link ClockchainClient}. */
export interface ClockchainConfig {
  apiKey: string;
  clientId: string;
  walletId: string;
  /** Gateway base URL. Defaults to https://node.clockchain.network */
  endpoint: string;
  /** Optional EVM JSON-RPC URL for ERC-8004 agent resolution. */
  evmRpcUrl?: string;
  /** Optional ERC-8004 chain id (decimal string or number). */
  erc8004Chain?: string;
  /** Optional ERC-8004 registry contract address. */
  erc8004RegistryAddress?: string;
}

export const DEFAULT_ENDPOINT = "https://node.clockchain.network";

/**
 * Build a {@link ClockchainConfig} from environment variables.
 *
 * Reads: CLOCKCHAIN_API_KEY, CLOCKCHAIN_CLIENT_ID, CLOCKCHAIN_WALLET_ID,
 * CLOCKCHAIN_ENDPOINT (default https://node.clockchain.network),
 * EVM_RPC_URL, ERC8004_CHAIN, ERC8004_REGISTRY_ADDRESS.
 */
export function readConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ClockchainConfig {
  return {
    apiKey: env.CLOCKCHAIN_API_KEY ?? "",
    clientId: env.CLOCKCHAIN_CLIENT_ID ?? "",
    walletId: env.CLOCKCHAIN_WALLET_ID ?? "",
    endpoint: env.CLOCKCHAIN_ENDPOINT ?? DEFAULT_ENDPOINT,
    evmRpcUrl: env.EVM_RPC_URL,
    erc8004Chain: env.ERC8004_CHAIN,
    erc8004RegistryAddress: env.ERC8004_REGISTRY_ADDRESS,
  };
}
