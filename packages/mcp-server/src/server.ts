import { readConfigFromEnv, type ClockchainConfig } from "@clockchain/core";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "./tools.js";
import type { KeeperGate } from "./entitlement.js";

/**
 * Build and return the configured Clockchain MCP server.
 *
 * Reads the delegated config from env. `overrides` lets an HTTP request supply
 * the caller's OWN Clockchain credentials (bring-your-own-key) per request — when
 * `overrides.apiKey` is present the server runs in BYO mode: it uses the caller's
 * key (their credits) and does not apply our delegated write budget.
 *
 * `gate` is the per-request keeper gate (LLD §6.2). When the caller is an
 * anonymous trial, keeper tools return a structured `402 account_required`
 * instead of running. Omit it (authenticated / BYO / static-token callers) to
 * disable the keeper layer entirely — backward compat (LLD §13).
 */
export function buildServer(
  overrides?: Partial<ClockchainConfig>,
  gate?: KeeperGate,
): McpServer {
  const config: ClockchainConfig = { ...readConfigFromEnv(), ...(overrides ?? {}) };
  const server = new McpServer({
    name: "clockchain-mcp",
    version: "0.1.0",
  });
  // MCP_SURFACE controls which tools are exposed (CLO-99):
  //   "full" (default) — all 31 tools, the full testnet surface (behavior-identical to v1).
  //   "product"        — only get_time, the production-safe slice.
  // The default path ("full" or unset) is byte-for-byte behavior-identical to pre-CLO-99.
  const surface = (process.env.MCP_SURFACE ?? "full") as "full" | "product";
  // `gate` (CLO-48) is the per-request keeper gate wired in regardless of surface.
  registerTools(server, config, { delegated: !overrides?.apiKey, surface, gate });
  return server;
}
