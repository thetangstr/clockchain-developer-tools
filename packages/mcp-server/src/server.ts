import { readConfigFromEnv, type ClockchainConfig } from "@clockchain/core";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "./tools.js";

/**
 * Build and return the configured Clockchain MCP server.
 *
 * Reads the delegated config from env. `overrides` lets an HTTP request supply
 * the caller's OWN Clockchain credentials (bring-your-own-key) per request — when
 * `overrides.apiKey` is present the server runs in BYO mode: it uses the caller's
 * key (their credits) and does not apply our delegated write budget.
 */
export function buildServer(overrides?: Partial<ClockchainConfig>): McpServer {
  const config: ClockchainConfig = { ...readConfigFromEnv(), ...(overrides ?? {}) };
  const server = new McpServer({
    name: "clockchain-mcp",
    version: "0.1.0",
  });
  registerTools(server, config, { delegated: !overrides?.apiKey });
  return server;
}
