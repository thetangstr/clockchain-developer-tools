import { readConfigFromEnv } from "@clockchain/core";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "./tools.js";

/** Build and return the configured Clockchain MCP server (reads env config). */
export function buildServer(): McpServer {
  const config = readConfigFromEnv();
  const server = new McpServer({
    name: "clockchain-mcp",
    version: "0.1.0",
  });
  registerTools(server, config);
  return server;
}
