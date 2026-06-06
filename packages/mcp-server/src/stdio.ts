#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildServer } from "./server.js";

/** stdio entry point — this is the `clockchain-mcp` bin target. */
async function main(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Keep stdout clean for the protocol; log to stderr only.
  console.error("[clockchain-mcp] stdio server ready");
}

main().catch((err) => {
  console.error("[clockchain-mcp] fatal:", err);
  process.exit(1);
});
