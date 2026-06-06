import { runHttp } from "./http.js";
import { buildServer } from "./server.js";

export { buildServer } from "./server.js";
export { registerTools } from "./tools.js";
export { runHttp } from "./http.js";

/** Dispatch on MCP_TRANSPORT: "http" runs the HTTP server, else stdio. */
async function main(): Promise<void> {
  if ((process.env.MCP_TRANSPORT ?? "stdio").toLowerCase() === "http") {
    await runHttp();
    return;
  }
  const { StdioServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/stdio.js"
  );
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[clockchain-mcp] stdio server ready");
}

// Run only when executed directly (not when imported).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("[clockchain-mcp] fatal:", err);
    process.exit(1);
  });
}
