import { buildServer } from "./server.js";
import { runHttp } from "./http.js";

export { buildServer } from "./server.js";
export { registerAppTools } from "./tools.js";
export { runHttp } from "./http.js";

/**
 * Dispatch on MCP_TRANSPORT: "http" runs the dev-mode connector server, else
 * stdio (handy for `npx @modelcontextprotocol/inspector` smoke tests).
 */
async function main(): Promise<void> {
  if ((process.env.MCP_TRANSPORT ?? "stdio").toLowerCase() === "http") {
    await runHttp();
    return;
  }
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[clockchain-chatgpt-app] stdio server ready");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("[clockchain-chatgpt-app] fatal:", err);
    process.exit(1);
  });
}
