import { readConfigFromEnv, type ClockchainConfig } from "@clockchain/core";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAppTools } from "./tools.js";
import {
  buildReceiptWidgetHtml,
  RECEIPT_WIDGET_CSP,
  RECEIPT_WIDGET_MIME,
  RECEIPT_WIDGET_URI,
} from "./widget.js";

/**
 * Build the Clockchain ChatGPT app MCP server.
 *
 * The Apps SDK *is* MCP: this is a normal MCP server that (a) exposes the curated
 * tool subset and (b) registers the read-only widget as an MCP resource. The
 * verify_cross_party tool points at the resource via _meta["openai/outputTemplate"].
 *
 * `overrides` lets an HTTP request supply the caller's own Clockchain credentials
 * (bring-your-own-key / per-tester key) per request.
 */
export function buildServer(overrides?: Partial<ClockchainConfig>): McpServer {
  const config: ClockchainConfig = { ...readConfigFromEnv(), ...(overrides ?? {}) };
  const server = new McpServer({
    name: "clockchain-chatgpt-app",
    version: "0.1.0",
  });

  registerAppTools(server, config, { delegated: !overrides?.apiKey });

  // Register the read-only verify widget as an MCP resource. ChatGPT loads this
  // when verify_cross_party returns, using the openai/outputTemplate link on the tool.
  server.registerResource(
    "receipt-widget",
    RECEIPT_WIDGET_URI,
    {
      title: "Verify-a-receipt widget",
      description: "Read-only card that renders a Clockchain verification result.",
      mimeType: RECEIPT_WIDGET_MIME,
    },
    async () => ({
      contents: [
        {
          uri: RECEIPT_WIDGET_URI,
          mimeType: RECEIPT_WIDGET_MIME,
          text: buildReceiptWidgetHtml(),
          _meta: { "openai/widgetCSP": RECEIPT_WIDGET_CSP },
        },
      ],
    }),
  );

  return server;
}
