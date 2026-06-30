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
 * The Apps SDK *is* MCP: this is a normal MCP server that exposes the time-only
 * curated tool subset (get_time + get_timestamp). It still registers the receipt
 * widget as an MCP resource, but that resource is currently orphaned — see the
 * TODO(CLO-83) at the registration below.
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

  // TODO(CLO-83): this receipt-widget resource is ORPHANED now that the surface is
  // time-only (CLO-57) — no tool links it via openai/outputTemplate anymore. Left
  // registered intentionally (harmless with no linking tool) pending a product
  // decision to delete widget.ts + scripts/build-widget.mjs + widget/receipt.tsx +
  // this registration, or to repurpose the widget.
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
