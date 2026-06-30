/**
 * TODO(CLO-83): this receipt verify widget is ORPHANED — the ChatGPT surface is
 * now time-only (get_time + get_timestamp) and the verify_* tools that linked it
 * have been removed (CLO-57). Pending a product decision on whether to delete this
 * file + scripts/build-widget.mjs + widget/receipt.tsx + the
 * server.registerResource("receipt-widget", ...) call, or to repurpose it. Left in
 * place intentionally: the resource registration is harmless when no tool links it.
 *
 * The read-only "verify-a-receipt" widget, exposed as an MCP resource.
 *
 * Apps SDK convention:
 *   - URI  ui://widget/receipt.html   (a cache key; bump on bundle changes)
 *   - mimeType  text/html+skybridge   (tells ChatGPT this is an inline widget)
 *   - the tool links to it via  _meta["openai/outputTemplate"]  (see tools.ts)
 *
 * The widget HTML inlines the esbuild bundle (dist/widget/receipt.js) so the
 * resource is fully self-contained. A basic CSP is applied two ways: an in-HTML
 * <meta> tag (defense in depth) and the host-enforced `openai/widgetCSP`.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

export const RECEIPT_WIDGET_URI = "ui://widget/receipt.html";
/** Apps SDK widget MIME type. */
export const RECEIPT_WIDGET_MIME = "text/html+skybridge";

/**
 * Host-enforced CSP for the widget iframe (Apps SDK `openai/widgetCSP`).
 * The widget is read-only and makes no network calls of its own, so connect is
 * limited to the Clockchain gateway (future-proofing) and resources to OpenAI's
 * static CDN. Keep this tight — reviewers check it.
 */
export const RECEIPT_WIDGET_CSP = {
  connect_domains: ["https://node.clockchain.network", "https://mcp.clockchain.network"],
  resource_domains: ["https://persistent.oaistatic.com"],
} as const;

/** In-document CSP (defense in depth alongside the host CSP). */
const HTML_CSP =
  "default-src 'none'; " +
  "script-src 'unsafe-inline'; " +
  "style-src 'unsafe-inline'; " +
  "img-src https: data:; " +
  "connect-src https://node.clockchain.network https://mcp.clockchain.network;";

let cachedHtml: string | null = null;

/** Read the bundled widget JS that `build:widget` emits next to this module. */
function readBundle(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return readFileSync(resolve(here, "widget/receipt.js"), "utf8");
}

/** Build (and cache) the full widget HTML document with the bundle inlined. */
export function buildReceiptWidgetHtml(): string {
  if (cachedHtml) return cachedHtml;
  const bundle = readBundle();
  cachedHtml = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${HTML_CSP}" />
  </head>
  <body style="margin:0">
    <div id="receipt-root"></div>
    <script type="module">${bundle}</script>
  </body>
</html>`;
  return cachedHtml;
}
