/**
 * Curated Apps SDK tool subset for the Clockchain ChatGPT app.
 *
 * Reuses @clockchain/core (the same client the main MCP server uses) and exposes
 * ONLY two read-only TIME tools for ChatGPT. Reviewers test every advertised tool,
 * so the surface is intentionally small and on-message:
 *
 *   get_time       (readOnly) — current consensus block time + height
 *   get_timestamp  (readOnly) — detailed consensus timestamp (Marzullo time, votes,
 *                               node participation)
 *
 * This is a time-only surface. The chatbot timestamp surface does NOT expose a
 * ledgerId or blockHeight, so there is nothing for the chatbot to verify and the
 * app makes NO anchoring or on-chain receipt claim. Both tools are read-only with
 * empty input schemas.
 */
import {
  ApiError,
  AuthError,
  ClockchainClient,
  InsufficientCreditsError,
  RateLimitError,
  type ClockchainConfig,
} from "@clockchain/core";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/** Standard MCP success payload from a JSON-serializable result. */
function ok(result: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}

/** Map a thrown error to an actionable MCP error payload. */
function fail(err: unknown) {
  let message: string;
  if (err instanceof RateLimitError) {
    message = "Rate limit exceeded. Wait and retry; the server does not retry automatically.";
  } else if (err instanceof InsufficientCreditsError) {
    message = "Insufficient logging credits. Top up the account before logging again.";
  } else if (err instanceof AuthError) {
    message = "Authentication failed. Check the x-api-key / Clockchain key is set and valid.";
  } else if (err instanceof ApiError) {
    message = `Clockchain API error (${err.status}): ${err.message}`;
  } else {
    message = err instanceof Error ? err.message : String(err);
  }
  return { isError: true as const, content: [{ type: "text" as const, text: message }] };
}

function trace(name: string, status: "ok" | "error", startMs: number): void {
  if (process.env.MCP_LOG === "off") return;
  console.error(`[clockchain-chatgpt-app] tool=${name} status=${status} ms=${Date.now() - startMs}`);
}

/** Run a plain (non-widget) tool with uniform timing, tracing, and error mapping. */
async function run(name: string, work: () => Promise<unknown>) {
  const start = Date.now();
  try {
    const result = ok(await work());
    trace(name, "ok", start);
    return result;
  } catch (err) {
    trace(name, "error", start);
    return fail(err);
  }
}

/**
 * Register the curated tool subset on the given MCP server.
 *
 * `opts.delegated` is informational here (the gateway enforces credits); the
 * scaffold keeps no separate write budget. The two time tools are read-only and
 * spend no credits; they use whatever key the per-request config carries (a
 * tester's allowlisted delegated key, or a BYO key).
 */
export function registerAppTools(
  server: McpServer,
  config: ClockchainConfig,
  _opts: { delegated?: boolean } = {},
): void {
  const client = new ClockchainClient(config);

  // ----- READ-ONLY: time -----
  server.registerTool(
    "get_time",
    {
      title: "Get consensus time",
      description:
        "Get the latest consented block time and height from the Clockchain network. Read-only.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => run("get_time", () => client.getTime()),
  );

  server.registerTool(
    "get_timestamp",
    {
      title: "Get consensus timestamp detail",
      description:
        "Get detailed consensus timestamp info (Marzullo time, votes, node participation) " +
        "from the Clockchain network. Read-only.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => run("get_timestamp", () => client.getTimestamp()),
  );
}
