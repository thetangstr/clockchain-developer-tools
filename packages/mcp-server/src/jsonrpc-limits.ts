import type { ServerResponse } from "node:http";

/**
 * Bounds shared by the HTTP MCP surfaces that answer JSON-RPC batches (/mcp, /connect/mcp) (security review
 * follow-up, finding 1).
 *
 * Every message in a batch is answered in full, so a small request made of cheap calls (tools/list, ping) could turn
 * into a response hundreds of times its size, held in memory until the client reads it. Batches are therefore capped.
 * An earlier unsent-bytes guard was removed: the MCP SDK writes each response in one write(), so it measured message
 * size, not a stalled reader, and cut off legitimate responses over its threshold (delta review, finding 1).
 */

/** The most JSON-RPC messages one request may carry. */
export const MAX_BATCH_MESSAGES = 10;

/** A JSON-RPC error with a null id, in the MCP transport's own format. */
export function writeJsonRpcError(res: ServerResponse, status: number, code: number, message: string): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }));
}

/** The answer to a batch longer than {@link MAX_BATCH_MESSAGES}: nothing in it is run. */
export function writeBatchTooLarge(res: ServerResponse): void {
  writeJsonRpcError(res, 400, -32600, `A JSON-RPC batch may hold at most ${MAX_BATCH_MESSAGES} messages; send fewer per request.`);
}

/** True for a parsed body that is a batch longer than {@link MAX_BATCH_MESSAGES}. */
export const isOversizedBatch = (body: unknown): boolean => Array.isArray(body) && body.length > MAX_BATCH_MESSAGES;
