import type { ServerResponse } from "node:http";

/**
 * Bounds shared by the HTTP MCP surfaces that answer JSON-RPC batches (/mcp, /connect/mcp), and the response guard
 * used on /mcp, /connect/mcp and /shadow/mcp (security review follow-up, finding 1).
 *
 * Every message in a batch is answered in full, so a small request made of cheap calls (tools/list, ping) could turn
 * into a response hundreds of times its size, held in memory until the client reads it. Batches are therefore capped,
 * and a response whose unsent bytes pile up past a few MB (a client that does not read) has its connection dropped.
 */

/** The most JSON-RPC messages one request may carry. */
export const MAX_BATCH_MESSAGES = 10;

/** Unsent response bytes past which the connection is dropped. */
export const MAX_UNSENT_RESPONSE_BYTES = 8 * 1024 * 1024;

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

/**
 * Drops the connection once the response's unsent bytes pass `maxBytes`, checked after every write and at the end.
 * `res.writableLength` counts what is still waiting on the socket, so a client that reads keeps it near zero.
 */
export function guardResponseBuffer(res: ServerResponse, onDrop?: () => void, maxBytes = MAX_UNSENT_RESPONSE_BYTES): void {
  let dropped = false;
  const check = (): void => {
    if (dropped || res.writableLength <= maxBytes) return;
    dropped = true;
    onDrop?.();
    res.socket?.destroy();
  };
  const write = res.write;
  const end = res.end;
  res.write = function (this: ServerResponse, ...args: unknown[]) {
    const ok = (write as (...a: unknown[]) => boolean).apply(this, args);
    check();
    return ok;
  } as ServerResponse["write"];
  res.end = function (this: ServerResponse, ...args: unknown[]) {
    const out = (end as (...a: unknown[]) => ServerResponse).apply(this, args);
    check();
    return out;
  } as ServerResponse["end"];
}
