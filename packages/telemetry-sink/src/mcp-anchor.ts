import { canonicalJson } from "./canonical.js";
import type { AnchorLedger, AnchorWrite, TsaAnchor } from "./sink.js";

/**
 * N4b-8 (Part B): the production TsaAnchor — calls `tsa_issue` on the
 * Clockchain MCP endpoint (`/mcp`) with the sink's own MCP bearer token.
 * Zero dependencies: a plain JSON-RPC POST over the stateless Streamable
 * HTTP transport (the server mints a fresh transport per request — no
 * session handshake is required).
 *
 *   POST <url>                        (e.g. http://mcp:8080/mcp)
 *   Authorization: Bearer <token>     (the sink's own Clockchain key)
 *   {"jsonrpc":"2.0","id":N,"method":"tools/call","params":{
 *     "name":"tsa_issue","arguments":{agent_id, commitment, deadline,
 *                                   idempotency_key}}}
 *
 * Idempotent by construction: the commitment text and deadline are fixed
 * per digest, so tsa_issue's deterministic commitmentId — and the
 * idempotency key — make a retry return the same anchor write.
 *
 * Retry policy lives here, not in the sink: transport errors and 5xx/429
 * retry per `backoffMs`; a 4xx, a JSON-RPC error, or an isError tool result
 * is deterministic and throws immediately. When the budget is exhausted the
 * throw propagates — the sink folds it into the signed head as
 * anchor:{status:"failed"}.
 */

export interface McpTsaAnchorOptions {
  /** MCP endpoint URL — e.g. http://mcp:8080/mcp (compose DNS, never public). */
  url: string;
  /** The sink's own MCP bearer token (a Clockchain MCP auth token). */
  token: string;
  /** tsa_issue agent_id — defaults to "telemetry-sink". */
  agentId?: string;
  /**
   * The commitment deadline carried by tsa_issue — required by the tool's
   * schema but meaningless for a head anchor. A FIXED far-future date keeps
   * the commitmentId deterministic per digest (idempotent retries).
   */
  deadline?: string;
  /** Per-attempt fetch timeout. Default 10s. */
  timeoutMs?: number;
  /** Delay before each retry after the first attempt. Default [250,1000,4000]. */
  backoffMs?: readonly number[];
  fetchImpl?: typeof fetch;
  now?: () => number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Extract the JSON-RPC response object from a plain-JSON or SSE body. */
function rpcResponseOf(contentType: string, text: string, id: number): Record<string, unknown> {
  if (contentType.includes("text/event-stream")) {
    // Streamable HTTP may answer SSE: each `data:` line is a JSON-RPC message.
    for (const line of text.split("\n")) {
      if (!line.startsWith("data:")) continue;
      try {
        const msg = JSON.parse(line.slice(5).trim()) as { id?: unknown };
        if (msg !== null && typeof msg === "object" && msg.id === id) {
          return msg as Record<string, unknown>;
        }
      } catch { /* keep scanning */ }
    }
    throw new Error("tsa_issue: no JSON-RPC response in SSE stream");
  }
  const msg: unknown = JSON.parse(text);
  if (msg === null || typeof msg !== "object") throw new Error("tsa_issue: malformed JSON-RPC response");
  return msg as Record<string, unknown>;
}

/** Pull the tsa_issue receipt out of an MCP tools/call result. */
function receiptOf(result: unknown): Record<string, unknown> {
  if (result === null || typeof result !== "object") throw new Error("tsa_issue: empty tool result");
  const r = result as Record<string, unknown>;
  if (r.isError === true) {
    const text = Array.isArray(r.content)
      ? (r.content as { text?: string }[]).map((c) => c?.text ?? "").join(" ")
      : "";
    throw new Error(`tsa_issue refused: ${text || "isError"}`);
  }
  if (r.structuredContent !== undefined && r.structuredContent !== null) {
    return r.structuredContent as Record<string, unknown>;
  }
  const text = Array.isArray(r.content)
    ? (r.content as { type?: string; text?: string }[]).find((c) => c?.type === "text")?.text
    : undefined;
  if (typeof text !== "string") throw new Error("tsa_issue: no structuredContent or text content");
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object") throw new Error("tsa_issue: malformed receipt");
  return parsed as Record<string, unknown>;
}

export function createMcpTsaAnchor(options: McpTsaAnchorOptions): TsaAnchor {
  const fetchImpl = options.fetchImpl ?? fetch;
  const agentId = options.agentId ?? "telemetry-sink";
  const deadline = options.deadline ?? "2099-12-31";
  const timeoutMs = options.timeoutMs ?? 10_000;
  const backoff = options.backoffMs ?? [250, 1_000, 4_000];
  let rpcSeq = 0;

  async function once(digestHex: string): Promise<AnchorWrite> {
    const id = ++rpcSeq;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(options.url, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${options.token}`,
        },
        body: canonicalJson({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: {
            name: "tsa_issue",
            arguments: {
              agent_id: agentId,
              commitment: `ac-telemetry-head ${digestHex}`,
              deadline,
              // Same digest → same commitment text → same commitmentId; the
              // key is belt-and-braces for gateway-side dedupe.
              idempotency_key: `anchor-${digestHex.slice(2, 34)}`,
            },
          },
        }),
      });
      if (res.status === 429 || res.status >= 500) {
        throw new Retryable(`tsa_issue transport: HTTP ${res.status}`);
      }
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`tsa_issue refused: HTTP ${res.status} ${text.slice(0, 200)}`);
      }
      const rpc = rpcResponseOf(res.headers.get("content-type") ?? "", await res.text(), id);
      if (rpc.error !== undefined) {
        const e = rpc.error as { code?: unknown; message?: unknown };
        throw new Error(`tsa_issue JSON-RPC error ${String(e.code)}: ${String(e.message)}`);
      }
      const receipt = receiptOf(rpc.result);
      const commitmentId = receipt.commitmentId;
      if (typeof commitmentId !== "string" || commitmentId.length === 0) {
        throw new Error("tsa_issue receipt carried no commitmentId");
      }
      const ledger = receipt.anchor as AnchorLedger | undefined;
      return {
        anchorId: `tsa:${commitmentId}`,
        eventHash: typeof receipt.eventHash === "string" ? receipt.eventHash : null,
        ledger: ledger !== undefined && ledger !== null && typeof ledger === "object"
          ? {
              ledgerId: String(ledger.ledgerId ?? ""),
              blockHeight: ledger.blockHeight ?? null,
              time: ledger.time ?? null,
              status: String(ledger.status ?? ""),
            }
          : null,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    async issue(digestHex: string): Promise<AnchorWrite> {
      let lastErr: unknown;
      for (let attempt = 0; attempt <= backoff.length; attempt += 1) {
        if (attempt > 0) await sleep(backoff[attempt - 1]);
        try {
          return await once(digestHex);
        } catch (err) {
          lastErr = err;
          if (!(err instanceof Retryable)) throw err;
        }
      }
      throw lastErr;
    },
  };
}

class Retryable extends Error {}
