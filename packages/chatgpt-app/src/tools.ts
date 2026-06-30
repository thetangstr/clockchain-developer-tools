/**
 * Curated Apps SDK tool subset for the Clockchain ChatGPT app.
 *
 * Reuses @clockchain/core (the same client the main MCP server uses) and exposes
 * ONLY the three tools that tell the launch story for ChatGPT — the in-chat
 * "timestamp this content → pending → anchored → verify it keylessly" loop.
 * Reviewers test every advertised tool, so the surface is intentionally small and
 * on-message:
 *
 *   get_time            (readOnly)            — current consensus block time + height
 *   log_action          (destructive, openWorld) — timestamp content (anchor a hash,
 *                                                wait:true so the reply carries the
 *                                                real blockHeight)
 *   verify_cross_party  (readOnly) + widget   — keyless on-chain verification
 *
 * verify_cross_party links the read-only React widget via
 * _meta["openai/outputTemplate"] = "ui://widget/receipt.html" and returns
 * `structuredContent` (read by the widget as window.openai.toolOutput).
 *
 * Truthful anchoring (CLO-84, load-bearing): pending vs anchored is reported
 * truthfully end to end. A null blockHeight means NOT anchored — log_action never
 * reports such a write as confirmed (it attaches an explicit PENDING warning), and
 * the widget's `status` is "anchored" ONLY when a blockHeight is present. This is a
 * single-validator testnet: independently verifiable, but not a court-grade claim.
 */
import {
  ApiError,
  AuthError,
  ClockchainClient,
  computeHash,
  InsufficientCreditsError,
  PoolDegradedError,
  RateLimitError,
  type AnchorStatus,
  type ClockchainConfig,
  type OnChainVerification,
  type PoolHealth,
} from "@clockchain/core";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { RECEIPT_WIDGET_URI } from "./widget.js";

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
  } else if (err instanceof PoolDegradedError) {
    message = err.message;
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

// ===== Truthful anchoring: write honesty + pool-health guard =====

/** Opt in to writing while the node pool is degraded (0% participation). */
const allowDegradedSchema = z
  .boolean()
  .optional()
  .describe(
    "Optional: proceed even if the node pool is degraded (0% participation). " +
      "Default false — a degraded pool refuses the write so it is never reported " +
      "as anchored when it may not be. Set true only when blocks are advancing.",
  );

const ANCHOR_STATUSES = new Set<AnchorStatus>(["anchored", "pending", "degraded"]);

/**
 * Honest success payload for a WRITE. Derives the anchor status (from an explicit
 * AnchorStatus `status`, else from blockHeight) and, when the write is NOT
 * anchored, attaches an explicit PENDING warning instead of an unqualified
 * success — so a null blockHeight is never read as confirmed.
 */
function okWrite(result: object): Record<string, unknown> {
  const r = result as { status?: string; blockHeight?: string | null };
  const existingStatusIsAnchor =
    typeof r.status === "string" && ANCHOR_STATUSES.has(r.status as AnchorStatus);
  const blockHeight = r.blockHeight ?? null;
  const anchorStatus: AnchorStatus =
    (existingStatusIsAnchor ? (r.status as AnchorStatus) : undefined) ??
    (blockHeight != null ? "anchored" : "pending");

  const payload: Record<string, unknown> = { ...(result as Record<string, unknown>) };
  payload.status = anchorStatus;
  if (anchorStatus !== "anchored") {
    payload.warning =
      "PENDING — not yet anchored (blockHeight is null); poll the ledger until a " +
      "real blockHeight is populated before treating this as confirmed.";
  }
  return payload;
}

/**
 * Pool-health guard (truthful anchoring): refuse a write when the node pool is
 * degraded (0% participation), since the write may report success without
 * anchoring. `allowDegraded` is the explicit caller opt-in to proceed anyway
 * (use it when blocks are advancing despite the 0% reading). Best-effort: if pool
 * health cannot be read, fail OPEN rather than block on a transient hiccup.
 */
async function ensurePoolHealthy(
  client: ClockchainClient,
  allowDegraded: boolean | undefined,
): Promise<void> {
  let health: PoolHealth | null = null;
  try {
    health = await client.getPoolHealth();
  } catch {
    return; // can't determine health -> don't block the write (fail open)
  }
  if (!allowDegraded && health.degraded) {
    throw new PoolDegradedError(
      "Node pool is degraded (0% participation): this write may not anchor, so " +
        "it is refused rather than reported as success. Retry when participation " +
        "recovers, or pass allow_degraded: true to proceed anyway (blocks may " +
        "still be advancing).",
    );
  }
}

// ===== Widget output (window.openai.toolOutput) =====

/** Stable shape the verify widget reads. Mirrors widget/receipt.tsx's WidgetOutput. */
const widgetOutputShape = {
  kind: z.enum(["receipt", "cross_party"]),
  status: z.enum(["anchored", "pending", "degraded", "unverified"]),
  confirmed: z.boolean(),
  match: z.boolean().nullable(),
  ledgerId: z.string().nullable(),
  blockHeight: z.union([z.string(), z.number()]).nullable(),
  verifiedAgainst: z.string(),
  eventHash: z.string().nullable().optional(),
  anchoredHash: z.string().nullable().optional(),
  consensusTime: z.string().nullable().optional(),
  network: z.string().nullable().optional(),
  summary: z.string(),
  raw: z.unknown(),
};
type WidgetOutput = {
  kind: "receipt" | "cross_party";
  status: "anchored" | "pending" | "degraded" | "unverified";
  confirmed: boolean;
  match: boolean | null;
  ledgerId: string | null;
  blockHeight: string | number | null;
  verifiedAgainst: string;
  eventHash?: string | null;
  anchoredHash?: string | null;
  consensusTime?: string | null;
  network?: string | null;
  summary: string;
  raw: unknown;
};

function crossPartyToWidget(onChain: OnChainVerification | null, advisory: unknown): WidgetOutput {
  // Truthful anchoring: "anchored" ONLY when the immutable on-chain block confirmed it.
  const verifiedOnChain = onChain?.verifiedAgainst === "on-chain block";
  const status: WidgetOutput["status"] = verifiedOnChain ? "anchored" : "pending";
  return {
    kind: "cross_party",
    status,
    confirmed: status === "anchored",
    match: onChain ? verifiedOnChain : null,
    ledgerId: onChain?.ledgerId ?? null,
    blockHeight: onChain?.blockHeight ?? null,
    verifiedAgainst: onChain?.verifiedAgainst ?? "none",
    anchoredHash: onChain?.anchoredHash ?? null,
    summary: verifiedOnChain
      ? "Verified keylessly against the immutable on-chain block."
      : "Not yet anchored on-chain (pending) — verified against the advisory cache only.",
    raw: { onChain, advisoryHashCheck: advisory },
  };
}

/** Run a widget tool: build structuredContent + a text block, tag the widget. */
async function runWidget(name: string, build: () => Promise<WidgetOutput>) {
  const start = Date.now();
  try {
    const structured = await build();
    trace(name, "ok", start);
    return {
      structuredContent: structured,
      content: [{ type: "text" as const, text: JSON.stringify(structured, null, 2) }],
    };
  } catch (err) {
    trace(name, "error", start);
    return fail(err);
  }
}

/** _meta linking a tool's result to the read-only widget template. */
const widgetMeta = (invoking: string, invoked: string) => ({
  "openai/outputTemplate": RECEIPT_WIDGET_URI,
  "openai/widgetAccessible": true,
  "openai/toolInvocation/invoking": invoking,
  "openai/toolInvocation/invoked": invoked,
});

/**
 * Register the curated tool subset on the given MCP server.
 *
 * `opts.delegated` is informational here (the gateway enforces credits); the
 * scaffold keeps no separate write budget. Writes spend whatever key the
 * per-request config carries (a tester's allowlisted delegated key, or a BYO key).
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

  // ----- WRITE: timestamp content (anchor a hash) -----
  server.registerTool(
    "log_action",
    {
      title: "Timestamp content on the ledger",
      description:
        "Timestamp content by anchoring its hash to the Clockchain testnet ledger. Pass " +
        "`content` (the server SHA-256-hashes it — the content is hashed, never stored) OR a " +
        "pre-computed `asset_hash`. By default this waits for on-chain confirmation so the reply " +
        "carries the real blockHeight; the result reports status `anchored` ONLY once a real " +
        "blockHeight lands — a null blockHeight is returned as PENDING, never as confirmed.",
      inputSchema: {
        content: z
          .string()
          .optional()
          .describe("Raw content to timestamp; the server SHA-256-hashes it. Provide this OR asset_hash."),
        asset_hash: z
          .string()
          .regex(/^[0-9a-fA-F]+$/, "asset_hash must be a hex string.")
          .optional()
          .describe("Pre-computed hex hash (64 hex chars for SHA-256). Provide this OR content."),
        asset_reference_id: z.string().describe("Stable reference id for the asset (exact-match on search)."),
        additional_info: z
          .string()
          .optional()
          .describe("Plain text only. The gateway strips punctuation/JSON server-side."),
        wait: z
          .boolean()
          .optional()
          .describe(
            "Wait for on-chain confirmation (poll until blockHeight populates) before returning. " +
              "Default true, so the reply carries the real blockHeight. Set false to return " +
              "immediately with a pending (blockHeight null) record.",
          ),
        wait_ms: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Max time to wait for confirmation, in ms. Default 15000. Only used when wait=true."),
        allow_degraded: allowDegradedSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    async ({ content, asset_hash, asset_reference_id, additional_info, wait, wait_ms, allow_degraded }) =>
      run("log_action", async () => {
        // Truthful anchoring: refuse the write up front if the pool is degraded (unless opted in).
        await ensurePoolHealthy(client, allow_degraded);
        let assetHash: string;
        if (content != null && content !== "") {
          assetHash = computeHash(content);
        } else if (asset_hash) {
          assetHash = asset_hash;
        } else {
          throw new Error("Provide either `content` (the server hashes it) or a pre-computed `asset_hash`.");
        }
        const result = await client.log({
          assetHash,
          assetReferenceId: asset_reference_id,
          hashType: "SHA-256",
          additionalInfo: additional_info,
        });
        // Default to waiting so the reply carries a real blockHeight (anchored), not just a pending id.
        const shouldWait = wait ?? true;
        const final = shouldWait
          ? await client.waitForConfirmation(result.ledgerId, wait_ms ?? 15000)
          : result;
        // Honest payload: anchored only with a real blockHeight; else an explicit PENDING warning.
        return okWrite(final);
      }),
  );

  // ----- READ-ONLY: cross-party keyless verification (widget) -----
  server.registerTool(
    "verify_cross_party",
    {
      title: "Cross-party (keyless) verification",
      description:
        "Keyless verification — what an outside counterparty runs with NO Clockchain account. " +
        "Verifies against the immutable on-chain block (by ledger_id, plus block_height when " +
        "known). Read-only. Renders a verification card; pending (un-anchored) entries are shown " +
        "as PENDING, never confirmed.",
      inputSchema: {
        ledger_id: z.string().optional().describe("A receipt's ledgerId to verify on-chain."),
        block_height: z
          .union([z.string(), z.number()])
          .optional()
          .describe("The receipt's anchor blockHeight (resolves directly to the immutable block)."),
        hash: z.string().optional().describe("Optional asset hash for an advisory cache lookup."),
      },
      outputSchema: widgetOutputShape,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      _meta: widgetMeta("Verifying on-chain…", "Verification complete."),
    },
    async ({ ledger_id, block_height, hash }) =>
      runWidget("verify_cross_party", async () => {
        if (!ledger_id && !hash) {
          throw new ApiError("Provide at least one of ledger_id or hash.", 400);
        }
        const onChain = ledger_id ? await client.verifyOnChain(ledger_id, block_height) : null;
        const advisory = hash ? await client.publicVerifyHash(hash) : null;
        return crossPartyToWidget(onChain, advisory);
      }),
  );
}
