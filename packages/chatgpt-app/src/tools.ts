/**
 * Curated Apps SDK tool subset for the Clockchain ChatGPT app.
 *
 * Reuses @clockchain/core (the same client the main MCP server uses) and exposes
 * ONLY the five tools the launch plan curates for ChatGPT — reviewers test every
 * advertised tool, so the surface is intentionally small:
 *
 *   get_timestamp       (readOnly)            — consensus time detail
 *   verify_receipt      (readOnly) + widget   — re-verify an Agent Attested Receipt
 *   verify_cross_party  (readOnly) + widget   — keyless cross-party verification
 *   log_action          (destructive, openWorld) — anchor content to the ledger
 *   attest_action       (destructive, openWorld) — attest an agent action
 *
 * The two verify tools link the read-only React widget via
 * _meta["openai/outputTemplate"] = "ui://widget/receipt.html" and return
 * `structuredContent` (read by the widget as window.openai.toolOutput).
 *
 * AGE-193: the widget output's `status` is "anchored" ONLY when a blockHeight is
 * present — a pending write is never presented as confirmed.
 */
import {
  ApiError,
  AuthError,
  ClockchainClient,
  computeHash,
  InsufficientCreditsError,
  RateLimitError,
  type AgentReceipt,
  type ClockchainConfig,
  type OnChainVerification,
  type ReceiptVerification,
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

/** AGE-193: anchored ONLY when a blockHeight is present. */
function anchorStatus(blockHeight: unknown): "anchored" | "pending" {
  return blockHeight != null && blockHeight !== "" ? "anchored" : "pending";
}

function receiptToWidget(v: ReceiptVerification): WidgetOutput {
  const status: WidgetOutput["status"] = !v.match ? "unverified" : anchorStatus(v.blockHeight);
  return {
    kind: "receipt",
    status,
    confirmed: status === "anchored",
    match: v.match,
    ledgerId: v.ledgerId,
    blockHeight: v.blockHeight,
    verifiedAgainst: v.verifiedAgainst,
    eventHash: v.eventHash,
    anchoredHash: v.anchoredHash,
    summary: !v.match
      ? "Hash does NOT match the anchored record."
      : status === "anchored"
        ? "Hash matches the immutable on-chain anchor."
        : "Hash matches the recorded entry, but it is not yet anchored on-chain (pending).",
    raw: v,
  };
}

function crossPartyToWidget(onChain: OnChainVerification | null, advisory: unknown): WidgetOutput {
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

  // ----- READ-ONLY: verify a receipt (widget) -----
  server.registerTool(
    "verify_receipt",
    {
      title: "Verify an Agent Attested Receipt",
      description:
        "Independently re-verify a receipt: recompute its event hash and confirm it matches " +
        "the hash anchored in the immutable on-chain block. Read-only. Renders a verification " +
        "card; a pending (un-anchored) entry is shown as PENDING, never confirmed.",
      inputSchema: {
        receipt: z
          .record(z.string(), z.unknown())
          .describe("The full receipt object returned by attest_action."),
      },
      outputSchema: widgetOutputShape,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      _meta: widgetMeta("Verifying receipt…", "Receipt verified."),
    },
    async ({ receipt }) =>
      runWidget("verify_receipt", async () => {
        const v = await client.verifyReceipt(receipt as unknown as AgentReceipt);
        return receiptToWidget(v);
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
        "known). Read-only. Renders a verification card; pending entries are shown as PENDING.",
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

  // ----- WRITE: log an action -----
  server.registerTool(
    "log_action",
    {
      title: "Log an action to the ledger",
      description:
        "Anchor content to the Clockchain ledger. Pass `content` (the server SHA-256-hashes it — " +
        "the content is hashed, never stored) OR a pre-computed `asset_hash`. Returns a ledgerId; " +
        "blockHeight is null (PENDING) until the leader writes the block — treat null as unconfirmed.",
      inputSchema: {
        content: z
          .string()
          .optional()
          .describe("Raw content to notarize; the server SHA-256-hashes it. Provide this OR asset_hash."),
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
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    async ({ content, asset_hash, asset_reference_id, additional_info }) =>
      run("log_action", async () => {
        let assetHash: string;
        if (content != null && content !== "") {
          assetHash = computeHash(content);
        } else if (asset_hash) {
          assetHash = asset_hash;
        } else {
          throw new Error("Provide either `content` (the server hashes it) or a pre-computed `asset_hash`.");
        }
        return client.log({
          assetHash,
          assetReferenceId: asset_reference_id,
          hashType: "SHA-256",
          additionalInfo: additional_info,
        });
      }),
  );

  // ----- WRITE: attest an agent action -----
  server.registerTool(
    "attest_action",
    {
      title: "Attest an autonomous agent action (Agent Attested Receipt)",
      description:
        "Fingerprint an agent action (SHA-256 of agent_id + action + inputs + outputs), anchor it " +
        "on-chain, and return a verifiable Agent Attested Receipt. This is a write; it spends a log " +
        "credit. The receipt's top-level `status` is 'pending' until anchored ('anchored').",
      inputSchema: {
        agent_id: z.string().describe("Who acted (ERC-8004 agentId or an agent label)."),
        action: z.string().describe('What they did, e.g. "execute_trade".'),
        inputs: z.record(z.string(), z.unknown()).optional().describe("The exact decision inputs."),
        outputs: z.record(z.string(), z.unknown()).optional().describe("The exact decision outputs."),
        wait: z
          .boolean()
          .optional()
          .describe("Wait for on-chain confirmation. Default true. Set false to submit without blocking."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    async ({ agent_id, action, inputs, outputs, wait }) =>
      run("attest_action", () =>
        client.attestAction({ agentId: agent_id, action, inputs, outputs, wait }),
      ),
  );
}
