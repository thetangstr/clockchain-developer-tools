import {
  ApiError,
  AuthError,
  ClockchainClient,
  InsufficientCreditsError,
  RateLimitError,
  resolveAgent,
  type ClockchainConfig,
} from "@clockchain/core";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

/** Standard MCP success payload from a JSON-serializable result. */
function ok(result: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(result, null, 2) },
    ],
  };
}

/** Map a thrown error to an actionable MCP error payload. */
function fail(err: unknown) {
  let message: string;
  if (err instanceof RateLimitError) {
    message =
      "Rate limit exceeded. Wait and retry; the server does not retry automatically.";
  } else if (err instanceof InsufficientCreditsError) {
    message =
      "Insufficient logging credits (No enough tokens to facilitate this logging). " +
      "Top up the wallet/account before logging again.";
  } else if (err instanceof AuthError) {
    message =
      "Authentication failed. Check CLOCKCHAIN_API_KEY (x-api-key) is set and valid.";
  } else if (err instanceof ApiError) {
    message = `Clockchain API error (${err.status}): ${err.message}`;
  } else {
    message = err instanceof Error ? err.message : String(err);
  }
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: message }],
  };
}

/**
 * Register all Clockchain tools on the given MCP server.
 *
 * NOTE: `schedule_trigger` is intentionally omitted. The gateway returns 404 for
 * /schedule, and on-chain scheduling conflicts with the non-custodial model.
 */
export function registerTools(
  server: McpServer,
  config: ClockchainConfig,
): void {
  const client = new ClockchainClient(config);

  server.registerTool(
    "get_time",
    {
      title: "Get Clockchain time",
      description:
        "Get the latest consented block time and height from the Clockchain network.",
      inputSchema: {},
    },
    async () => {
      try {
        return ok(await client.getTime());
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "get_timestamp",
    {
      title: "Get consensus timestamp detail",
      description:
        "Get detailed consensus timestamp info (Marzullo time, votes, node participation).",
      inputSchema: {},
    },
    async () => {
      try {
        return ok(await client.getTimestamp());
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "get_block",
    {
      title: "Get block",
      description:
        'Get a block by height. Use "latest" for the most recent block.',
      inputSchema: {
        height: z
          .union([z.string(), z.number()])
          .describe('Block height, or "latest".'),
      },
    },
    async ({ height }) => {
      try {
        return ok(await client.getBlock(height));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "get_validation",
    {
      title: "Get validation block",
      description:
        "Get validation data (votes, trust %, participation) for a block height. " +
        "Not all blocks have validation data.",
      inputSchema: {
        height: z
          .union([z.string(), z.number()])
          .describe("Block height to fetch validation data for."),
      },
    },
    async ({ height }) => {
      try {
        return ok(await client.getValidationBlock(height));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "log_action",
    {
      title: "Log an action to the ledger",
      description:
        "Anchor an asset hash to the Clockchain ledger. Returns a ledgerId; " +
        "blockHeight is null (pending) until the leader writes the block ~0.6s later.",
      inputSchema: {
        asset_hash: z.string().describe("Hex hash of the asset/content."),
        asset_reference_id: z
          .string()
          .describe("Stable reference id for the asset (exact-match on search)."),
        hash_type: z
          .string()
          .optional()
          .describe('Hash algorithm. Default "SHA-256" (MUST be hyphenated).'),
        version_number: z
          .number()
          .optional()
          .describe("Version number. Default 1."),
        additional_info: z
          .string()
          .optional()
          .describe(
            "Plain text only. The gateway strips punctuation/JSON server-side; " +
              "do NOT store structured metadata here.",
          ),
        did: z
          .string()
          .optional()
          .describe("Optional DID; if provided it is included in the reference id."),
        wait: z
          .boolean()
          .optional()
          .describe(
            "If true, poll until the entry is confirmed on-chain (blockHeight " +
              "populated) or wait_ms elapses, and return the confirmed record. " +
              "Default false (returns immediately with blockHeight null/pending).",
          ),
        wait_ms: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Max time to wait for confirmation, in ms. Default 15000. Only used when wait=true."),
      },
    },
    async ({
      asset_hash,
      asset_reference_id,
      hash_type,
      version_number,
      additional_info,
      did,
      wait,
      wait_ms,
    }) => {
      try {
        // If a DID is provided, fold it into the reference id so the anchor is
        // attributable to the agent identity. (additionalInfo is plain-text-only
        // and sanitized server-side, so identity must not be stored there.)
        const assetReferenceId = did
          ? `${did}:${asset_reference_id}`
          : asset_reference_id;
        const result = await client.log({
          assetHash: asset_hash,
          assetReferenceId,
          hashType: hash_type,
          versionNumber: version_number,
          additionalInfo: additional_info,
        });
        if (wait) {
          // Poll the ledger until blockHeight populates (confirmed) or timeout.
          // On timeout this returns the last (still-pending) record rather than
          // throwing, so the caller always gets the ledgerId back.
          const confirmed = await client.waitForConfirmation(
            result.ledgerId,
            wait_ms ?? 15000,
          );
          return ok(confirmed);
        }
        return ok(result);
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "search_actions",
    {
      title: "Search ledger by reference id",
      description:
        "Find ledger records by exact assetReferenceId (no prefix search).",
      inputSchema: {
        asset_reference_id: z
          .string()
          .describe("Exact assetReferenceId to search for."),
      },
    },
    async ({ asset_reference_id }) => {
      try {
        return ok(await client.searchAsset(asset_reference_id));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "get_log_entry",
    {
      title: "Get ledger entry",
      description: "Fetch a single ledger record by its ledgerId.",
      inputSchema: {
        ledger_id: z.string().describe("The ledgerId to fetch."),
      },
    },
    async ({ ledger_id }) => {
      try {
        return ok(await client.getLedgerEntry(ledger_id));
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "verify_asset",
    {
      title: "Verify an asset against the ledger",
      description:
        "Fetch a ledger record and compare a current hash to the anchored hash.",
      inputSchema: {
        ledger_id: z.string().describe("The ledgerId to verify against."),
        current_hash: z
          .string()
          .describe("The current hash of the asset to compare."),
      },
    },
    async ({ ledger_id, current_hash }) => {
      try {
        const record = await client.getLedgerEntry(ledger_id);
        const match = record.assetHash === current_hash;
        return ok({
          match,
          ledgerId: record.ledgerId,
          blockHeight: record.blockHeight,
          anchoredHash: record.assetHash,
          currentHash: current_hash,
          assetReferenceId: record.assetReferenceId,
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    "resolve_agent",
    {
      title: "Resolve an ERC-8004 agent identity",
      description:
        "Resolve an agent identity via ERC-8004 (read-only). Returns status " +
        '"unknown" if resolution is not configured.',
      inputSchema: {
        agent_id: z.string().describe("The agent id to resolve."),
      },
    },
    async ({ agent_id }) => {
      try {
        return ok(await resolveAgent(config, agent_id));
      } catch (err) {
        return fail(err);
      }
    },
  );
}
