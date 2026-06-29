import {
  ApiError,
  AuthError,
  ClockchainClient,
  computeHash,
  InsufficientCreditsError,
  PoolDegradedError,
  RateLimitError,
  resolveAgent,
  tsaAttest,
  tsaCheckpoint,
  tsaIssue,
  tsaSettle,
  tsaStatus,
  type AgentReceipt,
  type AnchorStatus,
  type ClockchainConfig,
  type ComplianceFormat,
  type ContractParams,
  type EvidencePackage,
  type PoolHealth,
  type ScheduleApproval,
} from "@clockchain/core";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { BudgetExceededError, getSharedLogBudget, unlimitedLogBudget } from "./budget.js";
import { idempotent } from "./idempotency.js";

/** Shared schema fragment: optional idempotency key for write tools. */
const idempotencyKeySchema = z
  .string()
  .optional()
  .describe(
    "Optional: a retry with the same key returns the original result instead of re-anchoring (no duplicate credit/record).",
  );

/** Standard MCP success payload from a JSON-serializable result. */
function ok(result: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(result, null, 2) },
    ],
  };
}

/** Shared schema fragment: opt in to writing while the node pool is degraded. */
const allowDegradedSchema = z
  .boolean()
  .optional()
  .describe(
    "Optional: proceed even if the node pool is degraded (0% participation). " +
      "Default false — a degraded pool refuses the write so it is never reported " +
      "as anchored when it may not be.",
  );

/**
 * Success payload for a WRITE that is honest about anchoring (truthful anchoring). Derives
 * the anchor status (from an explicit `status`, else from blockHeight) and, when
 * the write is NOT anchored, attaches an explicit PENDING note instead of an
 * unqualified success — so a caller never treats a pending write as confirmed.
 */
const ANCHOR_STATUSES = new Set<AnchorStatus>([
  "anchored",
  "pending",
  "degraded",
]);

function okWrite(result: object): Record<string, unknown> {
  const r = result as {
    status?: string;
    anchorStatus?: AnchorStatus;
    blockHeight?: string | null;
    anchor?: { status?: AnchorStatus; blockHeight?: string | null };
  };
  const existingStatusIsAnchor =
    typeof r.status === "string" && ANCHOR_STATUSES.has(r.status as AnchorStatus);
  const blockHeight = r.blockHeight ?? r.anchor?.blockHeight ?? null;
  // Resolve the anchor status from, in order: an explicit anchorStatus (identity
  // writes), a nested anchor.status (TSA receipts), a top-level `status` that is
  // itself an AnchorStatus (log writes), else derive from blockHeight.
  const anchorStatus: AnchorStatus =
    r.anchorStatus ??
    r.anchor?.status ??
    (existingStatusIsAnchor ? (r.status as AnchorStatus) : undefined) ??
    (blockHeight != null ? "anchored" : "pending");

  const payload: Record<string, unknown> = { ...(result as Record<string, unknown>) };
  // Surface the anchor status at the top level WITHOUT clobbering a meaningful
  // lifecycle `status` (identity writes use "active"/"revoked"/"delegated"): set
  // top-level `status` only when it is absent or already an AnchorStatus;
  // otherwise keep the lifecycle value and surface anchor honesty via
  // `anchorStatus`.
  if (r.status === undefined || existingStatusIsAnchor) {
    payload.status = anchorStatus;
  } else {
    payload.anchorStatus = anchorStatus;
  }
  if (anchorStatus !== "anchored") {
    payload.warning =
      "PENDING — not yet anchored; poll get_log_entry/complete_attestation " +
      "until blockHeight is populated before treating this as confirmed.";
  }
  return payload;
}

/**
 * Pool-health guard (truthful anchoring): refuse a write when the node pool is degraded
 * (0% participation), since the write may report success without anchoring.
 * `allowDegraded` is the explicit caller opt-in to proceed anyway. Best-effort:
 * if pool health cannot be read, we fail OPEN (allow the write) rather than
 * block on a transient time-endpoint hiccup.
 */
async function ensurePoolHealthy(
  client: ClockchainClient,
  allowDegraded: boolean | undefined,
): Promise<PoolHealth | null> {
  let health: PoolHealth | null = null;
  try {
    health = await client.getPoolHealth();
  } catch {
    return null; // can't determine health -> don't block the write (fail open)
  }
  if (!allowDegraded && health.degraded) {
    throw new PoolDegradedError(
      "Node pool is degraded (0% participation): this write may not anchor, so " +
        "it is refused rather than reported as success. Retry when participation " +
        "recovers, or pass allow_degraded: true to proceed anyway.",
    );
  }
  // Returned so a caller (e.g. attest_action) can thread it through and avoid a
  // second getPoolHealth round-trip.
  return health;
}

/** Map a thrown error to an actionable MCP error payload. */
function fail(err: unknown) {
  let message: string;
  if (err instanceof RateLimitError) {
    // Surface the upstream gateway's Retry-After hint when it gave one (per-user auth)
    // so the agent backs off for the right duration instead of guessing.
    message =
      "Rate limit exceeded. Wait and retry; the server does not retry automatically." +
      (typeof err.retryAfter === "number"
        ? ` Retry after ~${err.retryAfter}s (gateway Retry-After).`
        : "");
  } else if (err instanceof InsufficientCreditsError) {
    message =
      "Insufficient logging credits (No enough tokens to facilitate this logging). " +
      "Top up the wallet/account before logging again.";
  } else if (err instanceof AuthError) {
    message =
      "Authentication failed. Check CLOCKCHAIN_API_KEY (x-api-key) is set and valid.";
  } else if (err instanceof BudgetExceededError) {
    message = err.message;
  } else if (err instanceof PoolDegradedError) {
    message = err.message;
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
 * Per-call observability: one stderr line per tool call with status + duration.
 * stdout stays clean for the MCP protocol. Disable with MCP_LOG=off.
 */
function trace(name: string, status: "ok" | "error", startMs: number): void {
  if (process.env.MCP_LOG === "off") return;
  console.error(
    `[clockchain-mcp] tool=${name} status=${status} ms=${Date.now() - startMs}`,
  );
}

/**
 * Run a tool's work function with uniform timing, tracing, and error mapping.
 * Centralizing this keeps every handler a one-liner and guarantees consistent
 * ok()/fail() behavior. Handler arg types are unaffected (still inferred from
 * each tool's inputSchema), so schema<->handler type-checking is preserved.
 */
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
 * Register all Clockchain tools on the given MCP server, grouped into the five
 * lane-A modules: Time, Logging, Agent Identity, Scheduler, Audit.
 *
 * Scheduling wraps the live /api/contract/* surface (NOT the 404'd /schedule)
 * and stays non-custodial: create_schedule forwards a caller-supplied signature
 * + nonce; the server never holds a key.
 */
export function registerTools(
  server: McpServer,
  config: ClockchainConfig,
  opts: { delegated?: boolean } = {},
): void {
  const client = new ClockchainClient(config);
  // Budget (MCP_LOG_BUDGET) caps writes that spend OUR delegated key's credits.
  // Delegated requests share the process-wide cap; bring-your-own-key requests
  // (opts.delegated === false) spend the caller's own credits, so we don't cap
  // them. Disabled when MCP_LOG_BUDGET is unset -> identical to v1.
  const budget = opts.delegated === false ? unlimitedLogBudget() : getSharedLogBudget();

  // ===== TIME MCP =====

  server.registerTool(
    "get_time",
    {
      title: "Get Clockchain time",
      description:
        "Get the latest consented block time and height from the Clockchain network.",
      inputSchema: {},
    },
    async () => run("get_time", () => client.getTime()),
  );

  server.registerTool(
    "get_timestamp",
    {
      title: "Get consensus timestamp detail",
      description:
        "Get detailed consensus timestamp info (Marzullo time, votes, node participation).",
      inputSchema: {},
    },
    async () => run("get_timestamp", () => client.getTimestamp()),
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
    async ({ height }) => run("get_block", () => client.getBlock(height)),
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
    async ({ height }) =>
      run("get_validation", () => client.getValidationBlock(height)),
  );

  // ===== LOGGING MCP =====

  server.registerTool(
    "log_action",
    {
      title: "Log an action to the ledger",
      description:
        "Anchor content to the Clockchain ledger. Pass `content` (the server " +
        "SHA-256-hashes it — the content is hashed, never stored) OR a pre-computed " +
        "`asset_hash`. Returns a ledgerId; blockHeight is null (pending) until the " +
        "leader writes the block ~0.6s later.",
      inputSchema: {
        content: z
          .string()
          .optional()
          .describe("Raw content to notarize; the server SHA-256-hashes it (hashed, never stored). Provide this OR asset_hash."),
        asset_hash: z
          .string()
          .regex(
            /^[0-9a-fA-F]+$/,
            "asset_hash must be a hex string (e.g. a SHA-256 digest).",
          )
          .optional()
          .describe("Pre-computed hex hash (64 hex chars for SHA-256). Provide this OR content."),
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
        idempotency_key: idempotencyKeySchema,
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({
      content,
      asset_hash,
      asset_reference_id,
      hash_type,
      version_number,
      additional_info,
      did,
      wait,
      wait_ms,
      idempotency_key,
      allow_degraded,
    }) =>
      run("log_action", () => idempotent(idempotency_key, async () => {
        // Truthful anchoring: refuse the write up front if the pool is degraded (unless opted in).
        await ensurePoolHealthy(client, allow_degraded);
        // Enforce the optional per-process write cap before spending a credit.
        budget.check();
        // Derive the asset hash: prefer hashing `content` server-side (agent-friendly —
        // an LLM can't compute SHA-256, and the content is hashed, never stored), else
        // accept a pre-computed `asset_hash` (validated against its digest length).
        let assetHash: string;
        let effectiveHashType = hash_type;
        if (content != null && content !== "") {
          assetHash = computeHash(content);
          effectiveHashType = "SHA-256";
        } else if (asset_hash) {
          const hashAlg = (hash_type ?? "SHA-256").toUpperCase().replace(/[^A-Z0-9]/g, "");
          const HASH_HEX_LEN: Record<string, number> = { SHA256: 64, SHA1: 40, SHA224: 56, SHA384: 96, SHA512: 128, MD5: 32 };
          const need = HASH_HEX_LEN[hashAlg];
          if (need && asset_hash.length !== need) {
            throw new Error(
              `asset_hash is ${asset_hash.length} hex chars but ${hash_type ?? "SHA-256"} digests are ${need}. Pass the real ${hash_type ?? "SHA-256"} hex digest.`,
            );
          }
          assetHash = asset_hash;
        } else {
          throw new Error("Provide either `content` (the server hashes it) or a pre-computed `asset_hash`.");
        }
        // If a DID is provided, fold it into the reference id so the anchor is
        // attributable to the agent identity. (additionalInfo is plain-text-only
        // and sanitized server-side, so identity must not be stored there.)
        const assetReferenceId = did
          ? `${did}:${asset_reference_id}`
          : asset_reference_id;
        const result = await client.log({
          assetHash,
          assetReferenceId,
          hashType: effectiveHashType,
          versionNumber: version_number,
          additionalInfo: additional_info,
        });
        // Only count successful writes (a failed write spends no credit).
        budget.record();
        if (wait) {
          // Poll the ledger until blockHeight populates (confirmed) or timeout.
          // On timeout this returns the last (still-pending) record rather than
          // throwing, so the caller always gets the ledgerId back.
          const confirmed = await client.waitForConfirmation(
            result.ledgerId,
            wait_ms ?? 15000,
          );
          return okWrite(confirmed);
        }
        return okWrite(result);
      })),
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
    async ({ asset_reference_id }) =>
      run("search_actions", () => client.searchAsset(asset_reference_id)),
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
    async ({ ledger_id }) =>
      run("get_log_entry", () => client.getLedgerEntry(ledger_id)),
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
    async ({ ledger_id, current_hash }) =>
      run("verify_asset", async () => {
        const record = await client.getLedgerEntry(ledger_id);
        return {
          match: record.assetHash === current_hash,
          ledgerId: record.ledgerId,
          blockHeight: record.blockHeight,
          anchoredHash: record.assetHash,
          currentHash: current_hash,
          assetReferenceId: record.assetReferenceId,
        };
      }),
  );

  // ===== AGENT IDENTITY MCP =====
  // Read/attestation surface: ERC-8004 resolve + agent-attested receipts. The
  // hash-anchored identity writes (mint/revoke/delegate/history) are below.

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
    async ({ agent_id }) =>
      run("resolve_agent", () => resolveAgent(config, agent_id)),
  );

  server.registerTool(
    "attest_action",
    {
      title: "Attest an autonomous agent action (Agent Attested Receipt)",
      description:
        "Fingerprint an agent action (SHA-256 of agent_id + action + inputs + " +
        "outputs), anchor it on-chain, and return a verifiable Agent Attested " +
        "Receipt (event hash, on-chain anchor, consensus timestamp). This is a " +
        "write; it spends a log credit. For scale, set wait=false to SUBMIT " +
        "without blocking (returns a pending receipt immediately) and poll with " +
        "complete_attestation.",
      inputSchema: {
        agent_id: z.string().describe("Who acted (ERC-8004 agentId or an agent label)."),
        action: z.string().describe('What they did, e.g. "execute_trade".'),
        inputs: z.record(z.string(), z.unknown()).optional().describe("The exact decision inputs."),
        outputs: z.record(z.string(), z.unknown()).optional().describe("The exact decision outputs."),
        wait: z
          .boolean()
          .optional()
          .describe(
            "Wait for on-chain confirmation. Default true. Set false to submit " +
              "without blocking and poll with complete_attestation.",
          ),
        wait_ms: z.number().int().positive().optional().describe("Max wait, ms. Default 15000."),
        idempotency_key: idempotencyKeySchema,
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ agent_id, action, inputs, outputs, wait, wait_ms, idempotency_key, allow_degraded }) =>
      run("attest_action", () => idempotent(idempotency_key, async () => {
        // Guard + reuse: thread the health the guard already fetched into
        // attestAction so it doesn't fetch /getTime twice.
        const poolHealth = await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const receipt = await client.attestAction(
          {
            agentId: agent_id,
            action,
            inputs,
            outputs,
            wait,
            waitMs: wait_ms,
          },
          poolHealth,
        );
        budget.record();
        // Truthful anchoring: the receipt's top-level status already reflects anchoring
        // (confirmed:false -> "pending"/"degraded"); echo a PENDING warning so an
        // un-anchored attestation is never read as an unqualified success.
        if (receipt.status !== "anchored") {
          return {
            ...receipt,
            warning:
              "PENDING — not yet anchored; poll complete_attestation until " +
              "anchor.confirmed is true before treating this receipt as confirmed.",
          };
        }
        return receipt;
      })),
  );

  server.registerTool(
    "verify_receipt",
    {
      title: "Verify an Agent Attested Receipt",
      description:
        "Independently re-verify a receipt: recompute the event hash from the " +
        "receipt's own payload and confirm it matches the hash anchored in the " +
        "IMMUTABLE on-chain block (keyless GET /searchAssetFromChain, keyed by the " +
        "receipt's own blockHeight) — NOT the rewritable record cache, so a " +
        "tampered cache cannot redirect the check. Falls back to the cache only " +
        "when not yet anchored on-chain (see verifiedAgainst). Pass the full " +
        "receipt object returned by attest_action.",
      inputSchema: {
        receipt: z.record(z.string(), z.unknown()).describe("The receipt object from attest_action."),
      },
    },
    async ({ receipt }) =>
      run("verify_receipt", () => client.verifyReceipt(receipt as unknown as AgentReceipt)),
  );

  server.registerTool(
    "complete_attestation",
    {
      title: "Complete a pending Agent Attested Receipt (submit → poll)",
      description:
        "The poll half of the non-blocking attest path. Run attest_action with " +
        "wait=false to SUBMIT — it returns a pending receipt immediately " +
        "(anchor.confirmed=false, blockHeight null) without holding the connection " +
        "for the ~15s block wait. Then call this to POLL: it re-checks the ledger " +
        "and, once the block has landed, returns the COMPLETED receipt (blockHeight, " +
        "consensus time, validation filled in, anchor.confirmed=true). If the block " +
        "has not landed yet it returns the still-pending receipt — call again. " +
        "Read-only; spends no log credit.",
      inputSchema: {
        receipt: z
          .record(z.string(), z.unknown())
          .describe("The (possibly pending) receipt object from attest_action."),
      },
    },
    async ({ receipt }) =>
      run("complete_attestation", async () => {
        const completed = await client.completeReceipt(
          receipt as unknown as AgentReceipt,
        );
        // Truthful anchoring: a still-pending re-poll must keep saying so — never let the
        // poll path quietly look like success.
        if (completed.status !== "anchored") {
          return {
            ...completed,
            warning:
              "PENDING — not yet anchored; call complete_attestation again until " +
              "anchor.confirmed is true before treating this receipt as confirmed.",
          };
        }
        return completed;
      }),
  );

  // ===== SCHEDULER MCP =====
  // Wraps the live /api/contract/* surface. Testnet; non-custodial (the caller
  // signs — the server NEVER holds a key); create_schedule deploys a
  // time-triggered contract, which is a value-moving write.

  server.registerTool(
    "get_contract_types",
    {
      title: "List schedulable contract types",
      description:
        "List the ERC contract types the scheduler can deploy (e.g. ERC-20, " +
        "ERC-721). Testnet. Read-only; moves no value.",
      inputSchema: {},
    },
    async () => run("get_contract_types", () => client.getContractTypes()),
  );

  server.registerTool(
    "estimate_schedule",
    {
      title: "Estimate a scheduled contract deploy (propose)",
      description:
        "Propose step of propose-then-approve: price a time-triggered contract " +
        "deploy and return the exact params to sign. Testnet; non-custodial (the " +
        "caller signs, the server never holds a key). Required params include " +
        "blockchain, contractType, contractName, and scheduledTimestamp (epoch " +
        "seconds), plus per-ERC fields (symbol/supply/…). Moves no value.",
      inputSchema: {
        params: z
          .record(z.string(), z.union([z.string(), z.number()]))
          .describe(
            "Contract params (forwarded as query params): blockchain, " +
              "contractType, contractName, scheduledTimestamp, plus per-ERC fields.",
          ),
      },
    },
    async ({ params }) =>
      run("estimate_schedule", () =>
        client.estimateContract(params as ContractParams),
      ),
  );

  server.registerTool(
    "create_schedule",
    {
      title: "Create a scheduled contract deploy (approve)",
      description:
        "Approve step of propose-then-approve: deploy a time-triggered contract. " +
        "Accepts the params from estimate_schedule PLUS the gas numbers from the " +
        "chosen estimate, an INTEGER nonce, and a caller-supplied wallet " +
        "signature. The signature is a NON-CUSTODIAL EVM wallet signature " +
        "(personal_sign pattern) — the caller signs client-side and the server " +
        "NEVER holds a private key. The exact signed-message format and any " +
        "testnet enforcement are unconfirmed; NEVER fabricate a signature. " +
        "Testnet. This is a value-moving write.",
      inputSchema: {
        params: z
          .record(z.string(), z.union([z.string(), z.number()]))
          .describe("The same params priced by estimate_schedule."),
        gas_fees: z.number().describe("gasFees from the chosen estimate."),
        min_gas_fees: z.number().optional().describe("minGasFees from the chosen estimate."),
        max_gas_fees: z.number().optional().describe("maxGasFees from the chosen estimate."),
        total_payable_price: z.number().describe("totalPayablePrice from the chosen estimate."),
        total_payable_price_unit: z
          .string()
          .optional()
          .describe('Price unit, e.g. "ETH".'),
        nonce: z
          .number()
          .int()
          .describe("INTEGER nonce (per Swagger; NOT a string)."),
        signature: z
          .string()
          .describe(
            "Caller-produced EVM wallet signature (personal_sign pattern). " +
              "Non-custodial; never fabricated.",
          ),
        deadline: z.number().int().optional().describe("Deadline (epoch int)."),
        trust_percentage: z.number().int().optional().describe("trustPercentage (int)."),
      },
    },
    async ({
      params,
      gas_fees,
      min_gas_fees,
      max_gas_fees,
      total_payable_price,
      total_payable_price_unit,
      nonce,
      signature,
      deadline,
      trust_percentage,
    }) =>
      run("create_schedule", () => {
        const approval: ScheduleApproval = {
          gasFees: gas_fees,
          minGasFees: min_gas_fees,
          maxGasFees: max_gas_fees,
          totalPayablePrice: total_payable_price,
          totalPayablePriceUnit: total_payable_price_unit,
          nonce,
          signature,
          deadline,
          trustPercentage: trust_percentage,
        };
        return client.scheduleContract(params as ContractParams, approval);
      }),
  );

  server.registerTool(
    "list_schedules",
    {
      title: "List scheduled contracts",
      description:
        "List the scheduled contracts for the configured client via the real " +
        "endpoint GET /api/contract/client/{clientId} (returns {success, data}). " +
        "Testnet; read-only.",
      inputSchema: {},
    },
    async () => run("list_schedules", () => client.listScheduled()),
  );

  // ===== AUDIT MCP =====
  // Derivative: composes Time + Logging + Identity data and exports it in
  // regulator PRESETS. Mints no new primitive; formats are parameters, never
  // bespoke per-client tools. Testnet; designed-for court-grade, not certified.

  server.registerTool(
    "generate_audit_trail",
    {
      title: "Assemble an attested audit trail",
      description:
        "Assemble the attested history for an asset into an ordered trail " +
        "(events with hashes + block times). Derivative — composes existing " +
        "Logging + Time data, mints nothing. Testnet.",
      inputSchema: {
        asset_reference_id: z
          .string()
          .describe("Exact assetReferenceId to assemble a trail for."),
      },
    },
    async ({ asset_reference_id }) =>
      run("generate_audit_trail", () =>
        client.generateAuditTrail(asset_reference_id),
      ),
  );

  server.registerTool(
    "generate_compliance_report",
    {
      title: "Export a trail in a compliance preset",
      description:
        "Render the assembled trail into a regulator PRESET. `format` is a " +
        "parameter — adding a regulator is a preset, never a new tool. " +
        "Deterministic: same asset + format yields the same reportHash. Testnet; " +
        "designed-for court-grade, not certified.",
      inputSchema: {
        asset_reference_id: z
          .string()
          .describe("Exact assetReferenceId to report on."),
        format: z
          .enum(["eu_ai_act_art12", "sec_17a4", "iso_27001"])
          .describe("Compliance preset to render."),
      },
    },
    async ({ asset_reference_id, format }) =>
      run("generate_compliance_report", () =>
        client.generateComplianceReport(
          asset_reference_id,
          format as ComplianceFormat,
        ),
      ),
  );

  server.registerTool(
    "build_evidence_package",
    {
      title: "Build a self-contained evidence package",
      description:
        "Build a self-contained packet for one ledger record: the record + block " +
        "+ validation + a plain-English 'how to verify without trusting " +
        "Clockchain' note. Deterministic pkgHash. Testnet.",
      inputSchema: {
        ledger_id: z.string().describe("The ledgerId to package."),
      },
    },
    async ({ ledger_id }) =>
      run("build_evidence_package", () => client.buildEvidencePackage(ledger_id)),
  );

  server.registerTool(
    "verify_package",
    {
      title: "Verify an evidence package",
      description:
        "Recompute an evidence package's hash and compare its anchored hash " +
        "against the Clockchain ledger (never a local store). Returns a match " +
        "boolean. Pass the full package object from build_evidence_package.",
      inputSchema: {
        package: z
          .record(z.string(), z.unknown())
          .describe("The package object from build_evidence_package."),
      },
    },
    async ({ package: pkg }) =>
      run("verify_package", () =>
        client.verifyPackage(pkg as unknown as EvidencePackage),
      ),
  );

  // ===== AGENT IDENTITY MCP (writes) =====
  // Hash-anchored identity writes via the /log convention (did:mint / did:revoke
  // / did:delegate). This is identity VERIFICATION (valid-at-T), NOT
  // authentication. Testnet; metadata is hash-anchored (additionalInfo strips
  // structure, so the document stays client-side); cross-agent verification and
  // enumeration are backend-gated.

  server.registerTool(
    "mint_identity",
    {
      title: "Mint an agent identity",
      description:
        "Anchor SHA-256 of the canonical identity document under did:mint:{did}. " +
        "The document stays client-side; only its hash is anchored. This is " +
        "identity VERIFICATION (valid-at-T), not authentication. Testnet; " +
        "metadata is hash-anchored (additionalInfo strips structure). " +
        "Cross-agent verification / enumeration are backend-gated. Write.",
      inputSchema: {
        did: z.string().describe("The DID to mint (e.g. did:clockchain:…)."),
        document: z
          .record(z.string(), z.unknown())
          .describe("The identity document (kept client-side; only hashed)."),
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ did, document, allow_degraded }) =>
      run("mint_identity", async () => {
        await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const result = await client.mintIdentity(did, document);
        budget.record();
        return okWrite(result);
      }),
  );

  server.registerTool(
    "revoke_identity",
    {
      title: "Revoke an agent identity",
      description:
        "Anchor a revocation under did:revoke:{did}. The revoke-T is attested " +
        "(load-bearing for valid-at-T). Identity VERIFICATION (valid-at-T), not " +
        "authentication. Testnet; hash-anchored; cross-agent/enumerate are " +
        "backend-gated. Write.",
      inputSchema: {
        did: z.string().describe("The DID to revoke."),
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ did, allow_degraded }) =>
      run("revoke_identity", async () => {
        await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const result = await client.revokeIdentity(did);
        budget.record();
        return okWrite(result);
      }),
  );

  server.registerTool(
    "delegate_authority",
    {
      title: "Delegate scoped, time-boxed authority",
      description:
        "Anchor a scoped, time-boxed delegation under " +
        "did:delegate:{parent}:{child}. The scope SHOULD be a subset of the " +
        "parent's capabilities. Identity VERIFICATION (valid-at-T), not " +
        "authentication. Testnet; hash-anchored (document stays client-side); " +
        "cross-agent/enumerate are backend-gated. Write.",
      inputSchema: {
        parent_did: z.string().describe("The delegating parent DID."),
        child_did: z.string().describe("The delegate (child) DID."),
        scope: z
          .array(z.string())
          .describe("The delegated capabilities (a subset of the parent's)."),
        until: z
          .string()
          .describe("Delegation expiry (RFC 3339). Time-boxed; expiry is a valid-at-T fact."),
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ parent_did, child_did, scope, until, allow_degraded }) =>
      run("delegate_authority", async () => {
        await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const result = await client.delegateAuthority({
          parentDid: parent_did,
          childDid: child_did,
          scope,
          until,
        });
        budget.record();
        return okWrite(result);
      }),
  );

  server.registerTool(
    "get_identity_history",
    {
      title: "Get a DID's attested activity history",
      description:
        "Assemble a DID's mint / revoke / delegate history (ordered) by " +
        "exact-match search over the identity references. Identity VERIFICATION " +
        "(valid-at-T), not authentication. Testnet; cross-agent enumeration is " +
        "backend-gated (searchAsset is exact-match + client-scoped). Read-only.",
      inputSchema: {
        did: z.string().describe("The DID to assemble history for."),
      },
    },
    async ({ did }) =>
      run("get_identity_history", () => client.getIdentityHistory(did)),
  );

  server.registerTool(
    "verify_identity_at",
    {
      title: "Verify a DID's authorization VALID-AT-T",
      description:
        "VALID-AT-T, the dispute-winning query: was this DID's identity " +
        "authorized at the instant T? Authorized iff an attested mint exists at " +
        "or before T and no revoke does (acted-at-T1 vs revoked-at-T2 with " +
        "T1 > T2 ⟹ provably unauthorized). This is identity VERIFICATION (was " +
        "the binding valid at T?), not authentication. Both timestamps are " +
        "independently attested on-chain; a counterparty can re-verify them " +
        "keylessly via /ledger/{id}. Testnet; own-client history (cross-client " +
        "discovery is backend-gated). Read-only.",
      inputSchema: {
        did: z.string().describe("The DID to check authorization for."),
        at: z
          .string()
          .describe("The instant T to check (RFC 3339, e.g. 2026-06-11T14:00:00Z)."),
      },
    },
    async ({ did, at }) =>
      run("verify_identity_at", () => client.verifyIdentityAt(did, at)),
  );

  // ===== CROSS-PARTY (keyless) VERIFICATION MCP =====
  // VERIFIED live: GET /ledger/{id} and POST /verifyAsset need NO api key. This
  // is what an outside counterparty runs with no Clockchain account — present-
  // and-verify works cross-party today. (Only discovery/searchAsset is scoped.)

  server.registerTool(
    "verify_cross_party",
    {
      title: "Cross-party (keyless) verification",
      description:
        "KEYLESS verification — what an outside counterparty runs with NO " +
        "Clockchain account. Verifies against the IMMUTABLE on-chain block (GET " +
        "/searchAssetFromChain, keyed by block_height) — the AUTHORITATIVE record " +
        "a tampered cache (PUT /ledger/{id}) cannot redirect. Pass a ledger_id " +
        "(and block_height when known — e.g. from a receipt's anchor) to read the " +
        "on-chain record; if block_height is omitted it is discovered via the " +
        "record cache (advisory) then still checked against the chain. Optionally " +
        "pass a hash for an ADVISORY POST /verifyAsset cache lookup. No call sends " +
        "an api key. Testnet; read-only. Provide at least one of ledger_id or hash.",
      inputSchema: {
        ledger_id: z
          .string()
          .optional()
          .describe(
            "A receipt's ledgerId to verify on-chain (GET /searchAssetFromChain).",
          ),
        block_height: z
          .union([z.string(), z.number()])
          .optional()
          .describe(
            "The receipt's anchor blockHeight. Lets verification resolve directly " +
              "to the immutable block instead of discovering the height via the " +
              "rewritable cache.",
          ),
        hash: z
          .string()
          .optional()
          .describe(
            "An asset hash for an ADVISORY keyless cache lookup (POST /verifyAsset).",
          ),
      },
    },
    async ({ ledger_id, block_height, hash }) =>
      run("verify_cross_party", async () => {
        if (!ledger_id && !hash) {
          throw new ApiError(
            "Provide at least one of ledger_id or hash.",
            400,
          );
        }
        // Authoritative: resolve to the immutable on-chain block.
        const onChain = ledger_id
          ? await client.verifyOnChain(ledger_id, block_height)
          : null;
        // Advisory only (reads the mutable cache an api-key holder can rewrite).
        const advisoryHashCheck = hash
          ? await client.publicVerifyHash(hash)
          : null;
        return { onChain, advisoryHashCheck };
      }),
  );

  // ===== COMMITMENTS (TSA) MCP =====
  // A commitment lifecycle layered on the anchor primitives: issue -> checkpoint
  // -> attest (kept/broken) -> settle, plus status. Each write anchors a SHA-256
  // of a canonical event payload under a shared reference tsa:{commitmentId}; the
  // payload stays client-side (additionalInfo is plain-text-only). MVP boundary:
  // attest reconciles the on-chain anchor time vs the deadline into a kept/broken
  // verdict; the consequence is RECORDED, not enforced. Testnet.

  server.registerTool(
    "tsa_issue",
    {
      title: "Issue a time-stamped commitment",
      description:
        "Issue a commitment: anchor a SHA-256 of the agreement under " +
        "tsa:{commitmentId} and return a receipt the caller holds. The " +
        "commitmentId is deterministic (agent_id + commitment + deadline). The " +
        "payload stays client-side; only its hash + neutral time go on-chain. " +
        "Testnet. Write — spends a log credit.",
      inputSchema: {
        agent_id: z.string().describe("Who is committing (agentId or an agent label)."),
        commitment: z.string().describe("What is being committed to (plain text)."),
        deadline: z
          .string()
          .describe(
            "The deadline the verdict is judged against (gateway DD-MM-YYYY or ISO 8601).",
          ),
        consequence: z
          .string()
          .optional()
          .describe("Optional recorded (NOT enforced) consequence of breaking the commitment."),
        idempotency_key: idempotencyKeySchema,
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ agent_id, commitment, deadline, consequence, idempotency_key, allow_degraded }) =>
      run("tsa_issue", () => idempotent(idempotency_key, async () => {
        await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const receipt = await tsaIssue(client, {
          agentId: agent_id,
          commitment,
          deadline,
          consequence,
        });
        budget.record();
        // Truthful anchoring: lift anchor.status to a top-level status + PENDING warning so
        // a still-pending commitment is never read as confirmed.
        return okWrite(receipt);
      })),
  );

  server.registerTool(
    "tsa_checkpoint",
    {
      title: "Checkpoint progress against a commitment",
      description:
        "Anchor a progress checkpoint (a note + optional evidence hash) under the " +
        "commitment's tsa:{commitmentId} trail. The note stays client-side; only " +
        "its hash + neutral time go on-chain. Testnet. Write — spends a log credit.",
      inputSchema: {
        commitment_id: z.string().describe("The commitmentId from tsa_issue."),
        note: z.string().describe("Progress note (plain text; kept client-side, only hashed)."),
        evidence_hash: z
          .string()
          .optional()
          .describe("Optional hash of supporting evidence to anchor alongside the note."),
        idempotency_key: idempotencyKeySchema,
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ commitment_id, note, evidence_hash, idempotency_key, allow_degraded }) =>
      run("tsa_checkpoint", () => idempotent(idempotency_key, async () => {
        await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const receipt = await tsaCheckpoint(client, {
          commitmentId: commitment_id,
          note,
          evidenceHash: evidence_hash,
        });
        budget.record();
        return okWrite(receipt);
      })),
  );

  server.registerTool(
    "tsa_attest",
    {
      title: "Attest a commitment as kept/broken (with verdict)",
      description:
        "Attest a commitment kept/broken and reconcile it with on-chain time. The " +
        "neutral anchor time is judged against the deadline: onTime = attestTime <= " +
        "deadline (both parsed gateway DD-MM-YYYY first). Verdict: kept+onTime -> " +
        "'kept'; kept+late -> 'broken-late'; broken -> 'broken'. Returns the " +
        "outcome, onTime, verdict, attestedAt, deadline, anchor, and eventHash. " +
        "MVP: the verdict is RECORDED, not enforced. Testnet. Write — spends a log credit.",
      inputSchema: {
        commitment_id: z.string().describe("The commitmentId from tsa_issue."),
        outcome: z
          .enum(["kept", "broken"])
          .describe("The agent's self-reported outcome (reconciled with on-chain time)."),
        deadline: z
          .string()
          .describe("The deadline to judge onTime against (gateway DD-MM-YYYY or ISO 8601)."),
        evidence: z
          .string()
          .optional()
          .describe("Optional evidence reference (plain text; kept client-side, only hashed)."),
        idempotency_key: idempotencyKeySchema,
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ commitment_id, outcome, deadline, evidence, idempotency_key, allow_degraded }) =>
      run("tsa_attest", () => idempotent(idempotency_key, async () => {
        await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const receipt = await tsaAttest(client, {
          commitmentId: commitment_id,
          outcome,
          deadline,
          evidence,
        });
        budget.record();
        // Truthful anchoring critical case: a "kept"/onTime verdict on a still-pending anchor
        // must NOT read as a silent greenlight — surface top-level pending + warning.
        return okWrite(receipt);
      })),
  );

  server.registerTool(
    "tsa_settle",
    {
      title: "Settle a commitment (record outcome + consequence)",
      description:
        "Settle a commitment: RECORD (not enforce) the final outcome + consequence " +
        "as a terminal anchor in the tsa:{commitmentId} trail. Testnet. Write — " +
        "spends a log credit.",
      inputSchema: {
        commitment_id: z.string().describe("The commitmentId from tsa_issue."),
        outcome: z
          .enum(["kept", "broken"])
          .describe("The final settled outcome."),
        consequence: z
          .string()
          .describe("The recorded (NOT enforced) consequence of this outcome."),
        idempotency_key: idempotencyKeySchema,
        allow_degraded: allowDegradedSchema,
      },
    },
    async ({ commitment_id, outcome, consequence, idempotency_key, allow_degraded }) =>
      run("tsa_settle", () => idempotent(idempotency_key, async () => {
        await ensurePoolHealthy(client, allow_degraded);
        budget.check();
        const receipt = await tsaSettle(client, {
          commitmentId: commitment_id,
          outcome,
          consequence,
        });
        budget.record();
        return okWrite(receipt);
      })),
  );

  server.registerTool(
    "tsa_status",
    {
      title: "Read a commitment's on-chain trail",
      description:
        "Read the on-chain trail for a commitment via exact-match " +
        "searchAsset('tsa:{commitmentId}'). Reports the anchored SEQUENCE (count, " +
        "ledgerIds, block heights, times, hashes) — payloads live in the caller's " +
        "receipts, never on-chain. Testnet. Read-only.",
      inputSchema: {
        commitment_id: z.string().describe("The commitmentId to read the trail for."),
      },
    },
    async ({ commitment_id }) =>
      run("tsa_status", () => tsaStatus(client, commitment_id)),
  );
}
