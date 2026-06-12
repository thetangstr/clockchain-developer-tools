import {
  ApiError,
  AuthError,
  ClockchainClient,
  InsufficientCreditsError,
  RateLimitError,
  resolveAgent,
  type AgentReceipt,
  type ClockchainConfig,
  type ComplianceFormat,
  type ContractParams,
  type EvidencePackage,
  type ScheduleApproval,
} from "@clockchain/core";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { BudgetExceededError, createLogBudget } from "./budget.js";

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
  } else if (err instanceof BudgetExceededError) {
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
): void {
  const client = new ClockchainClient(config);
  // Optional per-process cap on successful log writes (MCP_LOG_BUDGET).
  // Disabled when unset -> identical to v1.
  const budget = createLogBudget();

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
        "Anchor an asset hash to the Clockchain ledger. Returns a ledgerId; " +
        "blockHeight is null (pending) until the leader writes the block ~0.6s later.",
      inputSchema: {
        asset_hash: z
          .string()
          .regex(
            /^[0-9a-fA-F]+$/,
            "asset_hash must be a hex string (e.g. a SHA-256 digest).",
          )
          .describe("Hex hash of the asset/content (64 hex chars for SHA-256)."),
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
    }) =>
      run("log_action", async () => {
        // Enforce the optional per-process write cap before spending a credit.
        budget.check();
        // Reject a hash whose length doesn't match its algorithm's digest, so a
        // malformed value can't be permanently anchored as if it were a real hash.
        const hashAlg = (hash_type ?? "SHA-256").toUpperCase().replace(/[^A-Z0-9]/g, "");
        const HASH_HEX_LEN: Record<string, number> = { SHA256: 64, SHA1: 40, SHA224: 56, SHA384: 96, SHA512: 128, MD5: 32 };
        const need = HASH_HEX_LEN[hashAlg];
        if (need && asset_hash.length !== need) {
          throw new Error(
            `asset_hash is ${asset_hash.length} hex chars but ${hash_type ?? "SHA-256"} digests are ${need}. Pass the real ${hash_type ?? "SHA-256"} hex digest.`,
          );
        }
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
        // Only count successful writes (a failed write spends no credit).
        budget.record();
        if (wait) {
          // Poll the ledger until blockHeight populates (confirmed) or timeout.
          // On timeout this returns the last (still-pending) record rather than
          // throwing, so the caller always gets the ledgerId back.
          return client.waitForConfirmation(result.ledgerId, wait_ms ?? 15000);
        }
        return result;
      }),
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
        "write; it spends a log credit.",
      inputSchema: {
        agent_id: z.string().describe("Who acted (ERC-8004 agentId or an agent label)."),
        action: z.string().describe('What they did, e.g. "execute_trade".'),
        inputs: z.record(z.string(), z.unknown()).optional().describe("The exact decision inputs."),
        outputs: z.record(z.string(), z.unknown()).optional().describe("The exact decision outputs."),
        wait: z.boolean().optional().describe("Wait for on-chain confirmation. Default true."),
        wait_ms: z.number().int().positive().optional().describe("Max wait, ms. Default 15000."),
      },
    },
    async ({ agent_id, action, inputs, outputs, wait, wait_ms }) =>
      run("attest_action", async () => {
        budget.check();
        const receipt = await client.attestAction({
          agentId: agent_id,
          action,
          inputs,
          outputs,
          wait,
          waitMs: wait_ms,
        });
        budget.record();
        return receipt;
      }),
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
      },
    },
    async ({ did, document }) =>
      run("mint_identity", async () => {
        budget.check();
        const result = await client.mintIdentity(did, document);
        budget.record();
        return result;
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
      },
    },
    async ({ did }) =>
      run("revoke_identity", async () => {
        budget.check();
        const result = await client.revokeIdentity(did);
        budget.record();
        return result;
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
      },
    },
    async ({ parent_did, child_did, scope, until }) =>
      run("delegate_authority", async () => {
        budget.check();
        const result = await client.delegateAuthority({
          parentDid: parent_did,
          childDid: child_did,
          scope,
          until,
        });
        budget.record();
        return result;
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
}
