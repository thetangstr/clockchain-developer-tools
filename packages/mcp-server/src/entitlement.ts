/**
 * Entitlement + keeper gate (LLD §4.1 A1/A4, §6.1, §6.2, §11).
 *
 * This is the decision layer that sits in front of tool dispatch. It answers two
 * questions:
 *
 *   1. WHO is the caller? — {@link Entitlement}: an `authenticated` principal
 *      (BYO key, static MCP token, or legacy v:1 demo token) that BYPASSES the
 *      trial/keeper layer entirely (LLD §13), or an `anonymous_trial` session.
 *   2. May this tool run? — {@link evaluateTool}: keeper actions are gated for
 *      anonymous sessions only (authenticated paid accounts are never keeper-
 *      gated, LLD §6.1). A blocked keeper action returns a structured, model-
 *      readable `402 account_required` — NEVER a raw 500 (LLD §6.2, §11).
 *
 * Run metering / ceiling ENFORCEMENT (A3/A5) and per-tool quota (CLO-101) are
 * NOT enforced here — see the {@link checkToolQuota}/{@link recordToolCall}
 * seams at the bottom.
 */
import type { Channel, Plan } from "./store.js";

/** Per-tool classification (LLD §6.1). */
export interface ToolClass {
  tier: "free" | "paid";
  keeper: boolean;
}

/**
 * Keeper classification table (LLD §6.1).
 *
 * The "generate-and-go" boundary: trial *generation* lands value before the wall
 * (never keeper); *keeping / sharing / exporting / continuity* is keeper-gated.
 * `build_evidence_package` is deliberately NOT keeper (generated + shown
 * in-session); exporting it (`generate_compliance_report`) IS.
 *
 * EVERY registered tool MUST appear in EITHER {@link KEEPER_TOOLS} or
 * {@link FREE_TOOLS}. {@link assertToolClassified} enforces this at registration
 * time (CLO-48 review FIX 2): an unclassified tool throws at boot rather than
 * silently defaulting to non-keeper — a future keeper tool added without listing
 * it here would otherwise be a silent paywall bypass (fail-open). We fail closed.
 */
export const KEEPER_TOOLS: ReadonlySet<string> = new Set([
  // Retrieve / persist later
  "get_log_entry",
  "search_actions",
  // External third-party verification (share-link / package)
  "verify_receipt",
  "verify_package",
  // Export deliverables
  "generate_compliance_report",
  "generate_audit_trail",
  // Continuity primitives
  "create_schedule",
  "delegate_authority",
]);

/**
 * Free / generation / read tools (LLD §6.1). The explicit complement of
 * {@link KEEPER_TOOLS}: value lands before the wall (generation, reads, in-
 * session verification). Listed explicitly so that adding a tool forces a
 * classification decision — see {@link assertToolClassified}.
 */
export const FREE_TOOLS: ReadonlySet<string> = new Set([
  // Time
  "get_time",
  "get_timestamp",
  "get_block",
  "get_validation",
  // Logging (write/generate; retrieval is keeper)
  "log_action",
  "verify_asset",
  // Agent identity / attestation (generate-and-show)
  "resolve_agent",
  "attest_action",
  "complete_attestation",
  "get_identity_history",
  "verify_identity_at",
  "verify_cross_party",
  "mint_identity",
  "revoke_identity",
  // Scheduling (estimate/list are free; create is keeper)
  "get_contract_types",
  "estimate_schedule",
  "list_schedules",
  // Evidence (build/show is free; export is keeper)
  "build_evidence_package",
  // TSA
  "tsa_issue",
  "tsa_checkpoint",
  "tsa_attest",
  "tsa_settle",
  "tsa_status",
]);

/**
 * The full classification map: every known tool, free ∪ keeper. A tool absent
 * from this set is UNCLASSIFIED and trips {@link assertToolClassified}.
 */
export const CLASSIFIED_TOOLS: ReadonlySet<string> = new Set([
  ...FREE_TOOLS,
  ...KEEPER_TOOLS,
]);

/** True if `name` has an explicit free/keeper classification. */
export function isClassified(name: string): boolean {
  return CLASSIFIED_TOOLS.has(name);
}

/**
 * Fail-closed registration guard (CLO-48 review FIX 2). Throws if `name` is not
 * in the known classification map. Called once per tool at registration time, so
 * shipping a tool without classifying it fails the build/boot instead of silently
 * exposing it free.
 */
export function assertToolClassified(name: string): void {
  if (!CLASSIFIED_TOOLS.has(name)) {
    throw new Error(
      `[clockchain-mcp] tool "${name}" is unclassified: add it to FREE_TOOLS ` +
        `or KEEPER_TOOLS in entitlement.ts (fail-closed; LLD §6.1).`,
    );
  }
}

/**
 * Classify a tool by name (LLD §6.1). Callers reach this only for tools that
 * passed {@link assertToolClassified} at registration, so an unclassified name
 * here means a keeper bug — treat it as keeper (fail closed), never free.
 */
export function classifyTool(name: string): ToolClass {
  if (KEEPER_TOOLS.has(name)) return { tier: "paid", keeper: true };
  if (FREE_TOOLS.has(name)) return { tier: "free", keeper: false };
  // Unclassified: fail closed — gate it rather than silently letting it through.
  return { tier: "paid", keeper: true };
}

/**
 * The resolved caller. `authenticated` callers skip the trial/keeper layer
 * (backward compat, LLD §13). `anonymous_trial` callers carry the live session
 * id + channel so the gate can build a forwardable claim.
 */
export type Entitlement =
  | {
      kind: "authenticated";
      /** Why we treated this caller as authenticated (observability/tests). */
      reason: "byo_key" | "static_token" | "demo_token_v1";
      plan: Plan;
    }
  | {
      kind: "anonymous_trial";
      sessionId: string;
      ephemeralDid: string;
      channel: Channel;
      plan: "trial";
    };

/** Shape of the structured keeper/ceiling 402 body (LLD §6.2 / §6.3). */
export interface AccountRequiredBody {
  error: "account_required";
  reason: "keeper_action" | "ceiling_reached";
  tool: string;
  upgradeUrl: string;
  claim: string;
  message: string;
}

const UPGRADE_BASE =
  process.env.MCP_UPGRADE_URL_BASE ?? "https://clockchain.com/upgrade";

/** Build the structured `402 account_required` body (LLD §6.2 / §11). */
export function buildAccountRequired(
  tool: string,
  claim: string,
  reason: AccountRequiredBody["reason"] = "keeper_action",
): AccountRequiredBody {
  const upgradeUrl = `${UPGRADE_BASE}?claim=${encodeURIComponent(claim)}`;
  const message =
    reason === "ceiling_reached"
      ? "You've reached the free trial limit. Create a free account to keep going — your existing receipts come with you."
      : "Create a free account to keep, share, or export this. Your existing receipts come with you.";
  return { error: "account_required", reason, tool, upgradeUrl, claim, message };
}

/**
 * The MCP tool-result shape (mirrors `ok`/`fail` in tools.ts) so the gate can
 * return a structured tool error without importing the SDK. `isError: true`
 * makes it a model-readable error, never a raw 500 (LLD §6.2).
 */
export interface ToolErrorResult {
  isError: true;
  content: { type: "text"; text: string }[];
  /** Structured payload mirrored for programmatic clients (the HTTP 402 body). */
  structuredContent: AccountRequiredBody;
}

/** Wrap an account-required body as a structured MCP tool error (LLD §6.2). */
export function keeperToolError(body: AccountRequiredBody): ToolErrorResult {
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(body, null, 2) }],
    structuredContent: body,
  };
}

/**
 * The per-request keeper gate handed to the tool layer. `check(tool)` returns a
 * structured tool error when the tool must be blocked, else undefined (allow).
 *
 * Claim minting is injected (a closure over MCP_PROMOTE_SECRET + the session) so
 * this module stays free of crypto/secret concerns.
 */
export interface KeeperGate {
  /**
   * Async (FIX 5a): minting a claim persists a session row (the claim hash +
   * keeper_blocked status) and we must AWAIT that write before returning the
   * claim — never hand out a claim whose session never persisted. Non-keeper
   * tools resolve `undefined` without any await.
   */
  check(tool: string): Promise<ToolErrorResult | undefined>;
}

/**
 * Build the keeper gate for a resolved entitlement.
 *
 *   - authenticated  -> no gate (every tool allowed; LLD §6.1/§13).
 *   - anonymous_trial -> keeper tools blocked with a structured 402 carrying a
 *     freshly-minted, forwardable claim (LLD §6.2). Generation/read tools below
 *     the ceiling always pass.
 *
 * `mintClaimFor()` returns the forwardable claim token for THIS session; it is
 * called lazily (only when a keeper tool is actually hit) so non-keeper calls
 * never pay the signing cost.
 */
export function buildKeeperGate(
  entitlement: Entitlement,
  mintClaimFor: () => string | Promise<string>,
): KeeperGate {
  if (entitlement.kind === "authenticated") {
    return { check: async () => undefined };
  }
  return {
    async check(tool: string): Promise<ToolErrorResult | undefined> {
      if (!classifyTool(tool).keeper) return undefined;
      // FIX 5a: await the mint (it persists the session) before returning.
      const claim = await mintClaimFor();
      const body = buildAccountRequired(tool, claim, "keeper_action");
      return keeperToolError(body);
    },
  };
}

// ---------------------------------------------------------------------------
// SEAMS for CLO-101 (per-tool quota) — signatures only, not enforced here.
// ---------------------------------------------------------------------------

/** Result of a quota check (CLO-101 will implement enforcement). */
export interface QuotaDecision {
  allowed: boolean;
  /** Populated when blocked: the structured 402 to return. */
  blocked?: AccountRequiredBody;
}

/**
 * STUB (CLO-101): check whether `tool` may run under `entitlement`'s per-tool
 * quota. Today it always allows — quota enforcement + run metering (A3) is
 * CLO-101's job. Kept here so the gate's call site is already shaped for it.
 */
export function checkToolQuota(
  _entitlement: Entitlement,
  _tool: string,
): QuotaDecision {
  return { allowed: true };
}

/**
 * STUB (CLO-101): record a successful tool call against quota / run counters.
 * No-op today; CLO-101 wires this to Store run counters + count-on-complete.
 */
export function recordToolCall(_entitlement: Entitlement, _tool: string): void {
  /* no-op seam */
}
