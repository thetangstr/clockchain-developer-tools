import { z } from "zod";

import { V2_HELPER_VERSION } from "./instructions.js";
import {
  AGENT_HANDSHAKE_V2_CHAIN_ID,
  AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS,
} from "./protocol.js";

export const V2_PUBLIC_TOOL_NAMES = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit_checkpoint",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

export type V2PublicToolName = typeof V2_PUBLIC_TOOL_NAMES[number];
export type V2PublicInvoke = (name: V2PublicToolName, args: Record<string, unknown>) => Promise<unknown>;

const access = z.string().min(27).max(4096);
const UUID_V4_SHAPE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const acceptanceIdempotencyKey = z.string().refine((value) => {
  if (UUID_V4_SHAPE.test(value)) return true;
  if (!BASE64URL.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length >= 16 && decoded.toString("base64url") === value;
  } catch {
    return false;
  }
}, "must be UUIDv4 or canonical base64url for at least 16 bytes");
const ROLE_SCOPED_TOOLS = new Set([
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit_checkpoint",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);
const TERMINAL_ERROR_NAMES = new Set([
  "AgentHandshakeV2ValidationError",
  "V2CoordinatorError",
  "V2InvitationError",
  "V2InvitationExpiredError",
  "V2RoleAccessError",
]);
const RETRYABLE_ERROR_NAMES = new Set([
  "HttpRequestError",
  "RpcRequestError",
  "TimeoutError",
  "V2TransientCoordinatorError",
  // A tripped per-dependency breaker (e.g. the anchoring gateway briefly unavailable) is a bounded, transient
  // condition — surface HANDSHAKE_TEMPORARILY_UNAVAILABLE (retryable, session-deadline bounded) instead of a
  // fatal abort that pins the session. Pairs with the per-host breaker in packages/core/resilience.ts.
  "CircuitOpenError",
]);
export function isV2RetryableToolError(error: unknown): boolean {
  const name = (error as Error)?.name;
  return RETRYABLE_ERROR_NAMES.has(name) &&
    !TERMINAL_ERROR_NAMES.has(name) &&
    (error as Error)?.message !== "rate_limited";
}
const SAFE_ERROR_NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
// Coarse public reason codes for terminal failures — enough for an honest
// caller to self-diagnose without leaking internals. Unmapped errors stay
// fully opaque.
const PUBLIC_ERROR_REASONS: Readonly<Record<string, string>> = Object.freeze({
  V2TermsMismatchError: "terms_mismatch",
  V2SigningWindowExpiredError: "signing_window_expired",
  V2RoleAccessError: "role_access_invalid",
  V2FundingTimeoutError: "funding_timeout",
  V2InvitationExpiredError: "invitation_expired",
  V2InvitationError: "invitation_invalid",
  V2CommitmentCheckpointError: "checkpoint_invalid",
  AgentHandshakeV2ValidationError: "request_invalid",
  V2CoordinatorError: "coordination_failed",
});
const identityPolicy = z.discriminatedUnion("erc8004", [
  z.object({
    erc8004: z.literal("required_fresh"),
    chainId: z.literal(AGENT_HANDSHAKE_V2_CHAIN_ID),
    registryAddress: z.literal(AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS),
  }).strict(),
  z.object({
    erc8004: z.literal("required_existing_or_fresh"),
    chainId: z.literal(AGENT_HANDSHAKE_V2_CHAIN_ID),
    registryAddress: z.literal(AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS),
  }).strict(),
  z.object({
    erc8004: z.literal("not_required"),
    chainId: z.null(),
    registryAddress: z.null(),
  }).strict(),
]);

const definitions = Object.freeze([
  {
    name: "agent_handshake_invite",
    title: "Create stakeholder handshake",
    description: "Create one handshake, the Initiator role access, and one single-use Responder invitation.",
    schema: {
      reference: z.string().min(1).max(128),
      statement: z.string().min(1).max(512),
      validForSeconds: z.string().regex(/^(?:[1-9]|[1-8][0-9]|90)$/),
      identityPolicy,
    },
  },
  {
    name: "agent_handshake_accept_invitation",
    title: "Accept stakeholder invitation",
    description: "Accept a Responder invitation with an optional acceptanceIdempotencyKey for retry-safe acceptance and receive non-transferable Responder role access.",
    schema: { invitation: z.string().min(80).max(4096), acceptanceIdempotencyKey: acceptanceIdempotencyKey.optional() },
  },
  { name: "agent_handshake_join", title: "Join handshake", description: "Bind this fresh local agent and its exact local policy to the assigned role.", schema: { access, helperVersion: z.literal(V2_HELPER_VERSION), sessionKeyAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/), policyDigest: z.string().regex(/^[0-9a-f]{64}$/) } },
  { name: "agent_handshake_status", title: "Read handshake status", description: "Read public progress for this role and session.", schema: { access } },
  { name: "agent_handshake_next", title: "Get next handshake operation", description: "Get the next typed local signing or registration operation, or wait safely.", schema: { access, waitMs: z.number().int().min(0).max(15_000).optional() } },
  { name: "agent_handshake_submit_checkpoint", title: "Submit adapter release checkpoint", description: "Submit the signed private adapter checkpoint and exact artifact signature that authorize release of the pending proposal or acceptance.", schema: { access, artifactSignatureHex: z.string().regex(/^0x[0-9a-f]{130}$/), checkpoint: z.record(z.string(), z.unknown()) } },
  { name: "agent_handshake_submit", title: "Submit local signature", description: "Submit only a signature over the exact bytes returned by the coordinator and the unchanged local-policy digest.", schema: { access, policyDigest: z.string().regex(/^[0-9a-f]{64}$/), signatureHex: z.string().regex(/^0x[0-9a-f]{130}$/) } },
  { name: "agent_handshake_get_certificate", title: "Get closing certificate", description: "Get the signed closing certificate for local verification.", schema: { access } },
] as const);

function withoutShellCommand(value: unknown): { changed: boolean; value: unknown } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return { changed: false, value };
  const record = value as Record<string, unknown>;
  if (typeof record.shellCommand !== "string") return { changed: false, value };
  return {
    changed: true,
    value: Object.fromEntries(Object.entries(record).filter(([key]) => key !== "shellCommand")),
  };
}

function structuredLocalAction(value: unknown): { changed: boolean; value: unknown } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return { changed: false, value };
  const record = value as Record<string, unknown>;
  let changed = false;
  const result = { ...record };
  const helperStep = withoutShellCommand(record.helperStep);
  if (helperStep.changed) {
    changed = true;
    result.helperStep = helperStep.value;
  }
  if (Array.isArray(record.helperSteps)) {
    result.helperSteps = record.helperSteps.map((entry) => {
      const stripped = withoutShellCommand(entry);
      if (stripped.changed) changed = true;
      return stripped.value;
    });
  }
  return { changed, value: changed ? result : value };
}

export function registerV2PublicTools(server: any, invoke: V2PublicInvoke): void {
  for (const definition of definitions) {
    server.registerTool(definition.name, {
      title: definition.title,
      description: definition.description,
      inputSchema: definition.schema,
      annotations: {
        readOnlyHint: ["agent_handshake_status", "agent_handshake_next", "agent_handshake_get_certificate"].includes(definition.name),
        destructiveHint: false,
        idempotentHint: definition.name !== "agent_handshake_invite" && definition.name !== "agent_handshake_accept_invitation",
        openWorldHint: false,
      },
    }, async (args: Record<string, unknown>) => {
      try {
        const result = await invoke(definition.name, args);
        const record = result as Record<string, unknown>;
        const authoritativeAccess = typeof record.roleAccess === "string"
          ? record.roleAccess
          : ROLE_SCOPED_TOOLS.has(definition.name)
            ? args.access
          : definition.name === "agent_handshake_invite"
            ? record.initiatorAccess
            : definition.name === "agent_handshake_accept_invitation"
              ? record.responderAccess
              : undefined;
        const { initiatorAccess: _initiator, responderAccess: _responder, ...publicRecord } = record;
        const body = typeof authoritativeAccess === "string"
          ? { ...publicRecord, roleAccess: authoritativeAccess }
          : publicRecord;
        const localAction = structuredLocalAction(body.localAction);
        const response: Record<string, unknown> = {
          content: [{ type: "text", text: JSON.stringify(body) }],
        };
        if (!localAction.changed) response.structuredContent = body;
        return response;
      } catch (error) {
        const observedName = (error as Error)?.name;
        const errorName = typeof observedName === "string" && SAFE_ERROR_NAME.test(observedName)
          ? observedName
          : "Error";
        console.warn(JSON.stringify({
          event: "agent_handshake_tool_failure",
          tool: definition.name,
          errorName,
        }));
        if (errorName === "V2RateLimitedError") {
          const reset = Number((error as { retryAfterMs?: unknown }).retryAfterMs);
          const body = {
            error: "rate_limited",
            retryable: true,
            retryAfterMs: Number.isSafeInteger(reset) && reset > 0 ? reset : 60_000,
          };
          return { isError: true, content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body };
        }
        const retryable = isV2RetryableToolError(error);
        const hinted = Number((error as { retryAfterMs?: unknown })?.retryAfterMs);
        const reason = PUBLIC_ERROR_REASONS[errorName];
        const body: Record<string, unknown> = retryable
          ? { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: Number.isSafeInteger(hinted) && hinted > 0 ? hinted : 5000 }
          : { error: "HANDSHAKE_UNAVAILABLE", retryable: false, ...(reason ? { reason } : {}) };
        // terms_mismatch additionally returns the host-published terms — public
        // discovery data — so the caller can resubmit inside the same window.
        // The note teaches verification, not blind trust: a careful agent
        // should confirm the fixture is identical-fielded before re-signing.
        if (!retryable && errorName === "V2TermsMismatchError") {
          const publishedTerms = (error as { publishedTerms?: unknown }).publishedTerms;
          if (publishedTerms !== null && typeof publishedTerms === "object" && !Array.isArray(publishedTerms)) {
            body.publishedTerms = publishedTerms;
            body.note = "publishedTerms are the same fixed public session terms this endpoint returns to every caller — fixture data, not a substitution targeted at your request. Verify before resubmitting: publishedTerms.identityPolicy (erc8004, chainId, registryAddress) must be identical to what you sent — a changed identityPolicy or chain is a genuine red flag; refuse and report it. If it is identical, call agent_handshake_invite again with publishedTerms verbatim.";
          }
        }
        return retryable
          ? { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body }
          : { isError: true, content: [{ type: "text", text: JSON.stringify(body) }] };
      }
    });
  }
}
