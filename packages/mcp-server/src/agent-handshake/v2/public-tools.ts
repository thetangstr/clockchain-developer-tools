import { z } from "zod";

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
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

export type V2PublicToolName = typeof V2_PUBLIC_TOOL_NAMES[number];
export type V2PublicInvoke = (name: V2PublicToolName, args: Record<string, unknown>) => Promise<unknown>;

const access = z.string().min(80).max(4096);
const TERMINAL_ERROR_NAMES = new Set([
  "AgentHandshakeV2ValidationError",
  "V2CoordinatorError",
  "V2InvitationError",
  "V2RoleAccessError",
]);
const RETRYABLE_ERROR_NAMES = new Set([
  "HttpRequestError",
  "RpcRequestError",
  "TimeoutError",
  "V2TransientCoordinatorError",
]);
const SAFE_ERROR_NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
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
    description: "Claim one Responder invitation once and receive non-transferable Responder role access.",
    schema: { invitation: z.string().min(80).max(4096) },
  },
  { name: "agent_handshake_join", title: "Join handshake", description: "Bind this fresh local agent and its exact local policy to the assigned role.", schema: { access, helperVersion: z.literal("2.1.2"), sessionKeyAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/), policyDigest: z.string().regex(/^[0-9a-f]{64}$/) } },
  { name: "agent_handshake_status", title: "Read handshake status", description: "Read public progress for this role and session.", schema: { access } },
  { name: "agent_handshake_next", title: "Get next handshake operation", description: "Get the next typed local signing or registration operation, or wait safely.", schema: { access } },
  { name: "agent_handshake_submit", title: "Submit local signature", description: "Submit only a signature over the exact bytes returned by the coordinator and the unchanged local-policy digest.", schema: { access, policyDigest: z.string().regex(/^[0-9a-f]{64}$/), signatureHex: z.string().regex(/^0x[0-9a-f]{130}$/) } },
  { name: "agent_handshake_get_certificate", title: "Get closing certificate", description: "Get the signed closing certificate for local verification.", schema: { access } },
] as const);

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
        return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result as Record<string, unknown> };
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
        const retryable = RETRYABLE_ERROR_NAMES.has((error as Error)?.name) &&
          !TERMINAL_ERROR_NAMES.has((error as Error)?.name) &&
          (error as Error)?.message !== "rate_limited";
        const body = retryable
          ? { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 5000 }
          : { error: "HANDSHAKE_UNAVAILABLE", retryable: false };
        return retryable
          ? { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body }
          : { isError: true, content: [{ type: "text", text: JSON.stringify(body) }] };
      }
    });
  }
}
