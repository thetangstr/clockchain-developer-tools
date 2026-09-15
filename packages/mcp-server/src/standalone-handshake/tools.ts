import { z } from "zod";

import { StandaloneAdmissionError } from "./session-store.js";
import { STANDALONE_CHAIN_ID, STANDALONE_REGISTRY_ADDRESS } from "./protocol.js";

export const STANDALONE_TOOL_NAMES = Object.freeze([
  "handshake_invite",
  "handshake_accept_invitation",
  "handshake_status",
  "consent_sign",
  "channel_open",
  "channel_send",
  "channel_read",
  "channel_status",
  "channel_close",
  "channel_revoke",
]);

export const STANDALONE_ROLE_SCOPED_TOOLS = Object.freeze(
  STANDALONE_TOOL_NAMES.filter((name) => name !== "handshake_invite" && name !== "handshake_accept_invitation"),
);

const identityPolicy = z.discriminatedUnion("erc8004", [
  z.object({ erc8004: z.literal("required_fresh"), chainId: z.literal(STANDALONE_CHAIN_ID), registryAddress: z.literal(STANDALONE_REGISTRY_ADDRESS) }).strict(),
  z.object({ erc8004: z.literal("required_existing_or_fresh"), chainId: z.literal(STANDALONE_CHAIN_ID), registryAddress: z.literal(STANDALONE_REGISTRY_ADDRESS) }).strict(),
  z.object({ erc8004: z.literal("not_required"), chainId: z.null(), registryAddress: z.null() }).strict(),
]);

const channelLimits = z.object({
  durationSeconds: z.string().regex(/^(?:[6-9][0-9]|[1-8][0-9]{2,3}|8[0-5][0-9]{3}|86[0-3][0-9]{2}|86400)$/),
  messageKinds: z.array(z.enum(["question", "proposal", "evidence", "note"])).min(1).max(4),
  maxMessageBytes: z.string().regex(/^(?:[1-9][0-9]{0,3}|1[0-5][0-9]{3}|16384)$/),
}).strict();

const readiness = z.object({
  sessionKeyAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  identity: z.any().nullable(),
  authorityStatement: z.object({ accountableParty: z.string().min(1).max(128), statement: z.string().min(1).max(512) }).strict(),
  authoritySignatureHex: z.string().regex(/^0x[0-9a-fA-F]{130}$/),
  capabilityManifest: z.object({ dataHandlingClass: z.enum(["public", "confidential", "restricted"]), purpose: z.string().min(1).max(256) }).strict(),
}).strict();

const access = z.string().min(20).max(200);

export const STANDALONE_TOOL_DEFINITIONS = Object.freeze([
  {
    name: "handshake_invite",
    title: "Propose a standalone handshake",
    description: "Propose bounded A2A communication: terms, channel limits, and your readiness package. Returns a single-use Responder invitation and your role access.",
    schema: { reference: z.string().min(1).max(128), purpose: z.string().min(1).max(256), channelLimits, identityPolicy, readiness },
    readOnly: false,
  },
  {
    name: "handshake_accept_invitation",
    title: "Accept a standalone handshake invitation",
    description: "Claim one invitation once with your readiness package. The coordinator runs the readiness checklist and issues your role access.",
    schema: { invitation: z.string().min(80).max(4096), readiness },
    readOnly: false,
  },
  { name: "handshake_status", title: "Read handshake status", description: "Read progress, checklist results, channel state, remaining time, and scope for this role.", schema: { access }, readOnly: true },
  { name: "consent_sign", title: "Sign consent", description: "Sign consent over the exact terms and checklist digest with your session key (local signing; the server never holds keys).", schema: { access, signatureHex: z.string().regex(/^0x[0-9a-fA-F]{130}$/) }, readOnly: false },
  { name: "channel_open", title: "Open the channel", description: "Open the witnessed channel once both consents are signed. Anchors the opening receipt (terms-readiness, consent, open) on the ledger.", schema: { access }, readOnly: false },
  { name: "channel_send", title: "Send a channel message", description: "Send one typed message within the consented scope — kind is one of question, proposal, evidence, note and body is a non-empty string within the channel's byte cap. Refused with a reason code when the channel is not open, expired, revoked, out of scope, oversized, malformed, or you are not a party.", schema: { access, kind: z.string().min(1).max(32), body: z.unknown() }, readOnly: false },
  { name: "channel_read", title: "Read channel messages", description: "Read the messages addressed to you on this channel.", schema: { access }, readOnly: true },
  { name: "channel_status", title: "Read channel status", description: "Thin post-open status: state, remaining time, scope, message counts.", schema: { access }, readOnly: true },
  { name: "channel_close", title: "Close the channel", description: "Close the channel explicitly; the closure is anchored as a ledger record.", schema: { access }, readOnly: false },
  { name: "channel_revoke", title: "Revoke the channel", description: "Revoke consent unilaterally. Admission stops immediately and permanently; the revocation is anchored.", schema: { access }, readOnly: false },
] as const);

const SAFE_ERROR_NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
const RETRYABLE_ERROR_NAMES = new Set(["StandaloneTransientCoordinatorError", "HttpRequestError", "TimeoutError", "CircuitOpenError"]);

export function registerStandaloneTools(server: any, invoke: (name: string, args: Record<string, unknown>) => Promise<Record<string, unknown>>): void {
  for (const definition of STANDALONE_TOOL_DEFINITIONS) {
    server.registerTool(definition.name, {
      title: definition.title,
      description: definition.description,
      inputSchema: definition.schema,
      annotations: {
        readOnlyHint: definition.readOnly,
        destructiveHint: definition.name === "channel_revoke",
        idempotentHint: definition.readOnly,
        openWorldHint: false,
      },
    }, async (args: Record<string, unknown>) => {
      try {
        const result = await invoke(definition.name, args);
        const body = { ...result };
        return { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body };
      } catch (error) {
        const observedName = (error as Error)?.name;
        const errorName = typeof observedName === "string" && SAFE_ERROR_NAME.test(observedName) ? observedName : "Error";
        console.warn(JSON.stringify({ event: "standalone_handshake_tool_failure", tool: definition.name, errorName }));
        const retryable = typeof observedName === "string" && RETRYABLE_ERROR_NAMES.has(observedName);
        // Unauthenticated clients see reason codes and constants only — never raw error messages.
        const body = error instanceof StandaloneAdmissionError
          ? { error: error.reason, retryable: false }
          : retryable
            ? { error: "HANDSHAKE_TEMPORARILY_UNAVAILABLE", retryable: true, retryAfterMs: 5000 }
            : { error: "STANDALONE_HANDSHAKE_UNAVAILABLE", retryable: false };
        return retryable
          ? { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body }
          : { isError: true, content: [{ type: "text", text: JSON.stringify(body) }] };
      }
    });
  }
}
