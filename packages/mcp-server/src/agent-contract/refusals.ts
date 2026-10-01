import { z } from "zod";

/**
 * Generic refusal codes for the `/contract/mcp` surface (LLD §3: "Refusals
 * use generic codes"). The refusal body is strict — `error`, `retryable` and
 * an optional `retryAfterMs` only — so a `MANDATE_REFUSED` reply can never
 * carry the mandate cap value, and no refusal leaks internals.
 */
export const CONTRACT_REFUSAL_CODES = Object.freeze([
  "MANDATE_REFUSED",
  "MANDATE_INVALID",
  "PAYLOAD_INVALID",
  "STATE_REFUSED",
  "ROLE_REFUSED",
  "NOT_FOUND",
  "CERTIFICATE_INVALID",
  "BIND_STATEMENT_INVALID",
  "ENVELOPE_INVALID",
  "ENVELOPE_EXPIRED",
  "NONCE_REUSED",
  "SIGNATURE_INVALID",
  "APPROVAL_INVALID",
  // N4b-8 (gap 5): a VALID signed approval carrying decision:"deny" — the
  // policy refused; the run ends blocked_by_policy (terminal).
  "POLICY_DENIED",
  "LISTING_UNAVAILABLE",
  "SEAT_TAKEN",
  "ALREADY_TERMINAL",
  "RATE_LIMITED",
  "CONTRACT_UNAVAILABLE",
] as const);

export const CONTRACT_PUBLIC_KEY_NOT_FOUND = "KEY_UNKNOWN";

export type ContractRefusalCode = (typeof CONTRACT_REFUSAL_CODES)[number] | typeof CONTRACT_PUBLIC_KEY_NOT_FOUND;

export const contractRefusalCodeSchema = z.enum([
  ...CONTRACT_REFUSAL_CODES,
  CONTRACT_PUBLIC_KEY_NOT_FOUND,
] as [string, ...string[]]);

export const contractRefusalSchema = z.object({
  error: contractRefusalCodeSchema,
  retryable: z.literal(false),
  retryAfterMs: z.number().int().positive().max(3_600_000).optional(),
  // The per-call nonce rides refusals too — the caller can correlate a
  // refused call to its receipt without a side channel (R8).
  serverNonce: z.string().regex(/^0x[0-9a-f]{32}$/).optional(),
}).strict();
export type ContractRefusal = z.infer<typeof contractRefusalSchema>;

export function isContractRefusalCode(value: unknown): value is ContractRefusalCode {
  return contractRefusalCodeSchema.safeParse(value).success;
}
