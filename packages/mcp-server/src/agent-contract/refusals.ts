import { z } from "zod";

/**
 * Generic refusal codes for the `/contract/mcp` surface (LLD §3: "Refusals
 * use generic codes"). The refusal body is strict — `error`, `retryable` and
 * an optional `retryAfterMs` only — so a `MANDATE_REFUSED` reply can never
 * carry the mandate cap value, and no refusal leaks internals.
 */
export const CONTRACT_REFUSAL_CODES = Object.freeze([
  "MANDATE_REFUSED",
  "STATE_REFUSED",
  "ROLE_REFUSED",
  "NOT_FOUND",
  "CERTIFICATE_INVALID",
  "ENVELOPE_INVALID",
  "ENVELOPE_EXPIRED",
  "NONCE_REUSED",
  "SIGNATURE_INVALID",
  "APPROVAL_INVALID",
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
}).strict();
export type ContractRefusal = z.infer<typeof contractRefusalSchema>;

export function isContractRefusalCode(value: unknown): value is ContractRefusalCode {
  return contractRefusalCodeSchema.safeParse(value).success;
}
