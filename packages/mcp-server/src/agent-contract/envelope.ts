import { randomBytes, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

import { z } from "zod";

import { canonicalDigest, canonicalJson } from "./canonical.js";
import { CONTRACT_PUBLIC_KEY_NOT_FOUND } from "./refusals.js";

/**
 * The server-signed prepare envelope of the pairing LLD §3/§13 — wire format
 * FROZEN and shared with the N5 local-signer lane (see
 * `test/fixtures/agent-contract-prepare-envelope-vectors.json`):
 *
 *   Envelope      = {schema, runId, tool, role, payload, payloadDigest,
 *                    expiresAt, nonce, serverKeyId, serverSig}
 *   payloadDigest = canonicalDigest(payload)
 *   signedMessage = UTF-8 bytes of canonicalJson(envelope without serverSig)
 *   serverSig     = {alg:"ed25519", keyId, sig} over signedMessage
 *
 * Every mutating tool's `*_prepare` returns one. The agent-side local signer
 * verifies `serverSig` (and runId/expiry/nonce freshness) before producing
 * its own signature, so it cannot sign bytes the server did not prepare —
 * whoever supplied them. Do not change this shape without a new vector
 * fixture; the signer lane depends on it byte-for-byte.
 */
export const PREPARE_ENVELOPE_SCHEMA_ID = "agent-contract.prepare-envelope/v1";
export const PREPARE_ENVELOPE_TTL_MS = 120_000;

const digestHex = z.string().regex(/^0x[0-9a-f]{64}$/);

export const ed25519SignatureSchema = z.object({
  alg: z.literal("ed25519"),
  keyId: z.string().min(1).max(64),
  sig: z.string().regex(/^0x[0-9a-fA-F]{128}$/),
}).strict();
export type Ed25519Signature = z.infer<typeof ed25519SignatureSchema>;

export const prepareEnvelopeSchema = z.object({
  schema: z.literal(PREPARE_ENVELOPE_SCHEMA_ID),
  runId: z.string().min(1).max(128),
  tool: z.string().min(1).max(64),
  role: z.enum(["buyer", "provider"]),
  payload: z.record(z.string(), z.unknown()),
  payloadDigest: digestHex,
  expiresAt: z.string().datetime({ offset: false }),
  nonce: z.string().regex(/^0x[0-9a-f]{32}$/),
  serverKeyId: z.string().min(1).max(64),
  serverSig: ed25519SignatureSchema,
}).strict();
export type PrepareEnvelope = z.infer<typeof prepareEnvelopeSchema>;

export interface ContractSigner {
  keyId: string;
  privateKey: KeyObject | string | Buffer;
}

/** keyId → Ed25519 public key (KeyObject or PEM/DER the crypto API accepts). */
export type ContractPublicKeys = Readonly<Record<string, KeyObject | string | Buffer>>;

/** The exact bytes the server signature covers — shared with the N5 signer lane. */
export function envelopeSignedMessage(envelope: Omit<PrepareEnvelope, "serverSig">): string {
  return canonicalJson(envelope);
}

export function signEnvelope(
  fields: {
    payload: Record<string, unknown>;
    runId: string;
    tool: string;
    role: "buyer" | "provider";
    nonce?: string;
    ttlMs?: number;
    nowMs?: number;
  },
  signer: ContractSigner,
): PrepareEnvelope {
  const nowMs = fields.nowMs ?? Date.now();
  const ttlMs = fields.ttlMs ?? PREPARE_ENVELOPE_TTL_MS;
  if (!Number.isInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 600_000) {
    throw new RangeError("envelope ttlMs out of bounds");
  }
  const payload = prepareEnvelopeSchema.omit({ serverSig: true }).parse({
    schema: PREPARE_ENVELOPE_SCHEMA_ID,
    runId: fields.runId,
    tool: fields.tool,
    role: fields.role,
    payload: fields.payload,
    payloadDigest: canonicalDigest(fields.payload),
    expiresAt: new Date(nowMs + ttlMs).toISOString(),
    nonce: fields.nonce ?? `0x${randomBytes(16).toString("hex")}`,
    serverKeyId: signer.keyId,
  });
  const sig = edSign(null, Buffer.from(envelopeSignedMessage(payload), "utf8"), signer.privateKey);
  return { ...payload, serverSig: { alg: "ed25519", keyId: signer.keyId, sig: `0x${sig.toString("hex")}` } };
}

export type EnvelopeVerdict =
  | { ok: true; envelope: PrepareEnvelope }
  | { ok: false; code: string };

/**
 * Verify a prepare envelope, in the frozen order: schema → recompute
 * payloadDigest → expiry → nonce freshness (per runId, via `nonceSeen`;
 * marking is the caller's job) → ed25519 signature against the pinned server
 * key for keyId. `serverKeyId` must equal `serverSig.keyId`.
 */
export function verifyEnvelope(
  candidate: unknown,
  publicKeys: ContractPublicKeys,
  options: { nowMs?: number; nonceSeen?: (runId: string, nonce: string) => boolean } = {},
): EnvelopeVerdict {
  const parsed = prepareEnvelopeSchema.safeParse(candidate);
  if (!parsed.success) return { ok: false, code: "ENVELOPE_INVALID" };
  const envelope = parsed.data;
  if (envelope.serverKeyId !== envelope.serverSig.keyId) {
    return { ok: false, code: "ENVELOPE_INVALID" };
  }
  if (envelope.payloadDigest !== canonicalDigest(envelope.payload)) {
    // Generic refusal — the wire must not leak which field mismatched.
    return { ok: false, code: "ENVELOPE_INVALID" };
  }
  if (Date.parse(envelope.expiresAt) <= (options.nowMs ?? Date.now())) {
    return { ok: false, code: "ENVELOPE_EXPIRED" };
  }
  if (options.nonceSeen?.(envelope.runId, envelope.nonce) === true) {
    return { ok: false, code: "NONCE_REUSED" };
  }
  const publicKey = publicKeys[envelope.serverSig.keyId];
  if (publicKey === undefined) return { ok: false, code: CONTRACT_PUBLIC_KEY_NOT_FOUND };
  const { serverSig, ...message } = envelope;
  const valid = edVerify(
    null,
    Buffer.from(envelopeSignedMessage(message), "utf8"),
    publicKey,
    Buffer.from(serverSig.sig.slice(2), "hex"),
  );
  if (!valid) return { ok: false, code: "ENVELOPE_INVALID" };
  return { ok: true, envelope };
}
