import { randomBytes, sign as edSign, verify as edVerify } from "node:crypto";

import { z } from "zod";

import { canonicalDigest, canonicalJson } from "./canonical.js";
import { CONTRACT_PUBLIC_KEY_NOT_FOUND } from "./refusals.js";
import { ed25519SignatureSchema, type ContractPublicKeys, type ContractSigner } from "./envelope.js";

/**
 * Run-scoped, signed, hash-chained receipts (LLD §3 "Every call produces a
 * signed, hash-chained receipt", §9 R8/R13, §15 T0 `ServerReceipt`). Every
 * business-surface call appends one receipt; at run end the chain head is
 * anchored with `tsa_issue`. There is deliberately NO `transport` field —
 * the server cannot tell an MCP client from a well-formed script, so
 * transport hints are evidence (`mcpSessionId`, `clientInfo`), never proof.
 */

export const RECEIPT_SCHEMA_VERSION = "agent-contract.server-receipt/v1";
/** `prevHash` of the first receipt in a chain — the genesis sentinel. */
export const RECEIPT_CHAIN_GENESIS = `0x${"0".repeat(64)}` as const;

const digestHex = z.string().regex(/^0x[0-9a-f]{64}$/);

export const serverReceiptSchema = z.object({
  schemaVersion: z.literal(RECEIPT_SCHEMA_VERSION),
  runId: z.string().min(1).max(128),
  receiptId: digestHex,
  ts: z.number().int().positive(),
  surface: z.enum(["handshake", "business", "anchoring"]),
  tool: z.string().min(1).max(64),
  argsDigest: digestHex,
  principal: z.object({
    role: z.enum(["buyer", "provider"]),
    keyId: z.string().min(1).max(64),
  }).strict(),
  outcome: z.string().min(1).max(64),
  mcpSessionId: z.string().min(1).max(128).optional(),
  clientInfo: z.object({
    name: z.string().min(1).max(128),
    version: z.string().min(1).max(64),
  }).strict().optional(),
  sourceIp: z.string().min(1).max(64).optional(),
  bindAssurance: z.literal("agentId-pinned-token").optional(),
  serverNonce: z.string().regex(/^0x[0-9a-f]{32}$/),
  responseDigest: digestHex,
  prevHash: digestHex,
  serverSignature: ed25519SignatureSchema,
}).strict();
export type ServerReceipt = z.infer<typeof serverReceiptSchema>;

/** 128-bit random per-call nonce (`0x` + 32 hex), echoed in the tool result so the model-side trace carries it (R8/R13). */
export function newServerNonce(): string {
  return `0x${randomBytes(16).toString("hex")}`;
}

function receiptPayload(receipt: Omit<ServerReceipt, "receiptId" | "serverSignature">): string {
  return canonicalJson(receipt);
}

/**
 * Append a receipt to the chain. `prev` is the previous receipt (null for the
 * genesis call); a `prev` from another runId is refused — a chain is scoped
 * to exactly one run. `fields` carries the call's evidence; the caller computes
 * `argsDigest` and `responseDigest` from the canonical wire values. The
 * `receiptId` is the canonical digest of the unsigned core — deterministic,
 * content-addressed, and inside the signature's coverage.
 */
export function makeReceipt(
  prev: ServerReceipt | null,
  fields: {
    runId: string;
    tool: string;
    argsDigest: string;
    principal: { role: "buyer" | "provider"; keyId: string };
    outcome: string;
    responseDigest: string;
    surface?: "handshake" | "business" | "anchoring";
    mcpSessionId?: string;
    clientInfo?: { name: string; version: string };
    sourceIp?: string;
    bindAssurance?: "agentId-pinned-token";
    serverNonce?: string;
    ts?: number;
  },
  signer: ContractSigner,
): ServerReceipt {
  if (prev !== null && prev.runId !== fields.runId) {
    throw new Error("makeReceipt: prev receipt belongs to a different runId");
  }
  const core = serverReceiptSchema.omit({ receiptId: true, serverSignature: true }).parse({
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    runId: fields.runId,
    ts: fields.ts ?? Date.now(),
    surface: fields.surface ?? "business",
    tool: fields.tool,
    argsDigest: fields.argsDigest,
    principal: fields.principal,
    outcome: fields.outcome,
    mcpSessionId: fields.mcpSessionId,
    clientInfo: fields.clientInfo,
    sourceIp: fields.sourceIp,
    bindAssurance: fields.bindAssurance,
    serverNonce: fields.serverNonce ?? newServerNonce(),
    responseDigest: fields.responseDigest,
    prevHash: prev === null ? RECEIPT_CHAIN_GENESIS : canonicalDigest(prev),
  });
  const sig = edSign(null, Buffer.from(receiptPayload(core), "utf8"), signer.privateKey);
  return {
    ...core,
    receiptId: canonicalDigest(core),
    serverSignature: { alg: "ed25519", keyId: signer.keyId, sig: `0x${sig.toString("hex")}` },
  };
}

export type ChainVerdict =
  | { ok: true; head: string | null }
  | { ok: false; code: string; index: number };

/**
 * Verify a receipt chain end to end: shape, `prevHash` continuity (a gap, a
 * dropped receipt or a reorder breaks the link), and every `serverSignature`
 * against the named public key. Returns the chain head for anchoring.
 */
export function verifyChain(receipts: readonly unknown[], publicKeys: ContractPublicKeys): ChainVerdict {
  let prev: ServerReceipt | null = null;
  let runId: string | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const parsed = serverReceiptSchema.safeParse(receipts[i]);
    if (!parsed.success) return { ok: false, code: "RECEIPT_MALFORMED", index: i };
    const receipt = parsed.data;
    // A chain is scoped to exactly one run; the head it yields is per-run.
    if (runId === null) runId = receipt.runId;
    else if (receipt.runId !== runId) return { ok: false, code: "RUN_MISMATCH", index: i };
    const expectedPrev = prev === null ? RECEIPT_CHAIN_GENESIS : canonicalDigest(prev);
    if (receipt.prevHash !== expectedPrev) return { ok: false, code: "CHAIN_LINK", index: i };
    const publicKey = publicKeys[receipt.serverSignature.keyId];
    if (publicKey === undefined) return { ok: false, code: CONTRACT_PUBLIC_KEY_NOT_FOUND, index: i };
    const { receiptId, serverSignature, ...core } = receipt;
    if (receiptId !== canonicalDigest(core)) {
      return { ok: false, code: "RECEIPT_ID", index: i };
    }
    const valid = edVerify(
      null,
      Buffer.from(receiptPayload(core), "utf8"),
      publicKey,
      Buffer.from(serverSignature.sig.slice(2), "hex"),
    );
    if (!valid) return { ok: false, code: "RECEIPT_SIGNATURE", index: i };
    prev = receipt;
  }
  return { ok: true, head: prev === null ? null : canonicalDigest(prev) };
}

/** The chain head to anchor with `tsa_issue` at run end; null for an empty chain. */
export function chainHead(receipts: readonly ServerReceipt[]): string | null {
  const last = receipts.at(-1);
  return last === undefined ? null : canonicalDigest(last);
}
