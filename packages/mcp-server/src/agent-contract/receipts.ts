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

/**
 * `initialize`'s `clientInfo`, at the exact bounds the receipt schema accepts.
 * The transport refuses an initialize carrying a clientInfo this rejects
 * (N4b-3 fix) — a value that can't ride a receipt can never poison the chain.
 */
export const receiptClientInfoSchema = z.object({
  name: z.string().min(1).max(128),
  version: z.string().min(1).max(64),
}).strict();

export const serverReceiptSchema = z.object({
  schemaVersion: z.literal(RECEIPT_SCHEMA_VERSION),
  runId: z.string().min(1).max(128),
  receiptId: digestHex,
  ts: z.number().int().positive(),
  surface: z.enum(["handshake", "business", "anchoring"]),
  tool: z.string().min(1).max(64),
  argsDigest: digestHex,
  /**
   * M4 (N4b-3): which scheme `argsDigest` uses — `"canonical"` =
   * `sha256(canonicalJson(args))`; `"hmac-sha256"` =
   * `HMAC-SHA256(scopeSalt, canonicalJson(args))` where scopeSalt is the
   * per-run `runSalt` (run receipts) or the per-principal pre-bind salt,
   * disclosed only through the verifier-scoped `/contract/run-salt`
   * endpoint. Cap-bearing calls (mandate_*, any `*Minor`/price/amount key)
   * are always salted so the observer feed cannot leak caps to a brute
   * force. Absent on receipts predating M4 — treat as `"canonical"`.
   */
  argsDigestScheme: z.enum(["canonical", "hmac-sha256"]).optional(),
  principal: z.object({
    role: z.enum(["buyer", "provider"]),
    keyId: z.string().min(1).max(64),
  }).strict(),
  outcome: z.string().min(1).max(64),
  /**
   * On a `contract_bind` receipt: the digest of THAT principal's pre-bind
   * receipt-chain head — the run chain's cross-link into the evidence the
   * principal produced before any run existed (M1). Absent elsewhere.
   */
  preBindHead: digestHex.optional(),
  mcpSessionId: z.string().min(1).max(128).optional(),
  clientInfo: receiptClientInfoSchema.optional(),
  sourceIp: z.string().min(1).max(64).optional(),
  bindAssurance: z.enum([
    "agentId-pinned-token",
    "late-certificate-party",
    "session-key-possession",
  ]).optional(),
  /**
   * D8 (N4b-7): rendezvous_send_invitation receipts disclose how the
   * stamped senderAgentId was established — or that nothing was proven.
   */
  senderProof: z.enum(["token-pinned", "certificate-bound", "unproven-pre-bind"]).optional(),
  /**
   * N4b-7: bind receipts record HOW the agentId was established — pinned in
   * the token at config time, or taken from the certificate's party on the
   * token's side at bind time (write-once) — and whether the session-key
   * possession statement was verified (the P-GAP hook, DRAFT schema).
   */
  bindMode: z.enum(["static", "late"]).optional(),
  bindStatement: z.enum(["verified", "absent"]).optional(),
  serverNonce: z.string().regex(/^0x[0-9a-f]{32}$/),
  responseDigest: digestHex,
  /**
   * N4b-3 review: the `responseDigest` scheme — `"canonical"` or
   * `"hmac-sha256"` under the same scope salt as `argsDigest`. Responses
   * carrying an amount (`*Minor`, price/fare/total…) are salted so the
   * observer feed can't be brute-forced into the agreed money values.
   */
  responseDigestScheme: z.enum(["canonical", "hmac-sha256"]).optional(),
  /**
   * N4b-6 (H1 honesty): set on every receipt of a run whose sim world was
   * seeded with a config-only fault — a verifier can tell a fault-injected
   * run from an honest one. Server-derived; never caller-supplied.
   */
  simFault: z.object({
    issueMismatch: z.enum(["fare", "travellers"]).optional(),
  }).strict().optional(),
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
/** The per-call evidence fields a receipt is built from. */
export interface ReceiptFields {
  runId: string;
  tool: string;
  argsDigest: string;
  /** M4: the argsDigest scheme — salted digests are disclosed per scope. */
  argsDigestScheme?: "canonical" | "hmac-sha256";
  principal: { role: "buyer" | "provider"; keyId: string };
  outcome: string;
  responseDigest: string;
  /** N4b-3: the responseDigest scheme — salted like cap-bearing args. */
  responseDigestScheme?: "canonical" | "hmac-sha256";
  /** Run genesis link to the principal's pre-bind chain head (M1). */
  preBindHead?: string;
  surface?: "handshake" | "business" | "anchoring";
  mcpSessionId?: string;
  clientInfo?: { name: string; version: string };
  sourceIp?: string;
  bindAssurance?: "agentId-pinned-token" | "late-certificate-party" | "session-key-possession";
  /** D8: rendezvous_send_invitation receipts only — sender proof kind. */
  senderProof?: "token-pinned" | "certificate-bound" | "unproven-pre-bind";
  /** N4b-7: bind receipts only — how the agentId was established. */
  bindMode?: "static" | "late";
  /** N4b-7: bind receipts only — whether the possession statement verified. */
  bindStatement?: "verified" | "absent";
  /** N4b-6: sim fault marker copied from the run — server-derived. */
  simFault?: { issueMismatch?: "fare" | "travellers" };
  serverNonce?: string;
  ts?: number;
}

type ReceiptCore = Omit<ServerReceipt, "receiptId" | "serverSignature">;

function draftCore(prev: ServerReceipt | null, fields: ReceiptFields): ReceiptCore {
  if (prev !== null && prev.runId !== fields.runId) {
    throw new Error("makeReceipt: prev receipt belongs to a different runId");
  }
  return serverReceiptSchema.omit({ receiptId: true, serverSignature: true }).parse({
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    runId: fields.runId,
    ts: fields.ts ?? Date.now(),
    surface: fields.surface ?? "business",
    tool: fields.tool,
    argsDigest: fields.argsDigest,
    argsDigestScheme: fields.argsDigestScheme,
    principal: fields.principal,
    outcome: fields.outcome,
    preBindHead: fields.preBindHead,
    mcpSessionId: fields.mcpSessionId,
    clientInfo: fields.clientInfo,
    sourceIp: fields.sourceIp,
    bindAssurance: fields.bindAssurance,
    ...(fields.senderProof !== undefined ? { senderProof: fields.senderProof } : {}),
    ...(fields.bindMode !== undefined ? { bindMode: fields.bindMode } : {}),
    ...(fields.bindStatement !== undefined ? { bindStatement: fields.bindStatement } : {}),
    serverNonce: fields.serverNonce ?? newServerNonce(),
    responseDigest: fields.responseDigest,
    responseDigestScheme: fields.responseDigestScheme,
    ...(fields.simFault !== undefined ? { simFault: fields.simFault } : {}),
    prevHash: prev === null ? RECEIPT_CHAIN_GENESIS : canonicalDigest(prev),
  });
}

/**
 * N4b-3 fix: build + schema-validate the receipt BEFORE dispatch. The
 * outcome/responseDigest are server-derived placeholders — every
 * caller-supplied field is checked, so a receipt that passes this check can
 * never fail construction after the action ran.
 */
export function checkReceiptDraft(
  prev: ServerReceipt | null,
  fields: Omit<ReceiptFields, "outcome" | "responseDigest">,
): boolean {
  try {
    draftCore(prev, {
      ...fields,
      outcome: "ok",
      responseDigest: RECEIPT_CHAIN_GENESIS,
    });
    return true;
  } catch {
    return false;
  }
}

export function makeReceipt(
  prev: ServerReceipt | null,
  fields: ReceiptFields,
  signer: ContractSigner,
): ServerReceipt {
  const core = draftCore(prev, fields);
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

/** Per-keyId validity window (ms epoch) — from the published key metadata. */
export interface KeyValidityWindow {
  /** Receipt `ts` must be ≥ this when set; null = unbounded start. */
  validFromMs: number | null;
  /** Receipt `ts` must be ≤ this when set; null = no expiry. */
  validUntilMs: number | null;
}

/**
 * Verify a receipt chain end to end: shape, `prevHash` continuity (a gap, a
 * dropped receipt or a reorder breaks the link), and every `serverSignature`
 * against the named public key. Returns the chain head for anchoring.
 *
 * Options (N4b-3):
 *  - `firstPrevHash`: the expected prevHash of the FIRST receipt — the
 *    carried-forward segment anchor for a pre-bind chain segment that does
 *    not start at genesis (default: the genesis sentinel).
 *  - `keyWindows`: LOW — published-key validity windows, keyed by keyId.
 *    A receipt timestamped outside its signing key's window fails
 *    `KEY_WINDOW`.
 */
export function verifyChain(
  receipts: readonly unknown[],
  publicKeys: ContractPublicKeys,
  options?: {
    firstPrevHash?: string;
    keyWindows?: Record<string, KeyValidityWindow>;
  },
): ChainVerdict {
  let prev: ServerReceipt | null = null;
  let runId: string | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const parsed = serverReceiptSchema.safeParse(receipts[i]);
    if (!parsed.success) return { ok: false, code: "RECEIPT_MALFORMED", index: i };
    const receipt = parsed.data;
    // A chain is scoped to exactly one run; the head it yields is per-run.
    if (runId === null) runId = receipt.runId;
    else if (receipt.runId !== runId) return { ok: false, code: "RUN_MISMATCH", index: i };
    const expectedPrev = prev === null
      ? (options?.firstPrevHash ?? RECEIPT_CHAIN_GENESIS)
      : canonicalDigest(prev);
    if (receipt.prevHash !== expectedPrev) return { ok: false, code: "CHAIN_LINK", index: i };
    const publicKey = publicKeys[receipt.serverSignature.keyId];
    if (publicKey === undefined) return { ok: false, code: CONTRACT_PUBLIC_KEY_NOT_FOUND, index: i };
    const window = options?.keyWindows?.[receipt.serverSignature.keyId];
    if (
      window !== undefined &&
      ((window.validFromMs !== null && receipt.ts < window.validFromMs) ||
        (window.validUntilMs !== null && receipt.ts > window.validUntilMs))
    ) {
      return { ok: false, code: "KEY_WINDOW", index: i };
    }
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
