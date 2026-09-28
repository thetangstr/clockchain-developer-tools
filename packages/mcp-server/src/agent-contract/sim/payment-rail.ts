import { z } from "zod";

import { canonicalDigest } from "../canonical.js";

/**
 * Simulated payment rail — a pure in-memory port of the travel repo's
 * `src/lib/payment/sandbox-payment-rail-store.ts`, run-scoped for N4b-2.
 *
 * Semantics preserved from the source module:
 *   - a transfer is keyed by `transferId`; re-executing with the SAME request
 *     returns the original receipt (idempotent), and reusing the id with a
 *     DIFFERENT request is refused as PAYMENT_IDEMPOTENCY_CONFLICT;
 *   - receipts carry `commercialTransfer: false` — this rail can never move
 *     real money;
 *   - receipt ids are digest-derived and deterministic per run.
 *
 * Everything additionally carries `simulated: true` per LLD §3 ("every
 * response carries simulated: true where the settlement sim is involved").
 * No network, no filesystem: the caller provides the clock.
 */

export type SimPaymentFailureCode = "PAYMENT_IDEMPOTENCY_CONFLICT" | "TRANSFER_INVALID";

export interface SimPaymentRefusal {
  ok: false;
  code: SimPaymentFailureCode;
}

export const simTransferRequestSchema = z
  .object({
    transferId: z.string().regex(/^sandbox-transfer:[0-9a-f]{16,64}$/).optional(),
    idempotencyKey: z.string().regex(/^0x[0-9a-f]{64}$/).optional(),
    agreementId: z.string().min(4).max(64),
    agreementDigest: z.string().regex(/^0x[0-9a-f]{64}$/).optional(),
    verificationDigest: z.string().regex(/^0x[0-9a-f]{64}$/).optional(),
    payerPartyId: z.string().min(1).max(64),
    providerPartyId: z.string().min(1).max(64),
    beneficiaryDigest: z.string().regex(/^0x[0-9a-f]{64}$/).optional(),
    amountMinor: z.number().int().nonnegative().max(1_000_000_000),
    currency: z.string().min(3).max(8),
  })
  .strict();

export interface SimTransferRequest extends z.input<typeof simTransferRequestSchema> {}

export interface SimTransferReceipt {
  schema: "agent-contract.sim-transfer-receipt/v1";
  railReceiptId: string;
  transferId: string;
  idempotencyKey: string;
  agreementId: string;
  agreementDigest?: string;
  verificationDigest?: string;
  payerPartyId: string;
  providerPartyId: string;
  beneficiaryDigest?: string;
  amountMinor: number;
  currency: string;
  status: "COMPLETED";
  acceptedAt: string;
  completedAt: string;
  commercialTransfer: false;
  simulated: true;
}

export type SimTransferResult =
  | { ok: true; receipt: SimTransferReceipt }
  | SimPaymentRefusal;

export type SimPaymentStatus =
  | { state: "none" }
  | { state: "released"; transferId: string };

export interface SimPaymentRail {
  execute(request: unknown): SimTransferResult;
  read(transferId: string): SimTransferReceipt | null;
  status(): SimPaymentStatus;
}

const iso = (ms: number): string => new Date(ms).toISOString();

export function createSimPaymentRail(options: {
  runId: string;
  now?: () => number;
}): SimPaymentRail {
  const now = options.now ?? Date.now;
  // Canonical request digest per transferId — the idempotency binding.
  const transfers = new Map<string, { requestDigest: string; receipt: SimTransferReceipt }>();
  let lastTransferId: string | null = null;

  return {
    execute(request) {
      const parsed = simTransferRequestSchema.safeParse(request);
      if (!parsed.success) return { ok: false, code: "TRANSFER_INVALID" };
      const req = parsed.data;

      const transferId = req.transferId
        ?? `sandbox-transfer:${canonicalDigest({
          runId: options.runId,
          agreementId: req.agreementId,
          kind: "SANDBOX_SETTLEMENT",
        }).slice(2, 34)}`;
      const normalized = { ...req, transferId };
      const requestDigest = canonicalDigest({ runId: options.runId, request: normalized });

      const existing = transfers.get(transferId);
      if (existing !== undefined) {
        return existing.requestDigest === requestDigest
          ? { ok: true, receipt: structuredClone(existing.receipt) }
          : { ok: false, code: "PAYMENT_IDEMPOTENCY_CONFLICT" };
      }

      const acceptedAt = iso(now());
      const idempotencyKey = req.idempotencyKey
        ?? canonicalDigest({ runId: options.runId, transferId, agreementId: req.agreementId });
      const receipt: SimTransferReceipt = {
        schema: "agent-contract.sim-transfer-receipt/v1",
        railReceiptId: `sandbox-receipt:${canonicalDigest({
          runId: options.runId,
          transferId,
          requestDigest,
        }).slice(2, 18)}`,
        transferId,
        idempotencyKey,
        agreementId: req.agreementId,
        ...(req.agreementDigest !== undefined ? { agreementDigest: req.agreementDigest } : {}),
        ...(req.verificationDigest !== undefined ? { verificationDigest: req.verificationDigest } : {}),
        payerPartyId: req.payerPartyId,
        providerPartyId: req.providerPartyId,
        ...(req.beneficiaryDigest !== undefined ? { beneficiaryDigest: req.beneficiaryDigest } : {}),
        amountMinor: req.amountMinor,
        currency: req.currency,
        status: "COMPLETED",
        acceptedAt,
        completedAt: acceptedAt,
        commercialTransfer: false,
        simulated: true,
      };
      transfers.set(transferId, { requestDigest, receipt });
      lastTransferId = transferId;
      return { ok: true, receipt: structuredClone(receipt) };
    },
    read(transferId) {
      const entry = transfers.get(transferId);
      return entry === undefined ? null : structuredClone(entry.receipt);
    },
    status() {
      return lastTransferId === null
        ? { state: "none" }
        : { state: "released", transferId: lastTransferId };
    },
  };
}
