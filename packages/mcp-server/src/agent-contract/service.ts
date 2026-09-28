import { z } from "zod";

import { verifyCertificateEnvelope, type HostRootPin } from "./certificate.js";
import { makeReceipt, type ServerReceipt } from "./receipts.js";
import type { ContractSigner } from "./envelope.js";
import type { ContractRole } from "./schemas.js";
import type { ContractRefusalCode } from "./refusals.js";

/**
 * Run-scoped contract state and the `contract_bind` decision logic
 * (LLD §3 — this slice: bind + status only; sim/business tools arrive in
 * later N4b slices).
 *
 * A run is keyed by the handshake `sessionId` its certificate attests. One
 * handshake maps to at most one contract run: the first role to bind creates
 * it, the second must present a certificate with the SAME canonical digest —
 * a different envelope claiming the same sessionId is a substitution attempt
 * and is refused as CERTIFICATE_INVALID. A principal (per-token `keyId`) may
 * be bound to at most one run, and one role per run.
 *
 * State is in-memory for this slice; durable per-run persistence on the
 * mcp_state volume plus the 24 h post-terminal TTL (LLD §3) is a later slice.
 */

export interface ContractPrincipal {
  readonly keyId: string;
  readonly role: ContractRole;
}

export interface BoundRole {
  readonly principalKeyId: string;
  readonly signerKey: { keyId: string; publicKeyHex: string };
  readonly approvalKey: { keyId: string; publicKeyHex: string };
  readonly boundAt: string;
}

export type ContractStage =
  | "rendezvous" | "handshake" | "bound" | "mandated" | "negotiating"
  | "agreed" | "booked" | "verified" | "settled" | "terminal";

export interface ContractRun {
  readonly runId: string;
  readonly certificateDigest: string;
  readonly createdAtMs: number;
  readonly bound: Partial<Record<ContractRole, BoundRole>>;
  readonly receipts: ServerReceipt[];
  stage: ContractStage;
}

export type BindOutcome =
  | { ok: true; runId: string; role: ContractRole; boundAt: string; run: ContractRun }
  | { ok: false; code: ContractRefusalCode };

export interface ContractService {
  bind(
    principal: ContractPrincipal,
    args: { certificate: unknown; signerKey: unknown; approvalKey: unknown },
    evidence: { argsDigest: string; sourceIp?: string },
  ): BindOutcome;
  /** Record a call's receipt onto the run chain (run-scoped, order-committed). */
  recordReceipt(
    run: ContractRun,
    fields: Omit<Parameters<typeof makeReceipt>[1], "runId">,
  ): ServerReceipt;
  runFor(runId: string): ContractRun | undefined;
  runIdForPrincipal(keyId: string): string | undefined;
}

const boundKeySchema = z.object({
  keyId: z.string().min(1).max(64),
  publicKeyHex: z.string().regex(/^0x[0-9a-fA-F]{64,132}$/),
}).strict();

export function createContractService(options: {
  hostRoots: readonly HostRootPin[];
  signer: ContractSigner;
  now?: () => number;
}): ContractService {
  const now = options.now ?? Date.now;
  const runs = new Map<string, ContractRun>();
  const principalRuns = new Map<string, string>();

  function bind(
    principal: ContractPrincipal,
    args: { certificate: unknown; signerKey: unknown; approvalKey: unknown },
    _evidence: { argsDigest: string; sourceIp?: string },
  ): BindOutcome {
    const signerKey = boundKeySchema.safeParse(args.signerKey);
    const approvalKey = boundKeySchema.safeParse(args.approvalKey);
    if (!signerKey.success || !approvalKey.success) return { ok: false, code: "CERTIFICATE_INVALID" };

    const verdict = verifyCertificateEnvelope(args.certificate, { hostRoots: options.hostRoots });
    if (!verdict.ok) return { ok: false, code: "CERTIFICATE_INVALID" };

    const existing = principalRuns.get(principal.keyId);
    if (existing !== undefined) {
      // Idempotent re-bind on the same run with the same keys is fine; any
      // other combination is a state violation for this principal.
      const run = runs.get(existing);
      const mine = run?.bound[principal.role];
      if (
        run === undefined || mine === undefined || verdict.sessionId !== run.runId ||
        mine.signerKey.keyId !== signerKey.data.keyId ||
        mine.signerKey.publicKeyHex !== signerKey.data.publicKeyHex ||
        mine.approvalKey.keyId !== approvalKey.data.keyId ||
        mine.approvalKey.publicKeyHex !== approvalKey.data.publicKeyHex ||
        verdict.certificateDigest !== run.certificateDigest
      ) return { ok: false, code: "STATE_REFUSED" };
      return { ok: true, runId: run.runId, role: principal.role, boundAt: mine.boundAt, run };
    }

    let run = runs.get(verdict.sessionId);
    if (run === undefined) {
      run = {
        runId: verdict.sessionId,
        certificateDigest: verdict.certificateDigest,
        createdAtMs: now(),
        bound: {},
        receipts: [],
        stage: "handshake",
      };
      runs.set(run.runId, run);
    } else if (run.certificateDigest !== verdict.certificateDigest) {
      // Same sessionId, different envelope → substitution attempt.
      return { ok: false, code: "CERTIFICATE_INVALID" };
    }

    const occupant = run.bound[principal.role];
    if (occupant !== undefined && occupant.principalKeyId !== principal.keyId) {
      return { ok: false, code: "ROLE_REFUSED" };
    }
    // A principal may not hold the other role's seat on the same run.
    const otherRole: ContractRole = principal.role === "buyer" ? "provider" : "buyer";
    if (run.bound[otherRole]?.principalKeyId === principal.keyId) {
      return { ok: false, code: "ROLE_REFUSED" };
    }

    const boundAt = new Date(now()).toISOString();
    run.bound[principal.role] = {
      principalKeyId: principal.keyId,
      signerKey: signerKey.data,
      approvalKey: approvalKey.data,
      boundAt,
    };
    principalRuns.set(principal.keyId, run.runId);
    if (run.bound.buyer !== undefined && run.bound.provider !== undefined) run.stage = "bound";
    return { ok: true, runId: run.runId, role: principal.role, boundAt, run };
  }

  return {
    bind,
    recordReceipt(run, fields) {
      const receipt = makeReceipt(run.receipts.at(-1) ?? null, { ...fields, runId: run.runId }, options.signer);
      run.receipts.push(receipt);
      return receipt;
    },
    runFor(runId) {
      return runs.get(runId);
    },
    runIdForPrincipal(keyId) {
      return principalRuns.get(keyId);
    },
  };
}
