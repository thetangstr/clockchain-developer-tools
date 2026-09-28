import { canonicalDigest } from "./canonical.js";
import type { ApprovalRecord } from "./schemas.js";
import { eip191RecoverPublicKey, normalizePublicKeyHex } from "./eip191.js";

/**
 * Consequential-action approval records (LLD §13): booking and settlement
 * require a signed record produced by the role's local signer policy, verified
 * here against the approval key bound at `contract_bind`.
 *
 *   approval.digest   = canonicalDigest({domain:"agent-contract.approval/v1",
 *                                        runId, tool, nonce, envelopeDigest, expiresAt})
 *                       — binds the approval to THIS run/tool/nonce/envelope (rev 6.1)
 *   signature         = EIP-191 over canonicalDigest({domain:"agent-contract.approval-sig/v1",
 *                                        runId, role, action, digest, policyDigest, decision, ts, approverKeyId})
 *
 * `action` is the payload kind being approved ("booking" | "settlement").
 * Both digests are server-side constants of the wire format — the vectors
 * freeze the envelope/role-sig half; this half is defined here so N5's signer
 * and this server agree on one record shape.
 */

export const APPROVAL_DIGEST_DOMAIN = "agent-contract.approval/v1";
export const APPROVAL_SIG_DOMAIN = "agent-contract.approval-sig/v1";

export function computeApprovalDigest(fields: {
  runId: string;
  tool: string;
  nonce: string;
  envelopeDigest: string;
  expiresAt: string;
}): string {
  return canonicalDigest({ domain: APPROVAL_DIGEST_DOMAIN, ...fields });
}

export function computeApprovalSigDigest(fields: {
  runId: string;
  role: "buyer" | "provider";
  record: Omit<ApprovalRecord, "signature">;
}): string {
  return canonicalDigest({ domain: APPROVAL_SIG_DOMAIN, runId: fields.runId, role: fields.role, record: fields.record });
}

/**
 * Verify an approval record: decision must be `allow` (the spec word —
 * `approve` is invalid), action must match the consequential payload kind,
 * digest must be the exact binding tuple, the policy digest must equal the
 * role's configured pin (`CONTRACT_POLICY_DIGESTS`, REQUIRED — a zero-digest
 * or unattested policy never passes), `approverKeyId` must be the bound
 * approval key's id, `ts` must fall inside the envelope's validity window,
 * and the EIP-191 signature must recover to the bound approval key.
 */
export function verifyApprovalRecord(fields: {
  approval: ApprovalRecord;
  runId: string;
  role: "buyer" | "provider";
  tool: string;
  action: string;
  nonce: string;
  envelopeDigest: string;
  expiresAt: string;
  approvalKey: { keyId: string; publicKeyHex: string };
  expectedPolicyDigest: string;
  nowMs?: number;
}): boolean {
  const a = fields.approval;
  if (a.role !== fields.role || a.action !== fields.action || a.decision !== "allow") return false;
  if (a.approverKeyId !== fields.approvalKey.keyId) return false;
  const expiresAtMs = Date.parse(fields.expiresAt);
  const nowMs = fields.nowMs ?? Date.now();
  // `ts` must fall within the envelope's validity: not after it expires and
  // not in the future relative to the server's own clock.
  if (!Number.isFinite(expiresAtMs) || a.ts > expiresAtMs || a.ts > nowMs) return false;
  if (
    a.digest !== computeApprovalDigest({
      runId: fields.runId,
      tool: fields.tool,
      nonce: fields.nonce,
      envelopeDigest: fields.envelopeDigest,
      expiresAt: fields.expiresAt,
    })
  ) return false;
  if (a.policyDigest !== fields.expectedPolicyDigest) return false;
  const sigDigest = computeApprovalSigDigest({
    runId: fields.runId,
    role: fields.role,
    record: { role: a.role, action: a.action, digest: a.digest, policyDigest: a.policyDigest, decision: a.decision, ts: a.ts, approverKeyId: a.approverKeyId },
  });
  const recovered = eip191RecoverPublicKey(Buffer.from(sigDigest.slice(2), "hex"), a.signature);
  if (recovered === null) return false;
  const expected = normalizePublicKeyHex(fields.approvalKey.publicKeyHex);
  return expected !== null && "0x" + Buffer.from(recovered).toString("hex") === expected;
}
