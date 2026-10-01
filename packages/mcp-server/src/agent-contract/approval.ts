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
  /** N11f: one pinned digest, or the role's set of acceptable digests. */
  expectedPolicyDigest: string | ReadonlySet<string>;
  nowMs?: number;
}): boolean {
  return checkApprovalRecord(fields) === "allow";
}

/**
 * N4b-8 (gap 5): like {@link verifyApprovalRecord} but returns the signed
 * DECISION — `"allow"`, `"deny"`, or `null` when any check fails. A `deny`
 * is a fully valid, cryptographically bound policy verdict (the sig digest
 * covers `decision`); the caller turns it into the terminal
 * `blocked_by_policy`, not into APPROVAL_INVALID.
 */
export function checkApprovalRecord(fields: {
  approval: ApprovalRecord;
  runId: string;
  role: "buyer" | "provider";
  tool: string;
  action: string;
  nonce: string;
  envelopeDigest: string;
  expiresAt: string;
  approvalKey: { keyId: string; publicKeyHex: string };
  /** N11f: one pinned digest, or the role's set of acceptable digests. */
  expectedPolicyDigest: string | ReadonlySet<string>;
  nowMs?: number;
}): "allow" | "deny" | null {
  const a = fields.approval;
  if (a.role !== fields.role || a.action !== fields.action) return null;
  if (a.decision !== "allow" && a.decision !== "deny") return null;
  if (a.approverKeyId !== fields.approvalKey.keyId) return null;
  const expiresAtMs = Date.parse(fields.expiresAt);
  const nowMs = fields.nowMs ?? Date.now();
  // `ts` must fall within the envelope's validity: not after it expires and
  // not in the future relative to the server's own clock.
  if (!Number.isFinite(expiresAtMs) || a.ts > expiresAtMs || a.ts > nowMs) return null;
  if (
    a.digest !== computeApprovalDigest({
      runId: fields.runId,
      tool: fields.tool,
      nonce: fields.nonce,
      envelopeDigest: fields.envelopeDigest,
      expiresAt: fields.expiresAt,
    })
  ) return null;
  const pinnedDigests = fields.expectedPolicyDigest;
  if (
    typeof pinnedDigests === "string"
      ? a.policyDigest !== pinnedDigests
      : !pinnedDigests.has(a.policyDigest)
  ) return null;
  const sigDigest = computeApprovalSigDigest({
    runId: fields.runId,
    role: fields.role,
    record: { role: a.role, action: a.action, digest: a.digest, policyDigest: a.policyDigest, decision: a.decision, ts: a.ts, approverKeyId: a.approverKeyId },
  });
  const recovered = eip191RecoverPublicKey(Buffer.from(sigDigest.slice(2), "hex"), a.signature);
  if (recovered === null) return null;
  const expected = normalizePublicKeyHex(fields.approvalKey.publicKeyHex);
  if (expected === null || "0x" + Buffer.from(recovered).toString("hex") !== expected) return null;
  return a.decision;
}
