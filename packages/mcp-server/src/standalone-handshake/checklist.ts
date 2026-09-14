import { canonicalBytes } from "../handshake/protocol.js";

import { standaloneAuthorityRecord, standaloneCanonicalRecord } from "./protocol.js";

export interface StandaloneCheck {
  check: "identity" | "authority" | "manifest";
  passed: boolean;
  reason?: string;
}

export interface StandaloneChecklistResult {
  passed: boolean;
  checks: readonly StandaloneCheck[];
  checklistDigest: string;
}

export async function evaluateStandaloneReadiness(input: {
  sessionId: string;
  terms: Readonly<Record<string, any>>;
  termsDigest: string;
  initiator: Readonly<Record<string, any>>;
  responder: Readonly<Record<string, any>>;
  resolveIdentity: (identity: Readonly<Record<string, any>> | null, sessionKeyAddress: string) => Promise<boolean>;
  recoverAddress: (input: { bytes: Buffer; signatureHex: string }) => Promise<string>;
}): Promise<StandaloneChecklistResult> {
  const { sessionId, terms, termsDigest, initiator, responder, resolveIdentity, recoverAddress } = input;
  const checks: StandaloneCheck[] = [];
  const required = terms.identityPolicy.erc8004 !== "not_required";

  const identityOk = !required
    ? true
    : (await resolveIdentity(initiator.identity, initiator.sessionKeyAddress)) && (await resolveIdentity(responder.identity, responder.sessionKeyAddress));
  checks.push({ check: "identity", passed: identityOk, ...(identityOk ? {} : { reason: "IDENTITY_UNVERIFIED" }) });

  const parties: readonly [string, any][] = [["initiator", initiator], ["responder", responder]];
  let authorityOk = true;
  for (const [role, readiness] of parties) {
    const bytes = canonicalBytes(standaloneAuthorityRecord(readiness));
    let recovered = "";
    try {
      recovered = (await recoverAddress({ bytes, signatureHex: readiness.authoritySignatureHex })).toLowerCase();
    } catch {
      recovered = "";
    }
    if (recovered !== String(readiness.sessionKeyAddress).toLowerCase()) authorityOk = false;
  }
  checks.push({ check: "authority", passed: authorityOk, ...(authorityOk ? {} : { reason: "AUTHORITY_INVALID" }) });

  const sameClass = initiator.capabilityManifest.dataHandlingClass === responder.capabilityManifest.dataHandlingClass;
  const purposesMatch = initiator.capabilityManifest.purpose === terms.purpose && responder.capabilityManifest.purpose === terms.purpose;
  checks.push({
    check: "manifest",
    passed: sameClass && purposesMatch,
    ...(sameClass && purposesMatch ? {} : { reason: sameClass ? "PURPOSE_MISMATCH" : "MANIFEST_MISMATCH" }),
  });

  const passed = checks.every((check) => check.passed);
  const digestRecord = {
    schema: "clockchain.standalone-handshake-checklist/v1",
    protocol: "clockchain.standalone-handshake/v1",
    sessionId,
    termsDigest,
    checks: checks.map(({ check, passed: ok, reason }) => (reason === undefined ? { check, passed: ok } : { check, passed: ok, reason })),
  };
  return { passed, checks: Object.freeze(checks), checklistDigest: standaloneCanonicalRecord(digestRecord).digest };
}
