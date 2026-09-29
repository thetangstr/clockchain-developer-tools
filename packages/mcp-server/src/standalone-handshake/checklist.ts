import { canonicalBytes } from "../handshake/protocol.js";

import { standaloneAuthorityRecord, standaloneCanonicalRecord } from "./protocol.js";

export type StandaloneCheckName = "identity" | "authority" | "data_class" | "purpose";
export type StandaloneFailureCode = "IDENTITY_UNVERIFIED" | "AUTHORITY_INVALID" | "DATA_CLASS_MISMATCH" | "PURPOSE_MISMATCH";
type Party = "initiator" | "responder";

export interface StandaloneCheck {
  check: StandaloneCheckName;
  passed: boolean;
  reason?: StandaloneFailureCode;
}

/**
 * One failed check, attributed to the party whose readiness caused it. `required` is a
 * machine-readable statement of what that party's readiness must contain to pass,
 * keyed by readiness field path.
 */
export interface StandaloneFailure {
  code: StandaloneFailureCode;
  party: Party;
  required: Readonly<Record<string, string>>;
}

export interface StandaloneChecklistResult {
  passed: boolean;
  checks: readonly StandaloneCheck[];
  /** Not part of the digest: which party failed which check, and what would pass. */
  failures: readonly StandaloneFailure[];
  checklistDigest: string;
}

const IDENTITY_REQUIRED = "an ERC-8004 registration on eip155:11155111 owned by sessionKeyAddress";
const AUTHORITY_REQUIRED = "an EIP-191 personal_sign by sessionKeyAddress over the bytes readiness_prepare returns for this address and authorityStatement";

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
  const parties: readonly [Party, Readonly<Record<string, any>>][] = [["initiator", initiator], ["responder", responder]];
  const failures: StandaloneFailure[] = [];

  if (terms.identityPolicy.erc8004 !== "not_required") {
    for (const [party, readiness] of parties) {
      if (!(await resolveIdentity(readiness.identity, readiness.sessionKeyAddress))) {
        failures.push({ code: "IDENTITY_UNVERIFIED", party, required: { identity: IDENTITY_REQUIRED } });
      }
    }
  }

  for (const [party, readiness] of parties) {
    const bytes = canonicalBytes(standaloneAuthorityRecord(readiness));
    let recovered = "";
    try {
      recovered = (await recoverAddress({ bytes, signatureHex: readiness.authoritySignatureHex })).toLowerCase();
    } catch {
      recovered = "";
    }
    if (recovered !== String(readiness.sessionKeyAddress).toLowerCase()) {
      failures.push({ code: "AUTHORITY_INVALID", party, required: { authoritySignatureHex: AUTHORITY_REQUIRED } });
    }
  }

  // The Initiator's class is the session's class: a Responder must match it.
  if (initiator.capabilityManifest.dataHandlingClass !== responder.capabilityManifest.dataHandlingClass) {
    failures.push({ code: "DATA_CLASS_MISMATCH", party: "responder", required: { "capabilityManifest.dataHandlingClass": initiator.capabilityManifest.dataHandlingClass } });
  }

  for (const [party, readiness] of parties) {
    if (readiness.capabilityManifest.purpose !== terms.purpose) {
      failures.push({ code: "PURPOSE_MISMATCH", party, required: { "capabilityManifest.purpose": terms.purpose } });
    }
  }

  const failed = (code: StandaloneFailureCode) => failures.some((failure) => failure.code === code);
  const identityRequired = terms.identityPolicy.erc8004 !== "not_required";
  const checks: StandaloneCheck[] = [
    check("identity", identityRequired ? !failed("IDENTITY_UNVERIFIED") : true, "IDENTITY_UNVERIFIED"),
    check("authority", !failed("AUTHORITY_INVALID"), "AUTHORITY_INVALID"),
    check("data_class", !failed("DATA_CLASS_MISMATCH"), "DATA_CLASS_MISMATCH"),
    check("purpose", !failed("PURPOSE_MISMATCH"), "PURPOSE_MISMATCH"),
  ];

  const passed = checks.every((item) => item.passed);
  const digestRecord = {
    schema: "clockchain.standalone-handshake-checklist/v1",
    protocol: "clockchain.standalone-handshake/v1",
    sessionId,
    termsDigest,
    checks: checks.map(({ check: name, passed: ok, reason }) => (reason === undefined ? { check: name, passed: ok } : { check: name, passed: ok, reason })),
  };
  return {
    passed,
    checks: Object.freeze(checks),
    failures: Object.freeze(failures.map((failure) => Object.freeze({ ...failure, required: Object.freeze({ ...failure.required }) }))),
    checklistDigest: standaloneCanonicalRecord(digestRecord).digest,
  };
}

function check(name: StandaloneCheckName, passed: boolean, reason: StandaloneFailureCode): StandaloneCheck {
  return passed ? { check: name, passed } : { check: name, passed, reason };
}
