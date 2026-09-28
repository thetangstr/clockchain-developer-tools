import { createHash, createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";

import { canonicalDigest, canonicalJson } from "./canonical.js";
import { normalizeV2Result } from "../agent-handshake/v2/protocol.js";

/**
 * Server-side verification of the handshake closing certificate that
 * `contract_bind` accepts (LLD §3: "Bind this contract session to a verified
 * handshake certificate — certificate verifies via the handshake host").
 *
 * The envelope is what `agent_handshake_get_certificate` returns:
 *
 *   {hostSessionKeyCertificate: {certificate, rootSignature}, result, signer}
 *
 *   certificate   = clockchain.host-session-key/v1 — the host ROOT certifying
 *                   the session ed25519 key for one handshake sessionId.
 *   rootSignature = ed25519 over canonicalJson(certificate), under a PINNED
 *                   host root identified by kid + sha256(publicKey).
 *   result        = clockchain.agent-handshake-result/v2 — the outcome record.
 *   signer        = ed25519 over canonicalJson(result), under the session key
 *                   that certificate.sessionPublicKey certifies.
 *
 * Wire semantics are proven byte-for-byte against
 * `test/fixtures/agent-handshake-v2-canonical.json` (certificateEnvelope):
 * the root signature verifies over canonicalJson(certificate), the session
 * signature over canonicalJson(result), and
 * result.hostSessionKeyCertificateDigest equals canonicalDigest of the
 * hostSessionKeyCertificate object (bare hex). Verified empirically
 * 2026-09-28 — keep the fixture test green if this ever changes.
 *
 * All failures collapse to one generic code — a refusal must not reveal which
 * check tripped (same discipline as contractRefusalSchema).
 */

export interface HostRootPin {
  readonly kid: string;
  /** sha256 hex of the raw 32-byte ed25519 root public key. */
  readonly fingerprint: string;
}

/** The host roots the public server publishes in its handshake instructions. */
export const PUBLISHED_HOST_ROOTS: readonly HostRootPin[] = Object.freeze([
  {
    kid: "root-2026-08",
    fingerprint: "da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8",
  },
]);

export type CertificateVerdict =
  | {
      ok: true;
      sessionId: string;
      /** canonicalDigest of the signed result — the run identity's digest half. */
      resultDigest: string;
      /** The verified session key this envelope was signed under (bytes, not label). */
      sessionKeyId: string;
      sessionPublicKey: string;
      result: Readonly<Record<string, unknown>>;
    }
  | { ok: false; code: "CERTIFICATE_INVALID" };

const INVALID: CertificateVerdict = { ok: false, code: "CERTIFICATE_INVALID" };

const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const B64_32 = /^(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{44})$/;
const B64_64 = /^[A-Za-z0-9+/]{86}==$/;
/** Canonical key labels: base64/base64url/hex token — no whitespace, padding games or unicode. */
const KEY_LABEL = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$/;
const MAX_CERT_GRACE_MS = 600_000; // ≤ 10 min, per spec

/**
 * Canonical base64: reject malleated encodings that decode to the same bytes
 * (a flipped last-char nibble under `==` padding changes the string but not
 * the decoded signature — encode-canonicalize-compare kills the mutation).
 */
function isCanonicalBase64(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    /^[A-Za-z0-9+/]*={0,2}$/.test(value) &&
    Buffer.from(value, "base64").toString("base64") === value
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function exactKeys(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((k) => typeof k !== "string" || !keys.includes(k))) return null;
  return value;
}

function ed25519Key(rawBase64: unknown): KeyObject | null {
  if (!isCanonicalBase64(rawBase64) || !B64_32.test(rawBase64)) return null;
  const raw = Buffer.from(rawBase64, "base64");
  if (raw.length !== 32) return null;
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
    format: "der",
    type: "spki",
  });
}

function edVerifyB64(publicKey: KeyObject, message: string, signature: unknown): boolean {
  if (!isCanonicalBase64(signature) || !B64_64.test(signature)) return false;
  const sig = Buffer.from(signature, "base64");
  if (sig.length !== 64) return false;
  return edVerify(null, Buffer.from(message, "utf8"), publicKey, sig);
}

/**
 * Verify a certificate envelope end to end. `hostRoots` pins the trust roots:
 * the rootSignature's public key must hash (sha256 of raw bytes) to the pinned
 * fingerprint for its `kid` — the certificate carries the key, the pin proves
 * it is the real host root.
 */
export function verifyCertificateEnvelope(
  candidate: unknown,
  options: { hostRoots: readonly HostRootPin[]; now?: () => number; graceMs?: number },
): CertificateVerdict {
  try {
    const envelope = exactKeys(candidate, ["hostSessionKeyCertificate", "result", "signer"]);
    if (envelope === null) return INVALID;

    // --- host session-key certificate + root signature ---------------------
    const hskc = exactKeys(envelope.hostSessionKeyCertificate, ["certificate", "rootSignature"]);
    if (hskc === null) return INVALID;
    const certificate = exactKeys(hskc.certificate, [
      "schema", "rootKid", "sessionId", "repositorySha", "sessionPublicKey", "validFromMs", "validUntilMs",
    ]);
    if (certificate === null) return INVALID;
    if (
      certificate.schema !== "clockchain.host-session-key/v1" ||
      typeof certificate.rootKid !== "string" ||
      typeof certificate.sessionId !== "string" || !UUID.test(certificate.sessionId) ||
      typeof certificate.repositorySha !== "string" || !GIT_SHA.test(certificate.repositorySha) ||
      typeof certificate.validFromMs !== "string" || !DECIMAL.test(certificate.validFromMs) ||
      typeof certificate.validUntilMs !== "string" || !DECIMAL.test(certificate.validUntilMs) ||
      BigInt(certificate.validFromMs) >= BigInt(certificate.validUntilMs)
    ) return INVALID;
    const sessionKey = ed25519Key(certificate.sessionPublicKey);
    if (sessionKey === null) return INVALID;

    // Freshness: the certified session key is only useful near its window —
    // validFromMs ≤ now ≤ validUntil + grace (grace configurable, capped at
    // 10 min) — a not-yet-valid certificate is refused too (H1).
    const now = options.now ?? Date.now;
    const graceMs = Math.min(Math.max(options.graceMs ?? MAX_CERT_GRACE_MS, 0), MAX_CERT_GRACE_MS);
    if (now() < Number(BigInt(certificate.validFromMs as string))) return INVALID;
    if (now() > Number(BigInt(certificate.validUntilMs as string)) + graceMs) return INVALID;

    const rootSignature = exactKeys(hskc.rootSignature, ["algorithm", "keyId", "publicKey", "signature"]);
    if (
      rootSignature === null ||
      rootSignature.algorithm !== "ed25519" ||
      rootSignature.keyId !== certificate.rootKid
    ) return INVALID;
    const pin = options.hostRoots.find((root) => root.kid === rootSignature.keyId);
    if (pin === undefined || !isCanonicalBase64(rootSignature.publicKey)) return INVALID;
    const presentedFingerprint = createHash("sha256").update(Buffer.from(rootSignature.publicKey, "base64")).digest("hex");
    if (presentedFingerprint !== pin.fingerprint) return INVALID;
    const rootKey = ed25519Key(rootSignature.publicKey);
    if (rootKey === null || !edVerifyB64(rootKey, canonicalJson(certificate), rootSignature.signature)) return INVALID;

    // --- result (schema, parties, anchors) ----------------------------------
    const result = normalizeV2Result(envelope.result);
    if (
      result.outcome !== "VERIFIED" ||
      result.externalBusinessActionPerformed !== false ||
      result.sessionId !== certificate.sessionId ||
      result.hostSessionKeyCertificateDigest !== canonicalDigest(hskc).slice(2) ||
      BigInt(result.issuedAtMs as string) < BigInt(certificate.validFromMs) ||
      BigInt(result.issuedAtMs as string) > BigInt(certificate.validUntilMs)
    ) return INVALID;

    // --- session-key signature over the result ------------------------------
    // The identity of the signer is the VERIFIED key bytes (publicKey must be
    // the certified sessionPublicKey); keyId is a canonical label pinned to
    // that key — never a substitute for it.
    const signer = exactKeys(envelope.signer, ["algorithm", "keyId", "publicKey", "signature"]);
    if (
      signer === null ||
      signer.algorithm !== "ed25519" ||
      typeof signer.keyId !== "string" ||
      !KEY_LABEL.test(signer.keyId) ||
      !isCanonicalBase64(signer.publicKey) ||
      signer.publicKey !== certificate.sessionPublicKey ||
      !edVerifyB64(sessionKey, canonicalJson(result), signer.signature)
    ) return INVALID;

    return {
      ok: true,
      sessionId: result.sessionId as string,
      // Run identity = sessionId + canonicalDigest(result): signed content
      // only, so unsigned envelope decoration can't mint a second identity.
      resultDigest: canonicalDigest(result),
      sessionKeyId: signer.keyId,
      sessionPublicKey: signer.publicKey,
      result,
    };
  } catch {
    return INVALID;
  }
}
