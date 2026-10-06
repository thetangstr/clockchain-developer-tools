/**
 * Mandates without a restart (mcp-coordination-design.md, "Mandates without
 * a restart"): `contract_register_policy` adds a buyer policy digest to the
 * allowed set at runtime.
 *
 * - The registration is signed by the family principal pinned for the
 *   caller's keyId in CONTRACT_PRINCIPALS: EIP-191 over
 *   canonicalDigest({domain:"agent-contract.policy/v2", audience, chainId,
 *   tokenKeyId, digest, expiresAt}) — the same encoding verifyMandate uses
 *   (business.ts). CDT-SEC L1: `audience` is this server's contract signer
 *   keyId (published on the server card) and `chainId` its ERC-8004 chain
 *   pin (null when none), so a registration signed for another deployment
 *   never verifies here.
 * - expiresAt must lie in (now, now + 24 h].
 * - CDT-SEC M1: a registration allows ONLY the keyId it was signed for. The
 *   allowed set for a buyer keyId is the env set (CONTRACT_POLICY_DIGESTS)
 *   plus that keyId's unexpired registrations whose signer is still the
 *   keyId's CONTRACT_PRINCIPALS pin (a removed or changed pin revokes them,
 *   on load and on every read). Caps: MAX_REGISTRATIONS_PER_KEY distinct
 *   digests per keyId, env ∪ own ≤ MAX_POLICY_DIGESTS_PER_ROLE, and a global
 *   memory bound of MAX_REGISTRATIONS_TOTAL entries.
 * - CDT-SEC M2: secp256k1 recovery is pure JS (~150 ms); the transport rate
 *   limits this tool per keyId before it gets here, and the outcome of a
 *   recovery is cached by (signed digest, signature bytes) so the same bytes
 *   sent again cost no second recovery.
 * - A signed registration is single-use (replay refused) until it expires.
 * - Registrations persist durably in `stateDir/registered-policies.json`
 *   (tmp at 0600 → fsync → rename → fsync dir); a corrupt file is a startup
 *   error.
 *
 * Provider digests stay env-pinned: there is no provider principal pin.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

import { canonicalDigest } from "./canonical.js";
import { eip191RecoverPublicKey, isCanonicalEip191Signature, publicKeyToAddress } from "./eip191.js";
import type { ContractRefusalCode } from "./refusals.js";

export const POLICY_REGISTRATION_DOMAIN = "agent-contract.policy/v2";
export const REGISTERED_POLICIES_FILE = "registered-policies.json";
export const REGISTERED_POLICIES_SCHEMA = "ac-registered-policies/v1";
/** A registration may live at most 24 h (the buyer batch TTL). */
export const MAX_POLICY_REGISTRATION_TTL_MS = 24 * 3600_000;
/** M1: distinct live registered digests per buyer keyId. */
export const MAX_REGISTRATIONS_PER_KEY = 8;
/** M1: live registrations across every keyId (a memory bound only — approval is per keyId). */
export const MAX_REGISTRATIONS_TOTAL = 1024;
/** M2: remembered recovery outcomes (signed digest + signature → recovered address). */
const RECOVERY_CACHE_MAX = 256;

interface Registration {
  keyId: string;
  role: "buyer";
  digest: string;
  expiresAtMs: number;
  /** canonicalDigest of the signed payload — the replay key and registrationId. */
  sigDigest: string;
  registeredAtMs: number;
  /** M1: the lowercase principal address that signed — re-checked against the current pin. */
  signer: string;
}

/**
 * The digest a principal signs (EIP-191) to register `digest` for
 * `tokenKeyId` on the server identified by `audience` (its contract signer
 * keyId) and `chainId` (its ERC-8004 chain pin, null when none).
 */
export function policyRegistrationDigest(fields: {
  audience: string; chainId: string | null; tokenKeyId: string; digest: string; expiresAt: string;
}): string {
  return canonicalDigest({
    domain: POLICY_REGISTRATION_DOMAIN,
    audience: fields.audience,
    chainId: fields.chainId,
    tokenKeyId: fields.tokenKeyId,
    digest: fields.digest,
    expiresAt: fields.expiresAt,
  });
}

/**
 * M1: one buyer keyId's live allowed set, handed to approval.ts (which only
 * calls `has`): the env pins plus that keyId's unexpired, pin-current
 * registrations, evaluated at the moment of the check.
 */
class KeyedDigestView extends Set<string> {
  constructor(private readonly allowed: (digest: string) => boolean) {
    super();
  }
  override has(value: string): boolean {
    return this.allowed(value);
  }
}

export interface PolicyRegistry {
  /** M1: the allowed buyer set for ONE keyId (env ∪ its own live registrations). */
  buyerFor(keyId: string): ReadonlySet<string>;
  register(
    principal: { keyId: string },
    input: { role: "buyer"; digest: string; expiresAt: string; principalSig: string },
  ):
    | { ok: true; result: { registered: true; role: "buyer"; digest: string; expiresAt: string; registrationId: string } }
    | { ok: false; code: ContractRefusalCode };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function loadRegistrations(stateDir: string): Registration[] {
  const file = path.join(stateDir, REGISTERED_POLICIES_FILE);
  if (!existsSync(file)) return [];
  const raw: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (!isRecord(raw) || raw.schema !== REGISTERED_POLICIES_SCHEMA || !Array.isArray(raw.entries)) {
    throw new Error(`corrupt ${REGISTERED_POLICIES_FILE}`);
  }
  return raw.entries.map((e) => {
    if (
      !isRecord(e) || typeof e.keyId !== "string" || e.role !== "buyer" ||
      typeof e.digest !== "string" || !/^0x[0-9a-f]{64}$/.test(e.digest) ||
      typeof e.expiresAtMs !== "number" || typeof e.sigDigest !== "string" ||
      typeof e.registeredAtMs !== "number" ||
      (e.signer !== undefined && (typeof e.signer !== "string" || !/^0x[0-9a-f]{40}$/.test(e.signer)))
    ) {
      throw new Error(`corrupt ${REGISTERED_POLICIES_FILE}`);
    }
    return {
      keyId: e.keyId, role: "buyer" as const, digest: e.digest, expiresAtMs: e.expiresAtMs,
      sigDigest: e.sigDigest, registeredAtMs: e.registeredAtMs,
      // An entry written before M1 names no signer: it can never be re-checked
      // against the current pin, so it is treated as revoked (dropped below).
      signer: typeof e.signer === "string" ? e.signer : "",
    };
  });
}

function persistRegistrations(stateDir: string, entries: readonly Registration[]): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, REGISTERED_POLICIES_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ schema: REGISTERED_POLICIES_SCHEMA, entries }));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dirFd = openSync(stateDir, "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

export function createPolicyRegistry(options: {
  stateDir?: string;
  /** The env-pinned buyer set (already validated, 1..cap). */
  envBuyer: ReadonlySet<string>;
  /** CONTRACT_PRINCIPALS: buyer keyId → pinned family-principal address. */
  principals?: ReadonlyMap<string, string>;
  maxPerRole: number;
  now: () => number;
  /** L1: this server's contract signer keyId — the signed `audience`. */
  audience: string;
  /** L1: this server's ERC-8004 chain pin (`eip155:<n>`), null when none. */
  chainId: string | null;
  /** Test seam: the secp256k1 recovery (default eip191RecoverPublicKey). */
  recoverPublicKey?: (digest32: Buffer, signature: string) => Uint8Array | null;
}): PolicyRegistry {
  const { now } = options;
  const recover = options.recoverPublicKey ?? eip191RecoverPublicKey;
  /** M1: a registration counts only while its signer is still its keyId's pin. */
  const pinCurrent = (e: Registration): boolean => {
    const pin = options.principals?.get(e.keyId);
    return pin !== undefined && e.signer !== "" && pin.toLowerCase() === e.signer;
  };
  const live = (list: readonly Registration[], t: number): Registration[] =>
    list.filter((e) => e.expiresAtMs > t && pinCurrent(e));
  // M1: entries reloaded from disk are re-checked against the CURRENT pins —
  // a removed or changed pin revokes that principal's registrations.
  let entries: Registration[] = live(
    options.stateDir === undefined ? [] : loadRegistrations(options.stateDir), now(),
  );
  /** M2: (signed digest, signature) → recovered lowercase address, or null. */
  const recoveries = new Map<string, string | null>();
  const recoverAddress = (sigDigest: string, signature: string): string | null => {
    const key = `${sigDigest}|${signature.toLowerCase()}`;
    if (recoveries.has(key)) return recoveries.get(key)!;
    const pub = recover(Buffer.from(sigDigest.slice(2), "hex"), signature);
    const address = pub === null ? null : publicKeyToAddress(pub).toLowerCase();
    if (recoveries.size >= RECOVERY_CACHE_MAX) recoveries.delete(recoveries.keys().next().value!);
    recoveries.set(key, address);
    return address;
  };

  return {
    buyerFor(keyId) {
      return new KeyedDigestView((digest) => {
        if (options.envBuyer.has(digest)) return true;
        entries = live(entries, now());
        return entries.some((e) => e.keyId === keyId && e.digest === digest);
      });
    },
    register(principal, input) {
      const t = now();
      const expiresAtMs = Date.parse(input.expiresAt);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= t || expiresAtMs > t + MAX_POLICY_REGISTRATION_TTL_MS) {
        return { ok: false, code: "PAYLOAD_INVALID" };
      }
      if (/^0x0{64}$/.test(input.digest)) return { ok: false, code: "PAYLOAD_INVALID" };
      const pinned = options.principals?.get(principal.keyId);
      if (pinned === undefined || !isCanonicalEip191Signature(input.principalSig)) {
        return { ok: false, code: "SIGNATURE_INVALID" };
      }
      const sigDigest = policyRegistrationDigest({
        audience: options.audience, chainId: options.chainId,
        tokenKeyId: principal.keyId, digest: input.digest, expiresAt: input.expiresAt,
      });
      const signer = recoverAddress(sigDigest, input.principalSig);
      if (signer === null || signer !== pinned.toLowerCase()) {
        return { ok: false, code: "SIGNATURE_INVALID" };
      }
      const current = live(entries, t);
      // Replay: a signed registration is single-use until it expires.
      if (current.some((e) => e.sigDigest === sigDigest)) return { ok: false, code: "NONCE_REUSED" };
      // M1 caps — per keyId first: this key's distinct registered digests,
      // and env pins ∪ this key's digests within the per-role cap; then the
      // global memory bound. An already-allowed digest is never "new".
      const own = new Set(current.filter((e) => e.keyId === principal.keyId).map((e) => e.digest));
      const allowed = new Set<string>([...options.envBuyer, ...own]);
      if (!allowed.has(input.digest)) {
        if (own.size >= MAX_REGISTRATIONS_PER_KEY || allowed.size >= options.maxPerRole) {
          return { ok: false, code: "RATE_LIMITED" };
        }
      }
      if (current.length >= MAX_REGISTRATIONS_TOTAL) return { ok: false, code: "RATE_LIMITED" };
      const next = [...current, {
        keyId: principal.keyId, role: "buyer" as const, digest: input.digest, expiresAtMs,
        sigDigest, registeredAtMs: t, signer,
      }];
      if (options.stateDir !== undefined) {
        try {
          persistRegistrations(options.stateDir, next);
        } catch {
          return { ok: false, code: "CONTRACT_UNAVAILABLE" };
        }
      }
      entries = next;
      return {
        ok: true,
        result: {
          registered: true, role: "buyer", digest: input.digest,
          expiresAt: input.expiresAt, registrationId: sigDigest,
        },
      };
    },
  };
}
