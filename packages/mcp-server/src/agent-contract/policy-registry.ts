/**
 * Mandates without a restart (mcp-coordination-design.md, "Mandates without
 * a restart"): `contract_register_policy` adds a buyer policy digest to the
 * allowed set at runtime.
 *
 * - The registration is signed by the family principal pinned for the
 *   caller's keyId in CONTRACT_PRINCIPALS: EIP-191 over
 *   canonicalDigest({domain:"agent-contract.policy/v1", tokenKeyId, digest,
 *   expiresAt}) — the same encoding verifyMandate uses (business.ts).
 * - expiresAt must lie in (now, now + 24 h].
 * - The allowed buyer set is the env set (CONTRACT_POLICY_DIGESTS) plus
 *   every unexpired registration, pruned on read; the per-role cap of 64
 *   (MAX_POLICY_DIGESTS_PER_ROLE) still holds for the union.
 * - A signed registration is single-use (replay refused) until it expires.
 * - Registrations persist durably in `stateDir/registered-policies.json`
 *   (tmp → fsync → rename → fsync dir); a corrupt file is a startup error.
 *
 * Provider digests stay env-pinned: there is no provider principal pin.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

import { canonicalDigest } from "./canonical.js";
import { eip191RecoverPublicKey, isCanonicalEip191Signature, publicKeyToAddress } from "./eip191.js";
import type { ContractRefusalCode } from "./refusals.js";

export const POLICY_REGISTRATION_DOMAIN = "agent-contract.policy/v1";
export const REGISTERED_POLICIES_FILE = "registered-policies.json";
export const REGISTERED_POLICIES_SCHEMA = "ac-registered-policies/v1";
/** A registration may live at most 24 h (the buyer batch TTL). */
export const MAX_POLICY_REGISTRATION_TTL_MS = 24 * 3600_000;

interface Registration {
  keyId: string;
  role: "buyer";
  digest: string;
  expiresAtMs: number;
  /** canonicalDigest of the signed payload — the replay key and registrationId. */
  sigDigest: string;
  registeredAtMs: number;
}

/** The digest a principal signs (EIP-191) to register `digest` for `tokenKeyId`. */
export function policyRegistrationDigest(fields: { tokenKeyId: string; digest: string; expiresAt: string }): string {
  return canonicalDigest({
    domain: POLICY_REGISTRATION_DOMAIN,
    tokenKeyId: fields.tokenKeyId,
    digest: fields.digest,
    expiresAt: fields.expiresAt,
  });
}

/**
 * The live allowed set handed to business. A real Set (approval.ts only
 * calls `has`), whose membership is the env pins plus the unexpired
 * registrations; `has` prunes expired registrations before answering.
 */
class LiveDigestSet extends Set<string> {
  constructor(private readonly refresh: () => void) {
    super();
  }
  override has(value: string): boolean {
    this.refresh();
    return super.has(value);
  }
}

export interface PolicyRegistry {
  /** The live buyer set (env ∪ unexpired registrations). */
  readonly buyer: ReadonlySet<string>;
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
      typeof e.registeredAtMs !== "number"
    ) {
      throw new Error(`corrupt ${REGISTERED_POLICIES_FILE}`);
    }
    return {
      keyId: e.keyId, role: "buyer" as const, digest: e.digest, expiresAtMs: e.expiresAtMs,
      sigDigest: e.sigDigest, registeredAtMs: e.registeredAtMs,
    };
  });
}

function persistRegistrations(stateDir: string, entries: readonly Registration[]): void {
  mkdirSync(stateDir, { recursive: true });
  const file = path.join(stateDir, REGISTERED_POLICIES_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w");
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
}): PolicyRegistry {
  const { now } = options;
  let entries: Registration[] = options.stateDir === undefined ? [] : loadRegistrations(options.stateDir);
  const unexpired = (list: readonly Registration[], t: number): Registration[] =>
    list.filter((e) => e.expiresAtMs > t);
  const live = new LiveDigestSet(() => sync(now()));
  function sync(t: number): void {
    entries = unexpired(entries, t);
    const want = new Set<string>([...options.envBuyer, ...entries.map((e) => e.digest)]);
    for (const d of [...Set.prototype.values.call(live)] as string[]) {
      if (!want.has(d)) Set.prototype.delete.call(live, d);
    }
    for (const d of want) Set.prototype.add.call(live, d);
  }
  sync(now());

  return {
    buyer: live,
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
        tokenKeyId: principal.keyId, digest: input.digest, expiresAt: input.expiresAt,
      });
      const recovered = eip191RecoverPublicKey(Buffer.from(sigDigest.slice(2), "hex"), input.principalSig);
      if (recovered === null || publicKeyToAddress(recovered).toLowerCase() !== pinned.toLowerCase()) {
        return { ok: false, code: "SIGNATURE_INVALID" };
      }
      const current = unexpired(entries, t);
      // Replay: a signed registration is single-use until it expires.
      if (current.some((e) => e.sigDigest === sigDigest)) return { ok: false, code: "NONCE_REUSED" };
      // Cap: the env pins plus every distinct live registered digest.
      const union = new Set<string>([...options.envBuyer, ...current.map((e) => e.digest)]);
      if (!union.has(input.digest) && union.size >= options.maxPerRole) {
        return { ok: false, code: "RATE_LIMITED" };
      }
      const next = [...current, {
        keyId: principal.keyId, role: "buyer" as const, digest: input.digest, expiresAtMs,
        sigDigest, registeredAtMs: t,
      }];
      if (options.stateDir !== undefined) {
        try {
          persistRegistrations(options.stateDir, next);
        } catch {
          return { ok: false, code: "CONTRACT_UNAVAILABLE" };
        }
      }
      entries = next;
      sync(t);
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
