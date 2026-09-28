import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import path from "node:path";

import { PUBLISHED_HOST_ROOTS, type HostRootPin } from "./certificate.js";
import { parseContractTokens, tokenAuthenticator } from "./http-handler.js";
import { createContractService, type ContractService } from "./service.js";
import type { ContractSigner } from "./envelope.js";
import type { IncomingHttpHeaders } from "node:http";
import type { ContractPrincipal } from "./service.js";
import type { PublishedServerKey } from "./server-card.js";

/**
 * Eager, fail-closed configuration for the `/contract/mcp` route (H3).
 *
 * `loadContractConfig` is called ONCE at startup and never throws — a bad
 * environment is a deterministic verdict the router turns into a closed
 * endpoint, not a mid-request exception:
 *
 *   disabled        CONTRACT_MCP_ENABLED != "1" → the route answers 404.
 *   misconfigured   enabled, but tokens/roots/seed are bad or the seed is
 *                   missing without CONTRACT_ALLOW_EPHEMERAL_KEY=1 → 503.
 *   ready           route serves; `service` is the shared run-state owner.
 *
 * The ephemeral dev signer is opt-in only and its keyId is FORCED to
 * `ephemeral-dev-*` — CONTRACT_SERVER_KEY_ID cannot disguise it.
 */

export type ContractRouteConfig =
  | { readonly kind: "disabled" }
  | { readonly kind: "misconfigured"; readonly reason: string }
  | {
      readonly kind: "ready";
      readonly authenticate: (headers: IncomingHttpHeaders) => ContractPrincipal | null;
      readonly hostRoots: readonly HostRootPin[];
      readonly signer: ContractSigner;
      readonly signerEphemeral: boolean;
      readonly callsPerMinute: number;
      readonly trustProxy: boolean;
      readonly stateDir: string;
      readonly maxRuns: number;
      readonly maxReceiptsPerRun: number;
      readonly maxReceiptsPerPrincipal: number;
      readonly runTtlMs: number;
      readonly certGraceMs: number;
      /** Idle MCP-session TTL for the stateful transport (M2). */
      readonly sessionTtlMs: number;
      /** Bearer token for the read-only observer receipt feed, if configured. */
      readonly observerToken?: string;
      /** §13 pins: the exact policy digest each role's approvals must carry. */
      readonly policyDigests: Readonly<{ buyer: string; provider: string }>;
      /** Family-principal pin per buyer keyId (`CONTRACT_PRINCIPALS`). */
      readonly principals: ReadonlyMap<string, string>;
      /** M3: the published receipt/envelope signing keys (card + /contract/keys). */
      readonly serverKeys: readonly PublishedServerKey[];
      readonly service: ContractService;
    };

const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";

function misconfigured(reason: string): ContractRouteConfig {
  return { kind: "misconfigured", reason };
}

export function loadContractConfig(env: NodeJS.ProcessEnv): ContractRouteConfig {
  if (env.CONTRACT_MCP_ENABLED !== "1") return { kind: "disabled" };

  let tokens: ReturnType<typeof parseContractTokens>;
  try {
    tokens = parseContractTokens(env.CONTRACT_AUTH_TOKENS);
  } catch (err) {
    return misconfigured(`CONTRACT_AUTH_TOKENS: ${(err as Error).message}`);
  }

  let hostRoots: readonly HostRootPin[] = PUBLISHED_HOST_ROOTS;
  const rootsRaw = (env.CONTRACT_HOST_ROOTS ?? "").trim();
  if (rootsRaw.length > 0) {
    const roots: HostRootPin[] = [];
    try {
      for (const entry of rootsRaw.split(",").map((s) => s.trim()).filter(Boolean)) {
        const [kid, fingerprint] = entry.split(":", 2);
        if (!kid || !/^[0-9a-f]{64}$/.test(fingerprint ?? "")) {
          throw new Error("malformed CONTRACT_HOST_ROOTS entry (want kid:sha256fingerprint)");
        }
        roots.push(Object.freeze({ kid, fingerprint }));
      }
    } catch (err) {
      return misconfigured((err as Error).message);
    }
    hostRoots = roots;
  }

  const seedB64 = (env.CONTRACT_SERVER_ED25519_SEED ?? "").trim();
  let signer: ContractSigner;
  let signerEphemeral = false;
  if (seedB64) {
    const seed = Buffer.from(seedB64, "base64");
    if (seed.length !== 32 || seed.toString("base64") !== seedB64) {
      return misconfigured("CONTRACT_SERVER_ED25519_SEED must be a canonical base64 32-byte seed");
    }
    signer = {
      keyId: env.CONTRACT_SERVER_KEY_ID ?? "contract-server",
      privateKey: createPrivateKey({
        key: Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX, "hex"), seed]),
        format: "der",
        type: "pkcs8",
      }),
    };
  } else if (env.CONTRACT_ALLOW_EPHEMERAL_KEY === "1") {
    const keys = generateKeyPairSync("ed25519");
    signerEphemeral = true;
    // Forced ephemeral-dev-* keyId: CONTRACT_SERVER_KEY_ID must not be able
    // to make a throwaway key look durable.
    const pubHex = Buffer.from(
      keys.publicKey.export({ format: "der", type: "spki" }).subarray(12),
    ).toString("hex");
    signer = { keyId: `ephemeral-dev-${pubHex.slice(0, 16)}`, privateKey: keys.privateKey };
  } else {
    return misconfigured(
      "CONTRACT_SERVER_ED25519_SEED is required when the contract surface is enabled " +
        "(or set CONTRACT_ALLOW_EPHEMERAL_KEY=1 for a disposable dev signer)",
    );
  }

  // M3: the signing key is published with rotation metadata — agents pin it
  // before any run so receipt chains verify offline. The validity window is
  // env-pinned (`CONTRACT_SERVER_KEY_VALID_*`, ISO-8601); an ephemeral dev
  // signer is always flagged `ephemeral: true` so it can never pass as a
  // durable production key.
  const keyValidFromRaw = (env.CONTRACT_SERVER_KEY_VALID_FROM ?? "").trim();
  const keyValidUntilRaw = (env.CONTRACT_SERVER_KEY_VALID_UNTIL ?? "").trim();
  const keyValidFrom = keyValidFromRaw === "" ? new Date().toISOString() : keyValidFromRaw;
  if (Number.isNaN(Date.parse(keyValidFrom))) {
    return misconfigured("CONTRACT_SERVER_KEY_VALID_FROM is not an ISO-8601 timestamp");
  }
  if (keyValidUntilRaw !== "" && Number.isNaN(Date.parse(keyValidUntilRaw))) {
    return misconfigured("CONTRACT_SERVER_KEY_VALID_UNTIL is not an ISO-8601 timestamp");
  }
  const publicKeyHex = `0x${Buffer.from(
    createPublicKey(signer.privateKey as Parameters<typeof createPublicKey>[0])
      .export({ format: "der", type: "spki" })
      .subarray(-32),
  ).toString("hex")}`;
  const serverKeys: readonly PublishedServerKey[] = [{
    keyId: signer.keyId,
    alg: "Ed25519",
    publicKeyHex,
    validFrom: keyValidFrom,
    validUntil: keyValidUntilRaw === "" ? null : keyValidUntilRaw,
    ...(signerEphemeral ? { ephemeral: true as const } : {}),
  }];

  // §13 approval policy pins are REQUIRED (N4b-2b): `buyer:0x…,provider:0x…`.
  // A missing pin is a startup error — the route refuses, never half-serves.
  const DIGEST = /^0x[0-9a-f]{64}$/;
  const policyDigests: { buyer?: string; provider?: string } = {};
  const policyRaw = (env.CONTRACT_POLICY_DIGESTS ?? "").trim();
  try {
    for (const entry of policyRaw.split(",").map((s) => s.trim()).filter(Boolean)) {
      const [role, digest] = entry.split(":", 2);
      if (
        (role !== "buyer" && role !== "provider") ||
        !DIGEST.test(digest ?? "") ||
        /^0x0{64}$/.test(digest ?? "") // the zero digest is not a pin
      ) {
        throw new Error("malformed CONTRACT_POLICY_DIGESTS entry (want buyer:0x…,provider:0x…)");
      }
      policyDigests[role] = digest;
    }
  } catch (err) {
    return misconfigured((err as Error).message);
  }
  if (policyDigests.buyer === undefined || policyDigests.provider === undefined) {
    return misconfigured("CONTRACT_POLICY_DIGESTS must pin both buyer: and provider: digests");
  }

  // Family-principal pins (`buyerKeyId:0xaddress`) — the mandate's EIP-191
  // signature must recover to the buyer's pinned principal (rev 6.5).
  const principals = new Map<string, string>();
  const principalsRaw = (env.CONTRACT_PRINCIPALS ?? "").trim();
  try {
    for (const entry of principalsRaw.split(",").map((s) => s.trim()).filter(Boolean)) {
      const [keyId, address] = entry.split(":");
      if (!keyId || !/^0x[0-9a-fA-F]{40}$/.test(address ?? "")) {
        throw new Error("malformed CONTRACT_PRINCIPALS entry (want keyId:0xaddress)");
      }
      principals.set(keyId, address.toLowerCase());
    }
  } catch (err) {
    return misconfigured((err as Error).message);
  }

  const callsPerMinute = Number(env.CONTRACT_CALLS_PER_MINUTE ?? "120");
  const maxRuns = Number(env.CONTRACT_MAX_RUNS ?? "1024");
  const maxReceiptsPerRun = Number(env.CONTRACT_MAX_RECEIPTS_PER_RUN ?? "4096");
  const maxReceiptsPerPrincipal = Number(env.CONTRACT_MAX_RECEIPTS_PER_PRINCIPAL ?? "512");
  const runTtlMs = Number(env.CONTRACT_RUN_TTL_MS ?? String(24 * 3600_000));
  const certGraceMs = Number(env.CONTRACT_CERT_GRACE_MS ?? "600000");
  const sessionTtlMs = Number(env.CONTRACT_SESSION_TTL_MS ?? String(30 * 60_000));
  const stateDir = env.CONTRACT_STATE_DIR ?? path.join(process.cwd(), "state", "contract");

  // Optional ERC-8004 chain/registry pins (LOW): when set, certificates must
  // attest exactly this deployment, not just the agent id.
  const expectedErc8004 =
    env.CONTRACT_ERC8004_CHAIN_ID !== undefined || env.CONTRACT_ERC8004_REGISTRY_ADDRESS !== undefined
      ? { chainId: env.CONTRACT_ERC8004_CHAIN_ID ?? "", registryAddress: env.CONTRACT_ERC8004_REGISTRY_ADDRESS ?? "" }
      : undefined;

  // N1/N2: construction can fail closed — corrupt/unreadable used-sessions or
  // a state dir already locked by a live process are misconfiguration, not a
  // mid-request exception.
  let service: ContractService;
  try {
    service = createContractService({
      hostRoots,
      signer,
      stateDir,
      maxRuns: Number.isFinite(maxRuns) ? maxRuns : 1024,
      maxReceiptsPerRun: Number.isFinite(maxReceiptsPerRun) ? maxReceiptsPerRun : 4096,
      maxReceiptsPerPrincipal: Number.isFinite(maxReceiptsPerPrincipal) ? maxReceiptsPerPrincipal : 512,
      runTtlMs: Number.isFinite(runTtlMs) ? runTtlMs : 24 * 3600_000,
      graceMs: Number.isFinite(certGraceMs) ? certGraceMs : 600_000,
      expectedErc8004,
      policyDigests: policyDigests as { buyer: string; provider: string },
      principals,
    });
  } catch (err) {
    return misconfigured(`contract state: ${(err as Error).message}`);
  }

  return {
    kind: "ready",
    authenticate: tokenAuthenticator(tokens),
    hostRoots,
    signer,
    signerEphemeral,
    callsPerMinute: Number.isFinite(callsPerMinute) ? callsPerMinute : 120,
    trustProxy: env.CONTRACT_TRUST_PROXY === "1",
    stateDir,
    maxRuns: Number.isFinite(maxRuns) ? maxRuns : 1024,
    maxReceiptsPerRun: Number.isFinite(maxReceiptsPerRun) ? maxReceiptsPerRun : 4096,
    maxReceiptsPerPrincipal: Number.isFinite(maxReceiptsPerPrincipal) ? maxReceiptsPerPrincipal : 512,
    runTtlMs: Number.isFinite(runTtlMs) ? runTtlMs : 24 * 3600_000,
    certGraceMs: Number.isFinite(certGraceMs) ? certGraceMs : 600_000,
    sessionTtlMs: Number.isFinite(sessionTtlMs) ? sessionTtlMs : 30 * 60_000,
    ...(env.CONTRACT_OBSERVER_TOKEN !== undefined && env.CONTRACT_OBSERVER_TOKEN !== ""
      ? { observerToken: env.CONTRACT_OBSERVER_TOKEN }
      : {}),
    policyDigests: policyDigests as { buyer: string; provider: string },
    principals,
    serverKeys,
    service,
  };
}
