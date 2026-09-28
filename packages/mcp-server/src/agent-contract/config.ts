import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import path from "node:path";

import { PUBLISHED_HOST_ROOTS, type HostRootPin } from "./certificate.js";
import { parseContractTokens, tokenAuthenticator } from "./http-handler.js";
import { createContractService, type ContractService } from "./service.js";
import type { ContractSigner } from "./envelope.js";
import type { IncomingHttpHeaders } from "node:http";
import type { ContractPrincipal } from "./service.js";

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
      readonly runTtlMs: number;
      readonly certGraceMs: number;
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

  const callsPerMinute = Number(env.CONTRACT_CALLS_PER_MINUTE ?? "120");
  const maxRuns = Number(env.CONTRACT_MAX_RUNS ?? "1024");
  const maxReceiptsPerRun = Number(env.CONTRACT_MAX_RECEIPTS_PER_RUN ?? "1024");
  const runTtlMs = Number(env.CONTRACT_RUN_TTL_MS ?? String(24 * 3600_000));
  const certGraceMs = Number(env.CONTRACT_CERT_GRACE_MS ?? "600000");
  const stateDir = env.CONTRACT_STATE_DIR ?? path.join(process.cwd(), "state", "contract");

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
    maxReceiptsPerRun: Number.isFinite(maxReceiptsPerRun) ? maxReceiptsPerRun : 1024,
    runTtlMs: Number.isFinite(runTtlMs) ? runTtlMs : 24 * 3600_000,
    certGraceMs: Number.isFinite(certGraceMs) ? certGraceMs : 600_000,
    service: createContractService({
      hostRoots,
      signer,
      stateDir,
      maxRuns: Number.isFinite(maxRuns) ? maxRuns : 1024,
      maxReceiptsPerRun: Number.isFinite(maxReceiptsPerRun) ? maxReceiptsPerRun : 1024,
      runTtlMs: Number.isFinite(runTtlMs) ? runTtlMs : 24 * 3600_000,
      graceMs: Number.isFinite(certGraceMs) ? certGraceMs : 600_000,
    }),
  };
}
