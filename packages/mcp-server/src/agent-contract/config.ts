import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import path from "node:path";

import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";

import { createTsaContractAnchor, type ContractAnchor } from "./anchor.js";
import { PUBLISHED_HOST_ROOTS, type HostRootPin } from "./certificate.js";
import { parseContractTokens, tokenAuthenticator } from "./http-handler.js";
import { canonicalDigest } from "./canonical.js";
import { createCloseEmitter } from "./close-emitter.js";
import { createContractService, type ContractRun, type ContractService } from "./service.js";
import type { SimFaults } from "./sim/index.js";
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
      /**
       * Bearer token for the verifier-scoped salt disclosure endpoint
       * (`/contract/run-salt`, M4). Deliberately a SEPARATE credential from
       * `observerToken` — the observer feed never discloses salts.
       */
      readonly verifierToken?: string;
      /** §13 pins: the exact policy digest each role's approvals must carry. */
      readonly policyDigests: Readonly<{ buyer: string; provider: string }>;
      /** Family-principal pin per buyer keyId (`CONTRACT_PRINCIPALS`). */
      readonly principals: ReadonlyMap<string, string>;
      /** M3: the published receipt/envelope signing keys (card + /contract/keys). */
      readonly serverKeys: readonly PublishedServerKey[];
      /** N4b-6: CONTRACT_ALLOW_SIM_FAULTS=1 — the card/keys must say so. */
      readonly simFaultsEnabled: boolean;
      /** N4b-7: CONTRACT_REQUIRE_BIND_STATEMENT=1 (mandatory at level S|P). */
      readonly requireBindStatement: boolean;
      /**
       * N4b-8 (gap 3): the telemetry sink's close-only listener base URL —
       * mandatory at S|P, optional at L (undefined = no close delivery).
       */
      readonly telemetryCloseUrl?: string;
      /** N4b-8 (gap 4): CONTRACT_ANCHOR_ENABLED=1 — tsa_issue-backed run anchoring. */
      readonly anchorEnabled: boolean;
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

  // M3 + LOW (N4b-3): the signing key is published with rotation metadata —
  // agents pin it before any run so receipt chains verify offline. The
  // validity window MUST come from pinned config — never boot time (a
  // boot-derived validFrom would look like a fresh key on every restart):
  // CONTRACT_SERVER_KEY_VALID_FROM is required whenever the surface is on;
  // CONTRACT_SERVER_KEY_VALID_UNTIL stays optional (null = no expiry).
  const keyValidFromRaw = (env.CONTRACT_SERVER_KEY_VALID_FROM ?? "").trim();
  const keyValidUntilRaw = (env.CONTRACT_SERVER_KEY_VALID_UNTIL ?? "").trim();
  if (keyValidFromRaw === "") {
    return misconfigured(
      "CONTRACT_SERVER_KEY_VALID_FROM is required (pinned ISO-8601 — never boot time)",
    );
  }
  const keyValidFrom = keyValidFromRaw;
  if (Number.isNaN(Date.parse(keyValidFrom))) {
    return misconfigured("CONTRACT_SERVER_KEY_VALID_FROM is not an ISO-8601 timestamp");
  }
  if (keyValidUntilRaw !== "" && Number.isNaN(Date.parse(keyValidUntilRaw))) {
    return misconfigured("CONTRACT_SERVER_KEY_VALID_UNTIL is not an ISO-8601 timestamp");
  }
  // N4b-4: an already-expired key can never sign — refuse to start.
  const keyValidUntilMs = keyValidUntilRaw === "" ? null : Date.parse(keyValidUntilRaw);
  if (keyValidUntilMs !== null && keyValidUntilMs <= Date.now()) {
    return misconfigured("CONTRACT_SERVER_KEY_VALID_UNTIL is already in the past — rotate the key before serving");
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

  // LOW (N4b-3): the verifier and observer credentials must differ — the
  // observer feed is salt-free by design, and a shared token would let one
  // credential both read the feed AND disclose the salts that unlock it.
  const observerTokenRaw = (env.CONTRACT_OBSERVER_TOKEN ?? "").trim();
  const verifierTokenRaw = (env.CONTRACT_VERIFIER_TOKEN ?? "").trim();
  if (observerTokenRaw !== "" && verifierTokenRaw !== "" && observerTokenRaw === verifierTokenRaw) {
    return misconfigured("CONTRACT_VERIFIER_TOKEN must differ from CONTRACT_OBSERVER_TOKEN");
  }

  // N4b-5/6: config-only sim fault seeds (A2 adverse cases) — JSON object
  // `{"<runId>": {"issueMismatch": "fare"|"travellers"}}`. This env is the
  // ONLY way a fault can be seeded over the served surface; there is no
  // tool/agent path by design. H1 honesty: seeding faults requires an
  // explicit CONTRACT_ALLOW_SIM_FAULTS=1 — a server that can inject faults
  // must say so (simFaultsEnabled on the card/keys, simFault on receipts).
  const simFaultsAllowed = env.CONTRACT_ALLOW_SIM_FAULTS === "1";
  const simFaultsRaw = (env.CONTRACT_SIM_FAULTS ?? "").trim();
  let simFaults: Record<string, SimFaults> | undefined;
  if (simFaultsRaw !== "" && !simFaultsAllowed) {
    return misconfigured("CONTRACT_SIM_FAULTS requires CONTRACT_ALLOW_SIM_FAULTS=1");
  }
  if (simFaultsRaw !== "") {
    try {
      const parsed: unknown = JSON.parse(simFaultsRaw);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("want an object keyed by runId");
      }
      simFaults = {};
      for (const [runId, fault] of Object.entries(parsed)) {
        if (typeof runId !== "string" || runId.length === 0 || runId.length > 128) {
          throw new Error("runId keys must be 1..128 chars");
        }
        const issueMismatch = (fault as { issueMismatch?: unknown }).issueMismatch;
        if (
          typeof fault !== "object" || fault === null || Array.isArray(fault) ||
          !Object.keys(fault).every((k) => k === "issueMismatch") ||
          (issueMismatch !== undefined && issueMismatch !== "fare" && issueMismatch !== "travellers")
        ) {
          throw new Error('want {"issueMismatch": "fare"|"travellers"} per runId');
        }
        simFaults[runId] = fault as SimFaults;
      }
    } catch (err) {
      return misconfigured(`CONTRACT_SIM_FAULTS: ${(err as Error).message}`);
    }
  }

  // N4b-7 (P-GAP): CONTRACT_LEVEL selects the deployment tier. At S|P the
  // bind-statement possession proof is MANDATORY — startup refuses without
  // CONTRACT_REQUIRE_BIND_STATEMENT=1. At L (default) it is optional: a
  // presented statement is still verified, but binds may omit it.
  const levelRaw = (env.CONTRACT_LEVEL ?? "L").trim().toUpperCase();
  if (levelRaw !== "L" && levelRaw !== "S" && levelRaw !== "P") {
    return misconfigured(`CONTRACT_LEVEL must be one of L|S|P, got "${env.CONTRACT_LEVEL}"`);
  }
  const requireBindStatement = env.CONTRACT_REQUIRE_BIND_STATEMENT === "1";
  if ((levelRaw === "S" || levelRaw === "P") && !requireBindStatement) {
    return misconfigured(`CONTRACT_LEVEL=${levelRaw} requires CONTRACT_REQUIRE_BIND_STATEMENT=1`);
  }
  // HIGH-1 (N4b-7 review): a late-binding `*` token without the statement
  // gate can claim ANY certificate party's agentId on first bind — an
  // identity takeover. Fail closed at startup at every level.
  if (!requireBindStatement && tokens.some((t) => t.principal.agentId === "*")) {
    return misconfigured(
      "CONTRACT_AUTH_TOKENS carries a late-binding (*) entry — CONTRACT_REQUIRE_BIND_STATEMENT=1 is required " +
      "(the certificate party's session-key signature is the only agentId proof)",
    );
  }

  // N4b-8 (gap 3): TELEMETRY_CLOSE_URL — the telemetry sink's close-only
  // listener (a compose DNS name on clockchain_edge, never a public route).
  // At S|P a terminal run MUST close against the sink — unset refuses the
  // boot (check-config surfaces the same verdict). At L it is optional: a
  // dev run may have no sink.
  const telemetryCloseRaw = (env.TELEMETRY_CLOSE_URL ?? "").trim();
  if ((levelRaw === "S" || levelRaw === "P") && telemetryCloseRaw === "") {
    return misconfigured(
      `CONTRACT_LEVEL=${levelRaw} requires TELEMETRY_CLOSE_URL (terminal close delivery is mandatory)`,
    );
  }
  if (telemetryCloseRaw !== "" && !/^https?:\/\/[^\s/?#]+/.test(telemetryCloseRaw)) {
    return misconfigured("TELEMETRY_CLOSE_URL must be an http(s) URL");
  }
  const telemetryCloseUrl = telemetryCloseRaw === "" ? undefined : telemetryCloseRaw;
  // Retry schedule for close delivery — test/dev can shorten it; default
  // retries ~5 attempts over ~30s. Non-numeric/negative entries refuse.
  const backoffRaw = (env.TELEMETRY_CLOSE_BACKOFF_MS ?? "").trim();
  let telemetryCloseBackoff: readonly number[] | undefined;
  if (backoffRaw !== "") {
    const parts = backoffRaw.split(",").map((s) => Number(s.trim()));
    if (parts.length === 0 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 120_000)) {
      return misconfigured("TELEMETRY_CLOSE_BACKOFF_MS wants a comma list of ms delays (0..120000)");
    }
    telemetryCloseBackoff = parts;
  }
  // N4b-9 (F12): per-attempt deadline (connect+headers+body) and total
  // delivery deadline for the close emitter — defaults 10s / 90s.
  const attemptTimeoutRaw = (env.TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS ?? "").trim();
  let telemetryCloseAttemptTimeoutMs: number | undefined;
  if (attemptTimeoutRaw !== "") {
    const n = Number(attemptTimeoutRaw);
    if (!Number.isFinite(n) || n < 100 || n > 120_000) {
      return misconfigured("TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS wants ms (100..120000)");
    }
    telemetryCloseAttemptTimeoutMs = n;
  }
  const deadlineRaw = (env.TELEMETRY_CLOSE_DEADLINE_MS ?? "").trim();
  let telemetryCloseDeadlineMs: number | undefined;
  if (deadlineRaw !== "") {
    const n = Number(deadlineRaw);
    if (!Number.isFinite(n) || n < 1000 || n > 600_000) {
      return misconfigured("TELEMETRY_CLOSE_DEADLINE_MS wants ms (1000..600000)");
    }
    telemetryCloseDeadlineMs = n;
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

  // N4b-8 (gap 4): the run anchor. CONTRACT_ANCHOR_ENABLED=1 backs it with
  // the in-process tsa_issue path (createTsaContractAnchor over the env-
  // configured ClockchainClient). Off by default: contract_status then reads
  // anchor:"disabled" — an unconfigured anchor is visible, never silent.
  // A failed anchor call lands on run.anchors as status:"failed".
  const anchorEnabled = env.CONTRACT_ANCHOR_ENABLED === "1";
  let anchor: ContractAnchor | undefined;
  if (anchorEnabled) {
    try {
      anchor = createTsaContractAnchor(new ClockchainClient(readConfigFromEnv(env)));
    } catch (err) {
      return misconfigured(`CONTRACT_ANCHOR: ${(err as Error).message}`);
    }
  }

  // N1/N2: construction can fail closed — corrupt/unreadable used-sessions or
  // a state dir already locked by a live process are misconfiguration, not a
  // mid-request exception.
  let service: ContractService;

  // N4b-8 (gap 3): the terminal close emitter. notify() is fired by the
  // service's onTerminalRun hook; delivery state is written back onto the
  // run (contract_status surfaces it) and the delivered/failed outcome is
  // receipted onto the run chain — a failed close is never silent. The
  // triggering principal is remembered so the evidence receipt names the
  // caller that ended the run.
  const terminalPrincipal = new Map<string, { role: "buyer" | "provider"; keyId: string }>();
  const closeEmitter = telemetryCloseUrl === undefined ? undefined : createCloseEmitter({
    signer,
    closeUrl: telemetryCloseRaw,
    ...(telemetryCloseBackoff !== undefined ? { backoffMs: telemetryCloseBackoff } : {}),
    ...(telemetryCloseAttemptTimeoutMs !== undefined ? { attemptTimeoutMs: telemetryCloseAttemptTimeoutMs } : {}),
    ...(telemetryCloseDeadlineMs !== undefined ? { deadlineMs: telemetryCloseDeadlineMs } : {}),
    setState: (runId, state) => {
      const run = service.runFor(runId);
      if (run !== undefined) run.telemetryClose = state;
    },
    recordOutcome: (outcome, d) => {
      const run = service.runFor(d.runId);
      if (run === undefined) return;
      const principal =
        terminalPrincipal.get(d.runId)
        ?? (run.bound.buyer !== undefined
          ? { role: "buyer" as const, keyId: run.bound.buyer.principalKeyId }
          : undefined)
        ?? (run.bound.provider !== undefined
          ? { role: "provider" as const, keyId: run.bound.provider.principalKeyId }
          : undefined);
      if (principal === undefined) return;
      service.recordReceipt(run, {
        tool: "telemetry_close",
        surface: "anchoring",
        argsDigest: canonicalDigest({
          runId: d.runId,
          terminalState: run.terminalState,
          receiptDigest: d.receiptDigest,
        }),
        argsDigestScheme: "canonical",
        principal,
        outcome: `telemetry_close_${outcome}`,
        responseDigest: canonicalDigest(
          d.response !== undefined ? d.response : { error: d.lastError ?? null, attempts: d.attempts },
        ),
        responseDigestScheme: "canonical",
      });
    },
  });

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
      // N4b-4: the service refuses to sign once the published window closes.
      signerValidUntilMs: keyValidUntilMs,
      // N4b-5: config-only sim fault seeds (A2) — never settable by a tool.
      ...(simFaults !== undefined ? { simFaults } : {}),
      // N4b-7: session-key possession proof at bind (mandatory at S|P).
      requireBindStatement,
      // N4b-8 (gap 2): the unbound v:2 seal wire exists only at level L.
      allowLegacySealV2: levelRaw === "L",
      // N4b-8 (gap 4): the tsa_issue-backed anchor (injected fake in tests).
      ...(anchor !== undefined ? { anchor } : {}),
      // N4b-8 (gap 3): POST the signed terminal receipt to the sink.
      ...(closeEmitter !== undefined
        ? {
            onTerminalRun: (run: ContractRun, terminalState: string, principal?: ContractPrincipal) => {
              if (principal !== undefined) {
                terminalPrincipal.set(run.runId, { role: principal.role, keyId: principal.keyId });
              }
              closeEmitter.notify({
                runId: run.runId,
                terminalState,
                ts: new Date().toISOString(),
              });
            },
          }
        : {}),
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
    ...(observerTokenRaw !== "" ? { observerToken: observerTokenRaw } : {}),
    ...(verifierTokenRaw !== "" ? { verifierToken: verifierTokenRaw } : {}),
    policyDigests: policyDigests as { buyer: string; provider: string },
    principals,
    serverKeys,
    simFaultsEnabled: simFaultsAllowed,
    requireBindStatement,
    ...(telemetryCloseUrl !== undefined ? { telemetryCloseUrl } : {}),
    anchorEnabled,
    service,
  };
}
