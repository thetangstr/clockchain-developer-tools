#!/usr/bin/env node
/**
 * check-config (N7b) — loads the `/contract/mcp` configuration exactly as the
 * server does (the same `loadContractConfig`) WITHOUT starting the route, and
 * prints a redacted readiness report to stdout.
 *
 *   node scripts/agent-contract/check-config.mjs          # uses process.env
 *   CONTRACT_MCP_ENABLED=1 … node …/check-config.mjs
 *
 * Exit codes:  0 ready · 1 misconfigured/refused · 2 disabled.
 *
 * The report never contains a bearer token, the seed, or any private key —
 * only roles, keyIds, sides, digests, addresses, and file paths.
 */

import { loadContractConfig } from "../../dist/agent-contract/config.js";
import { parseContractTokens } from "../../dist/agent-contract/http-handler.js";
import { PUBLISHED_HOST_ROOTS } from "../../dist/agent-contract/certificate.js";
import { DEFAULT_MAX_RUNS_PER_KEY } from "../../dist/agent-contract/run-routing.js";

const PRODUCTION_ROOTS = PUBLISHED_HOST_ROOTS.map(
  (r) => `${r.kid}:${r.fingerprint}`,
);

function isProductionRoot(root) {
  return PRODUCTION_ROOTS.includes(`${root.kid}:${root.fingerprint}`);
}

const trimmed = (env, name) => (env[name] ?? "").trim();
const isOn = (env, name) => trimmed(env, name) === "1";
/** Entry count of a comma list (CONTRACT_BRIEFS / CONTRACT_DIRECTORY) — never the entries. */
const listCount = (env, name) => trimmed(env, name).split(",").map((x) => x.trim()).filter((x) => x !== "").length;

/**
 * CDT wiring: verdicts for the default-off CDT feature switches. Every
 * switch was already validated by loadContractConfig (a malformed value is
 * a misconfiguration before we get here); this reports on/off/configured and
 * counts only — never a value. All "off"/"absent" == the b04059e surface.
 */
export function featureVerdicts(env, cfg) {
  return {
    telemetryLanes: cfg.telemetryLanes !== undefined ? "on" : "off",
    telemetrySinkKeyId: trimmed(env, "TELEMETRY_SINK_KEY_ID") === "" ? "absent" : "configured",
    policyRegistration: cfg.service.features.policyRegistration === true ? "on" : "off",
    serverAnchors: cfg.service.serverAnchors ? "on" : "off",
    expireAtTtl: isOn(env, "CONTRACT_EXPIRE_AT_TTL") ? "on" : "off",
    roleBriefs: cfg.service.roleBriefs ? "on" : "off",
    briefs: listCount(env, "CONTRACT_BRIEFS"),
    directory: listCount(env, "CONTRACT_DIRECTORY"),
  };
}

/** Settings that load but do nothing as combined — warnings, never a refusal. */
export function featureWarnings(env, cfg) {
  const warnings = [];
  if (cfg.service.serverAnchors && !cfg.anchorEnabled) {
    warnings.push("CONTRACT_SERVER_ANCHORS=1 without CONTRACT_ANCHOR_ENABLED=1: no server-side anchor will fire");
  }
  if (cfg.telemetryLanes === undefined && trimmed(env, "TELEMETRY_SINK_KEY_ID") !== "") {
    warnings.push("TELEMETRY_SINK_KEY_ID is set but TELEMETRY_LANES is off: it is ignored");
  }
  if (trimmed(env, "CONTRACT_BRIEFS") === "" && trimmed(env, "CONTRACT_BRIEFS_DIR") !== "") {
    warnings.push("CONTRACT_BRIEFS_DIR is set without CONTRACT_BRIEFS: it is ignored");
  }
  return warnings;
}

/**
 * Evaluate an env map the way the server would. Returns
 *   { exitCode, report } — no side effects beyond a state-dir lock that is
 *   released before returning (the ready path constructs the real service,
 *   so close() MUST run to free the lockfile for the subsequent server boot).
 */
export async function checkConfig(env, deps) {
  const enabled = env.CONTRACT_MCP_ENABLED === "1";
  // Same empty≡unset normalization as loadContractConfig: compose injects ""
  // for host-unset vars.
  const level = (env.CONTRACT_LEVEL ?? "").trim().toUpperCase() || "L";

  let cfg;
  try {
    cfg = loadContractConfig(env, deps);
  } catch (err) {
    return {
      exitCode: 1,
      report: { status: "misconfigured", reason: String(err), contractMcpEnabled: enabled, level },
    };
  }

  if (cfg.kind === "disabled") {
    return { exitCode: 2, report: { status: "disabled", contractMcpEnabled: false } };
  }
  if (cfg.kind === "misconfigured") {
    return {
      exitCode: 1,
      report: { status: "misconfigured", reason: cfg.reason, contractMcpEnabled: true, level },
    };
  }

  // ready — assemble the redacted report, then apply the staging/prod gates.
  const hostRoots = cfg.hostRoots.map((r) => ({
    kid: r.kid,
    fingerprint: r.fingerprint,
    production: isProductionRoot(r),
  }));
  const tokens = parseContractTokens(env.CONTRACT_AUTH_TOKENS).map((e) => ({
    role: e.principal.role,
    keyId: e.principal.keyId,
    agentId: e.principal.agentId,
    side: e.principal.side,
  }));
  const report = {
    status: "ready",
    contractMcpEnabled: true,
    level,
    requireBindStatement: cfg.requireBindStatement,
    signer: { keyId: cfg.signer.keyId, ephemeral: cfg.signerEphemeral },
    keyWindow: {
      validFrom: cfg.serverKeys[0]?.validFrom ?? null,
      validUntil: cfg.serverKeys[0]?.validUntil ?? null,
    },
    principals: [...cfg.principals.entries()].map(([keyId, address]) => ({ keyId, address })),
    tokens,
    // N11f: a single pin reports as the bare digest (back-compat); a set as a sorted array.
    policyDigests: Object.fromEntries(
      Object.entries(cfg.policyDigests).map(([role, set]) => [role, set.size === 1 ? [...set][0] : [...set].sort()]),
    ),
    observerToken: cfg.observerToken === undefined ? "absent" : "configured",
    verifierToken: cfg.verifierToken === undefined ? "absent" : "configured",
    // N4b-8 (gap 3): terminal close delivery — mandatory at S|P (the config
    // load itself misconfigures when unset); at L it may be absent.
    telemetryCloseUrl: cfg.telemetryCloseUrl ?? null,
    // N4b-8 (gap 4): CONTRACT_ANCHOR_ENABLED=1 — tsa_issue-backed run
    // anchoring (agreement digest + terminal chain head).
    anchorEnabled: cfg.anchorEnabled,
    // N4b-10 (D13): settlement rail — "simulated" (default) or
    // "stripe_test_mode". When the Stripe rail is selected, the key's
    // STATUS is resolved (configured|absent|refused) — never its bytes.
    settlementRail: cfg.settlementRailId,
    stripeTestKey: cfg.settlementRail === undefined
      ? null
      : await cfg.settlementRail.keyStatus().catch(() => "absent"),
    stateDir: cfg.stateDir,
    hostRoots,
    simFaultsEnabled: cfg.simFaultsEnabled,
    limits: {
      callsPerMinute: cfg.callsPerMinute,
      maxRuns: cfg.maxRuns,
      maxReceiptsPerRun: cfg.maxReceiptsPerRun,
      maxReceiptsPerPrincipal: cfg.maxReceiptsPerPrincipal,
      runTtlMs: cfg.runTtlMs,
      certGraceMs: cfg.certGraceMs,
      sessionTtlMs: cfg.sessionTtlMs,
      // O-3: live runs per keyId (validated 1..limit by loadContractConfig; default 1 = b04059e).
      maxRunsPerKey: Number(env.CONTRACT_MAX_RUNS_PER_KEY || String(DEFAULT_MAX_RUNS_PER_KEY)),
    },
    // CDT wiring: default-off feature switches (verdicts and counts only).
    features: featureVerdicts(env, cfg),
    warnings: featureWarnings(env, cfg),
  };

  // Release the state-dir lock before exiting — the check must not make a
  // following real boot look like a second process.
  try {
    cfg.service.close();
  } catch { /* lock release is best-effort */ }

  // N7b staging/prod gates: at S|P every pinned host root must be a published
  // production root (a `root-test`/unpublished fingerprint is a refusal), and
  // the ephemeral dev signer is never acceptable there.
  const refusals = [];
  if (level === "S" || level === "P") {
    const testRoots = hostRoots.filter((r) => !r.production);
    if (testRoots.length > 0) {
      refusals.push(
        `non-production host root pinned at CONTRACT_LEVEL=${level}: ${testRoots.map((r) => r.kid).join(", ")}`,
      );
    }
    if (cfg.signerEphemeral) {
      refusals.push(`ephemeral signer (ephemeral-dev-*) is not allowed at CONTRACT_LEVEL=${level}`);
    }
    // N4b-10 (D13): a REFUSED key status means non-test key material
    // resolved — a gate, never tolerated at S|P. `absent` is the honest
    // awaiting_stripe_test_key stop, not a refusal.
    if (report.stripeTestKey === "refused") {
      refusals.push(
        `CONTRACT_SETTLEMENT_RAIL=stripe_test_mode resolved a non-TEST key at CONTRACT_LEVEL=${level}`,
      );
    }
  }
  if (refusals.length > 0) {
    report.status = "refused";
    report.refusals = refusals;
    return { exitCode: 1, report };
  }
  return { exitCode: 0, report };
}

const isMain = process.argv[1] !== undefined
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const { exitCode, report } = await checkConfig(process.env);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exit(exitCode);
}
