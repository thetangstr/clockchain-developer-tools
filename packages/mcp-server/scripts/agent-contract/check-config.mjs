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

const PRODUCTION_ROOTS = PUBLISHED_HOST_ROOTS.map(
  (r) => `${r.kid}:${r.fingerprint}`,
);

function isProductionRoot(root) {
  return PRODUCTION_ROOTS.includes(`${root.kid}:${root.fingerprint}`);
}

/**
 * Evaluate an env map the way the server would. Returns
 *   { exitCode, report } — no side effects beyond a state-dir lock that is
 *   released before returning (the ready path constructs the real service,
 *   so close() MUST run to free the lockfile for the subsequent server boot).
 */
export function checkConfig(env) {
  const enabled = env.CONTRACT_MCP_ENABLED === "1";
  const level = (env.CONTRACT_LEVEL ?? "L").trim().toUpperCase();

  let cfg;
  try {
    cfg = loadContractConfig(env);
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
    policyDigests: { ...cfg.policyDigests },
    observerToken: cfg.observerToken === undefined ? "absent" : "configured",
    verifierToken: cfg.verifierToken === undefined ? "absent" : "configured",
    // N4b-8 (gap 3): terminal close delivery — mandatory at S|P (the config
    // load itself misconfigures when unset); at L it may be absent.
    telemetryCloseUrl: cfg.telemetryCloseUrl ?? null,
    // N4b-8 (gap 4): CONTRACT_ANCHOR_ENABLED=1 — tsa_issue-backed run
    // anchoring (agreement digest + terminal chain head).
    anchorEnabled: cfg.anchorEnabled,
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
    },
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
  const { exitCode, report } = checkConfig(process.env);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exit(exitCode);
}
