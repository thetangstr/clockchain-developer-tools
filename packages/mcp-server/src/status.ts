// Public status computation for the Clockchain MCP + Agent Handshake surface.
//
// Design rules (status-reporting-design.md):
//   - Every component is computed from a LIVE probe with a hard timeout; a
//     failed probe reports down/degraded with its observation time, never a
//     cached "healthy".
//   - The page and JSON carry explicit freshness labels (computedAtMs,
//     per-component observedAtMs) and an honest observation window ("since
//     process start" — there is no long-term persistence yet).
//   - Nothing sensitive is published: no session ids, role-access handles,
//     keys, addresses, statement text, or digests. Digests are truncated to
//     short prefixes (they are public ledger data, but the full value buys a
//     reader nothing on a status page).
//   - Overall state is the WORST component state; "unknown" is treated as
//     degraded so missing data can never look healthy.

import { V2_HELPER_VERSION } from "./agent-handshake/v2/instructions.js";

export type ComponentState = "ok" | "degraded" | "down" | "unknown";
export type OverallState = "operational" | "degraded" | "outage";

export interface ProbeResult {
  state: ComponentState;
  /** Short, safe-for-public explanation ("unreachable", "stale session"). */
  detail: string;
  observedAtMs: number;
  latencyMs?: number;
  meta?: Record<string, string | number | boolean>;
}

export interface StatusReport {
  schema: "clockchain.status/v1";
  computedAtMs: number;
  processStartedAtMs: number;
  overall: OverallState;
  components: Record<string, ProbeResult>;
  /**
   * Handshake-dependency readiness, SEPARATE from core MCP-host readiness.
   * True iff every handshake-only dependency (relay, gateway, pool, EVM) is
   * ok — i.e. the handshake surface would serve rather than fail closed.
   * /readyz (core MCP host) must NOT gate on this; /readyz/handshake does.
   */
  handshake_ready: boolean;
  build: { service: string; helperVersion: string; protocolRepositorySha?: string };
  /**
   * Protocol-evidence field — informational only, NEVER part of `overall`.
   * An idle service with no recent user traffic reports evidence
   * "none_observed" and stays fully operational; absence of a recent canary
   * is not an availability signal. Only a scheduled read-only synthetic
   * protocol probe may ever feed protocol readiness — user traffic never can.
   *   - fresh:          current session's relay result carries outcome VERIFIED
   *                     within the evidence window.
   *   - stale:          a VERIFIED result exists but is older than the window.
   *   - none_observed:  no verified certificate in the current session window
   *                     (normal on an idle service or early in a session).
   *   - unavailable:    the evidence probe itself failed — distinct from
   *                     "no evidence", and labeled as such.
   */
  lastVerifiedHandshake: {
    evidence: "fresh" | "stale" | "none_observed" | "unavailable";
    outcome?: string;
    observedAtMs?: number;
    ageSeconds?: number;
  };
  /**
   * Public performance summary — REAL bounded aggregates only, all covering
   * "since process start" and labeled as such. No persistence exists yet, so
   * nothing here may claim a 24h/7d window. Percentiles are estimated from
   * the same histogram buckets Prometheus scrapes; every label comes from
   * bounded allowlists (route class, tool name) — never request-specific data.
   */
  performance: {
    windowLabel: "since process start";
    uptimeSeconds: number;
    http: {
      totalRequests: number;
      totalErrors: number;
      errorRate: number;
      activeRequests: number;
      routes: {
        route: string;
        requests: number;
        errors: number;
        samples: number;
        p50Seconds?: number;
        p95Seconds?: number;
        p99Seconds?: number;
      }[];
    };
    handshakeTools: {
      totalCalls: number;
      totalFailures: number;
      activeCalls: number;
      completions: number;
      inflightSessions: number;
    };
  };
  window: { label: string; sinceProcessStartMs: number; cacheTtlMs: number };
}

/** What the HTTP layer supplies from its in-process metrics registry. */
export interface PerformanceSnapshot {
  http: {
    totalRequests: number;
    totalErrors: number;
    activeRequests: number;
    routes: {
      route: string;
      requests: number;
      errors: number;
      samples: number;
      p50Seconds?: number;
      p95Seconds?: number;
      p99Seconds?: number;
    }[];
  };
  handshakeTools: {
    totalCalls: number;
    totalFailures: number;
    activeCalls: number;
    completions: number;
    inflightSessions: number;
  };
}

export interface StatusDeps {
  now(): number;
  /** GET a JSON document with a hard timeout; throws on failure/non-2xx. */
  fetchJson(url: string, timeoutMs: number): Promise<unknown>;
  /** eth_chainId via the configured EVM RPC; throws on failure. */
  fetchEvmChainId(timeoutMs: number): Promise<string>;
  /**
   * Gateway pool participation, from the public time endpoint. Resolves when
   * the gateway answers; `nodeParticipationPct` is undefined when the gateway
   * answered but reported no participation field — that is "unknown", which
   * must stay distinct from both "down" (unreachable) and "degraded" (0%).
   */
  fetchPoolParticipation(timeoutMs: number): Promise<{ totalNodes: number; nodeParticipationPct?: number }>;
  /** In-process bounded aggregates for the public performance block. */
  performance(): PerformanceSnapshot;
  relayBaseUrl: string;
  probeTimeoutMs: number;
  /** Sessions mint on a rolling cadence; older than this means the supervisor stalled. */
  sessionStaleAfterMs: number;
  /** Grace after sessionDeadlineMs before the supervisor counts as behind. */
  sessionMintGraceMs: number;
  /** Verified-handshake evidence older than this is labeled stale. */
  evidenceStaleAfterMs: number;
  processStartedAtMs: number;
  serviceVersion: string;
}

const SEV: Record<ComponentState, number> = { ok: 0, unknown: 1, degraded: 2, down: 3 };

function worst(states: ComponentState[]): OverallState {
  const max = states.reduce((a, s) => Math.max(a, SEV[s]), 0);
  if (max >= SEV.down) return "outage";
  if (max >= SEV.unknown) return "degraded";
  return "operational";
}

function asObj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function num(v: unknown): number | undefined {
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

async function timed<T>(fn: () => Promise<T>): Promise<{ value: T; latencyMs: number }> {
  const start = Date.now();
  const value = await fn();
  return { value, latencyMs: Date.now() - start };
}

/** One-shot status computation — every probe runs live (callers cache). */
export async function computeStatus(deps: StatusDeps): Promise<StatusReport> {
  const now = deps.now;
  const observedAt = now();
  const components: Record<string, ProbeResult> = {};
  let repositorySha: string | undefined;

  components.mcp_host = {
    state: "ok",
    detail: "serving",
    observedAtMs: observedAt,
    meta: { uptimeSeconds: Math.max(0, Math.floor((observedAt - deps.processStartedAtMs) / 1000)) },
  };

  // Relay + supervisor: the discovery document is the real v2 shape
  // (clockchain.agent-handshake-discovery/v2 — createdAtMs /
  // invitationExpiresAtMs / sessionDeadlineMs as decimal strings). A live
  // session must cover "now": an expired deadline with no fresh mint means
  // the supervisor stalled; a very old createdAtMs with a far-future deadline
  // is caught by the staleness bound. Unreachable relay = every invite/join/
  // next will fail.
  const relayBase = deps.relayBaseUrl.replace(/\/+$/, "");
  let relayUp = false;
  let currentSessionId: string | undefined;
  if (relayBase === "") {
    components.relay_supervisor = { state: "down", detail: "relay not configured", observedAtMs: observedAt };
  } else try {
    const { value, latencyMs } = await timed(() =>
      deps.fetchJson(`${relayBase}/v1/discovery/current`, deps.probeTimeoutMs));
    relayUp = true;
    const disc = asObj(value);
    const createdAtMs = num(disc.createdAtMs);
    const sessionDeadlineMs = num(disc.sessionDeadlineMs);
    if (typeof disc.sessionId === "string") currentSessionId = disc.sessionId;
    repositorySha = typeof disc.repositorySha === "string" ? disc.repositorySha : undefined;
    const ageMs = createdAtMs === undefined ? Number.NaN : observedAt - createdAtMs;
    const expired = sessionDeadlineMs !== undefined && observedAt > sessionDeadlineMs + deps.sessionMintGraceMs;
    if (createdAtMs === undefined) {
      components.relay_supervisor = { state: "degraded", detail: "discovery missing session timing", observedAtMs: observedAt, latencyMs };
    } else if (expired) {
      components.relay_supervisor = {
        state: "down", detail: "session expired — supervisor not minting",
        observedAtMs: observedAt, latencyMs,
        meta: { sessionAgeSeconds: Math.floor(ageMs / 1000), deadlineAgeSeconds: Math.floor((observedAt - sessionDeadlineMs!) / 1000) },
      };
    } else if (ageMs > deps.sessionStaleAfterMs) {
      components.relay_supervisor = {
        state: "down", detail: "session stale — supervisor not minting",
        observedAtMs: observedAt, latencyMs,
        meta: { sessionAgeSeconds: Math.floor(ageMs / 1000), staleAfterSeconds: Math.floor(deps.sessionStaleAfterMs / 1000) },
      };
    } else {
      components.relay_supervisor = {
        state: "ok", detail: "current session fresh", observedAtMs: observedAt, latencyMs,
        meta: { sessionAgeSeconds: Math.floor(ageMs / 1000), staleAfterSeconds: Math.floor(deps.sessionStaleAfterMs / 1000) },
      };
    }
  } catch {
    components.relay_supervisor = { state: "down", detail: "unreachable", observedAtMs: observedAt };
  }

  // Anchoring gateway + pool participation: separate components even though
  // one call supplies both. Unreachable ⇒ both down; reachable but the pool
  // reports no participation field ⇒ gateway ok, pool "unknown" (degraded
  // overall — missing data can never look healthy); 0% ⇒ degraded; >0% ⇒ ok.
  let gateway: { totalNodes: number; nodeParticipationPct?: number } | undefined;
  let gatewayLatency: number | undefined;
  try {
    const r = await timed(() => deps.fetchPoolParticipation(deps.probeTimeoutMs));
    gateway = r.value;
    gatewayLatency = r.latencyMs;
  } catch {
    gateway = undefined;
  }
  if (gateway === undefined) {
    components.anchoring_gateway = { state: "down", detail: "unreachable", observedAtMs: observedAt };
    components.pool_participation = { state: "down", detail: "unreachable", observedAtMs: observedAt };
  } else {
    components.anchoring_gateway = { state: "ok", detail: "reachable", observedAtMs: observedAt, latencyMs: gatewayLatency };
    const pct = gateway.nodeParticipationPct;
    components.pool_participation = pct === undefined
      ? { state: "unknown", detail: "participation unreported", observedAtMs: observedAt, latencyMs: gatewayLatency,
          meta: { totalNodes: gateway.totalNodes } }
      : pct === 0
        ? { state: "degraded", detail: "pool reports degraded participation", observedAtMs: observedAt, latencyMs: gatewayLatency,
            meta: { nodeParticipationPct: pct, totalNodes: gateway.totalNodes } }
        : { state: "ok", detail: "pool participating", observedAtMs: observedAt, latencyMs: gatewayLatency,
            meta: { nodeParticipationPct: pct, totalNodes: gateway.totalNodes } };
  }

  // EVM RPC (Sepolia): required_fresh registrations fail without it.
  try {
    const { value: chainId, latencyMs } = await timed(() => deps.fetchEvmChainId(deps.probeTimeoutMs));
    components.evm_rpc = chainId === "0xaa36a7"
      ? { state: "ok", detail: "eip155:11155111", observedAtMs: observedAt, latencyMs }
      : { state: "down", detail: "unexpected chain id", observedAtMs: observedAt, latencyMs, meta: { chainId } };
  } catch {
    components.evm_rpc = { state: "down", detail: "unreachable", observedAtMs: observedAt };
  }

  // Handshake surface: configured and able to serve the v2 tools. Degraded
  // when a hard dependency is down (invites will fail closed) rather than
  // claiming the surface itself is broken.
  const depsDown = ["relay_supervisor", "anchoring_gateway", "evm_rpc"]
    .some((c) => components[c].state === "down");
  const depsDegraded = ["relay_supervisor", "anchoring_gateway", "pool_participation", "evm_rpc"]
    .some((c) => components[c].state === "degraded" || components[c].state === "unknown");
  components.handshake_surface = depsDown
    ? { state: "down", detail: "blocked by failed dependency", observedAtMs: observedAt }
    : depsDegraded
      ? { state: "degraded", detail: "dependency degraded — will fail closed", observedAtMs: observedAt }
      : { state: "ok", detail: "accepting", observedAtMs: observedAt };

  // Last verified handshake — evidence only, never an availability signal.
  // The current rolling session's result either shows a completed VERIFIED
  // certificate or it does not; absence on an idle service is "none_observed",
  // NOT degradation. A result-pending (404) is also "none_observed"; any other
  // probe failure is "unavailable" — distinct from "no evidence". Only a
  // scheduled read-only synthetic protocol probe may ever feed protocol
  // readiness; user-traffic-derived evidence never can.
  let lastVerified: StatusReport["lastVerifiedHandshake"] = { evidence: "none_observed" };
  if (!relayUp || currentSessionId === undefined) {
    // The evidence probe cannot run at all — relay unreachable or the
    // discovery document carried no session id. Labeled "unavailable",
    // distinct from "no certificate observed".
    lastVerified = { evidence: "unavailable" };
  } else {
    try {
      const { value } = await timed(() =>
        deps.fetchJson(`${relayBase}/v1/sessions/${encodeURIComponent(currentSessionId)}/result`, deps.probeTimeoutMs));
      const snap = asObj(value);
      // The relay returns the certificate envelope
      // {hostSessionKeyCertificate, result, signer}; the v2 result record
      // inside carries outcome + issuedAtMs (decimal string). Fall back to
      // the bare object if the endpoint ever serves the result directly.
      const cert = asObj(snap.result ?? snap.certificate ?? snap);
      const issuedAt = num(cert.issuedAtMs);
      if (cert.outcome === "VERIFIED" && issuedAt !== undefined) {
        const ageSeconds = Math.max(0, Math.floor((observedAt - issuedAt) / 1000));
        lastVerified = {
          evidence: ageSeconds * 1000 <= deps.evidenceStaleAfterMs ? "fresh" : "stale",
          outcome: "VERIFIED",
          observedAtMs: issuedAt,
          ageSeconds,
        };
      }
    } catch (e) {
      // 404 = result pending (normal mid-session); anything else = probe failed.
      lastVerified = { evidence: (e as { httpStatus?: number }).httpStatus === 404 ? "none_observed" : "unavailable" };
    }
  }

  const overall = worst([
    components.handshake_surface.state,
    components.relay_supervisor.state,
    components.anchoring_gateway.state,
    components.pool_participation.state,
    components.evm_rpc.state,
  ]);

  const perf = deps.performance();
  const httpPerf = {
    totalRequests: perf.http.totalRequests,
    totalErrors: perf.http.totalErrors,
    errorRate: perf.http.totalRequests === 0 ? 0 : perf.http.totalErrors / perf.http.totalRequests,
    activeRequests: perf.http.activeRequests,
    routes: perf.http.routes,
  };

  return {
    schema: "clockchain.status/v1",
    computedAtMs: observedAt,
    processStartedAtMs: deps.processStartedAtMs,
    overall,
    components,
    // Handshake readiness = the full handshake dependency set is confirmed
    // ok (surface would serve, not fail closed). Deliberately separate from
    // core MCP-host readiness: /readyz answers "is the MCP host serving",
    // /readyz/handshake answers this.
    handshake_ready: components.handshake_surface.state == "ok",
    build: { service: deps.serviceVersion, helperVersion: V2_HELPER_VERSION, ...(repositorySha ? { protocolRepositorySha: repositorySha } : {}) },
    lastVerifiedHandshake: lastVerified,
    performance: {
      windowLabel: "since process start",
      uptimeSeconds: Math.max(0, Math.floor((observedAt - deps.processStartedAtMs) / 1000)),
      http: httpPerf,
      handshakeTools: perf.handshakeTools,
    },
    window: {
      label: "live dependency probes; counters since process start",
      sinceProcessStartMs: deps.processStartedAtMs,
      cacheTtlMs: 0,
    },
  };
}

/**
 * TTL-cached, single-flight status computation for the public routes.
 * Concurrent callers during a cold/expired window share ONE in-flight
 * computation — the design doc's probe bound (traffic-independent) depends
 * on this: N simultaneous requests can never fan out into N probe rounds.
 */
export function createStatusCache(deps: StatusDeps, cacheTtlMs: number) {
  let cached: { report: StatusReport; expiresAt: number } | undefined;
  let inflight: Promise<StatusReport> | undefined;
  return (): Promise<StatusReport> => {
    const now = deps.now();
    if (cached && now < cached.expiresAt) return Promise.resolve(cached.report);
    inflight ??= computeStatus(deps).then((report) => {
      report.window.cacheTtlMs = cacheTtlMs;
      cached = { report, expiresAt: deps.now() + cacheTtlMs };
      inflight = undefined;
      return report;
    }, (err: unknown) => {
      inflight = undefined;
      throw err;
    });
    return inflight;
  };
}
