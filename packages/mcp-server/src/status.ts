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
  build: { service: string; helperVersion: string; protocolRepositorySha?: string };
  lastVerifiedHandshake: { outcome: string; observedAtMs: number; ageSeconds: number } | null;
  window: { label: string; sinceProcessStartMs: number; cacheTtlMs: number };
}

export interface StatusDeps {
  now(): number;
  /** GET a JSON document with a hard timeout; throws on failure/non-2xx. */
  fetchJson(url: string, timeoutMs: number): Promise<unknown>;
  /** eth_chainId via the configured EVM RPC; throws on failure. */
  fetchEvmChainId(timeoutMs: number): Promise<string>;
  /** Clockchain gateway pool health; throws when undeterminable. */
  fetchPoolHealth(timeoutMs: number): Promise<{ totalNodes: number; nodeParticipationPct: number; degraded: boolean }>;
  relayBaseUrl: string;
  probeTimeoutMs: number;
  /** Sessions mint on a rolling cadence; older than this means the supervisor stalled. */
  sessionStaleAfterMs: number;
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
  let lastVerified: StatusReport["lastVerifiedHandshake"] = null;

  components.mcp_host = {
    state: "ok",
    detail: "serving",
    observedAtMs: observedAt,
    meta: { uptimeSeconds: Math.max(0, Math.floor((observedAt - deps.processStartedAtMs) / 1000)) },
  };

  // Relay + supervisor: the rolling session must be fresh. A stale session
  // means the supervisor stopped minting; an unreachable relay means every
  // invite/join/next will fail.
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
    const createdAtMs = num(disc.issuedAtMs);
    if (typeof disc.sessionId === "string") currentSessionId = disc.sessionId;
    repositorySha = typeof disc.repositorySha === "string" ? disc.repositorySha : undefined;
    const ageMs = createdAtMs === undefined ? Number.NaN : observedAt - createdAtMs;
    if (createdAtMs === undefined) {
      components.relay_supervisor = { state: "degraded", detail: "discovery missing session timing", observedAtMs: observedAt, latencyMs };
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

  // Anchoring gateway + pool participation: one upstream call answers both.
  // The gateway being unreachable is down; a degraded pool is degraded (the
  // handshake surface intentionally fails closed in that state).
  let gateway: { totalNodes: number; nodeParticipationPct: number; degraded: boolean } | undefined;
  let gatewayLatency: number | undefined;
  try {
    const r = await timed(() => deps.fetchPoolHealth(deps.probeTimeoutMs));
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
    components.pool_participation = gateway.degraded
      ? { state: "degraded", detail: "pool reports degraded participation", observedAtMs: observedAt, latencyMs: gatewayLatency,
          meta: { nodeParticipationPct: gateway.nodeParticipationPct, totalNodes: gateway.totalNodes } }
      : { state: "ok", detail: "pool participating", observedAtMs: observedAt, latencyMs: gatewayLatency,
          meta: { nodeParticipationPct: gateway.nodeParticipationPct, totalNodes: gateway.totalNodes } };
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

  // Last verified handshake — evidence only. The current rolling session's
  // snapshot either shows a completed certificate or it does not; absence is
  // normal early in a session and is reported as "none observed", never as
  // a failure of the service.
  if (relayUp && currentSessionId !== undefined) {
    try {
      const { value } = await timed(() =>
        deps.fetchJson(`${relayBase}/v1/sessions/${encodeURIComponent(currentSessionId)}/result`, deps.probeTimeoutMs));
      const snap = asObj(value);
      const cert = asObj(snap.certificate ?? snap);
      if (cert.outcome === "VERIFIED" && num(cert.issuedAtMs) !== undefined) {
        const issuedAt = num(cert.issuedAtMs)!;
        lastVerified = {
          outcome: "VERIFIED",
          observedAtMs: issuedAt,
          ageSeconds: Math.max(0, Math.floor((observedAt - issuedAt) / 1000)),
        };
      }
    } catch {
      // Result pending or unavailable — lastVerified stays null; not a component.
    }
  }

  const overall = worst([
    components.handshake_surface.state,
    components.relay_supervisor.state,
    components.anchoring_gateway.state,
    components.pool_participation.state,
    components.evm_rpc.state,
  ]);

  return {
    schema: "clockchain.status/v1",
    computedAtMs: observedAt,
    processStartedAtMs: deps.processStartedAtMs,
    overall,
    components,
    build: { service: deps.serviceVersion, helperVersion: V2_HELPER_VERSION, ...(repositorySha ? { protocolRepositorySha: repositorySha } : {}) },
    lastVerifiedHandshake: lastVerified,
    window: {
      label: "live dependency probes; counters since process start",
      sinceProcessStartMs: deps.processStartedAtMs,
      cacheTtlMs: 0,
    },
  };
}

/** TTL-cached status computation for the public routes. */
export function createStatusCache(deps: StatusDeps, cacheTtlMs: number) {
  let cached: { report: StatusReport; expiresAt: number } | undefined;
  return async (): Promise<StatusReport> => {
    const now = deps.now();
    if (cached && now < cached.expiresAt) return cached.report;
    const report = await computeStatus(deps);
    report.window.cacheTtlMs = cacheTtlMs;
    cached = { report, expiresAt: now + cacheTtlMs };
    return report;
  };
}
