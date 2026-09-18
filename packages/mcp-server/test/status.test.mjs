// Unit tests for status computation: live probes, degradation rules,
// freshness labels, and the never-healthy-from-missing-data contract.
//
// The discovery/result stubs below mirror the REAL production v2 payloads:
//   discovery: clockchain.agent-handshake-discovery/v2 — createdAtMs,
//     invitationExpiresAtMs, sessionDeadlineMs, sessionOpenedBlock (decimal
//     strings), sessionId, repositorySha, externalBusinessActionPerformed.
//   result:    the certificate envelope {hostSessionKeyCertificate, result,
//     signer} where result is clockchain.agent-handshake-result/v2 carrying
//     outcome + issuedAtMs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeStatus, createStatusCache } from "../dist/status.js";

const T0 = 1_700_000_000_000;
const SESSION_ID = "3f6d1c2e-4a5b-4c6d-8e9f-0a1b2c3d4e5f";

function v2Discovery(now) {
  return {
    schema: "clockchain.agent-handshake-discovery/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION_ID,
    repositorySha: "abc123def4567890abc123def4567890abc12345",
    kitRepoUrl: "https://example.invalid/kit",
    relayUrl: "http://relay.test",
    createdAtMs: String(now - 60_000),
    invitationExpiresAtMs: String(now - 60_000 + 120_000),
    sessionDeadlineMs: String(now - 60_000 + 600_000),
    sessionOpenedBlock: "17100",
    hostSessionKeyCertificate: { certificate: { sessionId: SESSION_ID } },
    externalBusinessActionPerformed: false,
  };
}

function v2ResultEnvelope(issuedAtMs, outcome = "VERIFIED") {
  return {
    hostSessionKeyCertificate: { certificate: { sessionId: SESSION_ID } },
    result: {
      schema: "clockchain.agent-handshake-result/v2",
      outcome,
      issuedAtMs: String(issuedAtMs),
      sessionId: SESSION_ID,
      externalBusinessActionPerformed: false,
    },
    signer: "0xdeadbeef",
  };
}

function emptyPerformance() {
  return {
    http: { totalRequests: 0, totalErrors: 0, activeRequests: 0, routes: [] },
    handshakeTools: { totalCalls: 0, totalFailures: 0, activeCalls: 0, completions: 0, inflightSessions: 0 },
  };
}

function makeDeps(overrides = {}) {
  let now = T0;
  const deps = {
    now: () => now,
    _advance: (ms) => { now += ms; },
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) return v2Discovery(now);
      if (url.includes("/v1/sessions/") && url.endsWith("/result")) return v2ResultEnvelope(now - 30_000);
      throw new Error(`unexpected url ${url}`);
    },
    fetchEvmChainId: async () => "0xaa36a7",
    fetchPoolParticipation: async () => ({ totalNodes: 12, nodeParticipationPct: 100 }),
    performance: emptyPerformance,
    relayBaseUrl: "http://relay.test",
    probeTimeoutMs: 2000,
    sessionStaleAfterMs: 1_200_000,
    sessionMintGraceMs: 60_000,
    evidenceStaleAfterMs: 1_200_000,
    processStartedAtMs: T0 - 300_000,
    serviceVersion: "0.1.0-test",
    ...overrides,
  };
  return deps;
}

test("all probes ok → operational with VERIFIED last handshake", async () => {
  const r = await computeStatus(makeDeps());
  assert.equal(r.schema, "clockchain.status/v1");
  assert.equal(r.overall, "operational");
  for (const k of ["mcp_host", "handshake_surface", "relay_supervisor", "anchoring_gateway", "pool_participation", "evm_rpc"]) {
    assert.equal(r.components[k].state, "ok", k);
    assert.equal(typeof r.components[k].observedAtMs, "number", k);
  }
  assert.equal(r.lastVerifiedHandshake.evidence, "fresh");
  assert.equal(r.lastVerifiedHandshake.outcome, "VERIFIED");
  assert.equal(r.lastVerifiedHandshake.ageSeconds, 30);
  assert.equal(r.build.helperVersion.length > 0, true);
  assert.equal(r.build.protocolRepositorySha, "abc123def4567890abc123def4567890abc12345");
  assert.match(r.window.label, /since process start/);
  assert.equal(r.handshake_ready, true);
  assert.equal(r.computedAtMs, T0);
});

test("unreachable relay → relay down → handshake surface down → outage", async () => {
  const deps = makeDeps({ fetchJson: async () => { throw new Error("econnrefused"); } });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "down");
  assert.equal(r.components.handshake_surface.state, "down");
  assert.equal(r.overall, "outage");
  assert.equal(r.handshake_ready, false);
  assert.equal(r.lastVerifiedHandshake.evidence, "unavailable");
});

test("expired session deadline (no fresh mint) → supervisor down → outage", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        // created 700s ago, deadline passed 100s ago — supervisor is behind.
        return { ...v2Discovery(T0 - 640_000), sessionDeadlineMs: String(T0 - 100_000) };
      }
      throw new Error("pending");
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "down");
  assert.match(r.components.relay_supervisor.detail, /expired/);
  assert.equal(r.overall, "outage");
});

test("deadline inside mint grace → still ok", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        // Deadline passed 30s ago — inside the 60s mint grace.
        return { ...v2Discovery(T0 - 570_000), sessionDeadlineMs: String(T0 - 30_000) };
      }
      throw new Error("pending");
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "ok");
  assert.equal(r.overall, "operational");
});

test("stale rolling session (ancient createdAtMs) → supervisor down", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        return { ...v2Discovery(T0), createdAtMs: String(T0 - 9_999_000), sessionDeadlineMs: String(T0 + 9_000_000) };
      }
      throw new Error("pending");
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "down");
  assert.match(r.components.relay_supervisor.detail, /stale/);
  assert.equal(r.overall, "outage");
});

test("legacy issuedAtMs-only payload → degraded, not false-healthy", async () => {
  // A relay serving the old handshake-discovery/v2 shape (issuedAtMs) must NOT
  // be read as a live v2 session — missing createdAtMs degrades honestly.
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(T0 - 60_000), expiresAtMs: String(T0 + 540_000) };
      }
      throw new Error("pending");
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "degraded");
  assert.equal(r.overall, "degraded");
});

test("discovery missing session timing → degraded, never down-fabricated", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) return { sessionId: SESSION_ID };
      throw new Error("pending");
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "degraded");
  assert.equal(r.overall, "degraded");
});

test("unconfigured relay base → down with 'not configured'", async () => {
  const r = await computeStatus(makeDeps({ relayBaseUrl: "" }));
  assert.equal(r.components.relay_supervisor.state, "down");
  assert.match(r.components.relay_supervisor.detail, /not configured/);
  assert.equal(r.overall, "outage");
});

test("degraded pool → pool degraded, gateway ok, overall degraded", async () => {
  const deps = makeDeps({
    fetchPoolParticipation: async () => ({ totalNodes: 12, nodeParticipationPct: 0 }),
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.anchoring_gateway.state, "ok");
  assert.equal(r.components.pool_participation.state, "degraded");
  assert.equal(r.components.pool_participation.meta.nodeParticipationPct, 0);
  assert.equal(r.components.handshake_surface.state, "degraded");
  assert.equal(r.overall, "degraded");
});

test("gateway unreachable → gateway and pool both down → outage", async () => {
  const deps = makeDeps({ fetchPoolParticipation: async () => { throw new Error("timeout"); } });
  const r = await computeStatus(deps);
  assert.equal(r.components.anchoring_gateway.state, "down");
  assert.equal(r.components.pool_participation.state, "down");
  assert.equal(r.overall, "outage");
});

test("wrong EVM chain id → evm_rpc down → outage", async () => {
  const deps = makeDeps({ fetchEvmChainId: async () => "0x1" });
  const r = await computeStatus(deps);
  assert.equal(r.components.evm_rpc.state, "down");
  assert.equal(r.components.evm_rpc.meta.chainId, "0x1");
  assert.equal(r.overall, "outage");
});

test("unreachable EVM RPC → evm_rpc down", async () => {
  const deps = makeDeps({ fetchEvmChainId: async () => { throw new Error("abort"); } });
  const r = await computeStatus(deps);
  assert.equal(r.components.evm_rpc.state, "down");
});

test("result pending (404) → none_observed; idle service stays operational", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) return v2Discovery(T0);
      throw Object.assign(new Error("RESULT_PENDING"), { httpStatus: 404 });
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.lastVerifiedHandshake.evidence, "none_observed");
  // Zero traffic: no recent canary evidence, still fully operational.
  assert.equal(r.overall, "operational");
});

test("stale VERIFIED evidence → labeled stale, never affects overall", async () => {
  const deps = makeDeps({
    evidenceStaleAfterMs: 60_000, // 60s evidence window; cert is 300s old
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) return v2Discovery(T0);
      return v2ResultEnvelope(T0 - 300_000);
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.lastVerifiedHandshake.evidence, "stale");
  assert.equal(r.lastVerifiedHandshake.outcome, "VERIFIED");
  assert.equal(r.lastVerifiedHandshake.ageSeconds, 300);
  assert.equal(r.overall, "operational");
});

test("evidence probe failure → labeled unavailable, overall stays operational", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) return v2Discovery(T0);
      throw Object.assign(new Error("boom"), { httpStatus: 500 });
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.lastVerifiedHandshake.evidence, "unavailable");
  assert.equal(r.overall, "operational");
});

test("gateway answers but participation unreported → gateway ok, pool unknown, degraded", async () => {
  const deps = makeDeps({
    fetchPoolParticipation: async () => ({ totalNodes: 12, nodeParticipationPct: undefined }),
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.anchoring_gateway.state, "ok");
  assert.equal(r.components.pool_participation.state, "unknown");
  assert.match(r.components.pool_participation.detail, /unreported/);
  assert.equal(r.components.handshake_surface.state, "degraded");
  // Pool unconfirmed → handshake would fail closed → not handshake-ready.
  assert.equal(r.handshake_ready, false);
  assert.equal(r.overall, "degraded");
});

test("non-VERIFIED result → no lastVerified claim", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) return v2Discovery(T0);
      return v2ResultEnvelope(T0 - 10_000, "FAILED");
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.lastVerifiedHandshake.evidence, "none_observed");
});

test("public report never leaks the session id", async () => {
  const r = await computeStatus(makeDeps());
  const body = JSON.stringify(r);
  assert.ok(!body.includes(SESSION_ID), "session id leaked into public status");
});

test("unknown state never produces operational", async () => {
  const r = await computeStatus(makeDeps({ fetchJson: async () => { throw new Error("x"); } }));
  assert.notEqual(r.overall, "operational");
});

test("status cache serves the same report inside the TTL and recomputes after", async () => {
  let calls = 0;
  const deps = makeDeps({
    fetchJson: async (url) => {
      calls += 1;
      if (url.endsWith("/v1/discovery/current")) return v2Discovery(T0);
      throw new Error("pending");
    },
  });
  const cached = createStatusCache(deps, 15_000);
  const a = await cached();
  const probesAfterFirst = calls;
  const b = await cached();
  assert.equal(calls, probesAfterFirst, "cache should suppress probe fan-out");
  assert.equal(a.computedAtMs, b.computedAtMs);
  deps._advance(16_000);
  const c = await cached();
  assert.ok(calls > probesAfterFirst, "expired cache should recompute");
  assert.equal(c.computedAtMs, T0 + 16_000);
});

test("single-flight: concurrent cold requests share ONE probe round", async () => {
  let discoveryCalls = 0;
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        discoveryCalls += 1;
        // Slow probe — every concurrent caller must wait on the same flight.
        await new Promise((resolve) => setTimeout(resolve, 25));
        return v2Discovery(Date.now());
      }
      throw new Error("pending");
    },
  });
  const cached = createStatusCache(deps, 15_000);
  const reports = await Promise.all(Array.from({ length: 20 }, () => cached()));
  assert.equal(discoveryCalls, 1, "20 concurrent cold requests must not fan out into 20 probes");
  const computed = new Set(reports.map((r) => r.computedAtMs));
  assert.equal(computed.size, 1, "all callers share the same computed report");
});

test("single-flight: a degraded probe round does not wedge the cache — next window recovers", async () => {
  let poolCalls = 0;
  const deps = makeDeps({
    fetchPoolParticipation: async () => {
      poolCalls += 1;
      if (poolCalls === 1) throw new Error("transient");
      return { totalNodes: 12, nodeParticipationPct: 100 };
    },
  });
  const cached = createStatusCache(deps, 15_000);
  const first = await cached();
  assert.equal(first.overall, "outage"); // gateway down on the first round
  deps._advance(16_000);
  const second = await cached();
  assert.equal(poolCalls, 2, "cache cleared and re-probed after TTL");
  assert.equal(second.overall, "operational");
});

test("cached report records its TTL", async () => {
  const deps = makeDeps();
  const r = await createStatusCache(deps, 15_000)();
  assert.equal(r.window.cacheTtlMs, 15_000);
});

test("performance block is present and labeled since process start", async () => {
  const deps = makeDeps({
    performance: () => ({
      http: {
        totalRequests: 42,
        totalErrors: 1,
        activeRequests: 2,
        routes: [{ route: "mcp_rpc", requests: 40, errors: 1, samples: 40, p50Seconds: 0.02, p95Seconds: 0.4, p99Seconds: 0.9 }],
      },
      handshakeTools: { totalCalls: 17, totalFailures: 2, activeCalls: 1, completions: 3, inflightSessions: 1 },
    }),
  });
  const r = await computeStatus(deps);
  assert.equal(r.performance.windowLabel, "since process start");
  assert.equal(r.performance.uptimeSeconds, 300);
  assert.equal(r.performance.http.totalRequests, 42);
  assert.equal(r.performance.http.routes[0].p95Seconds, 0.4);
  assert.ok(Math.abs(r.performance.http.errorRate - 1 / 42) < 1e-9);
  assert.equal(r.performance.handshakeTools.completions, 3);
});

test("every component carries an observation timestamp and safe detail", async () => {
  const r = await computeStatus(makeDeps({ fetchPoolParticipation: async () => { throw new Error("boom-secret-internal"); } }));
  for (const [k, c] of Object.entries(r.components)) {
    assert.equal(typeof c.observedAtMs, "number", k);
    assert.equal(typeof c.detail, "string", k);
    assert.ok(c.detail.length < 200, k);
    assert.ok(!c.detail.includes("boom-secret-internal"), `${k} leaked raw error text`);
  }
});
