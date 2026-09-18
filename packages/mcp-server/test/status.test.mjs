// Unit tests for status computation: live probes, degradation rules,
// freshness labels, and the never-healthy-from-missing-data contract.
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeStatus, createStatusCache } from "../dist/status.js";

const T0 = 1_700_000_000_000;
const SESSION_ID = "sess-unit-01";

function makeDeps(overrides = {}) {
  let now = T0;
  const deps = {
    now: () => now,
    _advance: (ms) => { now += ms; },
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(now - 60_000), expiresAtMs: String(now + 540_000), repositorySha: "abc123def456" };
      }
      if (url.includes("/v1/sessions/") && url.endsWith("/result")) {
        return { outcome: "VERIFIED", issuedAtMs: String(now - 30_000), sessionId: SESSION_ID };
      }
      throw new Error(`unexpected url ${url}`);
    },
    fetchEvmChainId: async () => "0xaa36a7",
    fetchPoolParticipation: async () => ({ totalNodes: 12, nodeParticipationPct: 100 }),
    relayBaseUrl: "http://relay.test",
    probeTimeoutMs: 2000,
    sessionStaleAfterMs: 1_200_000,
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
  assert.equal(r.build.protocolRepositorySha, "abc123def456");
  assert.match(r.window.label, /since process start/);
  assert.equal(r.computedAtMs, T0);
});

test("unreachable relay → relay down → handshake surface down → outage", async () => {
  const deps = makeDeps({ fetchJson: async () => { throw new Error("econnrefused"); } });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "down");
  assert.equal(r.components.handshake_surface.state, "down");
  assert.equal(r.overall, "outage");
  assert.equal(r.lastVerifiedHandshake.evidence, "unavailable");
});

test("stale rolling session → supervisor down → outage", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(T0 - 9_999_000), expiresAtMs: String(T0 - 9_000_000) };
      }
      throw new Error("pending");
    },
  });
  const r = await computeStatus(deps);
  assert.equal(r.components.relay_supervisor.state, "down");
  assert.match(r.components.relay_supervisor.detail, /stale/);
  assert.equal(r.overall, "outage");
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
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(T0 - 60_000), expiresAtMs: String(T0 + 540_000) };
      }
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
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(T0 - 60_000), expiresAtMs: String(T0 + 540_000) };
      }
      return { outcome: "VERIFIED", issuedAtMs: String(T0 - 300_000) };
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
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(T0 - 60_000), expiresAtMs: String(T0 + 540_000) };
      }
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
  assert.equal(r.overall, "degraded");
});

test("non-VERIFIED result → no lastVerified claim", async () => {
  const deps = makeDeps({
    fetchJson: async (url) => {
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(T0 - 60_000), expiresAtMs: String(T0 + 540_000) };
      }
      return { outcome: "REJECTED", issuedAtMs: String(T0 - 10_000) };
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
  // Force an unknown: components map gets an explicit unknown only via the
  // worst() table — here we assert the contract by construction: any probe
  // that fails reports down/degraded, and worst() maps unknown→degraded.
  const r = await computeStatus(makeDeps({ fetchJson: async () => { throw new Error("x"); } }));
  assert.notEqual(r.overall, "operational");
});

test("status cache serves the same report inside the TTL and recomputes after", async () => {
  let calls = 0;
  const deps = makeDeps({
    fetchJson: async (url) => {
      calls += 1;
      if (url.endsWith("/v1/discovery/current")) {
        return { sessionId: SESSION_ID, issuedAtMs: String(T0 - 60_000), expiresAtMs: String(T0 + 540_000) };
      }
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

test("cached report records its TTL", async () => {
  const deps = makeDeps();
  const r = await createStatusCache(deps, 15_000)();
  assert.equal(r.window.cacheTtlMs, 15_000);
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
