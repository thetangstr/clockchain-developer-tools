# Clockchain MCP — status & performance reporting

Benchmark → design → implementation note for the public `/status` surface and
the private `/metrics` endpoint on `mcp.clockchain.network`.

## 1. Benchmark

What widely-used MCP servers and gateways actually do in production:

| Signal | Concrete anchor | What they ship |
|---|---|---|
| Adoption | `@playwright/mcp` ~5.97M npm dl/wk; Context7 ~62K★; Playwright MCP ~37K★; GitHub MCP ~33K★; `@upstash/context7-mcp` ~1.05M dl/wk; filesystem ~711K dl/wk; Notion ~156K; sequential-thinking ~122K; Smithery uses: Brave Search ~119K, Paper Search ~59K, Gmail/Sheets ~56K, PubMed ~42K, Slack ~12K | Registry-specific demand signals — these are the servers whose operational patterns operators copy |
| Reference impl | Official MCP Registry | Public `/health` (liveness) + `/metrics` (Prometheus exposition) |
| Gateway ops | GitHub MCP gateway guidance | Connection failures, timeouts, per-server call counts, error rates as first-class metrics |
| Trace semantics | Grafana MCP guidance | Spans carry `mcp.method.name`, `gen_ai.tool.name`, `mcp.session.id`; **high-cardinality values stay out of metric labels** |
| Telemetry shape | General production pattern | OTel traces + Prometheus-style metrics; p50/p95/p99 per tool/stage; counts, errors, concurrency, heartbeat/timeout, dependency readiness, rate-limit events; structured logs; W3C trace context; explicit degradation states |

Security requirements applied throughout (MCP auth guidance): validate every
protected request; tokens bound to the server audience; never pass client
tokens upstream; least privilege; **no credentials, session ids, addresses,
digests, statements, or raw error text in public telemetry or metric labels**;
sessions are not authentication.

## 2. What we built (mapping benchmark → Clockchain)

| Benchmark pattern | Clockchain implementation |
|---|---|
| `/health` + `/metrics` (official registry) | `GET /health` stays a cheap liveness probe; `GET /metrics` serves Prometheus text exposition — **Bearer-gated** by `MCP_METRICS_TOKEN`, 404 when unset (fails closed, unlike the registry's public metrics) |
| Public status page | `GET /status` (HTML for browsers, JSON otherwise) + `GET /status.json` — computed from **live dependency probes**, not remembered state |
| Dependency readiness | `GET /readyz` — 200 unless a hard dependency is down; separate from liveness and from component health detail |
| Per-tool/stage counts + latencies | `clockchain_handshake_tool_{calls_total,duration_seconds}` by `{tool,result}`; `clockchain_handshake_stage_total{stage}`; `clockchain_handshake_failures_total{reason}`; `clockchain_handshake_completed_total{outcome}` (deduped per session); `clockchain_handshake_inflight` + `clockchain_handshake_tool_active` + `clockchain_http_requests_active` gauges |
| Concurrency without drift | Active gauges are inc/dec under `try/finally` (tool invocations) and the `close` event (HTTP requests — fires exactly once, including aborts), so counters can never wedge positive |
| Gateway connection/timeout/error metrics | `clockchain_dependency_up{dep}` + `clockchain_dependency_probe_seconds{dep}` for `relay_discovery`, `relay_result`, `gateway_pool`, `evm_rpc` |
| Rate-limit events | `clockchain_rate_limit_events_total{surface}` for `handshake_call`, `handshake_invite`, `token_mint`, `chain_verify`, `mcp_call` |
| HTTP counters | `clockchain_http_requests_total{route,status}` + `clockchain_http_request_duration_seconds{route}` over bounded route classes |
| Low-cardinality labels | Every label value funnels through `bounded()` allowlists in `http.ts`; surprise values collapse to `"other"` |
| Last-verified evidence | `lastVerifiedHandshake` on the status report appears **only** when the relay's current-session result carries `outcome: VERIFIED` + `issuedAtMs` — evidence-backed, never synthetic |

No new dependencies: the exposition format is rendered in-process
(`metrics.ts`) — `prom-client`/OTel SDKs would add supply-chain surface for
functionality that is ~150 lines.

## 3. Health model — four distinct answers

| Layer | Route | Question it answers |
|---|---|---|
| Liveness | `GET /health` | Is the process serving HTTP? (cheap, no deps — load-balancer probe) |
| Readiness | `GET /readyz` | Should traffic be sent? 503 when a hard dependency is down |
| Component health | `GET /status{,.json}` | Which dependency is degraded/down and when was it observed? |
| Protocol/business health | `lastVerifiedHandshake` evidence in status | Did a real handshake recently complete end-to-end — **informational only** |

**Evidence independence (invariant):** `lastVerifiedHandshake` is a labeled
evidence field — `fresh` / `stale` / `none_observed` / `unavailable` — and is
**never** an input to `overall` or `/readyz`. An idle service with zero recent
user traffic reports `none_observed` and stays fully operational: absence of a
recent canary is not an availability signal. Only a *scheduled read-only
synthetic protocol probe* may ever feed protocol readiness — user-traffic-
derived evidence never can.

Component states: `ok` / `degraded` / `down` / `unknown`. Overall = **worst**
component; `unknown` ranks between ok and degraded. A failed probe reports
`down` with its observation timestamp — never a cached "healthy".

Probes (each ≤ `STATUS_PROBE_TIMEOUT_MS`, default 2s):

| Component | Probe |
|---|---|
| `mcp_host` | in-process (serving + uptime) |
| `relay_supervisor` | `GET {RELAY}/v1/discovery/current` — session `issuedAtMs` must be < `STATUS_SESSION_STALE_MS` (default 20min ≈ 2× mint cadence) |
| `anchoring_gateway` | `GET /getTime` reachability (gateway answered at all) |
| `pool_participation` | same call, separate component: `ok` (>0%), `degraded` (0%), `unknown` (field unreported — gateway reachable but pool state indeterminate), `down` (unreachable) |
| `evm_rpc` | `eth_chainId` == `0xaa36a7` (Sepolia; required for `required_fresh` ERC-8004) |
| `handshake_surface` | derived: down if any hard dep down, degraded if any dep degraded/unknown |
| `lastVerifiedHandshake` | `GET {RELAY}/v1/sessions/{current}/result` → `outcome=="VERIFIED"` + `issuedAtMs` — evidence field only, see independence invariant above |

Responses are TTL-cached (`STATUS_CACHE_MS`, default 15s) so a busy status page
cannot amplify dependency probes; `window.cacheTtlMs` is disclosed on every
response, and all public status responses carry `Cache-Control: no-store` —
a CDN/browser may never serve a stale snapshot.

## 4. Degradation rules & alert thresholds

| Condition | State | Suggested alert |
|---|---|---|
| All probes ok | operational | — |
| Any dep `unknown`/degraded, none down | degraded | warn if >10min: `clockchain_dependency_up == 0` for 10m |
| Any hard dep down | outage | page: `/readyz` 503 for 2 consecutive scrapes, or `clockchain_dependency_up{dep="gateway_pool"|"relay_discovery"} == 0` for 5m |
| Supervisor stopped minting (session age > staleAfter) | outage | `clockchain_dependency_up{dep="relay_discovery"} == 0` — supervisor cron/loop stalled |
| Invite/join error rate | metric | `rate(clockchain_handshake_failures_total[5m]) > 0.1/s` or `failures/ calls > 25%` |
| Rate-limit abuse | metric | `increase(clockchain_rate_limit_events_total[5m]) > 50` |
| Handshake completions halt | business (does NOT degrade `/status` overall) | `increase(clockchain_handshake_completed_total[1h]) == 0` during expected canary windows — alert on evidence `stale`/`unavailable`, never on `none_observed` |

## 5. Runbook

- **`/readyz` 503, `/status` shows `relay_supervisor` down, detail "unreachable"**
  → relay process/host down or network partition. Check the relay service on
  the box (`docker compose ps`), then the host network.
- **`relay_supervisor` down, detail "session stale"**
  → supervisor stopped minting rolling sessions. Check the host supervisor
  logs (`agent-handshake-host` container); invites will fail closed.
- **`pool_participation` degraded**
  → Clockchain pool below participation floor. Handshakes fail closed by
  design — verify pool state on the anchoring gateway, do **not** restart the
  MCP host.
- **`evm_rpc` down / "unexpected chain id"**
  → `EVM_RPC_URL` dead or pointing at the wrong chain. `required_fresh`
  registrations cannot fund. Fix the RPC endpoint.
- **`anchoring_gateway` down**
  → `CLOCKCHAIN_ENDPOINT` unreachable. Anchoring + pool checks fail.
- **`anchoring_gateway` ok but `pool_participation` "unreported"**
  → gateway answered but the time payload carried no participation field —
  the surface can't confirm the pool, so handshakes fail closed. Check the
  gateway's `/getTime` payload shape (field rename/regression upstream).
- **`lastVerifiedHandshake` = "unavailable"**
  → the result-probe failed while the relay is up — relay session store
  issue. Distinct from `none_observed` (normal idle) and `stale` (old cert).
- **`lastVerifiedHandshake` = "stale"**
  → a VERIFIED result exists but is older than `STATUS_EVIDENCE_STALE_MS`.
  Informational: if canaries are expected on a schedule, check the canary
  runner — do NOT treat as an availability incident.
- **Metrics scrape 401/404**
  → `MCP_METRICS_TOKEN` unset (404) or wrong bearer (401). Set the env var in
  the compose `.env` and redeploy.
- **Rollback**: revert to the previous merged SHA and
  `scripts/deploy-box.sh <prev-sha>`; all new routes are additive — no state
  or API changes to unwind.

## 6. Privacy & threat-model check

- **Labels** are bounded allowlists only (route class, tool, stage, result,
  reason, dep, surface). `bounded()` collapses anything unexpected to `other`.
- **Never in labels or public status**: session ids, role-access handles,
  invitations, keys, wallet/session-key addresses, certificate/statement
  digests, statement text, raw error text, upstream tokens, client IPs.
  Session ids exist only as in-memory map keys for the inflight gauge.
- **Digests**: repo SHA truncated to 12 chars on the page (public ledger data,
  but the full value buys a status reader nothing).
- **`/metrics` is private**: constant-time `timingSafeEqual` over SHA-256
  digests of presented vs expected tokens (fixed-size inputs — no length or
  partial-prefix timing leak); 404 when the token is unset — the route doesn't
  exist in unconfigured deployments.
- **Fail-closed**: every auth surface here defaults to deny (metrics without
  token, handshake with degraded pool) — consistent with the existing
  `POOL_HEALTH_UNAVAILABLE` / `POOL_DEGRADED` posture.
- **Probe amplification**: 15s TTL cache + 2s probe timeouts bound the worst
  case to ~8 upstream requests/minute regardless of status-page traffic.
- **No SSRF surface**: probe targets are env-configured (ops-controlled), not
  request-derived.
- **Sessions are not auth**: unchanged — nothing here mints or accepts a
  credential.

## 7. Deliberately deferred

- Long-term persistence (24h+ history, incident timeline) — the page labels
  counters "since process start" rather than fabricating history. A Prometheus
  scrape of `/metrics` gives real history once wired.
- OTel trace spans (`mcp.session.id` etc.) — metric surface first; tracing is
  additive later without changing this contract.
- Payload-size histograms — transport bodies aren't observed at our layer;
  request/tool durations carry the perf signal.
- Per-IP metrics — IPs are deliberately unbounded and never labels.
