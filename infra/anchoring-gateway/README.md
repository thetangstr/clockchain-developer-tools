# Owned Clockchain anchoring gateway — CANONICAL HOME

This is the **single canonical home** of the anchoring gateway (monorepo Phase 2). Earlier byte-identical copies
under `ac_m3/anchoring-gateway/` (non-git staging) and `clockchain-research …/infra/anchoring-gateway/` are
**retired pointers** — do not edit those; edit here. This is the copy the MCP box deploys.

Separate service implementing the Clockchain ledger contract the MCP coordinator's `anchorV2` calls, so
`CLOCKCHAIN_ENDPOINT` points at an owned gateway instead of the unowned, down `node.clockchain.network`.

- `gateway.mjs` — the service (Node stdlib only): durable append-only fsync'd ledger, block sealing, idempotency,
  **authenticated payload-bound signed requests** (`x-cc-*`, replay + tamper protection, fail-closed 503 without a
  key), `/healthz` + `/metrics`, restart recovery. Env: `GATEWAY_PORT`, `GATEWAY_DATA_DIR`, `GATEWAY_SYNC_SEAL`,
  `GATEWAY_SIGNING_KEYS`.
- `selftest.mjs` — `node selftest.mjs` drives the full anchorV2 sequence + auth failure modes (unsigned/tamper/
  stale/replay/wrong-key → 401, no-key → 503) + idempotency + restart recovery + the shared interop vector.
- `deploy-m3-hardening.sh` — self-gating box deploy (signer-MCP → enforcing gateway → edge lockdown) with
  automatic per-phase rollback.
- `outage-drill.sh` — non-destructive controlled gateway-outage drill (MCP-stays-healthy + bounded fast-fail +
  durable recovery). *(ACM3 backlog: run when the AWS management channel is restored.)*

The per-dependency circuit breaker + retryable `CircuitOpenError` now live in **versioned source**
(`packages/core/src/resilience.ts`, `packages/mcp-server/src/agent-handshake/v2/public-tools.ts`) — the former
runtime `patch-mcp-breaker.py` is **RETIRED**.

Deployed as container `clockchain-anchor-gateway` on the MCP box (the box git-fetches this canonical copy).
Rollback via the on-box `.acx-*-backup` files + the runbook.
