# N7b — `/contract/mcp` staging readiness runbook — PREPARED, NOT YET RUN

Manual, founder-gated bring-up of the agent-contract surface on the AWS box.
Nothing in this document has been executed. Standing rules: notify the
orchestrator before any production deploy; **no deploys during N6/N8**;
code-only deploy path only.

## 0. Preconditions

- `feat/contract-mcp-n4a` merged into the deploy branch — describe only: merge
  the branch into `main` (or the deploy branch the box tracks), tag the merge
  commit, and record the sha. The box deploys that sha, never a worktree.
- Secrets provisioned out-of-band: `CONTRACT_SERVER_ED25519_SEED` (founder),
  `CONTRACT_AUTH_TOKENS` + `CONTRACT_OBSERVER_TOKEN`/`CONTRACT_VERIFIER_TOKEN`
  (operator) — see `N7B-staging.env.example`; placeholders only, real values
  live in the box `.env` / SSM, never in git.
- `npm ci && npm run build -w @clockchain/mcp-server` on the box checkout —
  `check-config` and `probe-staging` import `dist/`.

## 1. Staging first — `/staging/contract/mcp`

Staging comes from the existing Caddy `/staging/*` strip to `mcp-staging`;
no edge change is needed.

```sh
# Box: mcp-staging env (separate .env or suffix-prefixed vars per local
# convention — the compose patch for a dedicated staging env is part of the
# deploy decision, not this package).
node packages/mcp-server/scripts/agent-contract/check-config.mjs
#  → prints the redacted report; exit MUST be 0 before touching anything.
#    Exit 1 = fix env and re-run; exit 2 = CONTRACT_MCP_ENABLED unset.

deploy-box.sh <sha>      # code-only; NEVER --full-restart
# --full-restart drops mcp, host AND caddy — including the pinned ACM4 demo
# instance — and is forbidden for this surface.

CONTRACT_PROBE_TOKENS="buyer:<tok>,provider:<tok>" \
  node packages/mcp-server/scripts/agent-contract/probe-staging.mjs \
    https://mcp.clockchain.network/staging
#  → PASS on every check before proceeding.
```

## 2. Production — `/contract/mcp`

Same order: `check-config` against the production env (exit 0) →
`deploy-box.sh <sha>` (code-only) → `probe-staging.mjs` against
`https://mcp.clockchain.network`. Production runs `CONTRACT_LEVEL=P`; staging
runs `S`. At `S|P` a non-production host root or an ephemeral signer fails
`check-config`.

## 3. What each tool covers

- `check-config` — static env verdict identical to the server's startup gate
  plus the S|P production-root / ephemeral-signer refusals. Run it on the box
  BEFORE the restart; it opens and releases the state-dir lock, so it can run
  while the server is down without leaving residue.
- `probe-staging` — post-deploy read-only conformance: server card +
  `cardDigest`, `/contract/keys`, `initialize`/`tools/list` per role token
  with digest comparison against the card, and the pre-bind `contract_status`
  rendezvous shape. It never calls a mutating tool. Note: the `contract_status`
  call itself appends ONE pre-bind receipt to the pre-bind chain (status sits
  in `POLL_TOOLS`) — "read-only" for the business surface, not literally
  side-effect-free; expect one extra receipt per probe run.

## 4. Rollback

The route is off unless `CONTRACT_MCP_ENABLED=1` — rollback is removing that
variable (and the CONTRACT_* block) from the env and redeploying the SAME sha
via `deploy-box.sh <sha> --no-deps`-equivalent code path. No state migration:
`/app/state/contract` stays on `mcp_state` and is inert while the route 404s.

## 5. N7a pairing

The contract server needs the sink's close URL on the compose network:
`http://telemetry-sink:8083` (production sink; `http://telemetry-sink-staging:8083`
for staging) — compose DNS names, never static IPs (they collide on the shared
edge subnet), per the N7a compose patch. The close call posts the signed terminal receipt — the
receipt signature is the only credential and the endpoint is never routed by
Caddy. Wire the env (`TELEMETRY_CLOSE_URL` or the equivalent host wiring) when
the N6 close-emitting path lands; until then the surface runs without it and
runs seal by window expiry only.

## 6. Egress

When `CONTRACT_SETTLEMENT_RAIL=stripe_test_mode` (off by default; the default
rail is in-process `simulated`), the box needs exactly two additional outbound
destinations:

- `api.stripe.com:443` — PaymentIntent create/confirm, TEST-mode keys only;
  `Idempotency-Key` on every POST.
- AWS Secrets Manager in `us-west-2` — `agentcontract/travel-stripe-test-key`,
  resolved at call time (never cached, never logged; `check-config` reports
  only its status: configured / absent / refused).

No other egress is introduced by the surface beyond the existing telemetry
close URL and the Clockchain client endpoints.

## 7. Notices

- Orchestrator notice before any production deploy — always.
- Founder gate on the deploy itself (N7): seed, tokens, and the merge sha are
  founder/operator provisioned.
- No deploys during N6/N8.
- Sink admin ownership remains a founder decision (status OPEN — see the N7a
  sink runbook); this surface never holds the sink's signing key.
