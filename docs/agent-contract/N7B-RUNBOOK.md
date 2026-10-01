# N7b — `/contract/mcp` staging readiness runbook — PREPARED, NOT YET RUN

Manual, founder-gated bring-up of the agent-contract surface on the AWS box.
Nothing in this document has been executed. Standing rules: notify the
orchestrator before any production deploy; **no deploys during N6/N8**;
code-only deploy path only.

## 0. Preconditions

- `feat/contract-mcp-n4a` merged into the deploy branch — describe only: merge
  the branch into `main` (or the deploy branch the box tracks), tag the merge
  commit, and record the sha. The box deploys that sha, never a worktree.
- Secrets provisioned out-of-band into SSM at `/clockchain/mcp/<NAME>` —
  `CONTRACT_SERVER_ED25519_SEED` (founder), `CONTRACT_AUTH_TOKENS` +
  `CONTRACT_OBSERVER_TOKEN`/`CONTRACT_VERIFIER_TOKEN` (operator). The exact
  parameter list, types, and formats are in `N7C-SSM-CONTRACT.md`;
  `N7B-staging.env.example` shows the same surface as a flat env template.
  Real values never touch git; `compose-up.sh` reads them with
  `--with-decryption` and never logs them.
- `npm ci && npm run build -w @clockchain/mcp-server` on the box checkout —
  `check-config` and `probe-staging` import `dist/`.

## 1. No staging deploy — route ships disabled

N7c (founder-approved D20 prep) changes the bring-up: there is **no staging
via `deploy-box`** and no dedicated staging environment. The `/contract/mcp`
route ships **disabled** — the deployed code answers 404 until
`CONTRACT_MCP_ENABLED=1` is set in SSM. Enabling is a pure environment
change, not another deploy.

`deploy-box.sh <sha>` remains code-only (`--only mcp`); NEVER
`--full-restart` — it drops mcp, host AND caddy, including the pinned ACM4
demo instance. This branch also touches `infra/clockchain-mcp/` (compose env
passthrough + `compose-up.sh` SSM reads), so the first deploy **is** infra
drift: expect the code-only path to refuse, and run it as
`deploy-box.sh <sha> --allow-infra-drift` — the assets land on disk and only
the mcp container is recreated. That is the expected determination, not an
exception.

```sh
# On the box — read the contract env exactly as compose-up.sh will see it:
node packages/mcp-server/scripts/agent-contract/check-config-from-ssm.mjs \
  --region us-west-2
#  → redacted report + present/absent per parameter; no values printed.
#    Expect exit 2 (disabled) before the enable step, 0 after.
```

## 2. Production — `/contract/mcp`

The D20 sequence on `i-0d6765d143da7e1ea`:

1. **Deploy 1** — `deploy-box.sh <sha> --allow-infra-drift` (code-only;
   installs the new compose/`compose-up.sh`, recreates `mcp` only). The route
   is still dark — `CONTRACT_MCP_ENABLED` is unset in SSM.
2. **Check canaries** — the deploy-box post-deploy probes + `/health` green;
   confirm `/contract/mcp` still 404s.
3. **Set SSM parameters** — every `/clockchain/mcp/<NAME>` row of
   `N7C-SSM-CONTRACT.md` marked required at L (tokens, seed, key window,
   policy digests, principals), EXCEPT `CONTRACT_MCP_ENABLED` which stays
   absent.
4. **`check-config-from-ssm.mjs`** — two passes: a plain run must report
   `status: "disabled"` (exit 2, every required parameter `present`), and a
   `CONTRACT_MCP_ENABLED=1`-prefixed run (local env overrides SSM) must
   report `status: "ready"` (exit 0). Only then enable.
5. **Enable the route** — write `CONTRACT_MCP_ENABLED=1` to SSM, then run
   `/opt/clockchain-mcp/compose-up.sh --only mcp` on the box so the env is
   re-read and the mcp container recreated (NOT `systemctl restart` — that is
   the full-stack path).
6. **Probe** — `check-config-from-ssm.mjs` must now exit 0
   (`status: "ready"`), then
   `CONTRACT_PROBE_TOKENS="buyer:<tok>,provider:<tok>" node
   packages/mcp-server/scripts/agent-contract/probe-staging.mjs
   https://mcp.clockchain.network` — PASS on every check.
7. **Conformance** — run the travel conformance set against the live surface
   (the harness lane's runbook covers it; this route must stay green while it
   runs).
8. **Rollback** — §4.

Level for D20 is `L` (default when `CONTRACT_LEVEL` is absent).

## 3. What each tool covers

- `check-config` — static env verdict identical to the server's startup gate
  plus the S|P production-root / ephemeral-signer refusals. Run it on the box
  BEFORE the restart; it opens and releases the state-dir lock, so it can run
  while the server is down without leaving residue.
- `check-config-from-ssm` (N7c) — same verdict, but the environment is loaded
  from `/clockchain/mcp/*` SSM parameters (decrypted, process-env only, never
  printed) instead of the shell env — the same resolution compose-up.sh does:
  a present SSM parameter wins, an absent one leaves the shell env untouched.
  So while `CONTRACT_MCP_ENABLED` is still absent in SSM,
  `CONTRACT_MCP_ENABLED=1 check-config-from-ssm.mjs` previews the enabled
  verdict before the route goes live.
- `probe-staging` — post-deploy read-only conformance: server card +
  `cardDigest`, `/contract/keys`, `initialize`/`tools/list` per role token
  with digest comparison against the card, and the pre-bind `contract_status`
  rendezvous shape. It never calls a mutating tool. Note: the `contract_status`
  call itself appends ONE pre-bind receipt to the pre-bind chain (status sits
  in `POLL_TOOLS`) — "read-only" for the business surface, not literally
  side-effect-free; expect one extra receipt per probe run.

## 4. Rollback

The route is off unless `CONTRACT_MCP_ENABLED=1`. Rollback for an env-enabled
route: delete `CONTRACT_MCP_ENABLED` (or set `0`) in SSM and re-run
`/opt/clockchain-mcp/compose-up.sh --only mcp` — no deploy, no state
migration; `/app/state/contract` stays on `mcp_state` and is inert while the
route 404s. To roll back the N7c code itself, `deploy-box.sh <previous-sha>`
(code-only; no infra drift on the way back unless the previous sha predates
the compose/`compose-up.sh` changes — then `--allow-infra-drift` again).

## 5. N7a pairing (telemetry sink)

The contract server needs the sink's close URL on the compose network:
`http://telemetry-sink:8083` (production sink) — compose DNS names, never
static IPs (they collide on the shared edge subnet), per the N7a compose
patch. The close call posts the signed terminal receipt — the receipt
signature is the only credential and the endpoint is never routed by Caddy.

`TELEMETRY_CLOSE_URL` is **mandatory at levels S and P** —
`loadContractConfig` refuses the boot without it (terminal close delivery is
part of the S/P contract). At **level L it is optional**: absent means no
close delivery and runs seal by window expiry only. The D20 run is L with no
sink deployed yet — leave the parameter absent; do not point it at a
placeholder.

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
