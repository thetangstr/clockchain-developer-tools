# Telemetry sink runbook (N7a / D22)

The agent-contract telemetry sink (`packages/telemetry-sink`) runs on the
production MCP box (`i-0d6765d143da7e1ea`, `mcp.clockchain.network`) as its
**own container**, `telemetry-sink`, behind the `telemetry` compose profile.
Founder decision D22: same box, own container, code-only deploy, **never
`--full-restart`**. Production only — there is no staging sink.

| What | Where |
|---|---|
| Service | `infra/clockchain-mcp/docker-compose.yml` → `telemetry-sink` (`profiles: ["telemetry"]`, uid 10001, volume `telemetry_state`) |
| Listeners | 8081 ingest, 8082 query + keys, 8083 close. `expose` only (no host port, no static IP), network `clockchain_edge` |
| Public routes | `infra/clockchain-mcp/Caddyfile`: `/telemetry/v1/*` → 8081, `/telemetry/query/*` → 8082 `/v1/*`, `/telemetry/keys` → 8082 `/v1/keys`. **8083 is never routed**; mcp reaches it as `http://telemetry-sink:8083` |
| Box-side script | `infra/clockchain-mcp/telemetry-sink/sink-up.sh` (`preflight`, `up`, `reload-caddy [rev]`, `status`, `stop`) |
| Config (public, String) | SSM `/clockchain/mcp/TELEMETRY_CONTRACT_KEYS` = `{keyId: public ed25519 JWK}` of the contract server, the only close authority |
| Optional switch (String) | SSM `/clockchain/mcp/TELEMETRY_RUN_SET_HEAD` = `0`\|`1` (per-run run-set head). Absent = unset = off (the pre-wiring sink); any other value refuses `sink-up.sh up` before the build. Read at sink start only — changing it needs a deliberate sink stop/up |
| Tests | `infra/test/telemetry-sink-compose.test.mjs`, `infra/test/caddy-contract.test.mjs`, `infra/test/telemetry-sink-up.test.mjs`, `packages/telemetry-sink/test/*` |

The default `docker compose up`, `compose-up.sh` (systemd, `deploy-box.sh`
code-only `--only mcp`) never build, start or recreate the sink, and the sink
never fails an mcp deploy (nothing in the default `up --wait` path includes
it). mcp's close-path env (`TELEMETRY_CLOSE_URL` and the backoff/deadline
values from SSM via `compose-up.sh`, PR #168) is unchanged and stays unset
until the close path is wired (step 8).

## Keys and config

- **Sink signing key:** an ed25519 key generated **inside the container on
  first boot** and persisted only on `telemetry_state`. Only the public JWK is
  served (`/telemetry/keys`). No env var, mount or CLI path can inject a private
  key: boot refuses any `TELEMETRY_*`/`SINK_*`/`AC_*` variable carrying key
  material. Deleting the volume mints a new key.
- **`TELEMETRY_CONTRACT_KEYS`** (required in production; empty refuses boot):
  public keys only, a JWK with `d` refuses boot. The keyId MUST equal the
  contract server's `CONTRACT_SERVER_KEY_ID` (the sink looks up the close
  signature's keyId in this set). Value for `contract-server-2026-10`:
  `{"contract-server-2026-10":{"kty":"OKP","crv":"Ed25519","x":"J3iURWKkx4kAg-leW-NDKp7AUZQNdowUfLb5HHlQ0xU"}}`
  (raw pub `0x2778…d315`, the key derived from `/clockchain/mcp/CONTRACT_SERVER_ED25519_SEED`).
- **No staging key is needed.** The sink refuses a production boot without a
  non-empty peer (staging) key set *unless* `TELEMETRY_PEER_ENV=none`, the
  explicit statement that no peer environment exists. Compose sets
  `TELEMETRY_PEER_ENV: "none"` and `sink-up.sh up` unsets
  `TELEMETRY_CONTRACT_KEYS_STAGING`. "none" is refused together with a
  non-empty peer set, so adding a staging environment later is loud.
  **To add staging later:** generate a staging contract-server keypair (seed →
  `/clockchain/staging/mcp/CONTRACT_SERVER_ED25519_SEED` SecureString, founder),
  put its public JWK at `/clockchain/mcp/TELEMETRY_CONTRACT_KEYS_STAGING`, drop
  `TELEMETRY_PEER_ENV: "none"` from the prod service, add a staging service
  (uid 10002, own volume) and `/staging/telemetry/*` routes, and export the
  staging set in `sink-up.sh up`. Prod and staging sets must be disjoint (boot
  check).
- **Not wired:** `TELEMETRY_ANCHOR_MCP_URL` / `TELEMETRY_ANCHOR_TOKEN` (the
  token is a secret). Heads carry no anchor; the ready line shows `anchor:false`.

## Deploy (orchestrator, D22)

Preconditions: the PR is merged (`SHA` = the merge commit on `origin/main`);
quiet window (no ACM4 demo in progress, not during N6/N8); the box checkout is
clean. Everything below is code-only. **Never `--full-restart`, never
`docker compose down`, never recreate caddy or host.**

Run from a laptop checkout of this repo, with AWS credentials for account
570035913370 (us-west-2). `box` runs one command on the box as root through
the same SSM channel `deploy-box.sh` uses and prints its output:

```bash
SHA=<merge-sha>                       # full 40-char sha on origin/main
I=i-0d6765d143da7e1ea; R=us-west-2
SINK=/opt/clockchain-mcp/app/infra/clockchain-mcp/telemetry-sink/sink-up.sh
box() {
  local cmd="$*" id st
  id=$(aws --region $R ssm send-command --instance-ids $I --document-name AWS-RunShellScript \
    --comment "telemetry-sink: ${cmd:0:80}" \
    --parameters "$(jq -cn --arg c "$cmd" '{commands:[$c],executionTimeout:["1800"]}')" \
    --query Command.CommandId --output text)
  st=InProgress
  while [[ $st == InProgress || $st == Pending || $st == Delayed ]]; do
    sleep 5
    st=$(aws --region $R ssm get-command-invocation --command-id "$id" --instance-id $I \
      --query Status --output text 2>/dev/null || echo Pending)
  done
  aws --region $R ssm get-command-invocation --command-id "$id" --instance-id $I \
    --query '[StandardOutputContent,StandardErrorContent]' --output text
  echo "== $st"
  [[ $st == Success ]]
}
```

**1. Public config (String, not secret).**

```bash
aws --region $R ssm put-parameter --type String --overwrite \
  --name /clockchain/mcp/TELEMETRY_CONTRACT_KEYS \
  --value '{"contract-server-2026-10":{"kty":"OKP","crv":"Ed25519","x":"J3iURWKkx4kAg-leW-NDKp7AUZQNdowUfLb5HHlQ0xU"}}'
aws --region $R ssm get-parameter --name /clockchain/mcp/TELEMETRY_CONTRACT_KEYS \
  --query Parameter.Value --output text | jq -e 'keys == ["contract-server-2026-10"]'
```

**2. Pre-flight (read-only).** `sink-up.sh` is not on the box until step 3, so
this one is inline. GATE: checkout clean; running Caddyfile == checkout.

```bash
box 'cd /opt/clockchain-mcp/app && O=$(stat -c %U .) && sudo -u $O git -c safe.directory=$PWD rev-parse HEAD && sudo -u $O git -c safe.directory=$PWD status --short && sha256sum infra/clockchain-mcp/Caddyfile && docker exec $(docker compose -f infra/clockchain-mcp/docker-compose.yml ps -q caddy 2>/dev/null) sha256sum /etc/caddy/Caddyfile && free -m | sed -n 2p && df -h /var/lib/docker | tail -1'
```

**3. Code-only deploy of the merge.** Recreates **only mcp** (a few-second
`/mcp` blip). The Caddyfile and compose file are infra drift, so the flag is
required; caddy keeps its running config until step 5.

```bash
scripts/deploy-box.sh "$SHA" --allow-infra-drift
```

GATE: output lists `infra/clockchain-mcp/Caddyfile` and `docker-compose.yml`
as drift; caddy and host `created=` identical BEFORE/AFTER; canaries pass
(health 200, manifest 200, `/next/handshake/mcp` 200, `/mcp` 401).

**4. Start the sink.**

```bash
box "bash $SINK preflight"     # GATE: checkout == $SHA, clean; sink not running
box "bash $SINK up"
```

`up` reads the public key set, validates it, builds the image, runs
`docker compose --profile telemetry up -d --no-deps --wait telemetry-sink`,
and refuses if the sink is already running. GATE: `== Success`;
`caddy/host/mcp unchanged` (compares `created=`; host's `started=` moves by design); `telemetry-sink … Up (healthy)`; the ready line
shows `"keyCreated":true` (first boot), `"contractKeyIds":["contract-server-2026-10"]`,
`"peerEnv":"none"`; `mcp -> telemetry-sink:8081/v1/health 200`.

**5. Caddy routes: in-place reload, no recreate.** `git checkout` replaced the
Caddyfile with a new inode, so the running container's bind mount still shows
the old file; `reload-caddy` copies the checkout file into the container at
`/tmp/Caddyfile.next`, `caddy validate`s and `caddy reload`s it, and checks the
container's Created/StartedAt are unchanged. The next caddy start reads the
checkout file, which has the same content.

```bash
box "bash $SINK reload-caddy"
```

**6. Verify (from anywhere).**

```bash
B=https://mcp.clockchain.network
c() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }
curl -fsS $B/telemetry/keys | jq -e '.schema=="ac-telemetry.sink-keys/v1" and (.keys|length)==1'
echo "ingest, no token:  $(c -X POST -H 'content-type: application/json' -d '{}' $B/telemetry/v1/traces)   (expect 401)"
echo "query, no token:   $(c $B/telemetry/query/runs/x/head)   (expect 401)"
echo "sink health:       $(c $B/telemetry/v1/health)   (expect 200)"
echo "close via ingest:  $(c -X POST -d '{}' $B/telemetry/v1/runs/x/close)   (expect 404: 8081 serves no close)"
echo "close at root:     $(c -X POST -d '{}' $B/v1/runs/x/close)   (expect mcp's 404, not the sink)"
echo "health:            $(c $B/health)   (200)"
echo "mcp no creds:      $(c -X POST -H 'content-type: application/json' -d '{}' $B/mcp)   (401)"
echo "acm4 pinned:       $(c $B/acm4/health)   (unchanged from before)"
box "bash $SINK status"   # caddy/host/mcp/acm4 created= == step 3 AFTER (host started= moves every ~121 s by design)
```

**7. Archive the sink public key** (the verifier's pin; also the evidence if
the volume is ever lost):

```bash
box 'install -d -m 0755 /opt/clockchain-mcp/telemetry-keys && curl -fsS https://mcp.clockchain.network/telemetry/keys -o /opt/clockchain-mcp/telemetry-keys/prod-$(date -u +%Y%m%dT%H%M%SZ).json && ls -l /opt/clockchain-mcp/telemetry-keys'
curl -fsS https://mcp.clockchain.network/telemetry/keys   # commit keyId + JWK to the travel ops docs
```

**8. (Separate, gated) wire the close path.** Only when no contract run is
open: `/clockchain/mcp/TELEMETRY_CLOSE_URL` (String) = `http://telemetry-sink:8083`,
then `scripts/deploy-box.sh "$SHA"` (code-only; no drift now) to recreate mcp
with it. GATE: mcp healthy; first real run's close lands (sink log `close`).

## Rollback

`PRE` = the pre-merge `origin/main`, i.e. the merge commit's first parent:
`PRE=$(git rev-parse "$SHA^1")` (full 40-char sha; deploy-box needs it on origin/main).

| Undo | Command |
|---|---|
| Caddy routes (5) | `box "bash $SINK reload-caddy $PRE"` (reloads the pre-sink Caddyfile in place; never recreate caddy) |
| Sink (4) | `box "bash $SINK stop"` — keeps `telemetry_state`; never delete the volume (new key, archived pin orphaned) |
| mcp/code (3) | `scripts/deploy-box.sh "$PRE" --allow-infra-drift` (the checkout's Caddyfile/compose revert on disk, consistent with the caddy rollback; reload caddy from the checkout afterwards or before) |
| Config (1) | `aws --region $R ssm delete-parameter --name /clockchain/mcp/TELEMETRY_CONTRACT_KEYS` |
| Close path (8) | delete `/clockchain/mcp/TELEMETRY_CLOSE_URL`, re-run `scripts/deploy-box.sh <sha>` |

Order: caddy routes first (stops public traffic to the sink), then the sink,
then code. `sink-up.sh` does not exist in a pre-sink checkout, so run the caddy
and sink rows **before** rolling the code back.

## Restarts lose open runs

Chain records live in process memory; only the sink key, `tokens.json` and the
`runs.json` open/close ledger are durable. **Any sink restart, recreate or crash
marks every open run `RUN_LOST`**: ingest answers 410, a later close signs a
`lost: true` head, and the verifier rejects it. Treat the evidence as gone and
re-run. Never delete `runs.json` by hand: with `tokens.json` present and
`runs.json` missing the sink refuses to boot.

- `sink-up.sh up` refuses while the sink runs; stopping it is a deliberate act.
- **A `--full-restart`, a `systemctl stop/restart clockchain-mcp`, or a reboot
  removes the sink container** (the unit's `ExecStop` is `docker compose down`,
  which removed a running profile-gated container in a local check on Compose
  v5.1.1; the volume survives), and the systemd start path never starts it again.
  After any of those: `box "bash $SINK up"` (caddy was recreated from the
  checkout file, so the routes are already live). Until then `/telemetry/*`
  answers 502.
- After each sink (re)start, compare the ready line's `contractKeyIds` with the
  archived set; whoever can write the SSM param decides who may close runs.

## Sink admin (minting)

Minting runs inside the container (`node dist/mint-cli.js ingest|query|global-query`,
see `packages/telemetry-sink/README.md`). Anyone with root on the box or
`ssm:SendCommand` to it can mint, which includes every principal that can run
`deploy-box.sh`. The separation plan (founder-only MFA role, fixed SSM
documents for sealed ingest mints and interactive query mints, CloudTrail
alerting, and the Tier-2 operator permission set) is in the travel repo,
`.omc/state/n7/SINK-DEPLOY-PLAN.md` §3; the founder-applied kit is in
`admin/` (`admin/FOUNDER-STEPS.md`).

What may be claimed depends on how far that has gone:

- **Until Phase F1 is complete** (the founder-only, MFA-gated
  `clockchain-telemetry-sink-admin` role and its documents exist, AND the
  CloudTrail trail + alert on `ssm:SendCommand`/`ssm:StartSession` to this box
  are live): there is **no** separate sink-admin authority. Anyone with root on
  the box or `ssm:SendCommand` to it — including the orchestrator and every
  agent running as SSO AdministratorAccess — can mint ingest and query tokens.
  Say exactly that.
- **After F1, until Tier 2:** "sink admin is a separate, MFA-gated founder
  path with alerting; the operator retains technical root on the box and could
  still mint (detectable, not prevented)".

Even after F1, the separation is detect-only while the orchestrator holds
AdministratorAccess. The draft scoped role is in `admin/orchestrator-scoped-role.json`,
and the residual-trust section of `admin/FOUNDER-STEPS.md` explains it.

Query tokens are plaintext and must not travel through SSM Run Command output.
After each run, reconcile the sink's minted-token records against the founder's
mint log. Inside the container, the read-only lister is
`node dist/list-tokens-cli.js [--runId <id>]`, exposed to the founder as the
`ClockchainSinkAdmin-ListTokens` document. An ingest record nobody minted means
the run's evidence is rejected.

Smoke after admin is set up (founder): mint an ingest token for
`smoke-<date>-1` role buyer sealed to a throwaway x25519 key, POST one OTLP/JSON
span to `/telemetry/v1/traces`, mint a query token, then
`GET /telemetry/query/runs/smoke-<date>-1/head` → a non-final head whose
signature verifies against the archived `/telemetry/keys` JWK. Sealed heads
verify offline with `verifyRecords(records, head, {keyId: publicKey})`.

## Invariants

- One container, profile-gated; default `up`, `compose-up.sh` and `deploy-box.sh` never touch it (tested).
- No host-published ports, no static IP; close listener 8083 never routed (tested).
- No secrets in compose; only the public contract-key set comes from SSM (tested).
- Production requires `TELEMETRY_CONTRACT_KEYS`; a peer set or the explicit `TELEMETRY_PEER_ENV=none` (boot check, tested).
- Caddy changes are applied by in-place reload, never by recreating caddy.
