# Telemetry sink deploy runbook (N7a) — PREPARED, NOT YET APPLIED

Deploy package for `ac-telemetry-sink` under separate authority. This runbook
describes a manual, founder-gated apply on the AWS box. Nothing here has been
executed; `infra/clockchain-mcp/docker-compose.yml`, `Caddyfile`, and
`infra/test/caddy-contract.test.mjs` ship as patch files under `proposed/` and
are applied at deploy time, not in git.

**Patch checksums** (verify before applying; update this line if the patches
change): run `shasum -a 256 infra/clockchain-mcp/telemetry-sink/proposed/*.patch`
and confirm the output is recorded in the deploy ticket before touching the box.

**Authority — trust assumption (MED-4):** "separate authority" means
*separation of box root/docker-group access*. The sink's trust boundary is not
a credential; it is that the sink admin is a different principal on the box
than the harness operator — whoever holds `docker compose exec` on the sink
containers and custody of `telemetry_state*` must not be who operates `mcp`.
**Sink admin ownership: founder decision — status OPEN.** Record who holds
sink admin before first apply.

The ed25519 signing key is generated inside the container on first boot and
never leaves `telemetry_state` (only the public JWK is served at
`/telemetry/keys`). No env var, mount, or CLI path can inject a private key —
boot refuses any `TELEMETRY_*`/`SINK_*`/`AC_*` variable carrying key material.

## Pre-deploy gates

- Notify the orchestrator before applying. **No deploys during N6 or N8.**
- Apply staging first, verify, then production. Never `--full-restart`.
- **Never recreate caddy** — see the Caddy step below.
- The sink lives behind the `telemetry` compose profile. The normal MCP
  deploy (`docker compose up`, `deploy-box.sh`) never builds, starts, or
  recreates it — and a sink boot refusal can never fail an MCP deploy,
  because no default `up --wait` path includes it.

## Apply order (staging first)

On the box, from the compose directory:

```sh
git checkout <merged-sha>
shasum -a 256 infra/clockchain-mcp/telemetry-sink/proposed/*.patch   # == ticket

# Patches: compose + Caddyfile + the caddy-contract test update.
git apply infra/clockchain-mcp/telemetry-sink/proposed/docker-compose.yml.patch
git apply infra/clockchain-mcp/telemetry-sink/proposed/caddy-contract.test.mjs.patch

# Caddyfile HIGH-2: `git apply` REPLACES the file (new inode) — the running
# caddy container's bind mount keeps the OLD inode and would never see the
# routes. Apply to scratch, then write the patched content IN PLACE.
git apply --check infra/clockchain-mcp/telemetry-sink/proposed/Caddyfile.patch
git show HEAD:infra/clockchain-mcp/Caddyfile > /tmp/Caddyfile.patched
patch /tmp/Caddyfile.patched < infra/clockchain-mcp/telemetry-sink/proposed/Caddyfile.patch
cp /tmp/Caddyfile.patched infra/clockchain-mcp/Caddyfile   # O_TRUNC: SAME inode

# Verify the RUNNING caddy sees the routes BEFORE reloading:
docker compose exec caddy cat /etc/caddy/Caddyfile | grep -c telemetry   # expect 6 handle blocks
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile     # reload only, NEVER recreate

# 1. STAGING — build + start only the staging service (profile-gated).
docker compose --profile telemetry build telemetry-sink-staging
docker compose --profile telemetry up -d --no-deps telemetry-sink-staging

# 2. Verify staging (below). Only then:
# 3. PRODUCTION
docker compose --profile telemetry build telemetry-sink
docker compose --profile telemetry up -d --no-deps telemetry-sink
```

`--no-deps` is required for every `up` — the MCP and host services are never
restarted by a sink deploy. Code-only redeploys use the same
`--profile telemetry build` + `up -d --no-deps` pair — never a bare `up`,
which would start the sink mid-MCP-deploy.

## Required env (public material only)

`TELEMETRY_CONTRACT_KEYS` and `TELEMETRY_CONTRACT_KEYS_STAGING` — the single
source of truth is **SSM on the box** (LOW-11: same source `compose-up.sh`
uses); they land in the compose `.env` at deploy time, never in git. JSON
`{keyId: <ed25519 public key PEM or JWK>}` — the contract server's pinned
PUBLIC keys, the only accepted close authority. The compose wiring feeds each
service its own set plus the OTHER environment's set as
`TELEMETRY_PEER_CONTRACT_KEYS`: prod and staging key MATERIAL must be
disjoint or the sink refuses to boot (MED-6). Production refuses to boot with
`TELEMETRY_CONTRACT_KEYS` unset (LOW-10). These are public keys, not secrets;
a private JWK entry refuses boot.

## First-boot key archival (MED-4)

Immediately after each service first reports healthy, archive its public key
and confirm the key was generated THIS boot — by the structured log field,
never by scraping `head`:

```sh
docker compose --profile telemetry logs --no-log-prefix telemetry-sink-staging \
  | jq -rs 'map(select(.event=="telemetry-sink-ready")) | .[0].keyCreated'   # -> true
curl -fsS https://mcp.clockchain.network/staging/telemetry/keys \
  -o /opt/clockchain-mcp/telemetry-keys/staging-$(date -u +%Y%m%dT%H%M%SZ).json
# …and for production after its apply:
docker compose --profile telemetry logs --no-log-prefix telemetry-sink \
  | jq -rs 'map(select(.event=="telemetry-sink-ready")) | .[0].keyCreated'   # -> true
curl -fsS https://mcp.clockchain.network/telemetry/keys \
  -o /opt/clockchain-mcp/telemetry-keys/prod-$(date -u +%Y%m%dT%H%M%SZ).json
```

`/opt/clockchain-mcp/telemetry-keys/` is the sink admin's custody archive —
staging and prod keys are archived under distinct names and MUST differ
(disjoint contract keys above are enforced at boot; the sink's own signing
keys are independently generated per volume). The archive is the evidence the
verifier uses if a volume is ever destroyed and a new key minted.

## Verification

```sh
docker compose --profile telemetry ps      # telemetry-sink(-staging) Up (healthy)
curl -fsS https://mcp.clockchain.network/staging/telemetry/keys   # public key doc
curl -fsS https://mcp.clockchain.network/telemetry/keys           # after prod apply
node --test infra/test/caddy-contract.test.mjs                    # patched contract test
```

Health: the image HEALTHCHECK hits `GET /v1/health` on the write port;
`/v1/health` on 8081/8082 returns `{"ok":true}` inside the network. The close
port serves nothing — a 404 from it is correct.

## Smoke test (ingest → seal → verifier fetch)

All in-network calls use compose DNS names — never static IPs (HIGH-3: the
shared `clockchain_edge` subnet gives no stable-address guarantee).

```sh
# Sink admin mints an ingest token sealed to the buyer services key:
docker compose --profile telemetry exec telemetry-sink-staging \
  node dist/mint-cli.js ingest \
  --runId run-smoke-1 --role buyer --seal-to 0x<buyer-services-x25519-pub>
# -> {"record":{...},"sealed":{...}}  (sealed box, bound to run+role)

# The forwarder (or a direct POST with the plaintext over the sealed path)
# ingests, then the mcp service posts the signed terminal receipt to the
# close listener over the internal DNS name:
docker compose exec mcp curl -fsS -X POST \
  http://telemetry-sink-staging:8083/v1/runs/run-smoke-1/close -d @receipt.json
# (prod: http://telemetry-sink:8083/v1/runs/<runId>/close — same pattern)
# -> run seals after flushGraceMs; final head signed once

# Sink admin mints the verifier query token (allowed only after first ingest):
docker compose --profile telemetry exec telemetry-sink-staging \
  node dist/mint-cli.js query --runId run-smoke-1
# -> {"record":{...},"token":"acq_..."}

curl -fsS -H "Authorization: Bearer acq_..." \
  "https://mcp.clockchain.network/staging/telemetry/query/runs/run-smoke-1/head"
# -> {head: {final:true, signature:…}, annex:…} — verify offline with the
#    public key from /telemetry/keys.
```

Sealed heads + records remain verifiable offline: `verifyRecords(records,
head, {keyId: publicKey})` needs only the exported record list and the public
key — the sink need not be running.

**Restart integrity (HIGH-1):** if a sink container restarts mid-run, its
durable `runs.json` ledger marks the run permanently lost — ingest refuses
`RUN_LOST` (410), a later close signs a `lost: true` head, and the verifier
REJECTs it. No partial post-restart chain can pass as complete. If you see a
`run_lost` close cause, treat the run's evidence as gone and re-run.

**By design, any redeploy loses in-flight runs.** Chain records live in
process memory; only the key, token records, and the `runs.json` open/close
markers are durable. A clean `up -d --force-recreate` (or even a crash) marks
every open run `RUN_LOST` — the run can still close (receipt-verified) but the
signed head is `lost: true` and verification rejects it. Schedule deploys so
no run is mid-flight, and never delete `runs.json` by hand: if `tokens.json`
exists without `runs.json` the sink refuses to boot, because a hand-deleted
ledger would silently resurrect lost runs.

## Rollback

Stop the service; sealed evidence already exported stays valid.

```sh
docker compose --profile telemetry stop telemetry-sink-staging   # or telemetry-sink
```

To fully remove: revert the compose patch, restore the Caddyfile IN PLACE the
same way it was patched (write the original content back through
`cp`, verify with `docker compose exec caddy cat …`, `caddy reload` — never
recreate caddy), and revert the test patch. The `telemetry_state*` volumes are
retained — deleting a volume mints a NEW sink key on next boot (old signed
heads then verify only against the previously published key — the first-boot
archives in `/opt/clockchain-mcp/telemetry-keys/` are what keep them checkable).

## Invariants the deploy must preserve

- Harness operator credentials do NOT write `telemetry_state*` — sink-admin only.
- Separate authority = separation of box root/docker-group access (not a credential).
- No env/mount supplies the sink private key (enforced at boot; tested).
- Close listener stays internal: no Caddy route, no published port (linted).
- Staging is isolated: own uid (10002), own volume, `/staging/telemetry/*` only.
- The sink is profile-gated (`--profile telemetry`); default `up` never touches it.
- Prod and staging contract-key sets are disjoint; prod requires keys (both
  enforced at boot; tested).
