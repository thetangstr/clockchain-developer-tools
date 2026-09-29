# Clockchain MCP and Agent Handshake on AWS

This deployment keeps the existing EC2, Docker Compose, and Caddy edge. Caddy is
the only public ingress. The authenticated MCP remains at `/mcp`; the isolated
eight-tool stakeholder handshake is at `/handshake/mcp`; `/health` stays public.
While the ACM4 demo pin is live (Caddyfile), `/handshake/mcp` routes to the
frozen 2.1.6 demo instance and this build's handshake surface is
`/next/handshake/mcp`.

## Required SSM parameters

The instance role may decrypt only `/clockchain/mcp/*` and
`/clockchain/host/*`. Store every item below as an independent SecureString and
never place a value in this repository, Compose, systemd, shell history, or a
support log.

The role also attaches AWS's `AmazonSSMManagedInstanceCore` policy so the SSM
agent can use Run Command without opening another administrative ingress path.
Provisioning does not report success until the exact new instance is SSM
`Online`; the parameter-read policy above remains separately prefix-limited.

- `/clockchain/mcp/CLOCKCHAIN_API_KEY`
- `/clockchain/mcp/MCP_AUTH_TOKENS`
- `/clockchain/mcp/MCP_TOKEN_SIGNING_SECRET`
- `/clockchain/mcp/GATEWAY_SIGNING_SECRET` — payload-bound request signing between the MCP and the
  owned anchoring gateway (both sides read the same value)
- `/clockchain/mcp/KEEPER_WEBHOOK_SECRET` — Standard-Webhooks server secret for timer/alarm
  deliveries; per-owner secrets are derived from it and shown to each owner at registration,
  the value itself is never disclosed
- `/clockchain/mcp/STANDALONE_WEBHOOK_SECRET` — Standard-Webhooks server secret for Standalone Handshake
  webhook nudges (F4). Separate from the keeper's; per-registration secrets are derived from it. Never disclosed.
  The Standalone public endpoint is pinned in compose-up.sh (`STANDALONE_PUBLIC_ENDPOINT`), not derived from Host.
- `/clockchain/mcp/AGENT_HANDSHAKE_RELEASE_PIN`
- `/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE`
- `/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS`
- `/clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_ACTIVE`
- `/clockchain/mcp/AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS` — optional; keep only while
  durable keyed accepts minted under the prior HMAC key can still retry
- `/clockchain/host/FUNDING_WALLET_JSON`
- `/clockchain/host/FUNDING_WALLET_PUBLIC_JSON`
- `/clockchain/host/FUNDING_PASSWORD`
- `/clockchain/host/CLOCKCHAIN_TOKEN`
- `/clockchain/host/AGENT_HANDSHAKE_V2_HOST_ROOT_KEY`

The release pin is public metadata held in SSM so that the deploy is atomic. It
must name the immutable helper release, manifest digest, and active/previous
host-root fingerprints. Role-access keys are server signing keys; generated
stakeholder capabilities are never stored in SSM. Acceptance HMAC keys are
separate from role-access signing keys and bind responder idempotency keys inside
the persistent invitation store. Rotate them independently: promote a new active
acceptance HMAC key, keep the old key as `AGENT_HANDSHAKE_ACCEPTANCE_HMAC_PREVIOUS`
until every referenced responder-access expiry has passed, and never rotate both
active and previous acceptance HMAC keys away in one deploy.

## The anchoring gateway (owned time + ledger)

The MCP does not anchor to `node.clockchain.network` (unowned, down). `compose-up.sh` points
`CLOCKCHAIN_ENDPOINT` at `http://clockchain-anchor-gateway:8090`: the owned anchoring gateway
(`infra/anchoring-gateway/gateway.mjs`) running as a standalone container on the compose
edge network (`clockchain-mcp_clockchain_edge`), deliberately outside Compose so an MCP
restart never takes the ledger down. It is the `/getTime` oracle and the durable ledger;
every request from the MCP is HMAC-signed with `GATEWAY_SIGNING_SECRET`. Deploy it per
`infra/anchoring-gateway/deploy-m3-hardening.sh` phase 3: copy `gateway.mjs` to
`/opt/clockchain-anchor-gateway/gateway.mjs`, then recreate the container with the same
network, the `anchor_gateway_data` volume, the read-only bind mount, and
`GATEWAY_SIGNING_KEYS` from SSM. Check it from inside the network:
`docker run --rm --network clockchain-mcp_clockchain_edge node:24-alpine wget -qO- http://clockchain-anchor-gateway:8090/healthz`.
Rollback: the on-box `gateway.mjs.*-backup` copies + the same recreate.

## Timer / alarm webhooks

`timer_set` / `alarm_set` deliver a signed POST only to hosts on `KEEPER_WEBHOOK_ALLOWLIST`
(set in `compose-up.sh`; deny-by-default in HTTP mode). Every delivery is DNS-pinned: the
host is resolved at delivery time, every address is range-checked, and the connection goes
to that vetted address with the hostname kept for TLS. Redirects are never followed. To let a
new receiver host through, extend the allow-list in `compose-up.sh`, deploy, and confirm with
a `timer_set` whose `webhook_url` targets it. Poll (`timer_status`) always works.

## Release and deploy order

1. Publish and independently verify the portable Node 24 helper release. Hash
   the raw manifest bytes against the approved release pin, hash the helper
   bytes against that verified manifest, and execute only the captured verified
   bytes in memory. Do not deploy a pin until the portable asset passes its
   clean-platform check. This release makes no native code-signing or
   notarization claim.
2. Install the matching Handshake commit in the host checkout, keep the checkout
   clean, load the active host-root private key from SSM, and record its public
   fingerprint in the release pin.
3. Install the matching MCP commit and rotate the active/previous role-access
   key pair if required. `scripts/deploy-box.sh <sha> [--yes] [--full-restart] [--allow-infra-drift]`
   does this step over SSM in one of two modes (flags in any order):

   - **Code-only (default).** Recreates only the `mcp` container; `caddy`
     (so `/acm4/*`, `/mcp` anchoring and TLS) and the v2 `host` keep running.
     From the exact checkout it runs
     `infra/scripts/install-clockchain-mcp-deploy-assets.sh --no-restart`
     (refreshes the out-of-checkout `compose-up.sh` and systemd unit, reloads
     systemd, does not restart), then the checked-out
     `infra/clockchain-mcp/compose-up.sh --only mcp`. That mode does the same
     SSM secret, release-pin and nonsecret environment preparation as the unit,
     verifies the Handshake SHA read-only, does not rewrite the private host
     files, and ends in
     `docker compose up -d --no-deps --build --wait --wait-timeout 180 mcp`.
     It prints the created/started times of the `caddy`, `host` and `mcp`
     containers before and after; `caddy` and `host` `created=` must not change
     (`host` restarts itself every ~121s by design, so its `started=` moves).
     In-memory `mcp` state is still lost, so the notice/freeze rule still applies.
     Before checking anything out, it **refuses** (box untouched) when:
     - the target's installer or `compose-up.sh` predates code-only deploys (no
       `deploy-box: supports ...` marker). Older versions ignore `--no-restart`
       and `--only mcp`, so a rollback to them would silently become a full
       restart. Message: "target predates code-only deploy; re-run with
       --full-restart" (exit 4);
     - the deploy diff touches the Caddyfile, `docker-compose.yml`, the unit, the
       installer or `compose-up.sh` (infra drift, exit 5). Use `--full-restart`
       to apply it, or `--allow-infra-drift` to install the files to disk and
       recreate only `mcp` anyway (caddy/host keep their current config until
       the next full restart).

     A dirty box checkout is refused the same way in both modes (exit 3). For
     these refusals (exit 3, 4, 5) `deploy-box.sh` prints
     `REFUSED (exit N): <reason> — production unchanged` and exits with the same
     code. Production was not touched. Any other remote failure prints
     `deploy FAILED ...` and exits 1: check production and follow the rollback.

     Code-only installs the new unit and wrapper to disk **before** `mcp` is
     proven healthy. A changed `ExecStop` or wrapper therefore takes effect at
     the next stop, full restart or reboot even if this deploy fails.
   - **Full restart (`--full-restart`).** For infra/config changes only. Notify
     the travel_mvp orchestrator and the ACM4 production owner first. From that
     exact checkout it runs `sudo infra/scripts/install-clockchain-mcp-deploy-assets.sh`.
     The installer first refreshes the out-of-checkout `compose-up.sh` and
     systemd unit, then restarts the service; the unit's `ExecStop` is
     `docker compose down`, so `mcp`, `host` and `caddy` are all recreated. The
     refreshed wrapper verifies the exact Handshake SHA before Docker starts and
     atomically replaces the private host files.

   Never restart the service directly after changing the checkout: systemd
   deliberately executes `/opt/clockchain-mcp/compose-up.sh`, not the copy
   inside the repo, so reinstall the deploy assets first (both modes do).
4. Deploy Research only after the production MCP manifest reports the same
   helper digest and host-root ring that Research pins.

The v2 host reserves both fresh-registration seats before either transfer. Its
private ledger survives restarts at `/app/runs/private/v2-funding-ledger.jsonl`.
New reservations use 0.01 Sepolia ETH per address and 0.02 per required-fresh
session, providing enough testnet gas margin for ERC-8004 registration and
metadata finalization during ordinary fee spikes. The restart-safe ledger still
accepts historical 0.02 entries. Rolling-hour and UTC-day limits remain 0.20 and
1.00; address-free warnings remain 0.16 and 0.80. Queue capacity is 16
reservations. This is gas-only infrastructure funding for public v2 identity
registration, never stakeholder payment or external business action; generic v1 and bilateral funding behavior is unchanged.

## Production canaries

Run these before any stakeholder demonstration:

```text
GET https://mcp.clockchain.network/health                         -> 200
GET https://mcp-aws.clockchain.network/health                     -> 200
GET https://mcp.clockchain.network/.well-known/agent-handshake.json -> 200 and the approved release pin
POST https://mcp.clockchain.network/next/handshake/mcp            -> MCP initialize on the current build (no creds); /handshake/mcp is the ACM4-pinned demo while the pin is live
POST https://mcp.clockchain.network/mcp                           -> still requires authenticated MCP credentials
```

Then run both client orders from empty homes: Codex Initiator to Claude Code
Responder, followed by Claude Code Initiator to Codex Responder. Require two
fresh post-session ERC-8004 registrations, three distinct Clockchain receipts,
two locally verified copies of the same closing certificate, and
`externalBusinessActionPerformed:false` throughout.

## Rollback

Keep the previous helper assets, Handshake commit, MCP commit, release pin, and
host-root public ring. If any readiness or canary check fails:

1. stop new v2 invitations by restoring the prior MCP image/release pin;
2. restore the previous Handshake checkout and restart Compose;
3. leave the persistent invitation, coordinator, and funding-ledger volumes in
   place for audit and duplicate-spend protection;
4. verify `/health`, authenticated `/mcp`, generic v1, and bilateral operation;
5. redeploy Research only after its pinned values match production again.

Do not delete the prior host-root public key until every certificate issued under
it is outside the supported verification window.

## Handshake state (durability, spec B2)

With `HANDSHAKE_STATE_DIR=/app/state` (set in `docker-compose.yml`), in-flight Standalone
handshakes and both surfaces' role-access handles survive an `mcp` restart or deploy. Everything
lives on the `mcp_state` volume mounted at `/app/state`:

| Path | Contents |
|---|---|
| `/app/state/standalone-handshake/sessions/<sessionId>.json` | One Standalone session's snapshot: stage, terms, readiness, checklist attempts, consents, turn and deadline state, timeline, anchors, closure pin, its unclaimed invitation (secret digest only), access-token digests. No message bodies |
| `/app/state/standalone-handshake/sessions/<sessionId>.messages.jsonl` | That session's messages: an append-only log, one fsync'd line per message (bounded at 256 MiB; a send beyond it is refused with `STORAGE_FULL`) |
| `/app/state/standalone-handshake/role-handles.json` | `csha_` handle map, sealed (see below) |
| `/app/state/standalone-handshake/ended-tokens.json` | Digests of evicted sessions' tokens, so late callers get `SESSION_ENDED` |
| `/app/state/agent-handshake-v2/role-handles.json` | `ccra_` handle map, sealed. v2 session state is unchanged at `/app/state/agent-handshake-v2-state.json` |

Every file is `0600` in a `0700` directory, written tmp -> fsync -> rename -> fsync(dir), with the
previous version kept as `<file>.bak`. Every change a client is told about is on disk before the call
returns (one commit per operation); only last-seen times and timeline notes are coalesced (at most
one write a second), and those are flushed on SIGTERM/SIGINT. A snapshot that would exceed its bound
is an error for that call, never a silent loss. Nothing secret is stored in the clear: tokens and invitation
secrets are digests; each handle record holds the token sealed under a key derived from the handle
and the handle sealed under a key derived from the token, so the files are useless without the
credentials clients already hold. There is no server key to back up or rotate for them. Message
bodies are deleted 24 hours after a session ends (digests stay).

Holds (long-polls) are not persisted: clients simply call `handshake_next` again.

**Backup.** Copy the directories while the stack runs (each file is replaced atomically, so any copy
is a consistent per-file snapshot):
`docker run --rm -v mcp_state:/s -v "$PWD":/b alpine tar czf /b/handshake-state.tgz -C /s standalone-handshake agent-handshake-v2`.

**Restore.** Stop `mcp`, extract into the volume keeping ownership and modes (`tar xzpf`), start
`mcp`. Files readable by group/other are refused.

**Boot.** Sessions are restored oldest first, bounded (20,000 sessions / 1 GiB, logged as
`handshake_state_restore_bounded` if exceeded), and `handshake_state_restored` logs the count and
time. Leftover `*.tmp` files are removed and `*.corrupt-*` copies older than 7 days are deleted. A
readiness check interrupted by the restart is rolled back and its invitation returned. Deadlines are
judged on consensus time only: until the consensus clock syncs after boot, no session is ended by a
clock and open-channel calls answer a retryable `HANDSHAKE_TEMPORARILY_UNAVAILABLE`.

**Corruption.** A file that does not parse (or a `.bak` readable by others) is copied to
`<file>.corrupt-<ms>`, logged as `handshake_state_corrupt`, and the `.bak` is used
(`handshake_state_restored_from_backup`). A Standalone session with no valid copy is skipped and
logged (`handshake_state_session_unreadable`) while the others load. An unreadable handle map is
never overwritten: that surface logs `handshake_handles_memory_only` and keeps serving from memory,
so only clients presenting a handle lost with the file are refused; everything else, including new
handles, keeps working. Restore or wipe the file, then restart.

**Wipe safely.** Only when every in-flight handshake may be abandoned: stop `mcp`, then remove
`/app/state/standalone-handshake/` and/or `/app/state/agent-handshake-v2/role-handles.json*`, then
start `mcp`. Clients holding old handles get an access error and must start a new handshake. Never
delete `agent-handshake-v2-state.json`, the invitation files or the funding ledger as part of this.

**Webhook secret rotation.** Webhook signing secrets for Standalone `notify` registrations are
derived from `STANDALONE_WEBHOOK_SECRET` and never stored. Rotating it changes the secret for every
restored session: their receivers will reject the next notices until the party registers again in a
new handshake. Rotate only when that is acceptable (or when no session with a webhook is in flight).

Tool failures log `standalone_handshake_tool_failure` with `reason` (the refusal code) when there is
one, so an admission loop in the logs names the exact refusal.

**Staging.** The staging container (`/opt/clockchain-mcp/staging-compose.yml`, not in this repo)
has no state volume. Test restarts there with `docker restart` (keeps the container filesystem),
not by recreating the container, and set `HANDSHAKE_STATE_DIR` to a path inside it.
