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
- `/clockchain/mcp/AGENT_HANDSHAKE_V2_ENROLLMENT_KEY` — optional (mcp); the coordinator's
  sender-enrollment key, JSON `{"kid","privateKeyPem"}` with a PKCS#8 Ed25519 PEM. Absent: the
  mcp gets it empty and posts no sender enrollments (the behaviour before them). `compose-up.sh`
  refuses any other key: the PEM must be the form `openssl genpkey -algorithm ed25519` and Node
  write (one 64-character base64 line, 48 bytes: the Ed25519 PKCS#8 header, then the seed).
- `/clockchain/mcp/AGENT_HANDSHAKE_V2_RELAY_BINDING` — optional (host); `off`, `observe` or
  `enforce`. Absent: the deploy passes `off` (the host itself also treats an unset value as `off` and logs one startup warning, `agent_handshake_v2_relay_binding_default_off`; an empty or unknown value fails at load).
- `/clockchain/mcp/AGENT_HANDSHAKE_V2_COORDINATOR_KEYS` — optional (host); the public
  coordinator key ring, single-line JSON array of 1-2 `{"kid","publicKey","fingerprint"}`:
  `publicKey` is the canonical base64 of the 32-byte raw Ed25519 public key and `fingerprint` the
  SHA-256 hex of those 32 bytes (`printf '%s' "$publicKey" | base64 -d | sha256sum`). Absent: the
  host gets no key-ring variable. `compose-up.sh` refuses to deploy when the binding is `observe`
  or `enforce` and this is absent, or when it is present and breaks any of these rules (the host
  applies the same rules in every binding mode).
  These two reach the host only through a full restart (`scripts/deploy-box.sh <sha> --full-restart`);
  code-only deploys leave the host running as it is. Replicas from `scripts/box-host-replicas.sh`
  copy host-1's environment, so re-run it after the full restart to bring them back.
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
     See "What a restart loses": the notice/freeze rule still applies.
     The profile-gated `telemetry-sink` is never touched by either mode's
     start path; a full restart (compose `down`) removes it and it must be
     started again with `sink-up.sh up` — see `telemetry-sink/RUNBOOK.md`.
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

**Brief pin (D1459).** `main` from `452f573b` on ships the family-travel door brief with digest `0x1a4e767a…`, so it needs SSM `/clockchain/mcp/CONTRACT_BRIEFS` = `family-travel-tc-door:0x1a4e767ae04df9be7621e2294242b215dc9b1ea68dc7ab5d9df4068f89f1a4a6` before it is deployed. With the older pin (`0xaac93fd9…`, for `2989630c` and earlier) the mcp refuses the brief at boot and `/contract/mcp` answers 503.

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
| `/app/state/standalone-handshake/mailboxes/<sha256(address)>.json` | One handshake-address mailbox (spec B4): owner key, allow/block fingerprints, open invitations (session ids only, no secrets), mailbox timeline, listen-token and client-IP digests. Challenge nonces are not stored. Deliveries are coalesced writes, so one made within a second of a crash can be lost; the Initiator then sees INVITATION_NOT_ACCEPTED at the TTL, as for any unanswered invitation |
| `/app/state/standalone-handshake/listen-handles.json` | `csla_` listen-handle map, sealed like the role handles |
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

**What a restart loses.** Checked against the code: `csha_`, `ccra_` and `csla_` handles are on disk
(`handshake-core/handle-map.ts`, with `HANDSHAKE_STATE_DIR` set in `docker-compose.yml`), and survive an
`mcp` restart or deploy, as this section says. An earlier line here said they were lost; that was out of date. A
handle map that can't be read falls back to memory (`handshake_handles_memory_only`, below). A restart still loses
calls and long-polls in flight, rate-limit windows, the `MCP_LOG_BUDGET` count, and trial sessions and entitlements
(`MCP_SESSION_FILE` isn't set, so that store is in memory). The notice/freeze rule still applies because of those.

**Backup.** Copy the directories while the stack runs (each file is replaced atomically, so any copy
is a consistent per-file snapshot). The compose volume is named after its project, so look it up, and stop if
it isn't found: a wrong name would make `docker run` create a new, empty volume. See "Back up Shadow and accounts"
for Shadow, which needs more care.
`VOL=$(docker volume ls -q --filter label=com.docker.compose.project=clockchain-mcp --filter label=com.docker.compose.volume=mcp_state); test -n "$VOL" && docker run --rm -v "$VOL":/s:ro -v "$PWD":/b alpine tar czf /b/handshake-state.tgz -C /s standalone-handshake agent-handshake-v2`.

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

## Hosted Shadow and sign-in

Shadow is a flight recorder for AI agents. The record stays on this box for 30 days, and only hashes go on the ledger.
Sign-in is OAuth 2.1 (`src/oauth.ts`), and an account has no email.

**This is a single-operator ledger.** Shadow anchors to the anchoring gateway above: one container on this box, run by
us. In hosted mode one operator holds the record, the signing key, the ledger and the clock, so a pass isn't independent
assurance, and the pin served with a packet proves only that the record is what this server signed. Don't say "validator",
"decentralized" or "independent network" about it. A pass means the record is intact. It doesn't mean it's true or compliant.

### Settings

All are optional SSM parameters under `/clockchain/mcp/`, stored as SecureString. Absent means the default.

| Setting | Default | What it does |
|---|---|---|
| `SHADOW_ENABLED` | off | `1` serves `/shadow/*`. Anything else: those paths answer as if Shadow didn't exist. |
| `SHADOW_STATE_DIR` | `/app/state/shadow` | Where records live, on the `mcp_state` volume. |
| `SHADOW_MAX_BYTES` | 1 GB | All of Shadow. New sessions stop at it and new steps at 125%. Shadow won't start if it's over half the filesystem's free space. |
| `SHADOW_ACCOUNT_MAX_BYTES` | 10 MB; with either logging flag 5 MB | One account. |
| `SHADOW_SESSION_STARTS_PER_DAY` | 30 | One account. |
| `SHADOW_LINK_CONCURRENCY` | 32 | Viewer and packet responses at once. |
| `SHADOW_LAZY_AUTH` | off | `1` adds `/shadow/chat/mcp`, which lists its tools before sign-in (claude.ai). Needs OAuth. |
| `SHADOW_ANON_PER_MINUTE` | 600 | Requests per client to that path before sign-in. |
| `SHADOW_AUTO_LOG` | off | `1`: logging on by default on **`/shadow/mcp` and `/shadow/chat/mcp`**. Never on a listed server. |
| `SHADOW_PREVIEW_AUTO_LOG` | off | `1` adds `/shadow/preview/mcp` and `/shadow/preview/chat/mcp`, logging by default. The other paths don't change. |
| `SHADOW_ANCHORS_PER_DAY`, `SHADOW_ANCHORS_PER_SESSION` | 60, 100; with either logging flag 400, 300 | Per account and session, on every endpoint: the flags raise them for the listed paths too. |
| `SHADOW_LOG_STEPS_PER_MIN` | 90 | `shadow_log_step` calls per account, with either logging flag. |
| `SHADOW_LEDGER_CLIENT_ID`, `SHADOW_LEDGER_WALLET_ID` | the delegated client | Shadow's own writer on the ledger. Set both. No email, and not the delegated id. |
| `SHADOW_WITNESS_KEY_FILE` | off | Path to an Ed25519 private key (PKCS8 PEM), provisioned like any other secret. Set: it signs signed-in accounts' checkpoints, its public half is served at `/.well-known/clockchain-witness-key.json`, and every account's held `key.json` is removed, at start for those that don't come back (its operator id stays in `operator.json`). A file that won't load stops Shadow (`shadow_unavailable`). Unset: a key per account, as before, and that URL answers 404. Unsetting it later makes new per-account keys; removed ones don't come back. |
| `SHADOW_STARTER_ANCHORS_PER_DAY` | 2000 | Only with `MCP_AGENT_KEYS=1`. Anchors per UTC day shared by every agent signed in with its own key (the Starter allowance); accounts never use it. Once it's used up, agents' checkpoints are still recorded and signed, and wait to be anchored. |
| `MCP_BYO_WRITES` | refuse | Emergency rollback only: `allow` lets a caller's own key write on the owned gateway again. |
| `MCP_OAUTH` | off | `1` turns sign-in on. Needs `MCP_TOKEN_SIGNING_SECRET`. |
| `MCP_OAUTH_APPROVALS_PER_HOUR` | 10 | Per IP. |
| `MCP_OAUTH_ACCOUNTS_PER_HOUR`, `MCP_OAUTH_ACCOUNTS_PER_IP_PER_HOUR` | 200, 10 | New accounts, in all and per IP. |
| `MCP_OAUTH_KEY_ATTEMPTS_PER_IP_PER_HOUR` | 20 | Account-key sign-in tries. |
| `MCP_AGENT_KEYS` | off | `1`, with `MCP_OAUTH=1`, lets an agent sign in with its own Ed25519 key and no person: the `client_credentials` grant on `/oauth/token` (a signed assertion for a one-hour Starter token, no refresh token), the public key list at `/agent-keys/<fingerprint>.json` with its replace and revoke routes, and `shadow_sign_checkpoint`. `/llms.txt` and `/shadow/connect` then say how. Keys are kept under `${MCP_STATE_DIR}/agent-keys`, public halves only. Any value but `0` or `1` turns only agent keys off, logged as `agent keys misconfigured (off)`. |
| `MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR` | 10 | Only with `MCP_AGENT_KEYS=1`. New agent keys accepted per IP per hour; a key already on the list doesn't count. |
| `MCP_AGENT_KEYS_NEW_PER_HOUR` | 200 | Only with `MCP_AGENT_KEYS=1`. New agent keys accepted per hour from every IP together, counting keys made by replace; a key already on the list doesn't count. Past it, a new key gets 429 for up to an hour. A bad value turns only agent keys off, like `MCP_AGENT_KEYS`. |
| `MCP_METRICS_TOKEN` | off | Bearer token for `/metrics`, which answers 404 without one. See `alerts.md`. |
| `OPENAI_APPS_CHALLENGE_TOKEN` | off | See "ChatGPT domain check". |

`MCP_AGENT_KEYS`, `MCP_AGENT_KEYS_NEW_PER_IP_PER_HOUR`, `MCP_AGENT_KEYS_NEW_PER_HOUR`, `SHADOW_WITNESS_KEY_FILE` and `SHADOW_STARTER_ANCHORS_PER_DAY` aren't passed
through `docker-compose.yml` yet, so setting them in SSM changes nothing until that wiring lands (after the founder's go).

A malformed Shadow setting stops Shadow from starting: every `/shadow` path answers 503, and the reason is in the log as
`shadow_unavailable`. To apply a setting with no code change, deploy the same commit again: `compose-up.sh` reads SSM each
time. A deploy that changes `docker-compose.yml` or `compose-up.sh` is refused as infra drift (exit 5). For a change that
only adds settings to `mcp`, like these, use `--allow-infra-drift`, which recreates only `mcp`.

### Logging is per endpoint

| Endpoint | With no flag | Who it's for |
|---|---|---|
| `/shadow/mcp`, `/shadow/chat/mcp` | The person asks, chat by chat. No log tools, no account setting, no footer. | Directory listings. OpenAI's package uses the first, Claude's the second. |
| `/shadow/preview/mcp`, `/shadow/preview/chat/mcp` | Don't exist. With `SHADOW_PREVIEW_AUTO_LOG=1`: logging on by default, an account-level "stop logging", the footer. | People who add the URL by hand. No discovery file names them. |

Why: Anthropic's policy says "Software must not collect extraneous conversation data, even for logging purposes" and
rules out "changes to Claude's behavior across sessions". OpenAI's rules out "overly broad triggering". See
`project-shadow/docs/launch/directory-rules.md`.

**Before listing, or after any deploy to a listed server,** check that the listed paths carry none of it. Both must print 0:

```bash
curl -s -X POST https://mcp.clockchain.network/shadow/chat/mcp -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | grep -cE 'shadow_log_step|without being asked|from any connector'
curl -s -X POST https://mcp.clockchain.network/shadow/chat/mcp -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"check","version":"1"}}}' | grep -cE 'without being asked|from any connector'
```

Turning on `SHADOW_AUTO_LOG` after listing is a material change that Anthropic must be told about (Policy 3.H). The server
logs `shadow_auto_log_on_listed_paths` at boot while it's on. Connectors added by hand to `/shadow/chat/mcp` stop logging by
default once `SHADOW_AUTO_LOG` is unset, so move them to the preview path first. A token isn't tied to one endpoint: an
account signed in on a listed path also works on a preview one, and on `/mcp`.

**A stored "stop logging" applies only on endpoints that log by default.** A listed endpoint reads no such setting.

**Either flag also changes what Shadow does on every endpoint,** the listed ones included, as an account's sessions can be
reached from all of them: the limits above, secrets redacted in `shadow_record` and session starts, an agent id holding a key
refused, `shadow_verify` needing the ledger for a pass (`indeterminate` with it down), and the viewer's table per step.
Only the logging tools, the instructions, the footer and the sign-in wording are per endpoint.

### Enable and disable

- **Enable Shadow:** set `SHADOW_ENABLED=1` and `MCP_OAUTH=1`, plus `SHADOW_LAZY_AUTH=1` for claude.ai and the ledger ids.
  Deploy. Run `node scripts/e2e-shadow-public.mjs` (read-only by default).
- **Disable Shadow:** set `SHADOW_ENABLED` to `0`, then deploy. Every `/shadow` path stops, including viewer links. Records
  stay on the volume. **The retention sweep stops with it,** and so does the 30-day deletion we promise, so run the purge
  below daily until Shadow is back. The same is true while a bad setting keeps Shadow from starting.
- **Disable sign-in:** set `MCP_OAUTH` to `0`, then deploy. Accounts and replay state stay on the volume. Nobody new can sign
  in, but tokens already issued still work on Shadow and `/mcp` until they expire, and so do those of deleted accounts,
  because nothing checks the deleted list while sign-in is off. Its sweep goes on.
- **Stop logging by default:** set `SHADOW_AUTO_LOG` and `SHADOW_PREVIEW_AUTO_LOG` to `0`, then deploy. Nothing is deleted.

### Rollback with state present

Roll back as in "Rollback" above, and leave the `mcp_state` volume alone. Older builds ignore files they don't know. What
changes, for a build older than this section:

- **Deleted accounts come back to life for a while.** Older builds don't read `accounts/d/`, so a deleted account's token
  works until it expires (access 7 days; a refresh token 60), and can start new records. Its old records stay gone.
- **Revoked links stay dead,** as their capability files are gone, but an older build still hands out the dead URL.
- **Sessions anchored under Shadow's new client** stop at `indeterminate` on the online check, not `fail`, as an older build
  searches only under `CLOCKCHAIN_CLIENT_ID`. It anchors under that client again too.
- **Logging by default returns on the listed paths** if `SHADOW_AUTO_LOG=1` is still set, with the old text. Older builds
  don't know `SHADOW_PREVIEW_AUTO_LOG`, and its paths answer 404.
- **Below `feat/auto-log`:** session metadata was capped at 256 KB. A session within the default 300 anchors can still be read;
  one over about 1,000, from a raised `SHADOW_ANCHORS_PER_SESSION`, can't.

The other way round, a newer build reads everything an older one wrote. Hashes on the ledger are never touched by any of this.

### Back up Shadow and accounts

Shadow, accounts and OAuth replay state all live on the `mcp_state` volume. Back up `shadow`, `accounts` and `oauth` together.
Without `oauth`, spent refresh tokens work again after a restore; without `accounts/d`, deleted accounts do.

```bash
VOL=$(docker volume ls -q --filter label=com.docker.compose.project=clockchain-mcp --filter label=com.docker.compose.volume=mcp_state)
test -n "$VOL" || { echo "no mcp_state volume found: stop"; exit 1; }
MCP=$(docker ps -q --filter label=com.docker.compose.project=clockchain-mcp --filter label=com.docker.compose.service=mcp)
docker stop "$MCP"
docker run --rm -v "$VOL":/s:ro -v "$PWD":/b alpine tar czf /b/mcp-state.tgz -C /s shadow accounts oauth standalone-handshake agent-handshake-v2
docker start "$MCP"
```

The volume lookup comes from Compose's labels and hasn't been run on the box, so check the first backup's contents.

**Stop `mcp` first, for a backup you may restore.** A session is an event log plus a metadata file, written one after the
other, so a live copy can catch the metadata ahead of the log. A session like that refuses to load after a restore
(`shadow_session_inconsistent`). `tar` also exits 1 if a file changes while it reads. A live copy is fine if a few open sessions
may be lost. If Shadow has never run, leave out the directories that don't exist, or `tar` stops.

**A backup is sensitive.** `shadow/owners/*/key.json` holds operator signing keys in the clear, and `events.jsonl` holds whatever
agents recorded, secrets included if they sent any. Encrypt it, and restrict who can read it. **Deleted records stay in old
backups:** delete backups within 30 days, or we keep records past what we promise. Restoring an old backup also brings back
records and accounts people have deleted since, so after a restore, tell the founder and check what came back.

The ledger is separate: back up the `anchor_gateway_data` volume too, as online checks read it. Losing it leaves every session's
online check at `indeterminate`. Restore as above: stop `mcp`, `tar xzpf` into the volume, start `mcp`.

### Purge

`scripts/shadow-purge.mjs` removes sessions by owner or age from the state directory. It's a dry run unless given `--apply`, and
prints no titles or content. From the box checkout:

```bash
MCP=$(docker ps -q --filter label=com.docker.compose.project=clockchain-mcp --filter label=com.docker.compose.service=mcp)
docker exec -i "$MCP" node --input-type=module - --older-than 30d < scripts/shadow-purge.mjs
docker exec -i "$MCP" node --input-type=module - --older-than 30d --apply < scripts/shadow-purge.mjs
docker exec -i "$MCP" node --input-type=module - --owner acct_XXXXXXXXXXXXXXXXXXXXXX --apply < scripts/shadow-purge.mjs
```

While Shadow is off, use `--older-than 30d` daily. Deleting removes the link too. A running server catches up its totals at the
next sweep or restart. The ledger keeps its hashes.

### People can delete their own data

Through tools, on every endpoint, with no help from us:

| Tool | What it does |
|---|---|
| `shadow_revoke_links` | Stops a session's links at once, for good. The record stays. |
| `shadow_delete_session` | Deletes the record and its links at once. |
| `clockchain_delete_account` | Without `confirm: true`, says what would go. With it: the account, all its records and links. The key, cookie and tokens stop working everywhere. |

Each result says hashes stay on the ledger. A deleted account leaves only its id in `accounts/d/`, kept 90 days, so that its tokens
stay refused until the last has expired. It holds no name or key hash.

### Rotating `MCP_TOKEN_SIGNING_SECRET`

**Don't, unless you must. It invalidates every registered client.** OAuth is stateless: a `client_id` is itself sealed under this
secret, as are access tokens, refresh tokens, codes and the account cookie. There's no previous-key support, so after a
rotation:

- Every connected app gets 401, and its refresh fails. Apps that cached their `client_id` get "Unknown client_id" and may not
  register again by themselves, so people may have to remove the connector and add it again.
- Everyone signs in again with their **account key**, which still works, as it's stored as a hash. Anyone with no key and an old
  cookie **has lost their account**: the cookie stops working too.
- `POST /token` keys, and `MCP_PROMOTE_SECRET` if it isn't set separately, stop working as well.
- Records and accounts aren't touched. Directory listings still work, once people reconnect.

Tell the founder and the travel orchestrator first. Treat a leak as the only good reason.

### Shadow's writer on the ledger

`CLOCKCHAIN_CLIENT_ID` in `compose-up.sh` is the founder's email, and without these settings every Shadow anchor shows it.

- **The gateway needs no change for a new id.** `gateway.mjs` has no list of clients. It checks only that a request is signed with
  `GATEWAY_SIGNING_SECRET`, and uses the client only to scope idempotency and search. If production ever anchors to a network that
  checks clients, the id would have to be registered there.
- **Old sessions keep working.** Search is scoped by client, so Shadow searches under both ids. Don't change
  `CLOCKCHAIN_CLIENT_ID` until 30 days after setting these, or older sessions' online checks stop at `indeterminate` until they expire.
- **Others can't use it.** `x-clockchain-client-id` and `-wallet-id` naming these ids get 403 on every MCP request.
- **It covers Shadow only.** `/mcp`'s own writes, including those from an account token, still show the delegated client.

### Directory reviewer account

Both directories want a populated test account. Records expire after 30 days and a review can take longer, so the script can run again:

```bash
node scripts/seed-reviewer-account.mjs --base http://localhost:8080 --key-file /secure/path/reviewer.txt
```

The first run creates the account and writes its key to that file, mode 0600. It prints the key nowhere. Later runs sign in with the
file, keep samples with over 10 days left, replace the rest and verify each. Each new sample spends 3 ledger writes, whose hashes can't
be removed. It refuses any base that isn't local or staging, and unknown hosts count as production. For the real account, the founder
runs it with `--base https://mcp.clockchain.network --allow-production`, just before submitting and at least every 20 days during
review. This creates a production account on purpose. Put the key in a password manager, and enter it only in the portal's secure
review form. To retire the account, call `clockchain_delete_account {confirm: true}`.

`scripts/chatgpt-review-cases.mjs` then runs the tools behind the review test cases against that account. See `infra/chatgpt-plugin/README.md`.

### ChatGPT domain check

OpenAI's portal gives a token to serve as plain text at `/.well-known/openai-apps-challenge`. Set
`/clockchain/mcp/OPENAI_APPS_CHALLENGE_TOKEN` to it and deploy. Check with `curl -s https://mcp.clockchain.network/.well-known/openai-apps-challenge`.
Unset, the path answers like any other unknown path. One hostname serves one plugin's token, so a second plugin here needs the parent domain.

### Moving to mainnet

Not rehearsed: no mainnet endpoint exists yet to test against. Do these in order, on staging first.

1. Get from the network team: the mainnet endpoint, the keys and writer identity, whether the ledger API and receipts match the testnet's, and what credits cost.
2. Decide free use. On mainnet the anonymous key from `POST /token` and trial tokens stop working, those already issued too, unless `MCP_MAINNET_FREE_TOKENS=1`. Signed-in accounts keep working on Shadow, within their limits, but `/mcp` refuses them with 403 unless that setting is on, because writes there spend the server's own credits with no per-account limit. `/promote` and `/connect/mcp` answer 503 too unless that setting is on. **`/handshake/mcp` and `/next/handshake/mcp` also write with the delegated key and take no account of this setting.** Decide before the switch whether they stay on, since they're frozen and aren't changed here.
3. Lower `SHADOW_ANCHORS_PER_DAY`, `MCP_RATE_PER_MIN` and the free-key limit to what the credits can pay for.
4. Set `CLOCKCHAIN_ENDPOINT`, `CLOCKCHAIN_SUBSTRATE`, the writer identity (`SHADOW_LEDGER_CLIENT_ID` and `SHADOW_LEDGER_WALLET_ID`, required on mainnet, and not an email address) and `SHADOW_NETWORK=mainnet` together. Nothing checks that the endpoint and the network name agree, and any value other than `testnet` or `mainnet` refuses to start, then deploy with `--full-restart`, because the settings are read at start. Tell the travel orchestrator first.
5. Run the public end-to-end check, then one session from real Claude Code, and look its last anchor up on the new ledger.

**What the switch changes:** the sign-in pages, `/shadow/connect`, the landing and status pages and the server instructions, none of which promise free use on mainnet. New sessions are recorded as `clockchain-mainnet`.

**What it doesn't change yet:** the clock tools' descriptions on `/mcp` and the receipts' `assurance` text in `packages/core` still say testnet and single validator. They need the network's real facts first, so write them then. The landing page's disclaimer also needs rewriting. `/handshake/*`, `/next/handshake/*` and `/acm4/*` are frozen and not touched, except that the handshake guide page's text uses the same network label.

**Sessions from before the switch** keep their network. They take no new steps (a log tool tells the agent to start a new session), and nothing they still owe goes to the new ledger. They can still close, signed but not anchored. `shadow_verify` checks them offline and says why, and the result is indeterminate rather than a pass when the check needs the ledger. Their packets and viewer links keep working until they expire. To check them online, the old gateway has to stay readable; there's no setting for that yet.

**Rollback:** set `SHADOW_NETWORK` and `CLOCKCHAIN_ENDPOINT` back and restart. Sessions started on mainnet then behave the same way in reverse.

### Memory

The server logs `process_memory` every 10 minutes: heap, resident memory and open `/mcp` streams. Production ran out of heap once, at 03:15 UTC on 6 November, after 18 hours up with about 350 MB still live, and restarted itself in about a second. **The cause isn't known.** Measured leaks explain about 1/70 of it, so if `heapUsedMb` climbs steadily, take a heap snapshot before it dies, or add `--heapsnapshot-near-heap-limit=1` with a `--diagnostic-dir` on the state volume, which needs spare memory and disk. `/mcp` allows `MCP_MAX_OPEN_STREAMS` held-open GETs at once (default 200, about 0.5 MB each) and answers 503 past that.

### Sessions that close by themselves

With logging on by default nobody asks to close, so an open session with no new step closes after `SHADOW_IDLE_CLOSE_HOURS` (default 24 when logging by default is on, otherwise off; `off` turns it off). The check runs with the hourly sweep and not at start-up, at most 200 sessions a pass, oldest first, and each spends one anchor from that account's daily limit. If the anchor can't land, because the gateway is down or the limit is used up, later passes retry it. It is on by default wherever logging by default is on, so deploying this build turns it on for production. Sessions from before this build count from their metadata file's last write. At the open-session limit, a session idle for over an hour closes to make room. A later step on a closed session gets `SHADOW_SESSION_CLOSED`, and the log tools tell the agent to start a new session. Logs: `shadow_idle_closed`, `shadow_idle_close_failed`.

### Publishing to the MCP registry

There's no publish script: `scripts/` has none, and `.github` doesn't do it. It's done by hand, from a person's machine. Nothing has been
published from this branch. These steps come from `mcp-launch-plan.md` and search results, not the publisher's own docs, so check them against
`mcp-publisher --help` first.

1. Get `mcp-publisher` from `modelcontextprotocol/registry`.
2. Log in for the `network.clockchain` namespace with DNS (`mcp-publisher login dns --domain clockchain.network`). It prints a TXT record for
   `clockchain.network`. The namespace was verified once already, as `network.clockchain/time` is published, but we don't hold that key in this repo.
3. `mcp-publisher validate`, then `mcp-publisher publish`, with `server.json` in the current directory. To publish the draft, copy
   `server.shadow.draft.json` to `server.json` elsewhere and remove its `___DRAFT_WARNING`.

Today (read 4 November):

- **`network.clockchain/time` is live and broken.** Version 0.1.0, published 7 July, status active, points at a Cloud Run URL that answers 503. It also
  says "neutral verified network time". Its source isn't in this repo.
- **`network.clockchain/clockchain` isn't published.** `server.json` is ready for a first publish, and passes the 2025-12-11 schema. It didn't before:
  its description was 290 characters, and the schema allows 100.
- **`network.clockchain/shadow`** is `server.shadow.draft.json`. Publish it only once the privacy, terms and support pages are live and
  production runs with `SHADOW_AUTO_LOG` unset.
- **`server.product.draft.json`** stays unpublished (`PRODUCT-VS-TEST.md`).
- **Order:** publish `clockchain`, mark `time` deprecated, and publish `shadow` when it's ready. `repository` points at the public
  `thetangstr/clockchain-developer-tools`, while the code now lives in the private `clockchain-network/clockchain-mcp`. A person checking the link sees the old repo. That's the founder's call.

