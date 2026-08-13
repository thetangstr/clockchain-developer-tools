# Clockchain MCP and Agent Handshake on AWS

This deployment keeps the existing EC2, Docker Compose, and Caddy edge. Caddy is
the only public ingress. The authenticated MCP remains at `/mcp`; the isolated
seven-tool stakeholder handshake is at `/handshake/mcp`; `/health` stays public.

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
- `/clockchain/mcp/AGENT_HANDSHAKE_RELEASE_PIN`
- `/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE`
- `/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS`
- `/clockchain/host/FUNDING_WALLET_JSON`
- `/clockchain/host/FUNDING_WALLET_PUBLIC_JSON`
- `/clockchain/host/FUNDING_PASSWORD`
- `/clockchain/host/CLOCKCHAIN_TOKEN`
- `/clockchain/host/AGENT_HANDSHAKE_V2_HOST_ROOT_KEY`

The release pin is public metadata held in SSM so that the deploy is atomic. It
must name the immutable helper release, manifest digest, and active/previous
host-root fingerprints. Role-access keys are server signing keys; generated
stakeholder capabilities are never stored in SSM.

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
   key pair if required. From that exact checkout, run
   `sudo infra/scripts/install-clockchain-mcp-deploy-assets.sh`. The installer
   first refreshes the out-of-checkout `compose-up.sh` and systemd unit, then
   restarts the service. The refreshed wrapper verifies the exact Handshake SHA
   before Docker starts and atomically replaces the private host files. Never
   restart the service directly after changing the checkout: systemd deliberately
   executes `/opt/clockchain-mcp/compose-up.sh`, not the copy inside the repo.
4. Deploy Research only after the production MCP manifest reports the same
   helper digest and host-root ring that Research pins.

The v2 host reserves both fresh-registration seats before either transfer. Its
private ledger survives restarts at `/app/runs/private/v2-funding-ledger.jsonl`.
New reservations use 0.02 Sepolia ETH per address and 0.04 per required-fresh
session, providing enough testnet gas margin for ERC-8004 registration and
metadata finalization during ordinary fee spikes. The restart-safe ledger still
accepts historical 0.01 entries. The rolling-hour limit defaults to 0.20 ETH and
may be raised only for a controlled test through
`AGENT_HANDSHAKE_V2_FUNDING_MAX_HOURLY_ETH` (the host rejects values above
0.40); the UTC-day limit remains 1.00. Address-free warnings remain 0.16 and
0.80. Queue capacity is 16
reservations. This is gas-only infrastructure funding for public v2 identity
registration, never stakeholder payment or external business action; generic v1 and bilateral funding behavior is unchanged.

## Production canaries

Run these before any stakeholder demonstration:

```text
GET https://mcp.clockchain.network/health                         -> 200
GET https://mcp-aws.clockchain.network/health                     -> 200
GET https://mcp.clockchain.network/.well-known/agent-handshake.json -> 200 and the approved release pin
POST https://mcp.clockchain.network/handshake/mcp                 -> MCP initialize without an authenticated-MCP credential
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
