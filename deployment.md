# MCP Server Deployment

Three hosting tiers, in order of when we use them:

1. **Local stdio** - for developers. `npx`, no host. (Already in the plan.)
2. **Mac mini test host** - for business users + AgentDash. **This is the new
   one.** A running HTTP endpoint testers can hit without installing anything.
3. **AWS or GCP** - production. Plans for both are below; build is gated on a go
   decision, and a *public* endpoint is gated to mainnet (Q9).

The Mac mini is a **private test endpoint**, not a public listing - it does not
conflict with the "no public distribution until mainnet" decision.

### Hosting as business scenarios (the Goldilocks pick)

Each tier is a different business situation, not just a different server. Framed
by who it serves, what it costs, and what it exposes:

| Tier | Business scenario | Cost / effort | Exposure | Fit |
|---|---|---|---|---|
| **Local stdio** | A single developer trying the tools on their laptop. No one else can reach it. | ~$0, minutes | none | **Too small** - can't put it in front of a business tester |
| **Mac mini test host** | "Let a handful of business users and our AgentDash agents try it this month" on hardware we already own. | ~$0 new, hours | private (LAN / tailnet) | **Goldilocks for testing now** |
| **GCP Cloud Run** | "Give me a real managed URL I can share, that scales to zero when idle and costs cents." Managed prod without an ops team. | ~$/mo, ~1 day | private or public (gated) | **Goldilocks for first real hosting** |
| **AWS ECS Fargate + ALB** | "Production launch posture" - always-on, autoscaled, full VPC/secrets/CI footprint. | $$/mo, days | public (mainnet-gated) | **Too big until we're launching** |

**Goldilocks reading:** use the **Mac mini now** (zero new spend, private, already
the AgentDash box) to get business feedback; when we need a real shareable
endpoint, **GCP Cloud Run** is the just-right next step (managed, scale-to-zero,
cheap, TLS included) before committing to the heavier always-on AWS stack. AWS
remains the documented path if we standardize there or need its specific
footprint. Pick the cloud by where the rest of the infra lives; the server image
is identical on both.

---

## 0. Network exposure model (FOR NETWORK-TEAM APPROVAL)

> **Status: PROPOSED - awaiting network-team sign-off.** The network team raised
> that we should not stand up a networked, credentialed endpoint that fronts the
> Clockchain server. This section is the proposal to address that, in a form they
> can approve. Sign-off block at the bottom.

### The concern, restated
Our MCP server holds a Clockchain API key and calls the gateway
(`node.clockchain.network`). If we host that MCP as a network-reachable endpoint,
it becomes a credentialed inbound path into Clockchain. The ask is to avoid that.

### Proposal (one line)
**Default to stdio (no network listener); when a networked endpoint is genuinely
needed, bind to the tailnet only; never a public bind for a key-holding endpoint.**

### Reachability scopes on the Mac mini (probed 2026-06)
| Scope | Address | Who can reach it |
|---|---|---|
| loopback | `127.0.0.1` | the Mac mini only |
| LAN | `192.168.86.0/24` (`192.168.86.48`) | anything on the office/home subnet |
| tailnet | `100.71.225.125` (Tailscale) | only devices in the Clockchain tailnet |
| public | only via a tunnel / port-forward | the entire internet |

(The box is behind NAT, so it is **not** publicly reachable unless we add a tunnel.
AgentDash's own deployment uses the same `loopback / lan / tailnet` bind modes.)

### Transport -> what it exposes
| Transport / bind | Reachable from | Credentialed exposure |
|---|---|---|
| **stdio** | nothing (no listener) | none |
| HTTP loopback | the Mac mini only | none beyond the host |
| HTTP LAN | the subnet | anyone on the LAN |
| HTTP tailnet | tailnet members | controlled membership |
| HTTP + public tunnel | the internet | maximal - avoid |

### Proposed posture by audience
- **AgentDash / Claude (run ON the Mac mini): stdio, or HTTP on loopback.** They
  are co-located, so they need nothing beyond the host. **No network exposure.**
- **Remote business testers: tailnet bind only** (Tailscale membership), never a
  LAN-wide or public bind.
- **Public bind / tunnel for a key-holding endpoint: not done.**
- **v3 on AWS:** an ALB is public by definition, so it only proceeds if the network
  team approves a public (mainnet-gated) endpoint; otherwise v3 is tailnet/VPN-only
  or we distribute the stdio server instead of hosting.

Note: the Clockchain gateway is on the public internet, so the MCP always makes an
**outbound** call to it. This proposal removes the **inbound** credentialed path,
not the outbound call (that only changes if the gateway itself is locked to a
private network).

### Decisions requested from the network team
1. Approve **stdio / loopback as the default** for co-located agents (no exposure). [ ]
2. Approve **tailnet-only** for any remote tester access (no LAN-wide, no public). [ ]
3. Clarify what "expose the Clockchain server" means:
   - (a) "Do not add a new hosted, credentialed MCP endpoint" -> covered by 1 + 2. [ ]
   - (b) "Lock `node.clockchain.network` itself to a private network / allowlist"
     -> larger change; consumers must then be on that network (tailnet fits). [ ]
4. v3 hosted-on-AWS: approve a public, mainnet-gated endpoint [ ], or require
   tailnet/VPN-only [ ], or do not host (distribute stdio) [ ].

### Question back to the network team (paste this)
> Our MCP server holds a Clockchain API key and calls `node.clockchain.network`
> outbound. Our default plan is to run it as a local stdio subprocess (no network
> listener) for the agents on the Mac mini, and to bind to the Tailscale tailnet
> only if a remote tester ever needs HTTP access - never a public or LAN-wide bind
> for the key-holding endpoint. Does that satisfy "do not expose the Clockchain
> server"? Or do you also want `node.clockchain.network` itself restricted to a
> private network / allowlist (in which case consumer machines would need to be on
> that network/tailnet)? And for an eventual AWS deployment, is a public
> mainnet-gated endpoint acceptable, or must it stay tailnet/VPN-only?

### Sign-off
- Network team reviewer: ____________________  Date: __________
- Decision: approved as proposed / approved with changes / needs discussion
- Notes: ________________________________________________

---

## 1. Mac mini test host (business-user testing)

Goal: one running MCP endpoint that business users and AgentDash can hit, with no
per-tester install.

### Run it

Docker is preferred (same image we'll run on AWS - parity):

```bash
docker run -d --name clockchain-mcp --restart unless-stopped \
  -p 3000:3000 \
  -e MCP_TRANSPORT=http -e MCP_PORT=3000 \
  -e CLOCKCHAIN_API_KEY=...           # stays on the box, never given to testers \
  -e CLOCKCHAIN_CLIENT_ID=... -e CLOCKCHAIN_WALLET_ID=... \
  -e EVM_RPC_URL=...                  # for the ERC-8004 read \
  -e MCP_AUTH_TOKENS=tester-a,tester-b   # tester tokens (MCP-layer auth) \
  clockchain/mcp-server
```

Lighter alternative without Docker: `pm2 start ecosystem.config.cjs` from
`packages/mcp-server` (after `set -a; source .env; set +a`). The runnable entry is
`dist/index.js` (it dispatches on `MCP_TRANSPORT`); `dist/server.js` only exports
`buildServer()` and does nothing when run directly.
Either way, disable Mac mini sleep so it stays reachable
(`sudo pmset -a sleep 0 disablesleep 1`).

### Expose it

- **AgentDash and same-LAN testers:** hit it directly at
  `http://<mac-mini-LAN-IP>:3000/mcp`. (AgentDash runs on the LAN at
  192.168.86.48, so if the Mac mini is on the same subnet this works with no
  tunnel.)
- **Off-network business testers:** put a **Cloudflare Tunnel** in front - a
  stable `https://mcp-test.<domain>` URL, free, TLS included, no port-forwarding,
  and optional Cloudflare Access to gate who can reach it. `ngrok` is the quick
  alternative for ad-hoc demos.

### Secure it (it is write-capable and reachable)

- **The Clockchain API key lives only on the Mac mini.** Testers never see it.
  Non-custodial: no private keys on the box.
- **Testers authenticate to the MCP with a separate tester token** (`x-api-key`
  at the MCP layer), not the Clockchain key. Rotate/revoke per tester.
- **Cap the credit budget** on the test Clockchain account so a runaway test
  cannot drain it.
- **Rate-limit and log every tool call** (the observability requirement) so we
  learn from the test sessions.
- **Scope the tools** to read + `log_action` for this test. Keep `schedule` /
  `attest_time` (key-bearing / EVM writes) off the test host.

### What a business tester needs

The endpoint URL and their tester token. Nothing installed. They (or AgentDash)
point an MCP client at the URL with the token header.

### Runbook (ready to run once the POC server exists)

> **Prerequisite:** the Phase 3 POC server must be built and published as an image
> (`clockchain/mcp-server`) or an npm package first. We are at spec stage - there
> is no server to run today. This is the script for the moment it exists; to make
> it runnable, the minimal server (Phase 1 core + Phase 3 stdio/http) has to be
> built. Everything below is copy-paste-ready except the `__FILL__` values.

**Step 0 - values to fill in** (from the checklist in section 3; most are shared
with AWS):
`CLOCKCHAIN_API_KEY`, `CLOCKCHAIN_CLIENT_ID`, `CLOCKCHAIN_WALLET_ID`,
`EVM_RPC_URL`, `ERC8004_CHAIN` (base / base-sepolia / ethereum), and a list of
`MCP_AUTH_TOKENS` for testers.

**Step 1 - prep the Mac mini**

```bash
# Docker Desktop (or Colima) installed and set to start on login.
# Keep the machine reachable:
sudo pmset -a sleep 0 disablesleep 1
# Note the LAN IP (AgentDash will use this):
ipconfig getifaddr en0
```

**Step 2 - env file** `~/clockchain-mcp/.env`

```
MCP_TRANSPORT=http
MCP_PORT=3000
CLOCKCHAIN_API_KEY=__FILL__
CLOCKCHAIN_CLIENT_ID=__FILL__
CLOCKCHAIN_WALLET_ID=__FILL__
EVM_RPC_URL=__FILL__
ERC8004_CHAIN=base-sepolia
MCP_AUTH_TOKENS=tester-a,tester-b
```

**Step 3 - run it**

```bash
docker run -d --name clockchain-mcp --restart unless-stopped \
  -p 3000:3000 --env-file ~/clockchain-mcp/.env \
  clockchain/mcp-server
```

> **This Mac mini specifically (probed 2026-06): no Docker installed.** It has
> node v26 at `/opt/homebrew/bin/node` and uses pnpm (that is how AgentDash runs).
> So either install Colima/Docker first, or - simpler, matches the box - run via
> node + pm2:
>
> ```bash
> pnpm --filter @clockchain/mcp-server build
> npm i -g pm2
> cd packages/mcp-server
> cp .env.example .env        # then fill in secrets
> set -a; source .env; set +a # export .env into the shell
> pm2 start ecosystem.config.cjs   # runs dist/index.js (MCP_TRANSPORT=http)
> pm2 save && pm2 startup     # survive reboots
> ```

**Step 4 - verify locally**

```bash
curl -s localhost:3000/health
curl -s -X POST localhost:3000/mcp \
  -H "x-api-key: tester-a" -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

**Step 5 - expose to off-network testers (Cloudflare Tunnel)**

```bash
brew install cloudflared
cloudflared tunnel login
cloudflared tunnel create clockchain-mcp
cloudflared tunnel route dns clockchain-mcp mcp-test.<domain>
# ingress -> service: http://localhost:3000, then:
cloudflared tunnel run clockchain-mcp
# Quick ad-hoc alternative (ephemeral URL, no domain needed):
# cloudflared tunnel --url http://localhost:3000
```

LAN testers and AgentDash skip step 5 and use `http://<LAN-IP>:3000/mcp` directly.

---

## 2. AgentDash integration (resolved 2026-06, by inspecting the box)

**AgentDash runs ON the Mac mini.** It *is* `mac-mini.lan` / `192.168.86.48`
(subnet `192.168.86.0/24`), a node process serving `:3100`. Internally the
product is "Paperclip" (`@paperclipai`). Two findings settle the wiring:

**AgentDash itself is not an MCP client.** Its codebase has no MCP client SDK
import, no `mcpServers` config, and no HTTP/SSE client transport (verified by
grep). It only *exposes itself* as an MCP server (`@paperclipai/mcp-server`,
stdio). So AgentDash-the-app will not dial our MCP directly - there is no
remote-MCP-client feature to rely on in the app.

**But AgentDash orchestrates agents through runtime adapters** - its constants
list `claude_local`, `codex_local`, `cursor`, `opencode_local`, `gemini_local`,
`hermes_local`, `openclaw_gateway`, plus generic `process` / `http`. Those
runtimes (Claude Code, Cursor, Codex, OpenCode, ...) are what support MCP servers,
including remote/HTTP. So the integration path is: **wire our MCP into the agent
runtime AgentDash launches** (in that runtime's MCP config), not into AgentDash.

**Co-located, so no tunnel for local agents.** Because those runtimes run on the
same Mac mini, they reach our MCP at `http://localhost:3000/mcp` (HTTP) or via
stdio (`npx`). `192.168.86.48:3000` works for anything else on the subnet. The
box is also on **Tailscale** (`100.71.225.125`), and AgentDash even has a
`tailnet` bind mode - so off-network testers can use the tailnet instead of a
Cloudflare Tunnel.

Net: an agent run by AgentDash can use our MCP, configured at the runtime layer on
localhost. Nothing changes in AgentDash itself.

### Clark = our Hermes agent (Slack) - the primary v2 consumer

**Clark** is our Slackbot, backed by a **Clockchain-profiled Hermes agent running
on the Mac mini** (`hermes ... --profile clockchain gateway run`, live on the box).
Hermes *is* the harness / MCP client, co-located with our server - so Clark reaches
our tools over **local stdio, no network, no Cloudflare**. Slack workspace/channel
membership is the access gate.

Hermes has a first-class MCP CLI (`hermes mcp add/list/test`), and MCP servers are
registered **per profile**. The `clockchain` profile currently has none, so adding
ours is clean. Registration (run on the Mac mini, once the built server is present
there):

```bash
hermes --profile clockchain mcp add clockchain \
  --command node \
  --args /Users/maxiaoer/clockchain-developer-tools/packages/mcp-server/dist/stdio.js \
  --env CLOCKCHAIN_API_KEY=... CLOCKCHAIN_CLIENT_ID=... CLOCKCHAIN_WALLET_ID=...
hermes --profile clockchain mcp test clockchain     # verify the connection
# then reload the clockchain gateway so Clark picks up the new toolset
```

Prerequisite: the server must exist on the box (e.g. `git clone` + `npm install` +
`npm run build`, or copy `dist/`). After this, Clark can use `get_time`,
`log_action`, `verify_asset`, etc. directly in Slack.

### Exact place to register our MCP (for a Claude Code / `claude_local` agent)

AgentDash's `process` adapter spawns the runtime with a `command` + `args` +
`cwd` and injects no MCP config. Claude Code (installed on the box - `~/.claude.json`
exists, with a `mcpServers` key already holding `chrome-devtools`) reads its MCP
servers from, in order:

1. **Per-project `.mcp.json`** at the run's `cwd` (the worktree AgentDash realizes).
2. **`~/.claude.json` -> `projects["<cwd>"].mcpServers`** (per-project, in the user
   config; the box already has project entries here).
3. **`~/.claude.json` -> top-level `mcpServers`** (global, all runs on the box -
   simplest for a test).

Drop our server into one of those. Simplest for a local agent on this box is
**stdio in the global `~/.claude.json` `mcpServers`**, next to `chrome-devtools`:

```json
"clockchain": {
  "command": "npx",
  "args": ["-y", "@clockchain/mcp-server"],
  "env": {
    "CLOCKCHAIN_API_KEY": "...", "CLOCKCHAIN_CLIENT_ID": "...",
    "CLOCKCHAIN_WALLET_ID": "...", "EVM_RPC_URL": "...",
    "ERC8004_CHAIN": "base-sepolia"
  }
}
```

Or, to point a Claude Code agent at the HTTP host we run for business testers
(same box, so localhost):

```json
"clockchain": {
  "type": "http",
  "url": "http://localhost:3000/mcp",
  "headers": { "x-api-key": "<tester token>" }
}
```

Recommendation: **stdio via `~/.claude.json` for AgentDash's local agents**
(simplest, no host needed), and reserve the HTTP endpoint on the Mac mini for
remote business testers. Both run off the same package; the POC ships both
transports.

---

## 3. AWS production deployment plan

Target architecture (from the spec): ECR image -> ECS Fargate service -> ALB
(TLS) -> endpoint; secrets in Secrets Manager; egress to
`node.clockchain.network` and the EVM RPC.

### Steps

1. Build and push the image to **ECR**.
2. Put secrets in **Secrets Manager**: `CLOCKCHAIN_API_KEY`, `EVM_RPC_URL`, MCP
   tester/auth tokens.
3. **ECS Fargate** service (256 MB / 0.25 vCPU to start) in a VPC with public
   egress; inject secrets as env.
4. **ALB** + **ACM** TLS cert + **Route53** record (test subdomain now;
   `mcp.clockchain.network` only at mainnet).
5. `/health` health check; CloudWatch logs; optional autoscaling.
6. **CI/CD:** GitHub Actions (repo is already on GitHub) -> build -> push ECR ->
   update ECS service, via an OIDC deploy role.

### What I need from you / D4 to finalize the AWS plan

**AWS account & access**
- [ ] AWS account ID and region
- [ ] Who has deploy access (IAM), or can we use a GitHub OIDC deploy role
- [ ] New VPC, or reuse the D4 node's account/VPC? (reusing simplifies egress and
      can share the ALB)

**Networking & domain**
- [ ] Endpoint hostname (e.g. `mcp-test.clockchain.network`)
- [ ] Is DNS in Route53? (needed for the ACM cert)

**Secrets & identity**
- [ ] Confirm Secrets Manager (or SSM Parameter Store)
- [ ] Which Clockchain account (API key + client/wallet) the hosted server uses
- [ ] Auth model for testers: one shared token, or per-user tokens; do we map
      them to Clockchain client IDs?

**Chain / RPC (new, from the ERC-8004 commit)**
- [ ] EVM RPC provider + URL
- [ ] Target chain for ERC-8004 reads: Base mainnet, Base Sepolia, or Ethereum?

**Scale & budget**
- [ ] Expected concurrent testers / call volume (to size Fargate + rate limits)
- [ ] Monthly cost ceiling, and the credit budget cap on the test account

Give me those and I can turn this into concrete Terraform / a deploy script. Most
of them also apply to the Mac mini host (API key, EVM RPC, target chain, tester
tokens), so answering them unblocks both.

---

## 4. GCP production deployment plan (alternative to AWS)

Same container, different cloud. **Cloud Run** is the recommended GCP target: it
is serverless, scales to zero (you pay only per request - cheap for a POC/early
prod), includes managed TLS, and deploys in one command. It is the "Goldilocks"
first real host above. (Use **GKE** instead only if we need long-lived connections
or already run a cluster.)

Target architecture: Artifact Registry image -> Cloud Run service -> managed
HTTPS URL; secrets in Secret Manager; egress to `node.clockchain.network` and the
EVM RPC. We already have a GCP project on hand (`yarda-740f4`).

### Steps

1. Build and push the image to **Artifact Registry**
   (`gcloud builds submit` or `docker push`).
2. Put secrets in **Secret Manager**: `CLOCKCHAIN_API_KEY`, `EVM_RPC_URL`, MCP
   tester/auth tokens; grant the Cloud Run service account access.
3. **Deploy to Cloud Run** (256-512 MB, scale-to-zero), injecting secrets as env:
   ```bash
   gcloud run deploy clockchain-mcp \
     --image <region>-docker.pkg.dev/<project>/mcp/clockchain-mcp \
     --region <region> --port 3000 \
     --set-env-vars MCP_TRANSPORT=http,MCP_PORT=3000,ERC8004_CHAIN=base-sepolia \
     --set-secrets CLOCKCHAIN_API_KEY=clockchain-api-key:latest,EVM_RPC_URL=evm-rpc-url:latest \
     --no-allow-unauthenticated      # keep it private until mainnet (Q9)
   ```
4. **Access control:** `--no-allow-unauthenticated` + IAM (or an internal load
   balancer / IAP) keeps it private - the non-public posture the network team
   asked for. Flip to public only at mainnet. Cloud Run gives a managed
   `*.run.app` HTTPS URL; map a custom domain when wanted.
5. **Health/observability:** `/health` check; logs/metrics flow to **Cloud
   Logging / Monitoring** automatically.
6. **CI/CD:** GitHub Actions -> **Workload Identity Federation** (keyless) -> build,
   push to Artifact Registry, `gcloud run deploy`.

### What I need from you / D4 to finalize the GCP plan

Mostly the same as AWS, GCP-flavored:
- [ ] GCP **project ID** + **region** (reuse `yarda-740f4`, or a dedicated project?)
- [ ] Deploy access: a CI service account, or GitHub **Workload Identity Federation**
- [ ] Confirm **Secret Manager** for the API key / RPC / tester tokens
- [ ] Which Clockchain account (API key + client/wallet) the hosted server uses
- [ ] **Public vs private**: keep `--no-allow-unauthenticated` (recommended pre-mainnet) or expose via IAP/allowlist
- [ ] Custom domain (e.g. `mcp-test.clockchain.network`) or use the `*.run.app` URL
- [ ] EVM RPC provider + target chain (Base mainnet / Base Sepolia / Ethereum)
- [ ] Expected call volume + monthly cost ceiling, and the credit budget cap

The chain/RPC, Clockchain account, and tester-token answers are shared with the
AWS and Mac mini setups - answering once unblocks all three.
