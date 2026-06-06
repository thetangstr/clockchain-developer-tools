# MCP Server Deployment

Three hosting tiers, in order of when we use them:

1. **Local stdio** - for developers. `npx`, no host. (Already in the plan.)
2. **Mac mini test host** - for business users + AgentDash. **This is the new
   one.** A running HTTP endpoint testers can hit without installing anything.
3. **AWS** - production. Plan is ready below; build is gated on a go decision, and
   a *public* endpoint is gated to mainnet (Q9).

The Mac mini is a **private test endpoint**, not a public listing - it does not
conflict with the "no public distribution until mainnet" decision.

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

Lighter alternative without Docker: `pm2 start dist/server.js` with the same env.
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
> env $(grep -v "^#" ~/clockchain-mcp/.env | xargs) \
>   pm2 start packages/mcp-server/dist/server.js --name clockchain-mcp
> pm2 save && pm2 startup   # survive reboots
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
