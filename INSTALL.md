# Install the Clockchain MCP server

Add Clockchain's tools (consensus time, notarization, smart-contract scheduling,
audit trails, agent identity verification — 25 tools across five modules) to your
AI coding agent. Two ways: **local** (you run it, recommended) or **remote** (you
connect to a hosted endpoint).

## Prerequisites
- **Node.js 18+**
- A **Clockchain API key** (from your Clockchain dashboard) + your client/wallet id

---

Your key stays on your machine; the server has **no network listener** (it only
calls Clockchain outbound).

## Install from source (current method)

The package isn't on npm yet, so install from the repo. You need **GitHub access
to `thetangstr/clockchain-developer-tools`** (it's private - ask the team).

```bash
git clone https://github.com/thetangstr/clockchain-developer-tools.git
cd clockchain-developer-tools
npm install
npm run build
```

### Register with Claude Code (run from the repo root)
```bash
claude mcp add clockchain \
  --env CLOCKCHAIN_API_KEY=<your key> \
  --env CLOCKCHAIN_CLIENT_ID=<you@example.com> \
  --env CLOCKCHAIN_WALLET_ID=<you@example.com> \
  -- node "$(pwd)/packages/mcp-server/dist/stdio.js"
```
Then open a **new** session, run `/mcp` (you should see `clockchain`), and ask:
*"use clockchain to get the current consensus time."*

### Claude Desktop / Cursor / any MCP host (manual config)
Add to the host's MCP config (`claude_desktop_config.json`, `~/.claude.json`
`mcpServers`, etc.) - use the **absolute path** to the built file:
```json
{
  "mcpServers": {
    "clockchain": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/clockchain-developer-tools/packages/mcp-server/dist/stdio.js"],
      "env": {
        "CLOCKCHAIN_API_KEY": "<your key>",
        "CLOCKCHAIN_CLIENT_ID": "<you@example.com>",
        "CLOCKCHAIN_WALLET_ID": "<you@example.com>"
      }
    }
  }
}
```
After pulling updates: `git pull && npm run build`, then restart your MCP host.

## Install via npm (coming soon)

Once `@clockchain/mcp-server` is published, install becomes one command (no clone):
```bash
claude mcp add clockchain \
  --env CLOCKCHAIN_API_KEY=<your key> \
  --env CLOCKCHAIN_CLIENT_ID=<you@example.com> \
  --env CLOCKCHAIN_WALLET_ID=<you@example.com> \
  -- npx -y @clockchain/mcp-server
```
Manual config (npm):
```json
{
  "mcpServers": {
    "clockchain": {
      "command": "npx",
      "args": ["-y", "@clockchain/mcp-server"],
      "env": {
        "CLOCKCHAIN_API_KEY": "<your key>",
        "CLOCKCHAIN_CLIENT_ID": "<you@example.com>",
        "CLOCKCHAIN_WALLET_ID": "<you@example.com>"
      }
    }
  }
}
```

### Optional: ERC-8004 identity reads (`resolve_agent`)
Defaults point at the ERC-8004 reference deployment on Ethereum Sepolia. Override:
```
EVM_RPC_URL=<rpc url>  ERC8004_CHAIN=<chain>  ERC8004_REGISTRY_ADDRESS=<0x...>
```

---

## Remote install (HTTP) - for users who shouldn't hold a key

Connect to a hosted Clockchain MCP endpoint with a per-user token (the Clockchain
key stays on the server). See `DELEGATED-ACCESS.md` for hosting + token issuance.
```bash
claude mcp add clockchain --transport http https://mcp.clockchain.network/mcp \
  --header "x-api-key: <your tester token>"
```

### Bring your own Clockchain key (own credits)

Two ways to use the hosted endpoint:

- **Delegated** (above): authenticate with the per-user MCP token; the server's own
  Clockchain key does the work, so writes spend *our* credits. Easiest for a quick
  test — you don't need a Clockchain key.
- **Bring-your-own-key**: send *your* Clockchain credentials as headers. The server
  uses them for your calls, so writes spend *your* credits. No MCP token needed —
  your Clockchain key authenticates you (the gateway validates it).

```bash
claude mcp add clockchain --transport http https://mcp.clockchain.network/mcp \
  --header "x-clockchain-api-key: <your clockchain api key>" \
  --header "x-clockchain-client-id: <you@example.com>" \
  --header "x-clockchain-wallet-id: <you@example.com>"
```

The endpoint is fixed server-side; you cannot redirect it. Headers travel over TLS.

### Claude Cowork / claude.ai / Claude Desktop (cloud connectors)

These clients reach your MCP server **from Anthropic's cloud, not from your
machine** - so the **local stdio install above does NOT work for them**. They
require the **remote HTTPS endpoint**, and it must be reachable over the public
internet from Anthropic's IP ranges (a server on localhost, a VPN, or behind a
firewall won't connect).

> **Status:** the hosted endpoint is **live** at `https://mcp.clockchain.network/mcp`
> (Cloud Run, token-gated). Config-file clients — **Claude Code (CLI or web)** and
> **Cursor** — connect with the `--header "x-api-key: <token>"` command above. The
> **chat-connector** clients (claude.ai chat, Cowork) only accept OAuth/authless in
> their connector UI, not a static token — so those need either an authless setup or
> the Claude-Desktop bridge; see the auth notes in [`auth-and-traffic-decision.md`](auth-and-traffic-decision.md).

Once the endpoint is hosted, add it as a **custom connector**:
1. In Cowork (or claude.ai / Desktop): **Settings → Connectors → Add custom connector**.
2. Paste the MCP server URL, e.g. `https://mcp.clockchain.network/mcp`.
3. Authenticate when prompted (OAuth or the per-user token the host issues - the
   Clockchain key stays server-side).

See Anthropic's guide: *Get started with custom connectors using remote MCP*
(support.claude.com). The server already speaks the right protocol
(StreamableHTTP, `packages/mcp-server/src/http.ts`); only hosting + a
connector-compatible auth layer remain.

---

## Network & tokens at a glance

| | Local (npm/stdio) | Remote (HTTP) |
|---|---|---|
| Network | no listener; outbound-only to the gateway | hosted endpoint (behind Cloudflare Access) |
| Who holds the Clockchain key | you (your machine) | the host (server-side) |
| Your "token" | your own Clockchain API key | a per-user token the host issues |
| Non-custodial | yes - no private keys in the server | yes - key custodied on the host, not shared |

## The tools you get
**25 tools across five modules** (`/mcp` should list `clockchain` with all 25):

- **Time oracle:** `get_time`, `get_timestamp`, `get_block`, `get_validation`.
- **Notarization:** `log_action`, `get_log_entry`, `search_actions`, `verify_asset`.
- **Scheduler:** `get_contract_types`, `estimate_schedule`, `create_schedule`,
  `list_schedules` (types/estimate/list live; `create_schedule` is a preview,
  blocked on the backend signing-message spec — non-custodial, the caller's EVM
  wallet signs).
- **Audit:** `generate_audit_trail`, `generate_compliance_report` (EU AI Act
  Art. 12 / SEC 17a-4 / ISO 27001 presets), `build_evidence_package`,
  `verify_package`.
- **Agent identity (verification, valid-at-T — not authentication):**
  `resolve_agent`, `attest_action`, `verify_receipt`, `mint_identity`,
  `revoke_identity`, `delegate_authority`, `get_identity_history`,
  `verify_identity_at`, `verify_cross_party`. Cross-party verification is keyless
  — it reads the immutable on-chain block, not the mutable ledger cache.

## Troubleshooting
- `command not found: npx` -> install Node.js 18+.
- `Authentication failed` -> check `CLOCKCHAIN_API_KEY`.
- `Insufficient logging credits` -> top up logs in your Clockchain dashboard.
- `clockchain` not in `/mcp` -> open a **new** session after adding it.
