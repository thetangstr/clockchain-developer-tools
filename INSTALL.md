# Install the Clockchain MCP server

Add Clockchain's tools (consensus time, notarization, agent-attested receipts,
ERC-8004 identity read) to your AI coding agent. Two ways: **local** (you run it,
recommended) or **remote** (you connect to a hosted endpoint).

## Prerequisites
- **Node.js 18+**
- A **Clockchain API key** (from your Clockchain dashboard) + your client/wallet id

---

## Local install (npm / stdio) - recommended

Once published to npm, it's one command per host. Your key stays on your machine;
the server has **no network listener** (it only calls Clockchain outbound).

### Claude Code
```bash
claude mcp add clockchain \
  --env CLOCKCHAIN_API_KEY=<your key> \
  --env CLOCKCHAIN_CLIENT_ID=<you@example.com> \
  --env CLOCKCHAIN_WALLET_ID=<you@example.com> \
  -- npx -y @clockchain/mcp-server
```
Then open a **new** session, run `/mcp` (you should see `clockchain`), and ask:
*"use clockchain to get the current consensus time."*

### Claude Desktop / Cursor / any MCP host (manual config)
Add to the host's MCP config (`claude_desktop_config.json`, `~/.claude.json`
`mcpServers`, etc.):
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
claude mcp add clockchain --transport http https://mcp.<domain>/mcp \
  --header "x-api-key: <your tester token>"
```

---

## Network & tokens at a glance

| | Local (npm/stdio) | Remote (HTTP) |
|---|---|---|
| Network | no listener; outbound-only to the gateway | hosted endpoint (behind Cloudflare Access) |
| Who holds the Clockchain key | you (your machine) | the host (server-side) |
| Your "token" | your own Clockchain API key | a per-user token the host issues |
| Non-custodial | yes - no private keys in the server | yes - key custodied on the host, not shared |

## The tools you get
`get_time`, `get_timestamp`, `get_block`, `get_validation` (time oracle) ·
`log_action`, `get_log_entry`, `search_actions`, `verify_asset` (notarization) ·
`attest_action`, `verify_receipt` (agent attested receipt) · `resolve_agent`
(ERC-8004 identity, read).

## Troubleshooting
- `command not found: npx` -> install Node.js 18+.
- `Authentication failed` -> check `CLOCKCHAIN_API_KEY`.
- `Insufficient logging credits` -> top up logs in your Clockchain dashboard.
- `clockchain` not in `/mcp` -> open a **new** session after adding it.
