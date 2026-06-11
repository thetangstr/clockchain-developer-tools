# Clockchain MCP (POC)

A minimal TypeScript monorepo exposing the Clockchain network API as MCP tools.

- `@clockchain/core` — typed client for the Clockchain gateway (time, blocks,
  validation, ledger logging/search, smart-contract scheduling, and ERC-8004
  agent-identity reads).
- `@clockchain/mcp-server` — an `npx`-able MCP server (stdio primary, HTTP
  optional) that surfaces the core client as tools for Claude Code.

Node 18+ required (uses built-in `fetch`).

## Build

From the repo root:

```bash
npm install
npm run build
```

This builds both workspaces with plain `tsc` (no bundler). Output lands in
`packages/*/dist`.

## Run (stdio — primary)

The server reads configuration from environment variables:

| Env var                    | Required | Default                          |
| -------------------------- | -------- | -------------------------------- |
| `CLOCKCHAIN_API_KEY`       | yes      | —                                |
| `CLOCKCHAIN_CLIENT_ID`     | yes      | —                                |
| `CLOCKCHAIN_WALLET_ID`     | yes      | —                                |
| `CLOCKCHAIN_ENDPOINT`      | no       | `https://node.clockchain.network`|
| `EVM_RPC_URL`              | no       | — (ERC-8004 resolution)          |
| `ERC8004_CHAIN`            | no       | —                                |
| `ERC8004_REGISTRY_ADDRESS` | no       | —                                |

```bash
CLOCKCHAIN_API_KEY=... \
CLOCKCHAIN_CLIENT_ID=... \
CLOCKCHAIN_WALLET_ID=... \
node packages/mcp-server/dist/stdio.js
```

Or, once published / linked, via the bin:

```bash
npx @clockchain/mcp-server   # runs the `clockchain-mcp` bin
```

## Run (HTTP — optional/secondary)

```bash
MCP_TRANSPORT=http MCP_PORT=3000 \
MCP_AUTH_TOKENS=secret1,secret2 \
CLOCKCHAIN_API_KEY=... CLOCKCHAIN_CLIENT_ID=... CLOCKCHAIN_WALLET_ID=... \
node packages/mcp-server/dist/index.js
```

If `MCP_AUTH_TOKENS` is set, requests must send `Authorization: Bearer <token>`.

## Wire into Claude Code (`~/.claude.json`)

Add an entry under `mcpServers` (stdio):

```jsonc
{
  "mcpServers": {
    "clockchain": {
      "command": "node",
      "args": ["/absolute/path/to/specs/packages/mcp-server/dist/stdio.js"],
      "env": {
        "CLOCKCHAIN_API_KEY": "your-api-key",
        "CLOCKCHAIN_CLIENT_ID": "your-client-id",
        "CLOCKCHAIN_WALLET_ID": "your-wallet-id"
      }
    }
  }
}
```

## Tools

**25 tools across five modules:**

- **Time:** `get_time`, `get_timestamp`, `get_block`, `get_validation`.
- **Logging:** `log_action`, `get_log_entry`, `search_actions`, `verify_asset`.
- **Scheduler:** `get_contract_types`, `estimate_schedule`, `create_schedule`,
  `list_schedules`. Types/estimate/list are live; `create_schedule` is a preview
  (blocked on the backend signing-message spec). Scheduling is non-custodial — the
  caller's own EVM wallet signs; the server never fabricates a signature.
- **Audit** (derivative — composes Time + Logging + Identity, no new primitive):
  `generate_audit_trail`, `generate_compliance_report` (EU AI Act Art. 12 /
  SEC 17a-4 / ISO 27001 presets), `build_evidence_package`, `verify_package`.
- **Agent identity** (verification, valid-at-T — not authentication):
  `resolve_agent`, `attest_action`, `verify_receipt`, `mint_identity`,
  `revoke_identity`, `delegate_authority`, `get_identity_history`,
  `verify_identity_at`, `verify_cross_party`. Cross-party verification is keyless
  — `GET /searchAssetFromChain?blockHeight={h}` reads the immutable on-chain block
  (the authoritative record), not the mutable `/ledger/{id}` cache.

### Notes / gotchas

- `hash_type` must be hyphenated (`SHA-256`); `SHA256` is rejected with HTTP 400.
- `log_action` returns a `ledgerId` immediately but `blockHeight` is `null`
  (pending) until the leader writes the block (~0.6s later).
- `additional_info` is plain text only — the gateway strips punctuation/JSON
  server-side, so do not store structured metadata there.
- `search_actions` is exact-match on `assetReferenceId` (no prefix search).
