# Quickstart - Clockchain MCP Server (v1)

Run and verify the Clockchain MCP server locally. v1 is the verified core: 8 tools
(time oracle + notarization) over stdio. Everything below is copy-paste tested.

> `resolve_agent` (ERC-8004 identity) is present but returns `status: "unknown"`
> until the EVM env vars are set - see the bottom. Smart-contract triggers are not
> available (gateway 404).

## 1. Get + build

```bash
git clone https://github.com/thetangstr/clockchain-developer-tools.git
cd clockchain-developer-tools
npm install
npm run build
```

## 2. Test (no network, no credentials)

```bash
npm test
# core: tests 19 pass 19   |   mcp-server: tests 25 pass 25
```

## 3. Configure (env, never committed)

```bash
export CLOCKCHAIN_API_KEY=<your key>
export CLOCKCHAIN_CLIENT_ID=you@example.com
export CLOCKCHAIN_WALLET_ID=you@example.com
```

## 4. Run it (local stdio)

The server binary is `packages/mcp-server/dist/stdio.js`. Three ways to use it:

**a) Register with Claude Code** (the real agent path):

```bash
claude mcp add clockchain \
  --env CLOCKCHAIN_API_KEY=$CLOCKCHAIN_API_KEY \
  --env CLOCKCHAIN_CLIENT_ID=$CLOCKCHAIN_CLIENT_ID \
  --env CLOCKCHAIN_WALLET_ID=$CLOCKCHAIN_WALLET_ID \
  -- node "$(pwd)/packages/mcp-server/dist/stdio.js"
```

Then open a **new** Claude Code session (MCP servers load at startup), run `/mcp`
(should list `clockchain` with 9 tools), and ask: *"use clockchain to timestamp the
text 'hello' and then verify it."*

**b) Narrated live demo** (spends one log credit):

```bash
cd packages/mcp-server && npm run demo
# time -> notarize -> wait for confirmation -> verify -> tamper-detect; prints RESULT: PASS
```

**c) Raw stdio** (for your own MCP client): `node packages/mcp-server/dist/stdio.js`

## 5. Verify (four levels)

1. **Build + tests** - `npm run build && npm test` -> 44 pass.
2. **Server speaks MCP** (no API key needed):
   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify","version":"1.0"}}}' \
     | node packages/mcp-server/dist/stdio.js 2>/dev/null | head -n 1
   # -> {"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"clockchain-mcp","version":"0.1.0"}},...}
   ```
3. **Live end-to-end** - `npm run demo` prints `RESULT: PASS` with a confirmed `blockHeight`.
4. **From the agent** - in a new Claude Code session, the timestamp/verify ask above returns `match: true`.

## The 8 core tools

**Time oracle:** `get_time`, `get_timestamp`, `get_block`, `get_validation`
**Notarization:** `log_action`, `get_log_entry`, `search_actions`, `verify_asset`
(`log_action` accepts `wait: true` to return only once the write is confirmed on-chain.)

## Optional: ERC-8004 identity read

`resolve_agent` stays `unknown` until you provide:

```bash
export EVM_RPC_URL=<rpc url>
export ERC8004_CHAIN=base-sepolia
export ERC8004_REGISTRY_ADDRESS=<registry contract address>
```

## Hosting (v2+)

To run a shared HTTP endpoint (Mac mini / GCP Cloud Run / AWS) with tester tokens,
a logging budget cap, and a `/health` probe, see `deployment.md` and
`packages/mcp-server/.env.example`.
