# AgentDash × Clockchain MCP — Integration Brief

A hand-off brief for the **AgentDash team**. Goal: have AgentDash use the new
**hosted Clockchain MCP server** (`https://mcp.clockchain.network/mcp`) for
attestation / agent-identity, instead of the current gateway-direct adapter.

Authored by the Clockchain/MCP side. Two integration options (A and B) — pick one.
Everything you need to build against the endpoint is here.

---

## 1. The hosted endpoint (what you connect to)

- **URL:** `https://mcp.clockchain.network/mcp` (live on GCP Cloud Run, TLS valid)
- **Health:** `GET https://mcp.clockchain.network/health` → `{"status":"ok"}`
- **Transport:** MCP over StreamableHTTP, **stateless** — one request each, no session
  id. Every request MUST send both headers:
  - `Content-Type: application/json`
  - `Accept: application/json, text/event-stream`
- **Responses are SSE:** the JSON-RPC payload is on a line beginning `data: ` — strip
  that prefix to parse. (Tool errors come back as `result.isError = true` with the
  message in `result.content[0].text`; the HTTP status is still 200.)
- **Methods:** `initialize` → `tools/list` → `tools/call`.

### Auth — two modes (your choice)

| Mode | Header(s) | Whose credits | When |
|---|---|---|---|
| **Delegated** | `x-api-key: <MCP token we issue you>` | **Ours** (we hold the Clockchain key) | Quick demo / no Clockchain key needed |
| **Bring-your-own-key (BYO)** | `x-clockchain-api-key: <key>` + `x-clockchain-client-id: <id>` + `x-clockchain-wallet-id: <wallet>` | **Yours** (AgentDash's Clockchain account) | Production — your usage on your credits. No MCP token needed; the key authenticates you. |

> For a real/long-running AgentDash integration, use **BYO** so attestation spend is
> on AgentDash's own Clockchain credits, not ours. Ask the Clockchain team for either
> an MCP token (delegated) or your own Clockchain key + client/wallet id (BYO).

### Smoke test (paste-and-run)

```bash
URL=https://mcp.clockchain.network/mcp
AUTH='-H x-api-key:<TOKEN>'        # or BYO headers
H='-H Content-Type:application/json -H Accept:application/json,text/event-stream'
# initialize
curl -s $URL $AUTH $H -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agentdash","version":"1"}}}'
# list tools (expect 25)
curl -s $URL $AUTH $H -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
# call get_time
curl -s $URL $AUTH $H -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_time","arguments":{}}}'
```

### Tools you'll care about (25 total; key ones below)

| Tool | Required args | Use |
|---|---|---|
| `get_time` | — | consensus time + latest block height |
| `log_action` | `asset_hash` (hex; 64 for SHA-256), `asset_reference_id` | anchor a content hash; opt: `hash_type`, `did`, `wait:true` |
| `attest_action` | `agent_id`, `action` | fingerprint+anchor an agent action → returns a verifiable receipt; opt: `inputs`, `outputs`, `wait:true` |
| `verify_receipt` | `receipt` (the full object from `attest_action`) | re-verify a receipt against the chain (`match:true/false`) |
| `verify_cross_party` | — (`ledger_id` + `block_height` recommended) | keyless verify against the immutable on-chain block |
| `mint_identity` | `did`, `document` | anchor an agent identity (doc hash; doc stays client-side) |
| `delegate_authority` | `parent_did`, `child_did`, `scope` (**array**), `until` | delegate scoped authority between agents |
| `verify_identity_at` | `did`, `at` (RFC3339) | was this agent authorized at instant T? |
| `build_evidence_package` | `ledger_id` | self-contained verify-able evidence pack |
| `generate_compliance_report` | `asset_reference_id`, `format` (`eu_ai_act_art12`\|`sec_17a4`\|`iso_27001`) | regulator-preset export |

`tools/call` shape: `{"jsonrpc":"2.0","id":N,"method":"tools/call","params":{"name":"<tool>","arguments":{...}}}`.

---

## 2. Where AgentDash stands today (current Clockchain code)

Found in the worktree `.claude/worktrees/loving-ellis-e2f1b5/` (not yet on `main`):

- **`packages/attestation/src/adapters/clockchain.ts`** — a periodic **batch** adapter
  that calls the **raw gateway** `node.clockchain.network` directly
  (`GET /api/time/time`, `POST /log`, `GET /searchAsset`) with `x-api-key`. It anchors
  activity-log rows after the fact; agents do **not** call Clockchain tools.
  ⚠️ `/api/time/time` is a scope-limited endpoint on the current key — the hosted MCP
  avoids that path.
- **`server/src/index.ts`** (~L1950) — bootstraps the attestation service from env
  (`AGENTDASH_ATTESTATION_ENABLED`, `AGENTDASH_ATTESTATION_ADAPTER`, `CLOCKCHAIN_API_KEY`,
  `CLOCKCHAIN_API_BASE`, interval/batch limit).
- **`server/src/services/plugin-tool-{registry,dispatcher}.ts`** — the plugin tool
  dispatch layer (the clean seam if you want agent-callable tools).
- **`packages/mcp-server/`** — AgentDash's own MCP server (Paperclip tools). No
  Clockchain tools there yet.

The "Meridian Pay" 7-agent demo is **not in the repo** — it's runtime data in a
deployed AgentDash instance, so the integration is data-agnostic (it works for any
company/agent).

---

## 3. Option A — repoint the attestation adapter to the MCP (smaller, ~½ day)

Keep the batch-attestation model; just send it through the hosted MCP instead of the
raw gateway. Edit `packages/attestation/src/adapters/clockchain.ts`:

- `getVerifiedTime()` → `tools/call get_time` (parse `latestBlockTime` / `latestBlockHeight`).
- `anchorBatch()` → `tools/call log_action` per row (`asset_hash` = your SHA-256 of the
  row, `asset_reference_id` = your stable id, `wait:true` to get the confirmed block).
- `verifyAnchor()` → `tools/call verify_asset` (or `verify_cross_party` for keyless).

Add an MCP-call helper (POST + SSE parse, as in §1). Config:
```
CLOCKCHAIN_MCP_URL=https://mcp.clockchain.network/mcp
# delegated:           CLOCKCHAIN_MCP_TOKEN=<token>        (sent as x-api-key)
# OR BYO:              CLOCKCHAIN_API_KEY / _CLIENT_ID / _WALLET_ID  (sent as x-clockchain-* headers)
```
**Wins:** fixes the scope-limited time path; one endpoint; works with delegated or BYO.
**Keeps:** the after-the-fact batch model (agents still don't *call* Clockchain).

---

## 4. Option B — agent-callable Clockchain tools (more demo impact, ~1–2 days)

Make agents explicitly attest their own consequential actions (the Meridian-Pay story:
mint identity → delegate authority → attest action → verify receipt → evidence pack).

Cleanest seam = the **PluginToolRegistry / PluginToolDispatcher**. Add a thin
**Clockchain MCP-client plugin** that:
1. On load, `initialize` + `tools/list` against `https://mcp.clockchain.network/mcp`.
2. Registers the (relevant) tools under a `clockchain:*` namespace in the registry.
3. On `clockchain:<tool>` calls, forwards `tools/call` to the hosted MCP and returns the
   result text to the agent.

Auth via the same env as Option A (delegated token or BYO headers). Agents then call
e.g. `clockchain:attest_action`, `clockchain:verify_receipt`, `clockchain:mint_identity`.

**Wins:** the compelling "agents using Clockchain" demo; reuses your existing tool
dispatch; no schema duplication (tools come from `tools/list`).

Recommendation: **B** for the exec demo, **A** if you just need attestation flowing
through the hosted MCP this week. They're not mutually exclusive — A can ship first.

---

## 5. Gotchas (field-tested)

- **SSE:** read the `data:` line; the body is one JSON object per response.
- **Stateless:** send the two headers on every request; no session id; don't reuse a
  transport across requests.
- **Tool errors** are `result.isError:true` + text, with HTTP **200** — check the flag,
  don't rely on status codes.
- **`attest_action` waits ~15s** for the block when `wait:true` — set client timeouts to
  ≥30s, or omit `wait` and poll/verify later.
- **Dates** from the network are **DD-MM-YYYY** (e.g. `"12-06-2026_14:41:29:089"`) — parse
  explicitly; `Date.parse` mis-reads them.
- **`asset_hash`** must be valid hex (64 chars for SHA-256) — enforced server-side now.
- **Only attest genuine business actions** — never anchor errors, retries, or status
  noise (it creates misleading permanent records).
- **`delegate_authority.scope` is an array**, not a string.

---

## 6. What to request from the Clockchain team

- **Delegated:** an MCP token (we mint per-consumer; revocable). 
- **BYO (recommended for prod):** AgentDash's own Clockchain **API key + client id +
  wallet id** so attestation spend is on AgentDash's credits.

Endpoint + protocol reference: `INSTALL.md` and `CLOUD-RUN.md` in the
`clockchain-developer-tools` repo. Endpoint is live; nothing blocks starting.
