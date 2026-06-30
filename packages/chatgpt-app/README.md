# @clockchain/chatgpt-app

Clockchain **ChatGPT app** built on the **OpenAI Apps SDK** — which *is* MCP (an
MCP server + tools + an optional iframe widget). This package is a
**dev-mode-ready scaffold** that delivers the in-chat
**timestamp → pending → anchored → verify-keylessly** loop on testnet: a curated
tool subset plus a read-only "verify-a-receipt" widget.

It reuses [`@clockchain/core`](../core) (the same typed gateway client the main
[`@clockchain/mcp-server`](../mcp-server) uses) — this is a *separate* package and
does **not** change the main server's tool set.

> Status: testnet, **no OAuth** in this milestone. Dev-mode uses a per-tester
> `x-api-key` header. Public listing later requires OAuth 2.1 — see
> [Going public](#going-public-oauth--age-193age-194) and
> [`../../mcp-launch-plan.md`](../../mcp-launch-plan.md) (Track 2).

## Tools (curated subset)

Reviewers test every advertised tool, so the surface is intentionally small.
Annotations/hints follow the Apps SDK guidance:

Launch focus = the **anchor → verify** loop: read consensus time, timestamp
content (anchor a hash), then verify it keylessly against the immutable on-chain
block.

| Tool | Hints | Widget |
| --- | --- | --- |
| `get_time` | `readOnly` | — |
| `log_action` | `destructive`, `openWorld` | — |
| `verify_cross_party` | `readOnly` | ✅ `ui://widget/receipt.html` |

`verify_cross_party` links the widget via `_meta["openai/outputTemplate"]` and
returns `structuredContent`, which the widget reads as `window.openai.toolOutput`.

The loop: **`log_action`** timestamps content (the server SHA-256-hashes it; with
`wait:true`, the default, the reply carries the real `blockHeight`), returning a
`ledgerId` + `blockHeight` + `status`. Pass those to **`verify_cross_party`** —
what an outside counterparty runs with **no Clockchain account** — to confirm the
hash against the immutable on-chain block.

### Truthful anchoring

Pending vs anchored is reported **truthfully** end to end. A **null `blockHeight`
means NOT anchored**: `log_action` never reports such a write as confirmed (it
attaches an explicit PENDING warning), and the widget shows
**"pending / unconfirmed" until a `blockHeight` is present** — a
recorded-but-not-yet-anchored entry is **never** rendered as confirmed. On a
degraded testnet pool (participation may read 0% while blocks still advance),
`log_action` refuses by default; pass `allow_degraded: true` to proceed when
blocks are advancing. This is a single-validator **testnet**: independently
verifiable, but **not** a court-of-law evidentiary claim. Matches the
truthful-anchoring semantics in `@clockchain/core` (`status: "anchored"` only once
the event has a block height).

## Build

```bash
# from the monorepo root (builds @clockchain/core first via project refs)
npm install
npm run build            # builds all workspaces

# or just this package
npm run build -w @clockchain/chatgpt-app
```

`build` runs two steps: `build:widget` (esbuild bundles `widget/receipt.tsx` →
`dist/widget/receipt.js`, a single ESM module) then `tsc -b` (the server). The
widget bundle is inlined into the `ui://widget/receipt.html` resource at runtime.

## Run locally

```bash
# stdio (best for MCP Inspector)
node packages/chatgpt-app/dist/index.js

# HTTP (the dev-mode connector transport)
CHATGPT_APP_TESTER_KEYS=devkey123 MCP_TRANSPORT=http PORT=3000 \
  node packages/chatgpt-app/dist/index.js
```

Clockchain credentials come from the standard env vars read by `@clockchain/core`
(`CLOCKCHAIN_API_KEY`, `CLOCKCHAIN_CLIENT_ID`, `CLOCKCHAIN_WALLET_ID`,
`CLOCKCHAIN_ENDPOINT`). Over HTTP a request can override the key per-tester via
the `x-api-key` header (see below).

## Smoke-test with MCP Inspector (read-only tools only)

```bash
npx @modelcontextprotocol/inspector node packages/chatgpt-app/dist/index.js
```

In the Inspector:

1. **List tools** — confirm exactly the three curated tools (`get_time`,
   `log_action`, `verify_cross_party`) and their hints.
2. Call **`get_time`** (no args) — read-only.
3. Call **`verify_cross_party`** with a known `ledger_id` (and `block_height` if
   you have it) — read-only; returns `structuredContent`.
4. **List resources** — confirm `ui://widget/receipt.html`
   (`text/html+skybridge`).

> `get_time` and `verify_cross_party` are read-only and spend no credits.
> `log_action` is the one write and it spends a log credit.

## ChatGPT developer-mode connector

No OAuth and no submission needed for this — it is a **private** connector.

1. Run this server over **HTTP** on a **public HTTPS URL** (e.g. a tunnel such as
   `ngrok`, or your hosted endpoint), with at least one tester key:
   ```bash
   CHATGPT_APP_TESTER_KEYS=devkey123 MCP_TRANSPORT=http PORT=3000 \
     node packages/chatgpt-app/dist/index.js
   ```
2. In ChatGPT: **Settings → Apps & Connectors → Advanced → Developer mode** (turn
   it on).
3. **Create / Add a connector** pointing at your MCP endpoint URL (e.g.
   `https://<your-tunnel>/`). Transport: **HTTP / MCP**.
4. Add a request header: **`x-api-key: devkey123`** (the value must match an entry
   in `CHATGPT_APP_TESTER_KEYS`). Alternatively, a tester may pass their **own**
   Clockchain API key as `x-api-key` (BYO — writes spend their credits), optionally
   with `x-clockchain-client-id` / `x-clockchain-wallet-id`.
5. Save, then in a chat run the loop (e.g. "timestamp this text on Clockchain,
   then verify it"). `log_action` anchors the hash; `verify_cross_party` renders
   the read-only widget card.

### Auth model (dev mode)

`x-api-key` is resolved per request:

- **Allowlisted tester key** (in `CHATGPT_APP_TESTER_KEYS`) → uses the server's
  delegated (env) Clockchain key; the header is just an access gate.
- **Any other key** → treated as the caller's own Clockchain key (BYO).
- **No key** → `401` with guidance.

## Going public (OAuth + truthful anchoring / per-user auth)

Public listing in ChatGPT does **not** allow user-supplied API keys. It requires
**OAuth 2.1** (MCP-conformant discovery, DCR/CIMD, PKCE S256, `resource`→`aud`)
mapping each ChatGPT user to a per-user Clockchain key, plus the launch gates
**truthful anchoring** and **per-user auth**.
Details and sequencing: [`../../mcp-launch-plan.md`](../../mcp-launch-plan.md).

This scaffold deliberately stops short of OAuth, deployment, and submission.
