# @clockchain/chatgpt-app

Clockchain **ChatGPT app** built on the **OpenAI Apps SDK** — which *is* MCP (an
MCP server + tools). This package is a **dev-mode-ready scaffold** exposing a
**time-only** surface: two read-only consensus-time tools and nothing else.

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

Launch focus = **time only** — read consensus time/timestamp detail.

| Tool | Hints | Widget |
| --- | --- | --- |
| `get_time` | `readOnly` | — |
| `get_timestamp` | `readOnly` | — |

The chatbot timestamp surface does not expose a `ledgerId` or `blockHeight`, so
there is nothing for the chatbot to verify: the app makes **no anchoring or
on-chain receipt claim**.

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

> Note: the receipt widget is currently **orphaned** — no tool links it now that
> the surface is time-only. It is kept behind `TODO(CLO-83)` pending a decision to
> delete or repurpose it. The build still produces it; it is harmless.

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

1. **List tools** — confirm exactly the two time tools (`get_time`,
   `get_timestamp`) and their read-only hints.
2. Call **`get_time`** (no args) — read-only.
3. Call **`get_timestamp`** (no args) — read-only.

> Both tools are read-only and spend no credits, so smoke-testing them is free.

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
5. Save, then in a chat invoke a tool (e.g. "what is the current Clockchain
   consensus time?"). Both tools are read-only and return JSON.

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
