# MCP Dashboard — Design Doc

Status: **proposed** (design only — no code until approved)
Date: 2026-06-14
Owner: yt
Decision inputs: build path = "design doc first"; availability = **live-only for v1** (no history store).

## 1. Goal

A single developer-facing page for the hosted Clockchain MCP that answers three
questions at a glance:

1. **Is it up?** (availability)
2. **What can it do?** (capability — the 31-tool catalog)
3. **Show me.** (live, in-browser demos on testnet)

It is the public "front door" for the MCP — the page you link from the README,
the deck, and registries. It is **not** the playground: the playground is a
conversational agent sandbox; the dashboard is a read-only status + capability
hub with a few scripted, runnable demos. They cross-link.

### Non-goals (v1)

- No historical uptime / incident management (live-only per decision; deferred to V2/V3).
- No auth / accounts / per-user dashboards.
- No admin controls (it never mutates server config).
- Not a replacement for the playground's agent loop.

## 2. Where it lives

- **New route** `/dashboard` in `clockchain-research` (the Next.js 16 app-router
  site, Tailwind 4, Material Design 3 tokens in `globals.css`, deployed on Vercel).
  Decision rationale: the playground is a self-contained chat UI; a dashboard is
  data-driven and read-only — a separate route keeps both clean. Cross-link both
  ways ("Watch an agent use it →" / "← Service status & tools").
- **Reuse:** the `clockchain.ts` client + tool registry, the MCP proxy pattern
  (`x-api-key`, SSE-aware) already in the playground, MD3 design tokens, and the
  status-dot styles (`.ndot.up/.down`).
- **Source of truth for the repo:** the MCP server lives in `specs/` (this repo);
  the dashboard UI lives in `clockchain-research`. ⚠️ Do not build against the
  volatile `/tmp/cr2` checkout — use the real `clockchain-research` repo.

## 3. Architecture

```
Browser (/dashboard, React)
   │  fetch (no secrets in the client)
   ▼
clockchain-research API routes (server-side, hold MCP_SERVER_TOKEN)
   ├─ GET  /api/dashboard/status      → live health + liveness + synthetic ping
   ├─ GET  /api/dashboard/catalog     → tools/list (cached ~60s)
   └─ POST /api/dashboard/demo/:name  → runs a scripted demo via the MCP proxy
   │  x-api-key (delegated key, server-held)
   ▼
mcp.clockchain.network  (StreamableHTTP, 31 tools)
   ▼
node.clockchain.network gateway (testnet)
```

Key rule: **the browser never holds a key.** All MCP calls go through
clockchain-research API routes that attach the server-held delegated key. This
also lets us throttle/cap public demo usage in one place.

## 4. Zone 1 — Availability (LIVE-ONLY for v1)

### Components

- Overall status banner: `● All systems operational` / `◐ Degraded` / `● Down`,
  derived from the component checks below.
- Header stats: current block height (advancing = liveness), p50 read latency
  (measured on this request, not historical), network label (Testnet).
- Per-component rows: **MCP endpoint**, **Gateway** (`node.clockchain.network`),
  and the **6 modules** (Time, Logging, Scheduler, Audit, Identity, Commitments).

### Signals & sources (all live, no store)

| Component | Check | Source |
|---|---|---|
| MCP endpoint | `GET /health` → `{status:"ok"}` | already exists (`http.ts`) |
| MCP liveness | `tools/list` returns ≥31 | live `tools/list` |
| Gateway / Time | `get_time` → block height present & numeric | synthetic `tools/call` |
| Other modules | one cheap read per module (e.g. `list_schedules`, `get_contract_types`) | synthetic `tools/call` |
| Read latency | wall-clock of the synthetic pings | measured this request |

### `/api/dashboard/status` contract

```jsonc
{
  "status": "operational",            // operational | degraded | down
  "checkedAt": "2026-06-14T04:10:00Z",
  "network": "testnet",
  "blockHeight": "3757937",           // null if get_time failed
  "latencyMs": { "p50": 130 },        // from this request's synthetic pings
  "components": [
    { "id": "mcp", "label": "MCP endpoint", "ok": true, "detail": "health ok, 31 tools" },
    { "id": "gateway", "label": "Gateway", "ok": true, "detail": "block 3757937 advancing" },
    { "id": "module.time", "label": "Time", "ok": true },
    { "id": "module.logging", "label": "Logging", "ok": true }
    // … one row per module
  ]
}
```

Refresh: client polls every ~30s. Degraded states must render clearly (amber
row + reason text), and a failed check must never crash the page — show the row
as down with the error detail. This mirrors how `coverage.test.mjs` already
treats graceful degradation server-side.

### Deferred (V2/V3, explicitly out of v1)

- Rolling uptime % (24h/30d/90d) — needs a store (Vercel KV cron, or GCP uptime
  checks, or a hosted provider like Better Stack/Instatus).
- Latency time-series graph — schedule `eval/perf.mjs` → store.
- Incident timeline + subscribe-to-updates.

## 5. Zone 2 — Capability (the tool catalog)

### Principle: render from `tools/list`, never hardcode

The server is self-describing. Pulling the catalog live means the dashboard
**cannot drift** from reality (this is exactly the "30 vs 31 tools" doc-drift
problem, solved structurally). Group the 31 tools by the 6 modules.

### Tool card anatomy

```
┌───────────────────────────┐
│ attest_action       W  $   │   ← name, write badge, "spends a credit"
│ Agent Attested Receipt     │   ← title
│ Fingerprint + anchor an    │   ← one-line description (from the schema)
│ agent action…              │
│ inputs: agent_id, action,  │   ← required args (rendered from JSON Schema)
│         inputs?, outputs?  │
│ [ schema ▾ ]  [ try ▶ ]    │   ← expand full schema; "try" deep-links a demo
└───────────────────────────┘
```

- **Badges:** `R` read / `W` write, `$` spends a credit, `preview` for
  `create_schedule`.
- **Module grouping:** Time (4), Logging (4), Scheduler (4), Audit (4),
  Identity (10), Commitments/TSA (5).
- **Copy MCP config** (top of zone, primary CTA): the `claude mcp add …` command
  and the JSON snippet for the hosted endpoint. This is the #1 conversion action
  on every MCP registry.
- **"Installs in"** row: Claude Code, Cowork, Cursor, etc.

### `/api/dashboard/catalog` contract

Thin pass-through of `tools/list` (cached ~60s), annotated with module + R/W/$:

```jsonc
{
  "count": 31,
  "modules": [
    { "id": "time", "label": "Time", "tools": ["get_time","get_timestamp","get_block","get_validation"] }
    // …
  ],
  "tools": {
    "attest_action": { "module": "identity", "write": true, "spendsCredit": true,
                       "title": "…", "description": "…", "inputSchema": { /* raw */ } }
    // …
  }
}
```

(Module + R/W/$ classification is a small static map keyed by tool name — the
only hardcoded part, and it's metadata, not the catalog itself.)

## 6. Zone 3 — Live demos

Scripted, in-browser, testnet-only. Reuse the playground's MCP proxy. Each demo
is a small form → live call(s) → rendered result.

| Demo | Flow | Tools | Writes? |
|---|---|---|---|
| **Notarize** | type text → anchor → show ledgerId → re-read chain | `log_action`, `get_log_entry` | yes ($) |
| **Tamper** | notarize, then flip one byte → verify goes RED | `log_action`, `verify_asset` | yes ($) |
| **Agent receipt** | attest an action → receipt card → independent verify ✓ | `attest_action`, `verify_receipt` | yes ($) |
| **Submit → poll** | `wait:false` pending → poll until confirmed (shows AGE-184) | `attest_action`, `complete_attestation` | yes ($) |
| **Commitment** | issue → attest kept/broken verdict | `tsa_issue`, `tsa_attest` | yes ($) |
| **Read-only tour** | live time + latest block + a search | `get_time`, `get_block`, `search_actions` | no |

The **Tamper** demo is the headline: watching verification fail on a changed
byte sells "immutable" better than any copy.

### ⚠️ Safety: public demos spend real credits

Every write demo spends a log credit on the delegated key and is publicly
triggerable. v1 must bound this:

- All demos run through `/api/dashboard/demo/:name` (server-side), which applies a
  **per-IP + global daily cap** (reuse the server's existing rate limiter /
  `MCP_LOG_BUDGET`; add a dashboard-specific demo budget).
- Default the page to the **read-only tour**; gate write demos behind an explicit
  "Run (spends a testnet credit)" button.
- Consider a dedicated low-balance demo key so a runaway can't drain the main key.
- Testnet only; receipts carry the existing "not court-of-law" disclaimer.

This budget/abuse question is the main open decision for the build (see §10).

## 7. Component inventory (to build)

New React components in `clockchain-research`:

- `StatusBanner` + `ComponentRow` + `StatusDot` (Zone 1)
- `ToolCatalog` → `ModuleSection` → `ToolCard` → `SchemaView` (Zone 2)
- `CopyConfig` (snippet + copy button)
- `DemoPanel` → `DemoForm` + `ResultViewer` + `ReceiptCard` (Zone 3)
- `CodeBlock`, `Badge` (shared primitives — none exist today; build minimal)

Reuse: MD3 tokens (`globals.css`), `clockchain.ts` client, playground MCP proxy,
status-dot CSS, date/format helpers from `BriefRenderer`.

## 8. Phased rollout

- **MVP** (1 focused build, all from data we have):
  - `/dashboard` scaffold + nav + tokens
  - Zone 1 live status (health + get_time + synthetic pings), `/api/dashboard/status`
  - Zone 2 live catalog from `tools/list` + Copy-config
  - Zone 3: **Notarize** + **Tamper** demos + read-only tour, with demo budget
- **V2:** remaining demos (receipt, submit→poll, commitment); receipt gallery of
  recent public anchors; latency from scheduled `perf.mjs`.
- **V3:** historical uptime + incidents (KV cron or hosted provider), subscribe,
  per-tool latency SLOs (ties into Tier-2 observability).

## 9. Mockup (MVP)

```
┌────────────────────────────────────────────────────────────┐
│  Clockchain MCP            ● All systems operational         │
│  mcp.clockchain.network    block 3,757,937 ↑   p50 130ms     │
├───────────────┬───────────────┬────────────────┬───────────┤
│ MCP endpoint ●│ Gateway      ● │ 31 tools live  │ Testnet   │
├────────────────────────────────────────────────────────────┤
│  CAPABILITY                         [ Copy MCP config ⧉ ]    │
│  Time(4) Logging(4) Scheduler(4) Audit(4) Identity(10) TSA(5)│
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │
│  │ get_time   R │ │ log_action W$│ │ attest_act W$│  …       │
│  └──────────────┘ └──────────────┘ └──────────────┘         │
├────────────────────────────────────────────────────────────┤
│  LIVE DEMO   [Read-only tour] [Notarize $] [Tamper $]       │
│  ┌──────────────────────────┐  ┌─────────────────────────┐  │
│  │ text: "hello world"      │  │ ledgerId: 0fe0a6…       │  │
│  │ [ Anchor it (1 credit) ] │  │ blockHeight: 3757940 ✓  │  │
│  └──────────────────────────┘  │ verified on-chain  ✅   │  │
│                                 └─────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

## 10. Open decisions (for build kickoff)

1. **Demo budget / abuse control** — per-IP + global daily cap value; dedicated
   low-balance demo key yes/no. (Blocks the write demos.)
2. **Read latency display** — show per-request measured p50 only (live-only), or
   pull in scheduled `perf.mjs` numbers (V2)?
3. **Route name** — `/dashboard` vs `/status` vs `/mcp`.
4. **Cross-link placement** — header nav entry + README/deck links.

## 11. References (existing assets)

- MCP server: `specs/packages/mcp-server/src/http.ts` (`/health`), `tools.ts`
  (31 tools), `server.ts` (`buildServer`).
- Capability source: live `tools/list` at `https://mcp.clockchain.network/mcp`.
- Latency source (future): `specs/eval/perf.mjs`.
- Conformance/coverage gates: `specs/packages/mcp-server/test/{conformance,coverage}.test.mjs`.
- Playground reuse: `clockchain-research` `src/lib/clockchain.ts`, the MCP proxy
  in `src/lib/playground-agent.ts`, MD3 tokens in `src/app/globals.css`.
```
