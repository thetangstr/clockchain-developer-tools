# @clockchain/keeper — the hosted keeper (Phase 2: fire-while-offline)

The keeper is the **off-chain dispatch layer** that lets an agent schedule a
verified-time trigger that fires **even when its client is offline**. Each fire
both delivers a signed webhook AND is anchored on-chain as a keyless-verifiable
receipt.

The chain stays pure — nothing is attached to it. The keeper is a separate
off-chain worker with two planes:

- **Control plane** — MCP tools `keeper_schedule`, `keeper_list`, `keeper_cancel`
  (named to avoid colliding with the mcp-server's contract-deploy
  `create_schedule` / `list_schedules`).
- **Data plane** — an always-on dispatch loop, disciplined to Clockchain
  consensus time, that fires due triggers.

> This is the first shippable increment. See **Deferred scope** below for the
> honest TODO list (multi-tenant scale, full OAuth, per-`sub` gateway sub-key
> budgets, DNS-rebind-safe SSRF).

## How a fire works

For each due trigger (`fireAtMs <= disciplinedNow`):

1. **Deliver** a [Standard-Webhooks](https://www.standardwebhooks.com)-style POST
   to the target URL: HMAC-SHA256 signature (`webhook-signature: v1,<b64>`),
   `webhook-id` (also the `idempotency-key`), `webhook-timestamp`. Retries use
   exponential backoff; exhaustion **dead-letters** the delivery.
2. **Anchor** the fire via `attest_action` (`@clockchain/core`) → an Agent
   Attested Receipt (event hash + on-chain anchor + consensus time).
3. **Finalize** — **AGE-193**: a fire is *not done until anchored*. A pending or
   failed anchor leaves the trigger armed, so it is retried next tick and re-armed
   after a restart. A due trigger is **never silently dropped**.

The `webhook-id` / idempotency key is `\${triggerId}#\${fireAtMs}` — stable across
retries *and* across a keeper restart re-fire, so a receiver can dedupe a fire it
already processed (a crash between deliver and anchor causes at-least-once
delivery with a stable key, never a lost fire).

## Durability & re-arm on boot

Triggers live in a pluggable, durable `KeeperStore`. The default `FileStore`
writes a single JSON file atomically (tmp + rename). On boot the dispatch loop's
first tick reloads every non-terminal trigger, so anything that came due while the
worker was down fires immediately. (`MemoryStore` is for tests; a SQLite store is
a drop-in TODO.)

## Run it as the always-on worker

```bash
# build (from repo root)
npm run build -w @clockchain/keeper

# stdio control plane + dispatch loop (local agent use)
CLOCKCHAIN_API_KEY=... CLOCKCHAIN_CLIENT_ID=... CLOCKCHAIN_WALLET_ID=... \
KEEPER_WEBHOOK_SECRET=whsec_... \
KEEPER_STORE_PATH=./data/keeper-store.json \
node packages/keeper/dist/worker.js

# HTTP control plane + dispatch loop (hosted) — POST /mcp, GET /healthz
# HTTP mode REQUIRES KEEPER_AUTH_TOKENS and a KEEPER_WEBHOOK_ALLOWLIST (deny-by-default).
MCP_TRANSPORT=http PORT=8080 KEEPER_AUTH_TOKENS=tok1,tok2 \
KEEPER_WEBHOOK_ALLOWLIST=hooks.example.com,api.partner.com \
CLOCKCHAIN_API_KEY=... CLOCKCHAIN_CLIENT_ID=... CLOCKCHAIN_WALLET_ID=... \
KEEPER_WEBHOOK_SECRET=whsec_... \
node packages/keeper/dist/worker.js
```

### Docker

```bash
docker build -f packages/keeper/Dockerfile -t clockchain-keeper .
docker run -p 8080:8080 \
  -e MCP_TRANSPORT=http \
  -e CLOCKCHAIN_API_KEY=... -e CLOCKCHAIN_CLIENT_ID=... -e CLOCKCHAIN_WALLET_ID=... \
  -e KEEPER_WEBHOOK_SECRET=whsec_... -e KEEPER_AUTH_TOKENS=... \
  -e KEEPER_WEBHOOK_ALLOWLIST=hooks.example.com \
  -v keeperdata:/data -e KEEPER_STORE_PATH=/data/keeper-store.json \
  clockchain-keeper
```

## Configuration (env)

| Variable | Purpose | Default |
| --- | --- | --- |
| `CLOCKCHAIN_API_KEY` / `CLOCKCHAIN_CLIENT_ID` / `CLOCKCHAIN_WALLET_ID` | Keeper's own delegated key used to **anchor** fires + read consensus time | — (required) |
| `CLOCKCHAIN_ENDPOINT` | Gateway base URL | `https://node.clockchain.network` |
| `KEEPER_WEBHOOK_SECRET` | Standard-Webhooks signing secret (raw or `whsec_…`) | — (required to sign) |
| `KEEPER_STORE_PATH` | JSON store path (persist on a volume) | `./data/keeper-store.json` |
| `KEEPER_TICK_MS` | Dispatch loop interval | `1000` |
| `KEEPER_RESYNC_MS` | Clock re-discipline interval | `60000` |
| `KEEPER_MAX_ATTEMPTS` / `KEEPER_BASE_DELAY_MS` / `KEEPER_MAX_DELAY_MS` | Delivery retry/backoff | `5` / `500` / `30000` |
| `KEEPER_ANCHOR_RETRY_MS` | Delay before re-polling a pending anchor | `1000` |
| `KEEPER_AGENT_ID` | Acting identity stamped on anchors | `agent:clockchain-keeper` |
| `KEEPER_MAX_PER_TICK` | Max due triggers processed per tick | `100` |
| `KEEPER_CONCURRENCY` | Max fires processed concurrently per tick | `10` |
| `KEEPER_MAX_RETAINED_FIRES` | Fire-history ring-buffer size per trigger | `50` |
| `KEEPER_MAX_PAYLOAD_BYTES` | Max serialized payload size | `65536` |
| `KEEPER_MAX_TRIGGERS_PER_SUB` | Max live triggers per owner | `1000` |
| `MCP_TRANSPORT` | `http` or `stdio` | `stdio` |
| `PORT` | HTTP port (Cloud Run injects this) | `8080` |
| `KEEPER_AUTH_TOKENS` | Comma-separated bearer tokens gating `/mcp`. **HTTP mode refuses to start if unset** (see `KEEPER_ALLOW_ANON`). | — |
| `KEEPER_ALLOW_ANON` | `1` lets HTTP mode start with NO tokens (trusted local use only) | — |
| `KEEPER_WEBHOOK_ALLOWLIST` | Comma-separated host-suffix allow-list. **Mandatory in HTTP mode** (deny-by-default). | — |
| `KEEPER_REQUIRE_ALLOWLIST` | `1` forces the allow-list even in stdio mode | — |
| `KEEPER_ALLOW_ANY_HOST` | `1` disables the mandatory-allow-list in HTTP mode (not recommended) | — |
| `KEEPER_ALLOW_LOOPBACK` | `1` permits loopback/private targets (dev/test only) | — |

## Credit-safety: anchor once, then poll

A fire is anchored EXACTLY ONCE. The chargeable write (`attestAction`, `wait:false`)
returns a pending receipt immediately; the keeper persists it and, on later ticks,
confirms via `completeReceipt` — a READ-ONLY re-fetch that spends no credit. The
dispatch loop never blocks on `wait:true` and never re-anchors, so a slow block or
a long retry backlog cannot drain credits or stall other due triggers.

## Per-user auth model (AGE-194)

Reuses the mcp-server's **bring-your-own-key** model. In HTTP mode a caller sends
their own Clockchain key as `x-clockchain-api-key`; a non-reversible fingerprint of
it (`byok:<sha256-16>`) becomes the request identity that **scopes `keeper_list` /
`keeper_cancel` / `keeper_schedule`** so one tenant can neither see nor cancel
another's triggers. In hosted (HTTP) mode this identity is **required** — an
identity-less request is refused and the client-supplied `sub` argument is ignored,
so a caller cannot read or cancel everyone's triggers by omitting it. A bearer token
(`KEEPER_AUTH_TOKENS`) gates the endpoint itself (constant-time compared).

Today the keeper anchors every fire with its **own** delegated key (env). Mapping
each `sub` to a distinct gateway sub-key / credit budget is deferred (below).

> **Recurring schedules + dead-letters:** an `interval` trigger re-arms after each
> *anchored* fire even if that fire's delivery dead-lettered (the fire is on-chain;
> a broken endpoint should not silently kill the schedule). Cancel it to stop. After
> downtime, an interval fast-forwards to the next future slot — it does not replay
> every missed slot.

## Runtime / infra requirements for a production keeper

The data plane is **stateful and long-lived**, which differs from the stateless
mcp-server. A prod keeper needs:

- **A single always-on instance** (not request-scoped, not scale-to-zero). A
  Cloud Run **service with `min-instances=1`, `max-instances=1`, CPU always
  allocated** — or a dedicated VM / Cloud Run **Job that stays running**. This
  `max-instances=1` constraint is **load-bearing**: there is no trigger leasing
  yet, so two instances on the same file store would double-fire (and double-charge
  anchors). Horizontal scale is deferred (below).
- **A persistent, durable volume** for `KEEPER_STORE_PATH` (Cloud Run needs a
  mounted volume / Filestore, or swap in the SQLite/DB store). Container-local
  disk is wiped on redeploy → lost schedules.
- **Outbound network egress** to deliver webhooks, plus reach to the Clockchain
  gateway for time + anchoring.
- **Secrets** in Secret Manager: `CLOCKCHAIN_API_KEY`, `KEEPER_WEBHOOK_SECRET`,
  `KEEPER_AUTH_TOKENS`. Never in git (placeholders only).
- **A funded keeper wallet** — every fire spends one log credit to anchor.
- **Clock reachability** — the worker refuses to fire until the disciplined clock
  has synced against consensus time at least once.
- **Monitoring**: alert on `status:"dead"` triggers (dead-letters) and on triggers
  stuck `firing` (anchor backlog), plus `/healthz`.

## Deferred scope (honest TODOs)

- **Multi-tenant scale / horizontal workers** — needs trigger leasing so multiple
  workers don't fire the same trigger; today assume one process per store.
- **SQLite / DB store** — interface is ready; only file + memory ship.
- **Full OAuth** — only bearer tokens + BYO-key fingerprinting today.
- **Per-`sub` gateway sub-key + credit budget** — so each tenant's anchors bill to
  them (mirrors the mcp-server `/token` TODO). Today all anchors use the keeper's
  delegated key.
- **DNS-rebind-safe SSRF** — the guard blocks literal private/loopback/metadata
  IPs (including IPv4-mapped IPv6 like `::ffff:169.254.169.254` and the unspecified
  `::`), enforces http(s), enforces a deny-by-default allow-list in HTTP mode, and
  does not follow redirects (`redirect: "manual"`). It does **not** yet resolve
  hostnames and pin the resolved IP at connect time (TOCTOU). The mandatory
  `KEEPER_WEBHOOK_ALLOWLIST` is the hard guarantee in prod until DNS pinning lands.
```
