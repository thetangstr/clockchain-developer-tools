# Auth & Traffic: Sizing the MCP Front Door

A decision memo. The MCP server is the front door to the Clockchain network.
This memo answers three coupled questions that keep coming up: how callers
authenticate (Cowork vs API key), how much traffic each channel actually carries,
and therefore where to spend engineering effort. It exists to size the OAuth
investment correctly and to surface the asks that belong to D4.

This is a direction memo and it sits downstream of two unresolved facts: we have
**no demand data yet** (no prospect has asked unprompted), and the identity
source of truth is **owned by D4, not the MCP team**. The numbers below are
planning assumptions, not forecasts. They are order-of-magnitude, meant to size
decisions, not to be budgeted against.

## TL;DR

- **Authenticate at the network identity, not at the connector.** One identity
  system (D4's existing API keys / wallet IDs / on-chain agent identity); the MCP
  server is a *resource server* that resolves every call to a network identity.
  Two credential *lanes* (API key, OAuth) both resolve to the **same** identity.
- **Cowork / web Claude is the small channel** for our use cases — plausibly
  low-single-digit % of call volume. High funnel value (where a champion first
  tries us), low traffic. Do **not** size OAuth for scale; size it for reach.
- **The API-key / production-agent path is 80–95% of traffic** and is where the
  real engineering belongs: metering, rate limits, idempotency, and the async
  attest pattern.
- **Infra is cheap and scales easily.** The binding constraints are (1) attest
  latency (~15s block wait → long-held requests / concurrency), and (2) **mainnet
  per-write cost**, which is the real COGS and the number that decides unit
  economics. Both need a D4 input.

## One identity, two credential lanes

The product's whole pitch is attested agent identity. The auth model should not
fork that into a second directory. So:

- **Single source of truth** — the network's identity: D4's API keys / wallet IDs
  today, and ultimately the on-chain Agent Identity the product already mints
  (`mint_identity` / `resolve_agent` / `delegate_authority` / `verify_identity_at`).
- **MCP = front door = resource server.** It owns no users. It validates a
  credential and resolves it to a network identity, then authorizes the call.
- **Credentials are plural; identity is not.**
  - **API key** (developer / production-agent lane) → resolves to a network identity.
  - **OAuth token** (Cowork-class connector lane) → issued by a thin OAuth server
    that has **no user store of its own** and delegates login to the network
    identity (Ory Hydra is built for exactly this). Satisfies Cowork's OAuth 2.1
    + DCR requirement without forking identity.

This rules out managed IdPs with their own user stores (WorkOS / Auth0 / Keycloak-
with-local-users) — each would *be* a second identity system, which is the thing
to avoid. The payoff: the identity an agent authenticates with is the same
identity that appears in every attested receipt. Front door and product are one
system.

> **D4 ask #1 — identity source of truth.** The MCP team owns the front-door
> adapter (resource-server validation + an OAuth server that delegates to the
> network). D4 owns the identity store. We need agreement that MCP authenticates
> *against* D4's identity system, and which store is canonical (API key DB? wallet
> registry? on-chain agent identity?). This is an org decision, not a vendor pick.

## Cowork: it's the *online* connector that needs OAuth, not Cowork per se

Two ways MCP reaches Cowork; only one is blocked:

- **Cloud custom connector** — added in the user's Claude account; the connection
  originates from Anthropic's servers. The connector UI offers **only OAuth or
  authless** — no bearer-token field
  ([issue #112](https://github.com/anthropics/claude-ai-mcp/issues/112), closed
  "not planned"). This is the path that forces OAuth.
- **Claude Desktop bridge** — a server configured in `claude_desktop_config.json`
  with an `Authorization: Bearer` header (via an `mcp-remote` launcher) is bridged
  into the Cowork VM. This path **takes our existing token** — no OAuth. It's a
  per-user local setup, not clean self-serve, and worth a short test before
  relying on it.

**"Authless" ≠ "API-key-less."** Authless drops only the *connector* credential.
Our server still holds the Clockchain API key and still spends it. Going authless
removes *per-caller identity*, so by default you cannot meter or bill — unless you
move identity into the **tool layer** (an `account_key` argument / `link_account`
tool, or a per-customer URL). That keeps the connector authless (Cowork connects)
while preserving metering and billing, and stays single-ID. Caveat: don't put
long-lived, high-privilege keys in tool arguments (they can land in transcripts) —
use scoped, short-lived keys or the per-customer-URL pattern; OAuth/Hydra is the
clean long-term that removes the in-payload-secret problem.

## Channel → surface → traffic

For our use cases, the channels do not route through Cowork equally:

| Channel | Surface used | Auth | Traffic profile |
|---|---|---|---|
| Production agents (attest every action) | Their agent infra / AgentDash, server-to-server | API key | **Highest volume** |
| Developers (wire MCP into their agent) | Claude Code (stdio), Cursor, own runtime | API key / bearer | Medium, bursty |
| Sales / marketing (try it) | **Our playground** (our web frontend) | Delegated (our key) | Low, demo |
| Cowork / web Claude (human adds connector) | Cowork cloud connector | OAuth / authless | **Lowest volume** |

None of the high-value, high-volume use cases run through Cowork. Court-grade
attestation of every agent action is inherently *programmatic* — it runs in the
customer's agent infrastructure with an API key, not in a person's Cowork chat.
The playground is *our* site, not Cowork.

**Near-term (design-partner phase, ~next quarter), planning assumptions:**

- Cowork / web connector users: a handful — **~5–30 individuals** across a few
  design partners + internal D4 + exec demos. Low call volume each (tens to
  low-hundreds of interactive calls/day). This is *evaluation* traffic.
- One production customer that converts (Meridian-Pay-style) can **dwarf all
  Cowork traffic combined**.

**Conclusion:** Cowork is high-funnel-value, low-traffic. Size its OAuth path for
**tens of users**, not thousands. Build it when a design partner specifically
needs Cowork, not before.

> **Strategic fork worth naming.** This holds under the current thesis (enterprise,
> autonomous agents, compliance). A *horizontal* pivot ("every knowledge worker's
> Claude attests their work") flips Cowork/web to the **primary** channel and
> inverts this memo. The traffic answer is downstream of "do we sell to agent
> platforms or to individuals." Today: the former.

## Capacity & cost — the API-key path (where it actually scales)

Cost drivers for the MCP host:

1. **Compute / bandwidth** to proxy calls — cheap.
2. **On-chain write cost** for attestations — free on testnet; **the real COGS on
   mainnet.**
3. **LLM cost — $0 to us.** The caller's agent pays for its own model.

**Traffic model (planning unit = one active production customer):**

- One attested business action ≈ ~1 write (`attest_action`) + ~3–5 reads
  (`resolve_agent`, `verify_*`). Call it ~5 calls per action.
- Assume a mid-size customer attests ~1,000 actions/day → ~5,000 calls/day ≈
  **0.06 calls/sec average**, peaks maybe 10–50× = a few calls/sec. Trivial for one
  server.
- 10 customers → ~50k calls/day ≈ 0.6/sec avg. Still tiny.
- 100 customers → ~500k calls/day ≈ 6/sec avg, peaks ~100–300/sec. Now you need
  horizontal scale + HA.

**The binding constraint is latency, not QPS.** `attest_action` waits ~15s for a
block. Long-held requests cap concurrency long before raw throughput does. The fix
is an **async / job pattern** (submit → poll/callback) rather than holding the
connection — this is the single most important piece of server engineering on the
API-key path.

**Cost shape:**

- **Infra:** a single small cloud instance ($20–100/mo) handles thousands of
  customers' read traffic; a few instances behind a load balancer for HA keeps it
  in the **low hundreds of $/mo** for a long time. Compute is not the constraint.
- **COGS = mainnet write cost per attestation.** This scales linearly with attested
  actions and **sets the price floor**: price-per-attestation must exceed
  on-chain-cost-per-attestation + margin. On testnet it's $0 (why the demo is
  free). We do not have a mainnet fee number — this is the number that decides unit
  economics.
- **LLM:** $0 to us.

> **D4 ask #2 — mainnet write economics.** What does one on-chain attestation cost
> on mainnet (gas / fee), and is there a batching path? This sets the paid-tier
> price floor. Until we have it, unit economics are unknowable.

> **D4 ask #3 — schedule signature spec.** `create_schedule` needs a wallet
> signature (undocumented). One sentence on what message the wallet signs for
> `/api/contract/schedule`, and whether it's enforced on testnet, unblocks the last
> preview feature.

## Where the engineering goes (sized by traffic)

| Investment | Channel served | Priority | Why |
|---|---|---|---|
| API-key issuance / rotation / scoping | Production + dev (80–95%) | **High** | The volume path; also the metering primitive |
| Per-account metering + rate limits | Production + dev | **High** | Required for billing + abuse control |
| Async attest pattern (submit → poll) | Production | **High** | The real concurrency constraint (~15s waits) |
| Idempotency keys | Production | Medium | Safe retries on writes |
| OAuth via Hydra (delegates to network identity) | Cowork (<5%) | **Low / on-demand** | Reach, not scale — build when a partner needs Cowork |
| Authless + tool-layer identity | Cowork demo | Now (capped) | Unblocks this week's demo with existing caps |

## Recommendation

1. **This week:** demo Cowork via the **Claude Desktop bridge** (takes our existing
   token) if the operators run Desktop; otherwise **authless with the existing rate
   + log-budget caps**. Either is fine for evaluation-scale traffic.
2. **v2:** build the **API-key path properly** — issuance, metering, rate limits,
   async attest, idempotency. This is where the traffic and the revenue are.
3. **v2/v3, on demand:** add **OAuth via a network-identity-delegating server
   (Hydra)** when a design partner specifically needs the Cowork cloud connector.
   Size it for tens of users.
4. **Blocked on D4:** identity source of truth (#1), mainnet write economics (#2),
   schedule signature spec (#3). The first two gate the architecture and the unit
   economics; resolve before committing tooling.
