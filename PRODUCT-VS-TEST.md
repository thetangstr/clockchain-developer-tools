# Product vs Test Surface — Clockchain MCP

**Related issues:** CLO-99 (this doc) · CLO-22 (product server) · CLO-59 (mainnet) · CLO-64 (get_time production-readiness)

---

## The two surfaces

| | **Product surface** | **Full / Test surface** |
|---|---|---|
| Tools exposed | `get_time` only | All 31 tools |
| Env var | `MCP_SURFACE=product` | `MCP_SURFACE=full` (or unset) |
| Network | _Unresolved — see open questions_ | Testnet |
| Purpose | Verified consensus time for production agents | Full testnet exploration / development |
| Manifest | `server.product.draft.json` (DRAFT — do not publish) | `server.json` |

---

## Critical mechanic: MCP manifests do NOT list tools

An MCP manifest (`server.json` / `server.product.draft.json`) describes the server's
**connection endpoint and required headers** — it does NOT enumerate tools.
The `tools/list` response is determined entirely at runtime by which tools the
**deployed server registers**.

This means surface enforcement is code-level, not manifest-level:
- Set `MCP_SURFACE=product` on the deployed Cloud Run service.
- The server registers only `get_time` and returns exactly `["get_time"]` on `tools/list`.
- No manifest edit, no MCP client config, and no publisher action can override this —
  the server is the authority.

Corollary: the draft product manifest (`server.product.draft.json`) is used only to
describe the product endpoint to `mcp-publisher` once the endpoint exists. It has no
effect on what tools are registered.

---

## Tool-promotion rule

A tool moves from the full surface to the product surface only when it is
**production-ready** — meaning:

1. The underlying API endpoint is stable on mainnet (not testnet-only).
2. The tool has been reviewed for honest error handling, rate-limit surfacing, and no
   inadvertent credit spend.
3. An explicit decision is recorded in a CLO issue before the tool is added to the
   product surface.

**Today (CLO-99), only `get_time` is a candidate.** Whether it is ready depends on
CLO-64 (get_time production-readiness gate). All other 30 tools remain on the full /
testnet surface until individually promoted.

---

## Mainnet notes

- `get_time` on **testnet** returns `latestBlockTime` + `latestBlockHeight`. On
  **mainnet** the response will NOT carry `ledgerId` or a per-log `blockHeight` because
  `get_time` is a read of the consensus clock, not a log entry. Callers must not
  assume a ledgerId in the response.
- **Testnet logging will not migrate to mainnet.** Log entries anchored via the full
  surface on testnet are testnet-only; there is no migration path. Applications that
  need mainnet anchoring must re-anchor on mainnet from scratch.

---

## Open questions (blockers before publishing the product manifest)

1. **Does `product` surface == mainnet?** The surface flag and the network are
   currently decoupled. `MCP_SURFACE=product` only controls which tools are registered;
   the network (`CLOCKCHAIN_ENDPOINT`) is set separately. A decision is needed on
   whether "product surface" always implies mainnet, or whether they stay independent
   env vars. _(CLO-99 / CLO-59)_

2. **Is `get_time` mainnet-ready?** CLO-64 gates this. Until CLO-64 closes with an
   explicit "yes", the product surface should not be deployed to a public endpoint even
   if `server.product.draft.json` exists. _(CLO-64)_

3. **Namespace / server name.** `server.product.draft.json` has a TODO for the
   `name` field. Options include `network.clockchain/time`, `network.clockchain/product`,
   or a versioned slug. Needs a decision before mcp-publisher submission. _(CLO-22)_

4. **Endpoint topology.** Will the product surface be a separate Cloud Run service
   (separate URL), or the same service gated by `MCP_SURFACE`? The draft manifest has
   a TODO for `url`. _(CLO-22 / CLO-59)_

---

## Env-var cutover

To activate the product surface on a deployed instance:

```
MCP_SURFACE=product
```

Set this in the Cloud Run service environment (or equivalent). The default (`MCP_SURFACE`
unset) is always the full surface — the pre-CLO-99 behavior is preserved exactly.

To verify locally:

```bash
MCP_SURFACE=product node dist/stdio.js
# In another terminal, send tools/list — should return exactly ["get_time"].
```

Or via the npm test suite (all green, including the product-surface tests):

```bash
cd packages/mcp-server
npm test
```

---

## Do NOT publish `server.product.draft.json`

The file `server.product.draft.json` at the repo root is a **DRAFT**. It must not be
fed to `mcp-publisher` or submitted to any MCP registry until all blockers above are
resolved. The real published manifest remains `server.json` (full / testnet surface).
