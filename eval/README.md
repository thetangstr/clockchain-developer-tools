# Clockchain MCP — eval harness

Execution-scored evaluation of the hosted Clockchain MCP server. Two layers:

- **Layer A — performance** (`perf.mjs`): per-tool latency (p50/p95/p99) and the
  "token tax" (how many tokens the tool definitions cost per request). Reads only,
  no credit spend.
- **Layer B — agent tool-use** (`run.mjs` + `tasks.mjs`): drives the `claude` CLI as
  an MCP client over the live endpoint, captures the tool-call trajectory + token
  usage, and scores each task with a **deterministic, on-chain check** — no LLM
  judge. Clockchain's edge: "did the receipt verify / the reference get anchored /
  the valid-at-T verdict come out right" are exact booleans we re-check independently.

## Run

```bash
# Layer A — performance (real numbers, no LLM)
MCP_TOKEN=<tester token> node eval/perf.mjs

# Layer B — agent eval (needs the `claude` CLI on PATH, used as the MCP client)
MCP_TOKEN=<tester token> node eval/run.mjs
#   env: MCP_URL (default https://mcp.clockchain.network/mcp), MAX_TURNS=12, TASK=<id filter>
```

`run.mjs` writes a temporary MCP config pointing the `claude` CLI at the endpoint
(`x-api-key`), allow-lists the `mcp__clockchain__*` tools, and runs each task headless
(`--output-format stream-json`). Swap in the Anthropic API as the agent backend by
replacing `runClaude()` if you'd rather not depend on the CLI.

## Metrics

Per task: **completion** (the on-chain `check` — the headline), **tool-selection**
(did it call the expected tools), **# tool calls** (trajectory efficiency), **tokens**.
Aggregate: completion rate, tool-selection rate, avg calls + tokens/task.

## Tasks (`tasks.mjs`)

Each task embeds a unique reference per run so the check verifies the *outcome* on the
live chain, independent of what the agent says. Covers Time, Logging (notarize →
search), Identity (attest → verify_receipt; mint → valid-at-T), and keyless
cross-party verify. Add tasks by appending `{ id, prompt, expectTools, check }`.

## CI

Layer A is cheap/deterministic and safe to run on every deploy. Layer B spends
testnet credits and needs the CLI/an API key — run it on demand or nightly, not on
every PR. Could become an eval gate once the score is stable.
