# Clockchain MCP — eval harness

Execution-scored evaluation of the hosted Clockchain MCP server. Three layers:

- **Layer 0 — offline coverage gate** (`packages/mcp-server/test/coverage.test.mjs`
  + `conformance.test.mjs`): deterministic, no network, runs in `npm test` so it
  gates every PR/deploy. Coverage asserts the ARGS matrix equals the registered
  tool set (all **31** tools — add a tool without coverage and CI fails) and that
  every tool degrades gracefully under an upstream failure (well-formed `isError`,
  never a throw). Conformance locks the MCP protocol contract (initialize, -32601,
  isError, Accept→406, stateless).
- **Layer A — performance** (`perf.mjs`): per-tool latency (p50/p95/p99) and the
  "token tax" (how many tokens the tool definitions cost per request). Reads only,
  no credit spend. Runs nightly via `.github/workflows/eval-nightly.yml`.
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
live chain, independent of what the agent says. 11 tasks spanning all six modules:
Time (`time-read`, `block-read`), Logging + Audit (`notarize`, `audit-trail`),
Receipts (`attest-verify`, `async-attest` submit→poll), Identity (`identity-valid-at`,
`cross-party-verify`), Commitments (`tsa-commitment`), plus two **adversarial** cases —
`adversarial-unknown-ledger` (must report "not found", not fabricate) and
`adversarial-no-write` (a read-only ask must call no credit-spending tool). Add tasks
by appending `{ id, prompt, expectTools, check }`; `check` receives
`{ callTool, trajectory, finalText }`.

## CI

- **Layer 0 (offline)** runs in `npm test` and gates every PR + the Cloud Run deploy
  (the deploy needs `test` green). This is the real eval gate: 31/31 tool coverage +
  protocol conformance, deterministic, no network.
- **Layer A (perf)** runs nightly (`eval-nightly.yml`, cron 08:17 UTC) and on manual
  dispatch. Needs repo secret `MCP_EVAL_TOKEN`; skips cleanly if unset. Reads only.
- **Layer B (agent)** spends testnet credits and needs the `claude` CLI — run on
  demand locally (`node eval/run.mjs`). Not wired into CI (no CLI/auth on runners).
