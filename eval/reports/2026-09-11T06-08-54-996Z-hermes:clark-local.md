# Clockchain MCP — agent test report: PASS

| | |
|---|---|
| Agent | `hermes:clark-local` (Hermes (local profile clark-local, kimi k3)) |
| Endpoint | https://mcp.clockchain.network/mcp |
| Credentials | tester token (the profile's configured x-api-key) |
| Run | `06934995` · 2026-09-11T06:08:54.996Z → 2026-09-11T06:10:59.164Z |
| Tasks | **4 / 4 passed** (on-chain checks, no LLM judge); tool selection 4 / 4 — partial suite: 4 of 24 tasks (`TASK=time-read,stopwatch,hosted-timer,hosted-alarm-cancel`) |
| Tools | 0 on the live surface: **0 exercised OK**, 0 exercised with an error result, 0 not single-agent testable (covered elsewhere), 0 not exercised |

## Tasks

| Task | Result | Tools | Calls | Evidence |
|---|---|---|---|---|
| `time-read` | ✅ PASS | as expected | 2 | live height 729; called get_time=true |
| `stopwatch` | ✅ PASS | as expected | 4 | stopwatch_verify called=true, verified=true, elapsedOnChainMs=9151 |
| `hosted-timer` | ✅ PASS | as expected | 4 | fired: ledger bfe3e28d-3762-4bb7-a94a-b98ca6c81819 block 742 |
| `hosted-alarm-cancel` | ✅ PASS | as expected | 5 | alarm 5890b2cc-ef6a-4137-bcb7-77601054cebe status=cancelled |

## Tool coverage (live `tools/list`)

| Tool | Status | Calls | Note |
|---|---|---|---|

Legend: ✅ called and returned the server's JSON success payload · ⚠️ called, returned an error/text result (see the task's evidence — expected where the substrate lacks the API) · ◻️ cannot be completed by one agent; covered by the named suites · ❌ not exercised in this run.

Verdict rule (partial suite): PASS = every selected task's on-chain check passed. The coverage matrix is informational — tools outside the selected tasks are not expected.
