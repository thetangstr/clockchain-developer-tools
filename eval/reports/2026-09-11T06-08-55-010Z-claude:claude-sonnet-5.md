# Clockchain MCP — agent test report: PASS

| | |
|---|---|
| Agent | `claude:claude-sonnet-5` (Claude Code claude-haiku-4-5-20251001+claude-sonnet-5) |
| Endpoint | https://mcp.clockchain.network/mcp |
| Credentials | self-serve demo token, minted with one unauthenticated `POST https://mcp.clockchain.network/token` (tier: demo) — no account, no signup |
| Run | `06935010` · 2026-09-11T06:08:55.010Z → 2026-09-11T06:10:07.231Z |
| Tasks | **4 / 4 passed** (on-chain checks, no LLM judge); tool selection 4 / 4 — partial suite: 4 of 24 tasks (`TASK=time-read,stopwatch,hosted-timer,hosted-alarm-cancel`) |
| Tools | 0 on the live surface: **0 exercised OK**, 0 exercised with an error result, 0 not single-agent testable (covered elsewhere), 0 not exercised |

## Tasks

| Task | Result | Tools | Calls | Evidence |
|---|---|---|---|---|
| `time-read` | ✅ PASS | as expected | 2 | live height 723; called get_time=true |
| `stopwatch` | ✅ PASS | as expected | 5 | stopwatch_verify called=true, verified=true, elapsedOnChainMs=5957 |
| `hosted-timer` | ✅ PASS | as expected | 5 | fired: ledger 9f317006-9014-4936-90f4-a7083f88d51b block 735 |
| `hosted-alarm-cancel` | ✅ PASS | as expected | 5 | alarm 7167d71e-c21a-4f08-ba86-b26aa9d06bf3 status=cancelled |

## Tool coverage (live `tools/list`)

| Tool | Status | Calls | Note |
|---|---|---|---|

Legend: ✅ called and returned the server's JSON success payload · ⚠️ called, returned an error/text result (see the task's evidence — expected where the substrate lacks the API) · ◻️ cannot be completed by one agent; covered by the named suites · ❌ not exercised in this run.

Verdict rule (partial suite): PASS = every selected task's on-chain check passed. The coverage matrix is informational — tools outside the selected tasks are not expected.
