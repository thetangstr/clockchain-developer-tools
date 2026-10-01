# N4c changes 5 (orchestrator, 2026-09-28): the Hermes extractor branch

N4d (the Hermes plugin, `feat/hermes-telemetry-n4d` @ `6707767`) emits records that the accepted sink **ingests and
chain-verifies**, but `verifyAndExtract` yields no rows because the extractor has no `hermes` branch. The attribute
contract is pinned in
`/Volumes/mac_studio_ssd/Projects/travel_mvp/.worktrees/hermes-telemetry-n4d/integrations/hermes-ac-telemetry/tests/n4c_compat.test.mjs`
(read-only):
- `event.name = "hermes.tool_call"`
- `runtime = "hermes"`
- `tool_name`
- `mcp_server`
- `function_args`
- `args_digest`
- `output` (structural nonce)
- `call_id`
- `timeUnixNano`

Add a `hermes` branch to the extractor, in your package, test-first.
- The tool name comes **only** from `tool_name`.
- The nonce is parsed structurally from `output`, exactly one, with `isError` / `error_type` → `error_result` and no nonce.
- The runtime is pinned via `roleRuntime` as for the others.

Add a fixture copied from the N4d compatibility test's record, labelled with its source. Tests: a row with the
nonce; an arg called `name` doesn't rename the tool; an error result gives no nonce; a runtime mismatch is refused.
Commit as "N4c changes 5 (hermes extractor)". Report the tails, then idle.
