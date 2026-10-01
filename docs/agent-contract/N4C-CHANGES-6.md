# N4c changes 6 (orchestrator, 2026-09-28): the extractor gaps found by the N4e live proofs

N4e (`feat/hermes-telemetry-n4d` @ `5a7a679`, `integrations/live-telemetry-proof/RESULTS.md` plus
`excerpts/`) ran real Claude Code 2.1.284, Codex 0.154.0 and Hermes 0.21.2 runs through the accepted sink.
**Hermes: nonce MATCH.** Codex and Claude: transport OK, but **0 nonces**, because of extractor format gaps (not weak
telemetry). Fix both, test-first, using the **real sanitized excerpts** as fixtures (copied, with their source noted).

1. **Codex.**
   - `codex.tool_result.output` wraps the MCP result in an exec preamble
     (`"Wall time: …\nOutput:\n{json}"`).
   - Add a codex-specific unwrap: strip **only** that exact, deterministic preamble (anchored regex; anything
     unexpected → no nonce, flagged `codex_output_unrecognized`), then apply the existing rule of one structural nonce.
   - Never do a substring search for nonces.
   - Tests: the real excerpt → nonce extracted; a preamble with two JSON bodies → ambiguous → no nonce; a non-matching
     wrapper → flagged.
2. **Claude Code 2.1.284.**
   - It emits span `claude_code.tool` with attribute `tool_name`, and an event `tool.output` with attribute `output`
     (clean JSON).
   - Support this shape **alongside** the fixture-era `claude_code.mcp.rpc` shape, keyed by version-agnostic
     structure. The tool name comes only from `tool_name`.
   - Tests: the real excerpt → nonce extracted; an event missing `output` → no nonce.
3. **Identity privacy (investigate, report).** Claude's exported logs carry `user.email`, `account_uuid` and org
   identity, and the sink stores raw bodies, so this identity lands in evidence.
   - The forwarder must stay byte-for-byte, so **find the source-side suppression**: Claude Code env or settings
     that drop account and user attributes from its telemetry. Check the installed binary and docs read-only, for
     example `OTEL_METRICS_INCLUDE_ACCOUNT_UUID`, `OTEL_RESOURCE_ATTRIBUTES` overrides, or logs-exporter scoping to
     spans only.
   - Report exactly which settings remove them, and whether spans alone carry what R13(d) needs (the finding says
     the nonce is in the span event), so the logs exporter can be off.
   - Don't change the sink's integrity model.

Commit as "N4c changes 6". Report the tails and the privacy finding. Then idle.
