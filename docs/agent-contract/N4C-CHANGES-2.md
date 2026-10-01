# N4c changes 2 (orchestrator, 2026-09-28): the re-review of 2c1a62b says ACCEPT WITH FIXES

The re-review closed C1, C2, H1, H2, H3 and M1–M4 with probe evidence
(`.omc/state/audit-2026-09-28/n4c-probe-r2.mjs`). Fix the remaining items, test-first (seen red).

## Must-fix
1. **No chain, no rows.**
   - Replace direct extraction with a single entry point, `verifyAndExtract(records, finalHead, sinkPublicKeys, {roleRuntime})`.
   - It first verifies the full chain against a **final** head (`final: true`, matching `recordCount`, a valid
     signature under a pinned key), and returns rows only if that passes.
   - `extractTelemetrySpans` becomes internal and isn't exported.
   - Test: a made-up record with a correct `bodyDigest` and a fake `recordDigest` gives no rows.
2. **Close authority: the sink, never the harness** (orchestrator decision). Remove the per-run `admin` close token.
   The sink closes a run only when **one** of these holds:
   - `POST /v1/runs/:runId/close` carries a **signed terminal receipt from the contract server** for that `runId`
     (ed25519 under a pinned contract-server key configured on the sink, with a terminal state in {`settled`,
     `no_agreement`, `verification_failed`, `blocked_by_policy`, `budget_exhausted`, `harness_error`});
   - or the run's maximum window (configured) has expired, which is an auto-close.

   The final head records the close cause, the terminal receipt digest, and a **count of ingests refused after
   close**, and it signs all three.

   Tests:
   - A close with no receipt, with a receipt from another run, or with a bad signature is refused.
   - Auto-close happens at the window.
   - The refused-after-close count is in the signed head.

   **Note for the verifier (the orchestrator will wire it into R13):** require `closedAt ≥` the last business
   receipt's `ts` + grace, and require the refused-after-close count to be 0 for ACCEPT. Put both facts in the final head.
3. **The pf rules in the README.** Rewrite them for macOS pf:
   - remove `set skip on lo0`;
   - put `pass out quick on lo0 proto tcp to {127.0.0.1, ::1} port <fwd> user <agent-uid>` **before**
     `block out quick on lo0 proto tcp to {127.0.0.1, ::1} port <fwd>`;
   - note that `user` on `out` rules matches the connecting process.

   Use distinct example ports for the sink and each role's forwarder, and include a probe command the harness can
   run to confirm the rules.

## Also fix
- Don't take a nonce from an `isError: true` result; flag the row `error_result`.
- Rename the v3 seal label to `"agent-contract seal ingest-token v3"`, so it's no longer confusingly `…v2`. The
  label is part of the context, so update the tests.
- Retrying a close after an anchor failure must re-anchor.
- Check the key file's owner uid, not only its mode.
- A post-close 409 is returned only after the token kind is checked (no oracle).

Same scope and limits. Commit as "N4c review fixes 2". Report commits, raw test tails and items with their test names. Then idle.
