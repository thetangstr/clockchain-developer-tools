# N4c changes 3 (orchestrator, 2026-09-28): the closing check of df4631a says ACCEPT WITH FIXES (completeness only)

**Closed:** `verifyAndExtract` as the only entry point, the isError/label/re-anchor/owner/409 items, and most of the
close authority. There's no fabrication path left. Fix these completeness gaps, test-first
(the probe is `.omc/state/audit-2026-09-28/n4c-probe-r3.mjs`):

1. **Receipt freshness and runId reuse.**
   - A closing receipt's `ts` must be at or after the run's first ingest (or its opening) and not in the future
     (bounded skew).
   - `closedAt` = the receipt's `ts` + flush grace. Ingest keeps being accepted until then, and the run seals at that point.
   - Refuse to mint tokens for a `runId` that's ever been used.
   - Tests: a 2020 receipt against a 2030 run → refused; a reused runId → refused.
2. **One final head, with no stale variants.**
   - The final head is signed **once** at close. Post-close refusals go into a **separately signed refusal annex**
     `{runId, finalHeadDigest, refusedAfterClose, updatedAt}`.
   - The anchor covers the digest of the **whole signed final head**.
   - `verifyAndExtract` needs the final head plus the latest annex. The verifier reads refusals from the annex, and a
     head or annex pair that doesn't match → refused.
   - Test: holding an early annex can't hide later refusals (the annex is monotonic and signed with `updatedAt`; the
     verifier fetches it itself).
3. **Auto-close time.** `closedAt` = the window's end, not the time the run is next accessed.
4. **pf README.**
   - Add the macOS steps: `pfctl -E`, loading the anchor from the main ruleset, and a verification command.
   - **Serve queries on a separate port** from ingest. Only agent uids can reach the ingest/forwarder ports; the
     harness and verifier uids can reach only the query port.
   - Note the residual: pf can't tell the agent CLI from other processes under the same uid, so sudoers for that uid
     must be restricted to the pinned agent binary. This is recorded under LLD E10.

Same scope and limits. Commit as "N4c review fixes 3". Report the tails and items with their test names. Then idle.
