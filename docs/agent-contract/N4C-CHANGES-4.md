# N4c changes 4 (orchestrator, 2026-09-28): two small follow-ups after ACCEPT (3699c33)

N4c is ACCEPTED as a local-only component. Two bounded follow-ups from the final review, test-first, in your package only:

1. **The used-runId check applies to ingest tokens only.** Query tokens for a run can still be minted after its
   first ingest (the verifier mints after sealing), but never before the run exists. Test: a query token minted after
   seal → works; an ingest token re-minted for a used runId → refused.
2. **A close-only listener for the contract server.**
   - This is a third listener, separate from write and query, serving **only** `POST /v1/runs/:runId/close`. It
     needs no token; the sink verifies the terminal-receipt signature under the pinned contract-server key, exactly
     as today.
   - The write listener no longer serves `/close`, so the agent-side forwarder can't deliver closes.
   - Update the pf README: only the contract-server host's address or uid can reach the close port.
   - Tests: `/close` on the write port → 404; `/close` on the close port with a genuine receipt → seals; with a forged
     receipt → refused; the forwarder can't reach `/close`.

Commit as "N4c follow-ups (changes 4)". Report the tails, then idle.
