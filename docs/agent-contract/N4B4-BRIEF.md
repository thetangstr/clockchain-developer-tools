# Brief N4b-4: remaining surface items before P (second travel Devin)

N4b-3 was ACCEPTED (local-only, `e48d0ec`). These are bounded items in the same scope, test-first:

1. **`booking_cancel` (provider).** Cancel a booking **before** settlement: after a `mismatch` verification, after
   `verification_failed`, or by mutual withdrawal before verification.
   - It goes through prepare → local sign → submit (the v2 envelope, a new payload kind `cancel`:
     `{agreementId, agreementDigest, bookingRef, reason}`), plus an approval record for `booking`-class actions.
   - It calls the sim's cancel. It's idempotent, and refused after settlement.
   - The cancelled order shows `CANCELLED` on `booking_lookup`, and the run's terminal state records it.
   - **Add `cancel` to `CONTRACT-PAYLOADS-v2.md`** as a proposal note in your report. The orchestrator re-freezes the vectors.
   - Tests: cancel after a mismatch; cancel after settlement is refused; idempotent replay; wrong role refused.
2. **The poll limiter is per principal**, not per session: the new-session reset found in the closing review.
3. **Key validity at the source.** The server refuses to sign once the published key's `validUntil` has passed,
   and refuses to start if it's already past.
4. **Not in scope:** listingId in the rendezvous seal context. It changes the N5 seal profile, so it waits until N5
   settles; the orchestrator will coordinate it.

Hard limits as before. Commit per item. Report the tails, then idle.
