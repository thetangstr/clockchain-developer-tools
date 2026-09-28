# N4b-2b changes 2 (orchestrator, 2026-09-28): the re-review of d3949a8 says ACCEPT WITH FIXES

**Closed with probe evidence:** the agreement rewrite (A), the self-written or raised cap (B), exact v2 builders, the
policy pin and `allow`, receipts first (D), non-latest accept, withdraw after booking, and verification write-once.
(Probe: `.omc/state/audit-2026-09-28/n4b2b-probe-r2.mjs`.)

The orchestrator's decisions for the rest, test-first (seen red):

1. **Listing burn (E, still OPEN).**
   - A listing holds **multiple pending sealed deliveries**: at most 16 per listing, and **one pending per sender per
     listing** (a new one replaces that sender's old one).
   - The listing is consumed only when **the provider acts**: when it binds the handshake that came from one
     delivery, or explicitly accepts one.
   - The provider's inbox lists every pending delivery.
   - Test: probe E. A well-formed junk seal from buyer X doesn't stop buyer Y's genuine delivery from reaching the
     provider, and once the provider acts, the rest are cleared.
2. **A false mismatch is terminal.** A buyer `mismatch` verification ends the run with `terminalState:
   "verification_failed"`, whether the server's observation agrees or not (the disagreement is recorded as a flag).
   No settlement is possible. Cancelling the issued sim booking is post-verdict cleanup, outside the run.
   Test: probe C's false-mismatch sequence ends terminal, not stuck.
3. **The mandate is single-use.** `mandateId` is single-use **per principal**, and the used ids are recorded durably
   in the state dir (fail-closed like `used-sessions`). Test: the same mandate in a second run → `MANDATE_INVALID`.
4. **Listing caps per provider.** Replace the global 512 with a per-provider cap (e.g. 32) plus a global safety cap.
   Test: one provider can't lock out another.
5. **`commercialTransfer: false`** also goes in the `settlement_authorize` result.

The deferrals are unchanged (they block P): M1 receipts before bind, M2, M3, the P-GAP, salted `argsDigest`,
`booking_cancel`, and listingId in the seal context. Commit as "N4b-2b review fixes 2". Report the tails, then idle.
