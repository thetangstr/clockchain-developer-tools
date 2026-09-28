# N4b-2b changes 1 (orchestrator, 2026-09-28): the security review REJECTED a677df5 + 5a78555

Your suite passes (652/652, and it reproduces), but it doesn't test these paths. The review's probe
(`/Volumes/mac_studio_ssd/Projects/travel_mvp/ac_travel_mvp/.omc/state/audit-2026-09-28/n4b2b-probe.mjs`,
read-only) was reproduced by the orchestrator:
- **Probe A:** a stale offer accepted after booking and a match verification rewrites the agreement, and settlement
  pays 430000 against a 479000 booking.
- **Probe B:** an empty mandate means no cap, and resubmitting raises the cap.

Fix everything below **test-first (seen red)**. Each test must fail on `5a78555`.

## Must-fix
1. **The agreement is write-once.**
   - Once `run.agreement` is set, refuse **every** `offer_*` / accept (`STATE_REFUSED`).
   - A new offer or counter supersedes all earlier live offers **from the same party**.
   - Accept only the counterparty's **latest** live offer.
   - The verification payload carries `agreementId` and `agreementDigest`. Settlement checks that they equal the
     current agreement **and** the booked order.
   - Tests: the probe-A sequence is refused at the second accept; accepting a stale offer is refused.
2. **The mandate is principal-signed** (the design decision in `CONTRACT-PAYLOADS-v2.md` §Mandate, rev 6.5, in the
   travel repo).
   - Required fields; a principal EIP-191 signature over the domain-separated digest; the principal pinned in config
     (`CONTRACT_PRINCIPALS`).
   - Write-once per run, and required before any buyer offer or accept.
   - Tests: an empty or partial mandate, a wrong principal, a resubmission, and an offer without a mandate are all refused.
3. **The prepare builders emit exactly the v2 shapes** (`CONTRACT-PAYLOADS-v2.md`):
   - `agreementDigest = canonicalDigest({domain: "agent-contract.agreement/v1", runId, offerDigest})`;
   - `accept` carries `offer` plus the flat terms;
   - `booking` = `{agreementId, agreementDigest, itineraryId, currency, totalMinor}`;
   - `verification` = `{agreementId, agreementDigest, bookingRef, result, findingsDigest}`;
   - `settlement` = `{agreementId, agreementDigest, verificationDigest, itineraryId, currency, amountMinor, simulated: true}`.

   **Test the builder output field-for-field against the payloads in the v2 vectors**, not only the signatures.
4. **Pin the approval policy digest.**
   - Add a required config pin `CONTRACT_POLICY_DIGESTS` (`role:policyDigest`); a missing pin is a startup error.
   - Require `decision === "allow"` (the spec name; `approve` is invalid).
   - `approverKeyId` must equal the bound approval key id, and `ts` must fall within the envelope's validity.
   - Refuse at bind an approval key that equals the signer key.
   - Test: the probe-C zero-digest approval is refused.
5. **Receipts first for consequential actions.**
   - Reserve the receipt slot (budget) **before** dispatch. If a receipt can't be written, the action doesn't happen
     (or is rolled back).
   - Test: probe D. With the budget exhausted, `settlement_authorize` does **not** release, and the call is refused.
6. **Refusals carry `serverNonce`**, and every schema or role refusal is receipted where a principal is known. This
   keeps R8 correlation complete.
7. **Rendezvous hardening.**
   - Only the listing's owner can close or reset a listing.
   - A delivery that doesn't parse as the v2 seal `{v, epk, iv, ct, tag}` is refused **without** burning the listing.
   - Deliveries are rate-limited per sender, and listings/inboxes have caps and a TTL.
   - Fix the `sealedBox` schema to accept the real v2 seal.
   - Test: a junk ciphertext can't make the legitimate sender get `LISTING_UNAVAILABLE`.

## Also fix
- **Withdrawal after an agreement** goes only through an explicit terminal path (`contract_withdraw` → `STATE_REFUSED`
  after booking; add a documented `booking_cancel` flow later if needed). A verification is **write-once** (a
  `mismatch` can't be overwritten).
- **`commercialTransfer: false`** goes on payment receipts, and `simulated: true` on the settlement payload.
  Currency must match `^[A-Z]{3}$`, and the note is limited to 280 characters.
- **LOW:** a constant-time observer token compare and a feed rate limit; the `rendezvous_search` filters must work.

## Deferred (note it in the report)
- Salting the receipt `argsDigest` for mandate/cap-bearing calls. It matters only if the feed leaves our side; it's a
  P-hardening item.
- M1–M3 and the P-GAP are still open, as before.

Same scope and limits. Commit as "N4b-2b review fixes". Report commits, raw test tails and each item with its test
name. Then idle.
