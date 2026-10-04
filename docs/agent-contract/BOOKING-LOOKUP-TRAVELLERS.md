# booking_lookup: `observation.travellers`

`booking_lookup` returns `{ observation, simulated, serverNonce }`. Since this change the
observation of a known order carries `travellers`: the party size the order was booked for.

- Source: the server's own order record (`travelerCount`, set at `booking_prepare`/`bookOrder`
  from the principal-signed mandate's `partySize`). It is never a caller input — the tool's
  input schema is strict, so a `travellers` argument is rejected as invalid tool arguments.
- It is distinct from `ticketCount`, what was actually issued. A buyer verifying a booking
  compares the two (and the itinerary, total and status); under the `issueMismatch: "travellers"`
  sim fault they differ (4 booked, 5 issued).
- Absent on `NOT_FOUND` (there is no order) and when the order was booked without a signed party size (a legacy mandate books the default of 1, which is not a claim — `bookingPayload` and `verification_submit` omit it the same way).
- Additive: no existing field changes. The tool descriptions and `tools/list` are untouched, so
  published guidance digests do not move. `contract_status`'s `booking` view is unchanged.

Found by live run p6-at-2026-10-04-2/-3: the observation had `ticketCount` but no party size, so the
buyer's front door showed `travellers: null` and an honest agent recorded `travellers_mismatch`.
