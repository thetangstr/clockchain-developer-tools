# N4b-4 changes 1 (orchestrator, 2026-09-28): freeze the cancel payload

The orchestrator reran N4b-4 (704/704, scope clean). The cancel payload is frozen in the travel repo's
`CONTRACT-PAYLOADS-v2.md` §Cancel (rev 6.7): `reason` is an **enum** (`verification_mismatch`, `verification_failed`
or `mutual_withdrawal`), and it must match the run's actual state. Right now `booking_cancel_prepare` takes any string.

Test-first:
1. Validate `reason` against the enum, **and** against the run state. For example, `verification_mismatch` needs a
   recorded mismatch verification, and `mutual_withdrawal` needs a state before verification.
2. Copy `cancel-envelope-vectors.v2.1.json` and `cancel-role-sig-vectors.v2.1.json` **unchanged** from
   `ac_travel_mvp/docs/travel-mvp/design/vectors/` into `test/fixtures/`. Test builder output field-for-field against
   the vector payload, and verify the role signature.

Commit as "N4b-4 cancel freeze". Report the tails, then idle.
