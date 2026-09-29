# Brief N4b-6 (orchestrator, 2026-09-28): make fault-injection visible; export the evidence routes

N4b-5 is ACCEPTED (`68ed6f7`, `c4c2d41`; 716/716 reproduced; frozen vectors byte-identical). Same scope. Test-first:

1. **Fault-injected runs must be visible in evidence** (honesty, H1).
   - `CONTRACT_SIM_FAULTS` is refused (misconfigured → 503) unless `CONTRACT_ALLOW_SIM_FAULTS=1`.
   - When allowed, the server card and `/contract/keys` publish `simFaultsEnabled: true`.
   - A run with a fault carries `simFault: {issueMismatch}` on its `booking_execute` receipt **and** on its
     terminal/status receipt, and the observer feed exposes it.
   - A verifier can therefore tell a fault-injected run from an honest one.
   - Tests: a fault without the allow flag → 503; the card flag; the receipt fields; a run with no fault has no `simFault` field.
2. **Export the evidence routes** so the l-stack stops mirroring them (the drift finding from N3 amendment 14).
   - Export the handlers behind `GET /contract/receipts`, `/contract/keys` and `/contract/run-salt`, with their
     auth and filtering exactly as `http.ts` uses them (e.g. `createContractEvidenceRoutes({service, observerToken, verifierToken, keysDoc})`).
   - `http.ts` must use the **same** exported functions (a single code path).
   - Add a `listenHost` option to whatever the l-stack needs, so a loopback-only server can mount the real routes.
   - Tests: `http.ts` and the exported handler give identical responses, and auth is unchanged.

Hard limits as before. Commit per item. Report the tails, then idle. (N3 will then swap the l-stack shim onto the exports.)
