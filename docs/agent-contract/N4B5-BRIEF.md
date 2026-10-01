# Brief N4b-5: Rome board and a run-scoped sim fault mode (second travel Devin; sim only)

For the Rome runbook (`ac_travel_mvp/docs/travel-mvp/ops/RUNBOOK-ROME-P4.md` §1 and §4, read-only). Scope:
`packages/mcp-server/src/agent-contract/sim/**` plus the sim tests, **only**. Test-first.

1. **The Rome board.** Add rows to `CANONICAL_BOARD`: SFO→FCO, USD, with new ids.
   - `IT-ROME-ZX118-ECON`: fare 481800 (nonstop)
   - `IT-ROME-ZX118-PREM`: fare 596000 (nonstop)
   - `IT-ROME-QW-ONESTOP`: fare 431000 (one stop via JFK)
   - two non-qualifying two-stop rows: `IT-ROME-2STOP-A` and `-B`, fares from the old `inventory.ts` two-stop routings
     (`ac_travel_mvp`, `feat/travel-mvp`, `src/lib/travel/simulator/inventory.ts`, read-only)

   **The existing ZRH→JFK rows and every frozen vector stay byte-identical.** Tests: `quote()` for SFO→FCO returns
   exactly these rows; ZRH→JFK is unchanged; the v2/v2.1 vector tests still pass.
2. **A run-scoped fault mode (for adverse case A2).**
   - A config-only fault seed per `runId` (e.g. `faults: {issueMismatch: "fare" | "travellers"}`) makes
     `issueTickets` issue tickets that deviate from the order, while `booking_lookup` reflects the deviation.
   - It's set only by server config or the l-stack, **never** by a tool call or agent argument.
   - Every affected response keeps `simulated: true`, and the fault is recorded in run state so evidence can show it.
   - Tests: with the fault set, buyer verification can detect the mismatch; without it, behaviour is unchanged; no
     tool argument can enable it.

No `http.ts` or business-logic changes beyond passing the config through to the sim. Hard limits as before. Commit
per item. Report the tails, then idle.
