# N4b-3 changes 1 (orchestrator, 2026-09-28): the security review of 2464882..1d18b2d says MUST-FIX

The suite passes (684/684, reproduced). The review's probe (`.omc/state/audit-2026-09-28/n4b3-probe.mjs`,
read-only) reproduced the two HIGH defects. Fix them test-first (seen red):

1. **HIGH: receipts first, for every cause.**
   - An empty `clientInfo {name:"", version:""}` at `initialize` makes `makeReceipt` throw **after**
     `settlement_authorize` has already settled (probe N4b3-3).
   - Fix structurally: **build and schema-validate the receipt before dispatch**. If it can't be built, the action
     doesn't run.
   - At `initialize`, **normalize or refuse** a `clientInfo` the receipt schema would reject.
   - Internal errors never leak zod text to the agent: return a generic code plus the serverNonce.
   - Tests: an empty or oversized `clientInfo` → the consequential call is refused before any state change.
2. **HIGH: the pre-bind cap locks principals out.**
   - `MAX_PREBIND_RECEIPTS` is per principal for the process lifetime.
   - Fix: **start a new pre-bind chain segment** after each bind, and roll old segments off by count or time. The
     head is carried forward, so it stays verifiable and linkable.
   - Rate-limit polling (`rendezvous_inbox`, `contract_status`) with its own limiter, **not** the evidence cap.
   - Test: 1000 polls over the segment boundary never lock out, and the chains still verify.
3. **MEDIUM: session caps.** Add a per-principal cap (e.g. 4) and a global cap, plus a periodic sweep of idle
   sessions. Test: the 5th session for one principal is refused, and swept sessions free their slots.
4. **MEDIUM: salted response digests.** Salt `responseDigest`, with the same scheme and field as `argsDigest`,
   wherever a response carries an amount (`agreement_get`, offers, settlement, …). Test: the agreed total can't be
   brute-forced from the observer feed without the salt.
5. **LOW:**
   - Refuse to start when `CONTRACT_VERIFIER_TOKEN` equals `CONTRACT_OBSERVER_TOKEN`.
   - Key `validFrom`/`validUntil` come from config (pinned), not boot time, and receipt verification helpers enforce them.
   - The pre-bind salt rotates with each segment.

Harness-side checks (pinning the server keyId and key out of band in the launch plan; refusing an `ephemeral:true`
key at P) are the orchestrator's to route to N3. Don't do them here. Commit as "N4b-3 review fixes". Report the
tails, then idle.
