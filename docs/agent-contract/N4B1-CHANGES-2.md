# N4b-1 changes 2 (orchestrator, 2026-09-28): the re-review of 0909d19 says ACCEPT WITH FIXES

The re-review closed C1, C2 (at the agreed `agentId-pinned-token` assurance), C3, H2, H3 and LOW. Its probe
(`/Volumes/mac_studio_ssd/Projects/travel_mvp/ac_travel_mvp/.omc/state/audit-2026-09-28/n4b1-probe-v2.mjs`,
read-only) found the new problems below. **Fix all of them test-first (seen red)**, going through the real
`runHttp` wiring where relevant.

1. **The used-sessions record must fail closed** (N1 + N2).
   - An unreadable, corrupt or wrong-permission `used-sessions.json` means the route is **misconfigured**: return
     503 and do **no** binds. Never treat it as empty.
   - Persist the used session id (write to a temp file, `fsync`, rename, `fsync` the directory) **before** changing
     any in-memory state. If persisting fails, the bind fails with no state change and no receipt.
   - Take an exclusive lock on the state directory, so two processes sharing the volume can't overwrite each other
     (refuse the second).
   - Tests: a corrupted file → 503 and no rebind; EACCES on write → bind refused with memory unchanged; a second
     process is refused.
2. **One party can't brick the other** (N3).
   - Give **each principal its own receipt budget** within a run.
   - At a cap, return a refusal (`RATE_LIMITED`, with `retryable` set honestly), **never throw**.
   - Test: the provider spamming `contract_status` to its own cap doesn't stop the buyer's calls from being receipted.
3. **Pin the roles and check freshness** (N4 + the H1 remainder).
   - Enforce **buyer = initiator and provider = responder** when parsing tokens (a mismatch is a startup error) and
     again at bind.
   - Check `validFromMs ≤ now ≤ validUntil + grace`.
   - Tests: a provider token pinned to the initiator is refused; a not-yet-valid certificate is refused.
4. **TTL eviction** (M4/M5 remainder). Ended runs past their TTL are **removed** (freeing their cap slot), not just
   marked. Test: with `maxRuns = 1`, a new run succeeds after the first one's TTL.
5. **LOW.** `publicKeyHex` must be lower-case even-length hex. The agentId check also compares the ERC-8004 chain and
   registry, not just the id.

M1–M3 and the P-GAP stay deferred to N4b-2 and block P, unchanged. Commit as "N4b-1 review fixes 2". Report commits,
raw `npm test` / `tsc -b` tails, and each item with its test name. Then idle.
