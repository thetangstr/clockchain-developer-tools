# N4c changes 1 (orchestrator, 2026-09-28): the security review REJECTED ffa3228 as R13(d) evidence

The functional checks pass (21/21, seal v2 cross-compatible with N5). But the review's probe
(`/Volumes/mac_studio_ssd/Projects/travel_mvp/ac_travel_mvp/.omc/state/audit-2026-09-28/n4c-probe.mjs`, read-only;
the orchestrator reproduced findings 1, 2, 3 and 5) shows that a query-token holder, meaning the harness, can
fabricate or trim evidence. Fix every item **test-first (seen red)**.

## Must-fix
1. **C1, body integrity.** `verifyRecords` must recompute `sha256(body)` for **every** record and compare it with
   `bodyDigest`. Extraction must refuse records that fail this. Test: swapping one body (keeping its metadata) makes
   `verifyRecords` false, and extraction throws or excludes that record.
2. **C2, run close and truncation.**
   - Add `POST /v1/runs/:runId/close` (callable with an **admin/close** credential, which is neither ingest nor query).
   - The sink signs **one final head**, `{runId, final: true, recordCount, headDigest, closedAt}`, and calls the
     anchor interface. **It revokes both ingest tokens.** Any later ingest gets 409.
   - Query responses expose the final head. `verifyRecords(records, finalHead)` requires `final: true` **and**
     `recordCount === records.length`. A non-final head verifies only as `incomplete`.
   - Tests: tail truncation plus the final head → false; any older non-final head → `incomplete`; ingest after close → 409.
3. **H1, the role comes from the record.**
   - Extraction stamps `role` from `record.role`, never the caller's input.
   - It pins the runtime per role from an input map `{buyer: runtimeId, provider: runtimeId}`; a mismatch is refused.
   - Test: a provider record never appears as buyer.
4. **H2, freshness.** Every extracted row carries `receivedAt` (the sink's clock). Matching uses `receivedAt` within
   the run window (open to close), never the body's `ts`. Test: a late or backdated span after close is refused (409);
   one before close but outside the declared window is flagged.
5. **H3, the fake verify field.** Remove the self-verifying `verify` field from query responses (or rename it
   `advisory` with `evidentiary: false`). Test: it's absent or marked.

## Also fix (each with a test)
- **M1, quotas.** Parse and validate OTLP/JSON at ingest (400 on non-JSON or wrong shape). Add per-run byte and record
  caps (refuse when full). `/records` is paged. The forwarder enforces a body limit (413).
- **M2, no wildcard.** `runId: "*"` is refused. A global reader is a separate, explicit token kind the harness never gets.
- **M3, structured nonce parsing.**
  - Parse MCP results structurally, including `content[].text` JSON parts, and require **exactly one** nonce.
  - The tool name comes only from the dedicated tool-name attribute, never from `arguments.name` or `arguments.tool`.
  - Tests: the probe's double-encoded result and the `name` argument case.
- **M4, bind the seal.** The seal AAD includes `runId` and `role`. The forwarder checks that the `runId` in the sink's
  reply equals its own. This changes the seal context: **tell the orchestrator in your report**, so N5 can be kept
  compatible. Don't change the N5 code.
- **LOW:** accept only the literal `127.0.0.1` and `::1`, not `localhost`; parse IPv6 in `AC_LISTEN`; the head
  signature covers `keyId` and `alg`; add a request read timeout; check the services key file's mode (0600).
- **pf:** document in the README the exact pf rules the harness must install: only the role's agent uid may reach the
  forwarder port, over v4 and v6 loopback. The harness and the other role are blocked. It's a harness probe item, not code here.

Same scope and hard limits. Commit as "N4c review fixes". Report commits, raw test tails and each item with its test
name. Then idle.
