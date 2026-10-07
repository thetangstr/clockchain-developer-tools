# Milestone log: server-side Clockchain entries per business milestone

Status: local implementation on `track-c/milestone-log`, based on CDT `a5559a7`, which is live. It has not been
deployed, nothing has been written to Clockchain, and it is off by default. Design: travel harness
`docs/travel-mvp/design/MILESTONE-TIMELINE.md` §4 ("Option A", branch `track-c`).

## What it does

When `CONTRACT_MILESTONE_LOG=1` and the run anchor is configured (`CONTRACT_ANCHOR_ENABLED=1`), the contract server
writes one Clockchain entry for each of the six business milestones of a run, at the moment that milestone completes.
The milestones are discover, proposal, negotiation, agreement, execution and settlement. The server is the neutral
party: it already signs every receipt and anchors the agreement and the terminal head. No agent can skip, forge or
delay an entry.

Each entry has:

- `asset_reference_id = ac-milestone:<runId>:<n>-<milestone>`, where `n` is 1–6.
- `asset_hash = sha256(canonicalJson(payload))`, sent to the gateway as bare lower hex. In `contract_status` it appears
  as `0x…`. `canonicalJson` is `src/agent-contract/canonical.ts`, which is byte-compatible with the travel harness.
- `additional_info = "agent contract milestone <milestone>"`. This is plain text because the gateway strips punctuation.

```
payload = {
  schema: "ac.milestone-log/v1",
  runId, milestone, index,            // index 1..6
  firstTs, lastTs,                    // ISO times of the first/last member receipt, null when empty
  receiptIds[],                       // member run-chain receipt ids, sorted
  approvalDigests[],                  // the feed's receipt-linked approval digests, in order
  prevEntryDigest                     // the previous entry's digest; null for discover
}
```

`prevEntryDigest` chains the entries, so one verification walks the deal in order. The payload holds only ids,
digests and times. It never carries a price, itinerary, name, PNR, payment reference, note, token or key. A test
asserts this.

The payload (the preimage) is published in `contract_status`, so anyone can recompute the hash. The harness copies
it into the evidence bundle.

## When each milestone completes (what the server can observe)

Checked against the tool names and the gating in `business.ts`:

| Milestone | Members (run-chain receipts) | Completes when |
|---|---|---|
| 1 discover | `contract_bind` ×2, `mandate_prepare`, `mandate_submit` | `mandate_submit` succeeds. A mandate needs a fully bound run, so this covers both binds plus the mandate. The design text says "at both binds", but the code makes the mandate part of Discover: the stage goes `bound` → `mandated`, and buyer offers and accepts refuse without it. |
| 2 proposal | `catalog_quote`, the first `offer_prepare` / `offer_submit` | The first `offer_submit` succeeds. A provider offer made before the buyer's mandate is held, and the mandate then completes discover and proposal together. |
| 3 negotiation | Later offers (counters), `offer_reject` | An agreement forms. If the first offer was accepted, this entry is sealed empty and still chained, which proves there was no negotiation. |
| 4 agreement | `offer_accept_prepare`, `offer_accept_submit` | `offer_accept_submit` succeeds. |
| 5 execution | `booking_*`, `booking_lookup`, `verification_*` | `verification_submit` succeeds. |
| 6 settlement | `settlement_prepare`, `settlement_authorize` | The terminal transition. The terminal call's own receipt is included. |

Rules:

- **Stage-agnostic tools** take the first open milestone, which is the deal stage at that moment. These are
  `contract_status`, `agreement_get`, `settlement_status` and `contract_withdraw`, plus any tool not listed above.
  The same applies to a fixed-class call that arrives after its milestone sealed. Refusals are members too, because
  they are receipts, but only an `ok` receipt completes a milestone.
- **Any terminal transition** completes every milestone up to the last one that holds evidence. That includes
  withdraw, cancel, verification failure, blocked, the TTL sweep and the half-bound release. Later milestones are never
  written, and `contract_status` reports them as `not-reached`. A completed deal therefore has six entries. A walk-away
  during negotiation has three.
- **Never members:** the server's own `anchoring`-surface receipts (`anchor`, `telemetry_close`).

What the server cannot observe, and what is therefore not in any entry:

- Pre-bind activity: rendezvous listing, search and invitation, the handshake, and ERC-8004 registration. Those
  receipts are on each principal's pre-bind chain, not the run chain. Each `contract_bind` receipt's `preBindHead`
  commits to that chain, so the discover entry covers it by reference.
- Model narration and front-door calls. The harness timeline (`ac.milestone-timeline/v1`) still carries those. Its
  planned entries are computed over a wider event set, so their digests will differ from the server's. From now on
  the harness should copy the server's payloads instead of computing its own.

## Writes, states and recovery

Writes reuse the run anchor (`ContractAnchor`, `anchor.ts`), which gains an optional `log` / `confirmLog` pair.

- **Production backing:** `createTsaContractAnchor` does `searchAsset(reference)` and then `log(assetHash, reference)`.
  If a record with the same hash already exists under that reference, it is returned, so a re-issue never writes
  twice. **Idempotent per (runId, milestone, digest).** Confirmation reads the record by ledger id
  (`getLedgerEntry`).
- **States:** the same honest states as the existing anchors. `anchoring` is in flight. `pending` means the write
  landed but has no block and time yet; it is re-confirmed on the same delay and attempt budget as agreement/terminal
  (`anchorConfirmDelayMs` / `anchorConfirmMaxAttempts`). `anchored` means block and time are confirmed. `failed`
  carries the error. A failure never blocks the deal or any other anchor.
- **Ordering:** writes are serialized per run, so ledger order matches index order.
- **Unchained:** an entry's outcome is recorded on the run and its durable terminal job, like the server-side
  terms/brief/final anchors. It is never minted as a receipt, and the final anchor does not wait for it.
- **Boot recovery:** entries persisted on a terminal job as `anchoring` or `pending` are re-driven at boot. The
  re-issue finds the existing record instead of writing again. A terminal job with open entries is "unfinished", so
  it is never pruned.
- **Restart limits:** live runs are in-memory, so a restart loses a live run's open milestones along with its receipts.
  This is the existing behaviour of everything on a live run. If a crash lands between the terminal transition and
  the deferred close, which is one macrotask, the job is never closed and its unsealed milestones render as `lost`.

Cost: at most six `log` writes per run, plus one `searchAsset` before each. There are three writes for a deal that
walks away during negotiation, and one for a run that only bound. These come on top of the agreement/terminal anchors.
The core client has no `MCP_LOG_BUDGET`; the per-credit price is still an open founder question (design §6.3).

## `contract_status`

With the flag on, `anchors.milestones` is always six rows, in order:

```
{ index, milestone, assetReferenceId,
  status: open | not-reached | lost | anchoring | pending | anchored | failed,
  digest, anchorId (= assetReferenceId once written), eventHash, ledger, error,
  payload }   // null until sealed
```

It is present on a live run and on a terminal run read after a restart (from the durable job). When the flag is on,
`anchors` is an object even before any anchor has fired; its `agreement`/`terminal` fields are `null` until they fire.
The `anchor` summary still covers only agreement/terminal.

**Flag off (default):** no tracker on any run, no `milestoneLog` on any job, no gateway call, and no `milestones` key.
`contract_status`, `tools/list`, the guidance digests, the receipt chain and the anchors are byte-identical to
`a5559a7`. Tests pin this. The output schema change is optional and is not part of `tools/list`, so the guidance
digests do not move.

## Flags and wiring

| Setting | Where |
|---|---|
| `CONTRACT_MILESTONE_LOG` (`0`/`1`, default off; anything else is a boot misconfiguration) | `config.ts` → `createContractService({ milestoneLog })` |
| Requires `CONTRACT_ANCHOR_ENABLED=1` | otherwise it loads but is inert, and `check-config` warns |
| SSM `/clockchain/mcp/CONTRACT_MILESTONE_LOG` (optional) | `infra/clockchain-mcp/compose-up.sh` `read_optional_env`, and `docker-compose.yml` `"${CONTRACT_MILESTONE_LOG:-}"` |
| Pre-flight | `check-config-from-ssm.mjs` `ENV_PARAMETERS`; `check-config` reports `features.milestoneLog: on/off` and the warning |

Code: `src/agent-contract/milestone-log.ts` (attribution, sealing, writer), plus hooks in `service.ts` (receipt append,
bind, `endRun`, boot recovery), `server.ts` (`contract_status`), `anchor.ts` (`log`/`confirmLog`),
`terminal-jobs.ts` (persisted entries) and `schemas.ts` (status output schema).
Tests: `test/agent-contract-milestone-log.test.mjs` (unit, integration with the fake gateway, flag off, config), plus
the existing CDT wiring and infra tests extended with the new name.

## Rollout (a future production window; nothing here deploys)

1. **Agree the names with Track B.** That means the reference namespace `ac-milestone:` and the payload schema
   `ac.milestone-log/v1`. Also agree whether the milestone log should later reference Track B's terms/brief/final
   anchors (the design's "index over anchors") instead of writing all six. This implementation writes six chained
   entries, as specified for this task.
2. **Founder go** on credit spend: up to 6 writes and 6 searches per run.
3. **Code deploy** of this branch, after review and merge, in a production window, on top of whatever CDT is live.
   With `CONTRACT_MILESTONE_LOG` absent in SSM the behaviour is unchanged. Deploy the code first with the flag absent
   and confirm `check-config-from-ssm` reports `milestoneLog: off` and no warnings.
4. **Flip the flag:** put SSM `/clockchain/mcp/CONTRACT_MILESTONE_LOG = 1` (`CONTRACT_ANCHOR_ENABLED` is already `1` in
   production). Re-run `check-config-from-ssm.mjs` and expect `milestoneLog: on` with no warning. Then restart the mcp
   through `compose-up.sh`.
5. **Verify on one real run:** all six `contract_status.anchors.milestones` rows reach `anchored`. For each row,
   `get_log_entry(ledgerId)` returns `assetHash == digest` (without `0x`), and the hash recomputed from `payload`
   matches. `search_actions("ac-milestone:<runId>:1-discover")` finds exactly one record.
6. **Rollback:** set the flag to `0` or delete the parameter and restart. Entries already written stay on the ledger.
   Nothing else depends on them.

## Open questions

- Should Discover complete at both binds, as the design text says, or at the mandate, as implemented? The server
  can only observe a meaningful "both bound and mandated" at the mandate.
- `verified` status polls land in Settlement, because Execution seals at `verification_submit`. That is consistent with
  the design's §1 edge, which still awaits founder confirmation.
- Should status polls be members? Today they are, which makes `receiptIds` larger. The alternative is fixed-class
  tools only.
- Should the six writes stay independent, or should the milestones where Track B already anchors (brief, terms, final)
  reference those anchor ids instead?
- What happens to the `lost` gap? Persisting the per-milestone buckets on the terminal job would close it.
