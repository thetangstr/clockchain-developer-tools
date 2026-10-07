# Milestone log: server-side Clockchain entries per business milestone

Status: local implementation on `track-c/milestone-log`, based on CDT `a5559a7`, which is live. It has not been
deployed, nothing has been written to Clockchain, and it is off by default. Design: travel harness
`docs/travel-mvp/design/MILESTONE-TIMELINE.md` §4 ("Option A", branch `track-c`), with the founder's answers of
2026-10-06 applied, plus the follow-up rules: a failed referenced anchor falls back to an own write, and settlement is
always written.

## What it does

When `CONTRACT_MILESTONE_LOG=1` and the run anchor is configured (`CONTRACT_ANCHOR_ENABLED=1`), the contract server
keeps one chained entry for each of the six business milestones of a run, sealed at the moment that milestone
completes. The milestones are discover, proposal, negotiation, agreement, execution and settlement. The server is the
neutral party: it signs every receipt and already anchors the agreement and the terminal head. No agent can skip,
forge or delay an entry.

Each entry has a payload and a digest:

```
payload = {
  schema: "ac.milestone-log/v1",
  runId, milestone, index,            // index 1..6
  firstTs, lastTs,                    // ISO times of the first/last member receipt; null when empty
  receiptIds[],                       // member run-chain receipt ids, sorted
  approvalDigests[],                  // the feed's receipt-linked approval digests, in order
  pollCount,                          // status polls made while this milestone was open (not members)
  anchorRef,                          // {kind, digest} of the server anchor this entry is indexed to, or null
  prevEntryDigest                     // the previous entry's digest; null for discover
}
digest = sha256(canonicalJson(payload))   // canonical.ts, byte-compatible with the travel harness
```

`prevEntryDigest` chains all six entries, so one verification walks the deal in order. The payload holds only ids,
digests, counts and times. It never carries a price, itinerary, name, PNR, payment reference, note, token or key. A
test asserts this. The payload (the preimage) is published in `contract_status`, so anyone can recompute the digest.
The harness copies it into the evidence bundle.

## Index over anchors: which entries are written

Where the run already has a server anchor for a milestone, the entry references it (`anchorRef`) and writes nothing
new:

| Milestone | Indexed to | Available when |
|---|---|---|
| discover | `terms` (the certificate's signed statement digest, anchored at the first bind), else the run's `brief` anchor | `CONTRACT_SERVER_ANCHORS=1` |
| agreement | `agreement` (the agreement digest) | always, with the anchor enabled |
| settlement | `final` (the run chain head once the terminal job finishes: it covers every receipt, the settling call included) | `CONTRACT_SERVER_ANCHORS=1`. **Settlement is still always written too** (see below). |

Every other milestone, any of these without its anchor, and **settlement in every case** gets its own write:

- `asset_reference_id = ac-milestone:<runId>:<n>-<milestone>`
- `asset_hash = digest`, sent as bare lower hex
- `additional_info = "agent contract milestone <milestone>"`

`terminal` does not cover settlement. Its head is taken at the transition, before the settling call's own receipt is
appended, so it would not cover that receipt.

A referenced entry's own payload is still committed on chain, because the next own write's `prevEntryDigest` covers
it.

**Settlement is always an own write.** It still names `final` in `anchorRef` when server anchors are on. It is the
chain's last entry, so writing it puts the chain head's own payload hash on Clockchain, and that hash transitively
commits to all six entries. `final`'s subject digest is known only once it fires, so the payload carries
`{kind: "final", digest: null}`. A run has exactly one final anchor, under `agent-contract:<runId>`, and
`contract_status` fills in its digest once it has fired.

**A failed referenced anchor falls back to an own write.** If the anchor a discover or agreement entry is indexed to
reaches `failed`, the entry is written as its own `ac-milestone` record, and its row reads
`source: "own-write (fallback)"`. The payload and digest are unchanged, so `anchorRef` still names the failed anchor
and the chain is unaffected. This happens whether the failure lands before or after the seal, while the run is live,
after it ends, or at boot. Each fallback adds one write and one lookup.

| Configuration | Own writes per completed deal |
|---|---|
| `CONTRACT_SERVER_ANCHORS` off | 5: discover, proposal, negotiation, execution, settlement |
| `CONTRACT_SERVER_ANCHORS=1` (production since the 2026-10-07 window, Stage 3) | 4: proposal, negotiation, execution, settlement |

## When each milestone completes

| Milestone | Members (run-chain receipts) | Completes when |
|---|---|---|
| 1 discover | the two `contract_bind` receipts | Both contract binds have succeeded (founder answer 1). |
| 2 proposal | `mandate_prepare`, `mandate_submit`, `catalog_quote`, the first `offer_prepare` / `offer_submit` | The first `offer_submit` succeeds. |
| 3 negotiation | Later offers (counters), `offer_reject` | An agreement forms. If the first offer was accepted, the entry is sealed empty and still chained, which proves there was no negotiation. |
| 4 agreement | `offer_accept_prepare`, `offer_accept_submit` | `offer_accept_submit` succeeds. |
| 5 execution | `booking_*`, `booking_lookup`, `verification_*` | `verification_submit` succeeds. |
| 6 settlement | `settlement_prepare`, `settlement_authorize` | The terminal transition. The terminal call's own receipt is included. |

Rules:

- **Polls are counted, not listed (founder answer 2).** `contract_status`, `settlement_status`, `agreement_get`,
  `rendezvous_inbox` and `contract_get_brief` are stage-agnostic reads. They are not in `receiptIds`. Instead they
  increment the open milestone's `pollCount`, so nothing is hidden and the receipt lists stay small.
- **Other stage-agnostic calls are members of the open milestone.** These are state-changing calls such as
  `contract_withdraw`, plus any tool not listed above. The same applies to a fixed-class call that arrives after its
  milestone has sealed.
- **Refusals are members too,** because they are receipts. Only an `ok` receipt completes a milestone.
- **Any terminal transition** completes every milestone up to the last one that holds evidence. That includes
  withdraw, cancel, verification failure, blocked, the TTL sweep and the half-bound release. Later milestones are never
  written and show as `not-reached`.
- **Never counted:** the server's own `anchoring`-surface receipts (`anchor`, `telemetry_close`).

What the server cannot observe:

- **Pre-bind activity:** rendezvous, the handshake and ERC-8004 registration. Those receipts are on each principal's
  pre-bind chain, not the run chain. Each `contract_bind` receipt's `preBindHead` commits to that chain.
- **Narration and front-door calls:** those stay in the harness timeline. The harness should copy the server's payloads
  rather than compute its own, because its planned entries cover a wider event set and their digests will differ.

## Writes, states, durability

- **Production backing:** `createTsaContractAnchor.log` does `searchAsset(reference)` and then `log(assetHash,
  reference)`. If a record with the same hash already exists under that reference, it is returned (`reused`), so a
  re-issue never writes twice. Confirmation reads the record by ledger id (`getLedgerEntry`).
- **States for own writes:** `anchoring` is in flight. `pending` means the write landed but has no block and time yet;
  it is re-confirmed on the same delay and attempt budget as agreement/terminal. `anchored` means block and time are
  confirmed. `failed` carries the error. Writes are serialized per run, so ledger order matches index order.
- **States for referenced entries:** they show the referenced anchor's state live, or `awaiting-anchor` until it fires.
  If the referenced anchor fails, the entry falls back to an own write (above), and its row then shows the own write's
  state.
- **Unchained:** entry outcomes are never minted as receipts, and no other anchor waits for them.
- **Durability (founder answer 5):** the whole tracker (per-milestone receipt lists, poll counts, seal count, chain
  head and entries) is persisted on the run's terminal job:
  - at every seal, which creates the job before the terminal transition, the way the agreement anchor already does;
  - inside `endRun`'s durable enqueue.

  A job whose tracker is not closed, or which has an own write still `anchoring`/`pending`, is "unfinished", so it is
  never pruned and is visited at boot. At boot:
  - **Terminal job never closed** (a crash between the terminal transition and the seal, which is a one-macrotask
    window): the job is closed from its persisted buckets, and only the entries that were missing are sealed and
    written.
  - **Non-terminal job** (a live run lost with the process): it is marked `interrupted`. What it reached stays sealed
    and written, and its unsealed milestones show as `interrupted`. A run dropped from memory before it ended is
    marked the same way.
  - **Pending own writes** are re-driven without a second write.

  Nothing reads "lost".

## `contract_status`

With the flag on, `anchors.milestones` always has six rows, in order. Each row is what the UI shows for one logging
event:

```
{ index, milestone, assetReferenceId,
  source: "own-write" | "track-b-anchor" | "own-write (fallback)" | null,   // null until sealed
  status: open | not-reached | interrupted | awaiting-anchor | anchoring | pending | anchored | failed,
  digest,          // the entry's chain digest (sha256 of payload)
  assetHash,       // what is on the ledger: own write = digest; track-b = the referenced anchor's event hash
  anchorRef, anchorId, ledgerId, blockHeight,
  sealedAt,        // server time the entry sealed
  anchoredAt,      // ledger time, once anchored
  error, payload }
```

`anchors.clockchainCalls = {writes, lookups}` counts this run's Clockchain calls through the run anchor (founder
answer 4):

- tsa writes for terms, agreement, terminal and final;
- confirm lookups;
- milestone lookups and writes.

The shared per-digest brief anchor is not counted, because it is not any one run's call. The count is kept on the job,
so it survives a restart. Calls per completed deal:

| Configuration | Writes | Lookups | Total |
|---|---|---|---|
| Server anchors off | 7 (agreement, terminal, 5 milestone) | 5 | 12 |
| Server anchors on | 8 (terms, agreement, terminal, final, 4 milestone) | 4 | 12 |
| Each fallback | +1 | +1 | +2 |
| Each confirm read of a pending write | | +1 | +1 |

Both completed-deal totals are within the founder's budget of about 12 calls. A run that ends early makes fewer calls.

The rows are present on a live run and on a terminal run read after a restart (from the job). With the flag on,
`anchors` is an object even before any anchor fires. The `anchor` summary still covers only agreement/terminal.

**Flag off (default):**

- No milestone tracker on any run, and no `milestoneLog` or `clockchainCalls` on any job.
- No counting wrapper: the run anchor is the configured anchor object itself.
- No gateway call, and no `milestones` or `clockchainCalls` key.
- `contract_status`, `tools/list`, the guidance digests, the receipt chain and the anchors are byte-identical to
  `a5559a7`. Tests pin this. The output schema change is optional and is not part of `tools/list`.

## Flags and wiring

| Setting | Where |
|---|---|
| `CONTRACT_MILESTONE_LOG` (`0`/`1`, default off; anything else is a boot misconfiguration) | `config.ts` → `createContractService({ milestoneLog })` |
| Requires `CONTRACT_ANCHOR_ENABLED=1` | otherwise it loads but is inert, and `check-config` warns |
| `CONTRACT_SERVER_ANCHORS=1` (optional) | lets terms cover discover; settlement then also names final |
| SSM `/clockchain/mcp/CONTRACT_MILESTONE_LOG` (optional) | `compose-up.sh` `read_optional_env`, and `docker-compose.yml` `"${CONTRACT_MILESTONE_LOG:-}"` |
| Pre-flight | `check-config-from-ssm.mjs` `ENV_PARAMETERS`; `check-config` reports `features.milestoneLog` and the warning |

Code: `src/agent-contract/milestone-log.ts` (attribution, sealing, index over anchors, writer, recovery). Hooks are in:

- `service.ts`: receipt append, bind, `endRun`, `dropRun`, boot recovery, and the call-counting wrapper;
- `server.ts`: `contract_status`;
- `anchor.ts`: `log`/`confirmLog`;
- `terminal-jobs.ts`: the persisted tracker and call counts;
- `schemas.ts`: the status output schema.

Tests: `test/agent-contract-milestone-log.test.mjs`. It covers:

- unit tests;
- integration with the fake gateway through the production adapter, with server anchors off and on;
- settlement always written;
- fallback when the agreement or terms anchor fails;
- pending and failed writes;
- boot recovery;
- two crash-between-end-and-seal cases;
- an interrupted live run;
- the TTL sweep;
- flag off;
- config.

## Rollout (a future production window; nothing here deploys)

1. **Confirm with Track B** the `ac-milestone:` namespace, the `ac.milestone-log/v1` payload (including `pollCount`
   and `anchorRef`), and the anchor kinds that are referenced.
2. **Code deploy** of this branch, after review and merge, in a production window, with `CONTRACT_MILESTONE_LOG`
   absent. The behaviour is unchanged. `check-config-from-ssm` should report `milestoneLog: off` and no warnings.
3. **Flip the flag:** put SSM `/clockchain/mcp/CONTRACT_MILESTONE_LOG = 1` (`CONTRACT_ANCHOR_ENABLED` is already `1`).
   Re-run `check-config-from-ssm.mjs` and restart through `compose-up.sh`. The step-by-step sheet is
   `MILESTONE-LOG-WINDOW.md`.
4. **Verify on one real run:**
   - all six rows reach `anchored`, and `clockchainCalls` stays within budget;
   - for each own write, `get_log_entry(ledgerId).assetHash == digest` (without `0x`), the hash recomputed from
     `payload` matches, and `search_actions(assetReferenceId)` finds exactly one record;
   - for each referenced row, the referenced anchor verifies as today.
5. **Rollback:** set the flag to `0` or delete the parameter and restart. Entries already written stay on the ledger,
   and nothing else depends on them.

## Open questions

- `verified` status polls count toward settlement's `pollCount`, because execution seals at `verification_submit`.
- A referenced anchor that stays `pending` for good, and never reaches `failed`, does not trigger a fallback.
