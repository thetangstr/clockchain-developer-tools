# Clockchain Verifiable Time Beacon — Spec (draft)

**Status:** draft · 2026-06-23 · testnet stage (design target, not certified)
**One-liner:** A continuously broadcast, signed, anchored stream of consensus time —
a Roughtime+drand-style *pulse chain* whose value is not "what time is it" (NTP does
that, free) but **provable, independently-verifiable proof of what the agreed official
time was at instant X.**

## 1. Why (and why not)

- **Not** a faster/better NTP. NTP/NTS/PTP are free, ms-to-µs accurate, and ubiquitous.
  A blockchain feed is slower and adds nothing for "what time is it now."
- **The differentiator is the proof, not the time.** Every pulse is signed by the
  validator set, chained to the prior pulse, and periodically anchored on-chain, so a
  consumer can prove *after the fact* what the official time was — keylessly, without
  trusting the Clockchain API. This is the notary thesis in **push** form.
- **Demand (researched 2026-06-24, web):** the demand is for *verifiable* time, not
  *accurate* time. Accuracy is commodity/free — NTP (free), NTS (secured), AWS Time Sync
  (<100µs free via Nitro hardware clock), PTP (sub-µs). The paid demand is regulation-forced:
  **MiFID II / RTS 25** mandates documented, annually-audited UTC traceability, which already
  spawned a "Traceable Time as a Service" subscription category (Hoptroff, Safran, NPLTime,
  Pico/Corvil). Roughtime (verifiable, equivocation-detecting time for IoT) and drand
  (publicly-verifiable broadcast beacon, given away free "like NTP") validate the architecture
  AND the free-feed norm. Blockchain time-oracle demand is real but narrow (derivatives,
  insurance, contract triggers) and — critically — "regulatory compliance may mandate temporal
  guarantees that blockchain timestamps alone cannot provide," which is the opening.
- **Realistic wedge:** the intersection nobody owns cleanly — verifiable + neutral/multi-party
  + on-chain-anchored + agent-native — sold into compliance/audit and agent cross-party
  ordering. NOT "time as a service" broadly (loses to free NTP) and NOT HFT trade-timestamping
  (loses to PTP grandmasters; see §8 precision ceiling). RFC 3161 TSAs / Sigstore already serve
  generic "prove-when-this-existed," so lead with neutrality + ordering + agent-native, not raw
  timestamping.
- **A beacon is a building block, not an alarm.** It disseminates *now*; a keeper still
  compares each pulse to its deadline to fire (see §6). Give the raw feed away like
  drand; monetize the proof/compliance tier.

## 2. Non-goals

- Replacing NTP for wall-clock sync. Sub-millisecond precision. Custody / value movement.
- Marketing as "court-grade" before a real multi-validator threshold signature exists
  (the testnet is single-validator today — see §7).

## 3. Pulse format (`clockchain.beacon/v1`)

```json
{
  "schema": "clockchain.beacon/v1",
  "network": "clockchain-testnet",
  "round": 4522639,                       // monotonic pulse counter (tracks block height)
  "blockHeight": "4522639",
  "time": "2026-06-23T05:36:16.291Z",     // consensus (Marzullo) time, UTC
  "uncertaintyMs": 99,                     // half-width of the Marzullo interval (AbsTimeDifference)
  "cadenceMs": 600,                        // nominal interval between pulses
  "prevPulseHash": "<sha256>",             // links to the previous pulse (append-only chain)
  "pulseHash": "<sha256>",                 // SHA-256 over canonical {network,round,blockHeight,time,uncertaintyMs,prevPulseHash}
  "validators": { "signed": 1, "total": 1, "threshold": "2/3" },
  "signature": "<bls-aggregate>",          // validator-set signature over pulseHash
  "anchor": { "ledgerId": "<id|null>", "blockHeight": "<h|null>", "anchored": false }
}
```

- `pulseHash` is the canonical commitment; the chain of `prevPulseHash` makes the whole
  broadcast an append-only, gap-evident log.
- `uncertaintyMs` is mandatory and load-bearing: consumers must treat the trusted time as
  an **interval** `[time - uncertaintyMs, time + uncertaintyMs]`, then widen by their own
  `RTT/2` (Cristian's algorithm). Never expose `time` as exact.
- `anchor` is populated on the periodic on-chain checkpoint (§5), not every pulse.

## 4. Transport

- **Pull:** `GET /beacon/latest` and `GET /beacon/{round}` (public, no api key).
- **Stream:** `GET /beacon/stream` as `text/event-stream` (SSE) — the default subscriber path.
- **Stream (bi-di):** `wss://.../beacon` (WebSocket) for clients that prefer it.
- **Keys:** `GET /.well-known/clockchain/validators` returns the published validator public
  keys + threshold, so verification needs no account.
- Cadence: emit every block (~0.6s) or a fixed `cadenceMs`; SSE re-emits last pulse on
  reconnect so a dropped socket never silently skips a round.

## 5. On-chain anchoring (the non-repudiation leg)

- Every N pulses (e.g. once per minute), checkpoint the latest `pulseHash` on-chain via the
  existing log-anchor convention, under reference id `beacon:{network}:{round}`.
- That gives long-term, tamper-evident "the beacon said T at round R" provable against the
  **immutable** chain (`searchAssetFromChain` by block height), not the rewritable cache.
- Per-pulse signatures give live trust; periodic anchoring gives durable, court-grade trust.

## 6. Keyless verification

A consumer with **no Clockchain account** verifies a pulse:

1. Fetch published validator keys from `/.well-known/clockchain/validators`.
2. Recompute `pulseHash` from the canonical fields.
3. Verify `signature` (BLS aggregate) over `pulseHash` meets `threshold`.
4. Check `prevPulseHash` links to the previously seen pulse (continuity / no silent gaps).
5. For an "as-of" proof, confirm the round's checkpoint on the immutable chain by `blockHeight`.
6. Apply the interval: trusted time ∈ `[time - uncertaintyMs - RTT/2, time + uncertaintyMs + RTT/2]`.

## 7. Alarm / keeper integration (why this composes)

The beacon is the clock feed under the unbuilt keeper (see the scheduled-trigger work):

```
keeper subscribes to /beacon/stream
  on each pulse p:
    if p.time >= deadline:
      fire(external_action)                      // webhook / contract call / log
      attach proof = { p.round, p.pulseHash, p.signature }   // "fired at official time T"
```

The fired event references the triggering pulse, so "it fired at the agreed time" is itself
verifiable — turning a plain webhook into a *court-grade* "time reached" event.

## 8. Trust model & caveats

- **Single-validator testnet today** (`totalNodes: 1`, 0% participation): `validators` will
  read `signed:1/total:1`, so the signature proves origin but **not multi-party consensus**.
  The beacon's core selling point (attested, neutral time) is not real until a multi-validator
  set with a real threshold exists. Do not pitch as court-grade before then.
- Liveness: the beacon depends on validator + transport uptime; subscribers must tolerate
  gaps and verify `prevPulseHash` continuity rather than assume every round arrived.
- **Precision ceiling (researched 2026-06-24):** a ~0.6s block-cadence beacon cannot meet
  MiFID II RTS 25's 100µs HFT-timestamping requirement — that tier belongs to PTP grandmasters
  and is out of reach. Serve the *traceability/audit/proof* layer, the 1s voice-trade tier, and
  agent/audit use cases; do NOT pitch into microsecond HFT trade timestamping.

## 9. Phasing

| Phase | Scope |
|---|---|
| P1 | Read-through `GET /beacon/latest` over the existing consensus time (`get_timestamp`); add `uncertaintyMs`. |
| P2 | SSE `/beacon/stream` + `pulseHash` + `prevPulseHash` chaining. |
| P3 | Validator signatures + published keys + a small keyless verify lib. |
| P4 | Periodic on-chain anchoring + multi-validator threshold signature (gates the "court-grade" claim). |

## 10. Positioning

Ship it as **"the Clockchain verifiable time beacon"** — a public, free, signed pulse feed
(à la drand) that is the *distribution layer* feeding the alarm/keeper and audit products.
Monetize the proof/compliance tier (regulated timestamping, exportable evidence), not the
raw feed. The moment it's pitched as "broadcast the time" without "signed, anchored, and
provable-after-the-fact," it's a worse NTP.
