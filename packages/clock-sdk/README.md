# @clockchain/clock-sdk

Client-side **verified-time primitives** over [`@clockchain/core`](../core): a
Clockchain-disciplined clock, a local **alarm / timer** scheduler, and a **stopwatch** —
each producing a tamper-evident, independently-verifiable receipt anchored to Clockchain.

It lets an application or agent **act on neutral, verifiable time** (and prove it did),
without trusting a local system clock — and without handing its schedule, its keys, or its
actions to any third party.

---

## Why this runs on your side (the trust model in one paragraph)

A blockchain provides neutral, verifiable time and an immutable record; it **cannot — and,
for neutrality, must not — reach into your systems to execute on your behalf.** So the
scheduling and the firing of actions run inside **your** trust boundary, here in this SDK.
Clockchain holds **no schedule, no keys, and never acts for you**; it supplies only
(a) the consensus clock you discipline to, and (b) a keyless-verifiable anchor for each
fire. This is the same separation regulated buyers expect from a notary: the notary attests
*when*; it does not run your business.

## What you get

| Primitive | What it proves | Built on |
|---|---|---|
| **Stopwatch** | tamper-evident **elapsed** time between two points | `log_action` ×2 + `verify_cross_party` — works through the MCP alone |
| **Timer** | a verifiable **duration** (`now + D`) elapsed | scheduler + anchored markers |
| **Alarm** | fired at a future time **T**, provably on verified time | disciplined clock + scheduler + `attest_action` |

## Install

```bash
npm install @clockchain/clock-sdk @clockchain/core
```

Configure gateway access via environment (read by `readConfigFromEnv()`); **never hard-code
credentials** — supply them from your secret manager:

```
CLOCKCHAIN_API_KEY=…      CLOCKCHAIN_CLIENT_ID=…      CLOCKCHAIN_WALLET_ID=…
# CLOCKCHAIN_ENDPOINT defaults to https://node.clockchain.network
```

## Quickstart

```js
import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";
import { ClockchainClock, ClockScheduler } from "@clockchain/clock-sdk";

const cc = new ClockchainClient(readConfigFromEnv());
const clock = new ClockchainClock(cc);
await clock.sync();            // NTP-style discipline to Clockchain consensus time
clock.startAutoResync();       // periodic re-calibration (bounds drift)

const scheduler = new ClockScheduler({ clock, client: cc, confirmSource: cc });
scheduler.schedule({
  fireAt: clock.now().epochMs + 60_000,   // 60s out, on verified time
  mode: "confirmed",                       // re-check consensus at the boundary
  agentId: "your-agent",
  action: (ctx) => doYourThing(ctx),       // runs in YOUR environment
});
// each fire is anchored via attest_action → a keyless-verifiable receipt
```

Runnable examples: [`examples/alarm-live.mjs`](examples/alarm-live.mjs) (live testnet
alarm: sync → arm → fire → anchor → keyless verify) and
[`examples/clark-slack-alarm.mjs`](examples/clark-slack-alarm.mjs) (production daemon —
register over HTTP, fire to Slack, durable + re-arm on restart, runs under `pm2`).

## Trust & security model

- **Non-custodial.** The SDK holds and transmits **no private keys**. Credentials come from
  your environment/secret manager and are used only to authenticate gateway calls.
- **Hashed, never stored.** Content is SHA-256-hashed client-side; only the **hash** plus
  receipt metadata is anchored — your payloads never leave your environment.
- **Keyless, third-party verification.** Any counterparty verifies a fire against the
  **immutable on-chain block** (`verify_cross_party` / `/searchAssetFromChain`) with **no
  API key and no Clockchain account** — authoritative, not the rewritable cache.
- **No false precision.** Every clock reading carries an explicit `uncertaintyMs`
  (round-trip/2 + the network's reported offset). Treat time as an interval, not a point;
  use `mode: "confirmed"` when the boundary matters.
- **Your trust boundary.** Schedule, actions, and outbound calls stay on your side. The SDK
  talks only to the Clockchain gateway (`get_timestamp`, `log`/`attest`, `verify`).
- **Auditable by construction.** Every fire yields a receipt (event hash + on-chain anchor
  + consensus time) that you, your auditor, or a counterparty can re-verify independently.

## Operating it in production

- **Run on an always-on host** (e.g. under `pm2`, like the hosted MCP). A client-side alarm
  fires only while its process is running; an always-on host removes that gap.
- **Persist the schedule.** The default job store is in-memory; back it with durable storage
  and **re-arm pending alarms on startup** (the daemon recipe shows the pattern). Alarms
  whose time passed while the host was down are surfaced as *missed*, never silently fired.
- **Confirmation.** Poll to confirmation before treating a fire as on-chain (`core`
  `waitForConfirmation`); the gateway's default confirmation wait can be short on testnet —
  use a longer timeout, then `verifyOnChain`.

## Latency & current limits (state honestly)

- **Fire latency** ≈ sub-second to ~1s (poll interval + clock uncertainty); **proof latency**
  ≈ 1–2s (block cadence), occasionally longer on testnet backfill.
- **Not microsecond / not HFT.** This serves the audit / SLA / agent-deadline tier; precision
  trading-grade timing is out of scope (use PTP).
- **Maturity:** the current network is **single-validator testnet**, so "court-grade" is a
  **target, not a present claim** — multi-validator consensus gates that. Receipts are real
  and independently verifiable today; the validator-signature attestation is mainnet-gated.

## Roadmap

A managed, hosted **keeper** — exposed via MCP `schedule_trigger` / `list` / `cancel` tools —
will let teams that prefer not to run a companion fire alarms **server-side**, with the same
verifiable receipts (control plane in the MCP tools; firing in a dedicated off-chain worker).
Until it ships, run this SDK. See the repo [`roadmap.md`](../../roadmap.md).
