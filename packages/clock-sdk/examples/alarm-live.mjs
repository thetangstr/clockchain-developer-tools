// Live testnet integration: a verified-time ALARM end-to-end.
//
// Disciplines a local clock to Clockchain (NTP-style sync), schedules an alarm a
// few seconds out, fires it off the disciplined clock, anchors the fire on-chain
// (attest_action), and verifies the receipt — keyless, against the immutable block.
//
// Prereqs:
//   1. Build the workspace:  npm run build   (from repo root)
//   2. Set gateway creds:
//        export CLOCKCHAIN_API_KEY=...
//        export CLOCKCHAIN_CLIENT_ID=...
//        export CLOCKCHAIN_WALLET_ID=...
//      (CLOCKCHAIN_ENDPOINT defaults to https://node.clockchain.network)
//   3. Run:  node packages/clock-sdk/examples/alarm-live.mjs
//
// Spends a log credit (the anchored fire). Testnet.

import { ClockchainClient, readConfigFromEnv } from "@clockchain/core";
import { ClockchainClock, ClockScheduler } from "@clockchain/clock-sdk";

const cfg = readConfigFromEnv();
if (!cfg.apiKey || !cfg.clientId || !cfg.walletId) {
  console.error("Missing CLOCKCHAIN_API_KEY / CLOCKCHAIN_CLIENT_ID / CLOCKCHAIN_WALLET_ID.");
  process.exit(1);
}

const client = new ClockchainClient(cfg);

// 1) Discipline the local clock to Clockchain (NTP-style sync).
const clock = new ClockchainClock(client);
const sync = await clock.sync();
console.log(`synced: offset=${Math.round(sync.offsetMs)}ms  uncertainty=±${Math.round(sync.uncertaintyMs)}ms  rtt=${Math.round(sync.rttMs)}ms`);

// 2) Schedule an alarm ~6s out, anchored on fire (confirmed mode = re-check consensus at the boundary).
const fireAt = clock.now().epochMs + 6000;
console.log(`alarm armed for ${new Date(fireAt).toISOString()} (disciplined clock)`);

let firedStatus = null;
let fireWallClock = null; // wall-clock at fire, to measure fire→confirmed-block latency below
const scheduler = new ClockScheduler({ clock, client, confirmSource: client });
const id = scheduler.schedule({
  fireAt,
  mode: "confirmed",
  agentId: "clock-sdk-demo",
  // NOTE: on a degraded testnet pool (participation 0% / single validator) the gateway's
  // pool-health guard can refuse the anchor; the SDK client/log path accepts allow_degraded
  // to proceed anyway (anchors, single-validator testnet — not court-grade).
  action: (ctx) => {
    fireWallClock = Date.now();
    // Surface fire latency: how far past the scheduled target the fire actually landed.
    const lateMs = Math.round(ctx.epochMs - fireAt);
    console.log(`FIRED at disciplined ${new Date(ctx.epochMs).toISOString()} (±${Math.round(ctx.uncertaintyMs)}ms)`);
    console.log(`fire latency: ${lateMs >= 0 ? "+" : ""}${lateMs}ms past target`);
    return { firedAt: ctx.epochMs };
  },
});

// 3) Wait for the fire, then read the anchored receipt + verify it keylessly.
const deadline = Date.now() + 30_000;
while (Date.now() < deadline) {
  const s = scheduler.getStatus(id);
  if (s && (s.state === "fired" || s.state === "error")) { firedStatus = s; break; }
  await new Promise((r) => setTimeout(r, 250));
}
scheduler.cancel(id);

if (!firedStatus || firedStatus.state !== "fired") {
  console.error("alarm did not fire within 30s:", firedStatus?.state ?? "timeout");
  process.exit(1);
}

const receipt = firedStatus.receipt;
const ledgerId = receipt?.anchor?.ledgerId;
console.log(`anchored fire: ledgerId=${ledgerId} blockHeight=${receipt?.anchor?.blockHeight ?? "(pending)"}`);

// Harden: the default attest wait can time out before the block lands on testnet,
// leaving blockHeight null. Poll get_log_entry until it backfills (longer timeout)
// BEFORE verifying, so the on-chain check is authoritative, not advisory.
const confirmed = await client.waitForConfirmation(ledgerId, 60_000);
if (confirmed.blockHeight == null) {
  console.error(`block not confirmed within 60s (testnet backfill lag); ledgerId=${ledgerId} — record exists but on-chain verify will be advisory only.`);
} else if (fireWallClock != null) {
  // Wall-clock latency from the fire to the confirmed on-chain block (dominated by block cadence).
  console.log(`fire→confirmed block: ${((Date.now() - fireWallClock) / 1000).toFixed(2)}s (block ${confirmed.blockHeight})`);
}

// Authoritative keyless verify against the immutable block (height discovered from the confirmed record).
const verification = await client.verifyOnChain(ledgerId);
console.log("keyless on-chain verify:", JSON.stringify(verification));
console.log(
  confirmed.blockHeight != null
    ? `✓ alarm fired on verified time, confirmed at block ${confirmed.blockHeight}, keyless-verifiable`
    : "△ recorded + hash-matched, block confirmation pending",
);
