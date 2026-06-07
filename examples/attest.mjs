// Agent Attested Receipt - the "five-line" hook.
//
// Connect an agent to Clockchain and get independently verifiable proof of a
// high-stakes autonomous action. Crypto, RPC nodes, and Web3 infra stay hidden.
//
// Run (from the repo root, after `npm install && npm run build`):
//   CLOCKCHAIN_API_KEY=... CLOCKCHAIN_CLIENT_ID=you@example.com \
//   CLOCKCHAIN_WALLET_ID=you@example.com \
//   node --experimental-loader ... examples/attest.mjs
// or simply import "@clockchain/core" from your own project.

import { ClockchainClient } from "@clockchain/core";

const cc = new ClockchainClient(); // reads CLOCKCHAIN_* from the environment
const receipt = await cc.attestAction({
  agentId: "agent:treasury-bot",
  action: "execute_trade",
  inputs: { pair: "USDC/ETH", size: "250000", trigger: "price<3000" },
  outputs: { decision: "EXECUTE", txIntent: "0xabc123" },
});
console.log(`Receipt ${receipt.anchor.ledgerId} @ block ${receipt.anchor.blockHeight}`);
console.log(`Event hash ${receipt.eventHash}`);

// Anyone can re-verify later - recomputes the hash and checks the on-chain anchor.
console.log("verified:", (await cc.verifyReceipt(receipt)).match);
