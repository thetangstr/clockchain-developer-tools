# Clockchain - Product Findings

Findings from hands-on evaluation of the live network and the
`services.clockchain.network` dashboard on 2026-06-02. These are observations
about the product as it exists today, with recommendations. Severity is from a
developer-adoption standpoint, not a code-correctness one.

Summary of what we did: tested the Timestamp API end to end, attempted real log
writes, walked the Logging / Token Management / Purchase Logs dashboards, and
hit the token-purchase flow.

---

## 1. Three separate balances, only one is visible where you need it

**Severity: high (causes immediate confusion and dead ends)**

There are three independent meters and they are easy to confuse:

| Meter | Where it shows | What it pays for |
|---|---|---|
| API Requests | Timestamp API dashboard (`21 / 1,000`) | Read calls: time, timestamp, block, search, validation |
| D4D Tokens | Token Management (`5,000`) | The native crypto token (Sepolia testnet) |
| Logs | Logging dashboard (`Remaining Logs: 0`) | What `POST /log` actually spends |

A user with "5,000 tokens" and "979 API requests left" still cannot log
anything, because logging spends **logs**, and logs start at zero. Worse, the
API returns a misleading error for this state:

```
POST /log  ->  400  {"message":"No enough tokens to facilitate this logging"}
```

It says "tokens"; the real empty meter is "Logs." Nothing on the primary API
dashboard hints that a separate log balance exists.

**Recommendation**
- Surface all three balances in one place, and in the CLI `status` command.
- Fix the error copy: "No logging credits remaining. Buy logs at /logging-buy-logs."
- Consider collapsing "tokens vs logs" conceptually for non-crypto users (see #2).

---

## 2. Funding logs with crypto is an onboarding cliff

**Severity: high (blocks the "5 minute" promise)**

The Purchase Logs page offers two rails:

```
1,000 Logs   $2.00   or   10 D4D TOKEN
10,000 Logs  $19.00  or   95 D4D TOKEN
...
100,000 Logs $99.00  or  495 D4D TOKEN
```

Choosing the token rail triggers a MetaMask transaction on **Sepolia testnet**.
Spending `d4dt` needs **SepoliaETH** for gas. On testnet that gas is free and
valueless - you grab it from a faucet (e.g. Google Cloud Web3 hands out ~0.05 a
day) - so this is not a cost wall. It is a **steps** wall: install MetaMask, find
and use a faucet, get testnet ETH, approve the token, sign the transaction. A
first-time user who just wanted to buy logs hits all of that before anything
happens. (Observed first attempt failed with "Insufficient funds ... not enough
SepoliaETH" simply because the faucet step hadn't been done yet.)

Two things make this matter beyond "it's a few extra steps":

- **On mainnet the gas is no longer free.** The same flow then charges real ETH
  per transaction, a recurring cost on top of the log price. The testnet hides
  that cost today.
- **An AI agent cannot do any of these steps at all** - faucets, swaps, MetaMask
  signing. See #3.

**Recommendation**
- Make the **fiat ($) rail the default** and visually primary. The card path
  (Stripe) buys logs with no wallet, no gas, no swap.
- Treat the crypto rail as an advanced option for crypto-native users.
- If the token rail stays, sponsor gas (meta-transactions / relayer) so a user
  never needs to hold the native gas token to spend D4D.

---

## 3. Agents cannot fund logging the way it works today

**Severity: critical for Product B (Agent-SDK)**

This is the most important finding. Product B's premise is that an AI agent logs
its actions to Clockchain. But the only self-serve way to fund logging is a
MetaMask swap on Sepolia. **An agent cannot manage a wallet, hold gas, or sign
swap transactions.** If wallet-based purchase is the only funding path, Product B
cannot ship.

**Requirement (hard dependency for Product B)**
- Logging must be fundable via **API key / account credit**, set up once by the
  agent's human operator (card or account balance on file), with no per-write
  wallet interaction.
- An agent's `log_action` call should draw down a prepaid credit pool tied to the
  API key - never prompt for a signature.
- This is not a nice-to-have. It gates whether the Agent-SDK is buildable at all.

---

## 4. `hashType` values and the validation message disagree with the UI

**Severity: medium (will cause integration errors)**

The `POST /log` validation error lists:

```
Invalid hash type. Valid hash types: MD5|SHA-1|SHA-2|SHA-256
```

But the live logging form's dropdown offers a broader set:

```
SHA-256, MD5, SHA-1, SHA-384, SHA-512, SHA3, RIPEMD-160
```

Two problems: the sets do not match (API says `SHA-2`, UI says `SHA-384/512`,
etc.), and the value must be **hyphenated** (`SHA-256`, not `SHA256` - the latter
is rejected). Any SDK will guess wrong without trial and error.

**Recommendation**
- Publish one canonical, documented enum and make the API and UI agree.
- Return the accepted set in a machine-readable field, not just a prose message.

---

## 5. Rate limiting is far stricter than documented

**Severity: medium (breaks polling / streaming use cases)**

Internal docs describe 50 requests/minute. In practice, 1-2 calls in quick
succession trip `Rate limit exceeded` (HTTP 400) with a roughly 100-second
cooldown. This may be per-key burst limiting or same-day budget exhaustion, but
either way it makes any `watch` / live-dashboard / high-frequency pattern
impractical on the current tier.

**Recommendation**
- Document the real limit and the cooldown behavior.
- Distinguish "burst limit" from "monthly quota" in responses, with
  `Retry-After`.
- If real-time use is a goal, offer a higher-rate tier or a streaming endpoint.

---

## 6. Smart-contract scheduling is not on the public gateway

**Severity: medium (feature unavailable, not just unfinished)**

`/schedule` returns `404` on `node.clockchain.network` (GET, POST, and
`/api/schedule`). The Smart Contracts tab exists in the dashboard, but the
documented scheduling endpoint is not reachable through the public API we were
given. Any "time-triggered contract" tooling is blocked until the gateway
proxies it.

**Recommendation**
- Confirm whether smart-contract scheduling is meant to be publicly available
  yet. If yes, expose it on the gateway; if no, mark it clearly as not-yet-public
  so it is not pitched as available.

---

## 7. Network is a single node, so "consensus" and "proof" are hollow today

**Severity: context (expected for testnet, but shapes the story)**

The timestamp endpoint reports `totalNodes: 1.0`, `consentedOffset: -999.0`
(a sentinel for no consensus), and every validation block shows `0` positive
votes, `0.0%` trust, `0.0%` participation. The timestamping works, but the
multi-validator consensus that makes a proof "court-grade" is not exercised on
the current testnet.

**Recommendation**
- Be precise in customer-facing material: timestamps are real; the
  multi-validator legal-evidence story is a mainnet property, not something a
  single-node testnet entry demonstrates today.

---

## 8. Dashboard field names do not match the API

**Severity: low (friction for SDK authors)**

The Create Log / Asset Hashing form uses `assetId`, `assetName`, `assetHash`,
`hashType`, `version`, `additionalInfo`. The `/log` API uses `assetReferenceId`,
`assetHash`, `hashType`, `versionNumber`, `additionalInfo`, plus `clientId` and
`walletId` (which the UI injects from the session). The naming drift (`assetId`
vs `assetReferenceId`, `version` vs `versionNumber`) will trip up anyone moving
from the UI to the API.

**Recommendation**
- Align field names between UI and API, or document the mapping explicitly.

---

## What works well today

- The **Timestamp API is solid**: time, timestamp, and block-by-height all
  return clean, fast, correctly-shaped data.
- **The logging endpoint itself is fully wired** - it validated our payload and
  failed only at the (correct) credit check. Once logs are funded, the write
  path should work.
- **Search** returns sensible empty results and is ready to use.
- The dashboard covers the full surface (logging, search, twitter logging,
  purchase, token management, smart contracts, timestamp API) - the product
  scope is real and present.

---

## Priorities, if it were our call

1. **Add an API/account-credit funding path for logs** (unblocks Product B). #3
2. **Make fiat the default purchase rail** and fix the misleading token error. #1, #2
3. **Reconcile hash-type enums and document the real rate limit.** #4, #5
4. **Clarify smart-contract availability and the single-node proof caveat.** #6, #7
