# Product A Identity: ERC-8004 vs Proprietary DID

A decision memo. Product A (Agent Identity) currently mints a proprietary
`did:clockchain:agent:{uuid}` as a convention on `/log`. In 2026 the agent
ecosystem converged on a standard - ERC-8004 plus SIWA - that 30,000+ agents
already use. This memo lays out the options and recommends one.

This is a direction decision, and it sits downstream of customer discovery: the right answer depends on who
Product A is for.
The recommendation below states that dependency explicitly.

## TL;DR

**Do not build the proprietary DID deeper. Lean toward a hybrid: adopt ERC-8004
for the identity primitive, and position Clockchain where it is actually
differentiated - as a time-based validation and action-trail layer within the
ERC-8004 model, not as a competing identity system.** Clockchain's edge is
*time*, not identity. ERC-8004 already owns identity. Competing on identity is
fighting where we are weakest; plugging into it on validation is playing where we
are strongest.

Caveat: if customer discovery shows Product A's buyer is non-crypto enterprise
compliance (not the agent economy), ERC-8004 may be irrelevant and a simple
internal identity is fine. Decide the customer first; this memo assumes the
agent-economy positioning the products are currently sold on.

## What ERC-8004 actually is

[ERC-8004 "Trustless Agents"](https://eips.ethereum.org/EIPS/eip-8004) is an
Ethereum standard for on-chain agent identity, structured as three registries:

- **Identity Registry** - each agent is an ERC-721 NFT with a unique `agentId`
  and an `agentURI` pointing to a JSON registration file (name, operator,
  capabilities).
- **Reputation Registry** - feedback signals (scores, tags) from clients to
  agents.
- **Validation Registry** - third-party validator attestations, explicitly
  including zkML, TEE, and staked re-execution.

[SIWA (Sign In With Agent)](https://siwa.builders.garden/) sits on top: agents
authenticate by signing challenges with the key tied to their on-chain identity,
and critically the private key never resides in the agent - signing runs through a
separate keyring proxy ([Turnkey](https://www.turnkey.com/blog/agent-identity-erc-8004-siw)).
[QuickNode's developer guide](https://blog.quicknode.com/erc-8004-a-developers-guide-to-trustless-ai-agent-identity/)
and Ledger, Eco, and others now document it as foundational infrastructure, with
30,000+ agents registered.

## The three options

**Option A - stay proprietary (`did:clockchain:agent`).**
What we have: a `/log` convention (verified working as a hash anchor). What it
lacks (verified): no cross-client resolution, no enumeration, sanitized metadata,
and no reputation or validation layer. It is a private per-client log, not an
interoperable identity.

**Option B - full ERC-8004 adoption.**
Agents register via ERC-8004; Clockchain drops the proprietary DID entirely.
Interoperable and standards-aligned. But ERC-8004 registries live on Ethereum /
EVM L2s, so identity would live *off* Clockchain - which raises the question of
what Clockchain's role even is in the identity story.

**Option C - hybrid (recommended).**
Adopt ERC-8004 as the identity primitive, and make Clockchain a **Validation
Registry provider** and **action-trail notary** within it. Clockchain's
consensus-time becomes a validation method (a time-stamped, consensus-attested
"this agent did X at this verifiable time"); Clockchain logging anchors the
agent's action trail, referenced from its ERC-8004 identity. Play the standard
where identity is commodity; play Clockchain's time where it is differentiated.

## Comparison

| Dimension | A: Proprietary | B: Full ERC-8004 | C: Hybrid |
|---|---|---|---|
| Interoperability with the 30k+ agent economy | None (siloed) | Full | Full |
| Plays to Clockchain's real edge (time) | Incidental | Loses our role | Yes - validation layer |
| Cross-agent verification | Blocked (client-scoped) | Native | Native (via ERC-8004) |
| Reputation / validation layer | None | Native | Native + our time attestations |
| Build & maintain burden | All on us | Low (consume standard) | Medium (integrate + validation svc) |
| Where identity lives | Clockchain `/log` | EVM chains | EVM identity + Clockchain attestations |
| Standard-churn risk | None | Bet on a young EIP | Bet on a young EIP |
| Strategic position | "another DID" | "we adopted the standard" | "the time/validation layer for agent identity" |

## The key insight

Clockchain's differentiator is **time**, not identity. ERC-8004's Validation
Registry was built precisely to accept third-party attestations (zkML, TEE,
staked re-execution). A consensus-time attestation - "this agent action occurred
at this independently-verifiable moment" - is a natural fourth validation method.
That is a lane no one else fills, and it is exactly Clockchain's Marzullo-
consensus strength.

So the framing flips: the question is not "should Clockchain build its own DID or
adopt ERC-8004." It is "Clockchain should adopt ERC-8004 for identity and compete
on being the best *time and validation* layer underneath it." That is a stronger
position than a proprietary identity competing head-on with a standard.

## Architecture implications to resolve

- **Where do registries live?** ERC-8004 is EVM/ERC-721. Clockchain runs
  CometBFT with an EVM layer (Besu) and the D4D token already lives on an EVM
  testnet (Sepolia), so EVM compatibility exists. Decide: does Clockchain host an
  ERC-8004-compatible registry on its own EVM layer, or do agents register on
  Ethereum/Base and Clockchain provides attestations referencing that identity?
  The hybrid leans to the latter - register where the agents already are, attest
  from Clockchain.
- **How does a Clockchain log reference an ERC-8004 agent?** The `assetReferenceId`
  preserves `:` and `-`, so an `agentId` / CAIP-style reference fits as the log's
  reference key, tying an action-trail entry to the agent's ERC-8004 identity.
- **Non-custodial alignment.** SIWA's keyring-proxy model (keys never in the
  agent) matches the non-custodial requirement already in the MCP spec. Adopting
  ERC-8004 + SIWA resolves the identity side of that requirement for free.

## Risks

- **ERC-8004 is young.** It is a recent EIP; 30k agents is real traction but the
  standard may still change. The hybrid limits exposure - we depend on the
  identity interface, not on owning it.
- **Customer mismatch.** If Product A's real buyer is non-crypto enterprise
  compliance, ERC-8004 is irrelevant overhead. This is the dependency on customer
  discovery - do not commit to ERC-8004 integration before confirming the buyer
  is in the agent/EVM economy.
- **Our edge must be real.** The time-validation differentiator only holds once
  Clockchain runs a real multi-validator network. On a single-node testnet the
  consensus attestation is as hollow as the proofs are today.

## Recommendation

1. **Stop deepening the proprietary DID.** Keep the `/log` anchor convention only
   as a POC stand-in, clearly labeled experimental.
2. **Default to Option C (hybrid)**, conditional on customer discovery confirming
   an agent-economy buyer.
3. **Frame Clockchain as the time/validation layer for ERC-8004 agents**, not as
   an identity issuer. Prototype a Clockchain attestation that targets the
   ERC-8004 Validation Registry.
4. **Sequence it behind the customer-discovery question.** If the buyer is not
   in the agent economy, revisit.

## Open questions to validate

- Is Product A's buyer in the ERC-8004 / agent economy at all? (Customer discovery.)
- Does Clockchain host its own ERC-8004 registry, or attest to identities on
  Ethereum/Base? (Architecture + the D4 team.)
- Is "time as an ERC-8004 validation method" something agent builders would
  actually consume? (Design-partner conversation.)
- Does the multi-validator network land in time for the time-attestation to be
  credible? (Backend dependency.)

The decision itself - proprietary vs hybrid - should be made by Product (Yang)
with the D4 backend team, after the customer question is answered. This memo's
job is to make sure the proprietary path is not built deeper by default before
that decision is made.
