# Standalone Handshake — design

**Date:** 2026-09-14 · **Status:** approved design, pre-implementation
**Source requirements:** stakeholder doc "Standalone Handshake" (Google Docs, 2026-09-14)
**Repo:** `clockchain-mcp` · **Branch:** `feat/standalone-handshake`

## Problem and product definition

Two previously unconnected agents need a trustworthy way to begin talking: establish
who is present, whether entry conditions are met, and what each side consented to
discuss. Standalone Handshake is the pre-negotiation, mutually authenticated gateway
that verifies identity and readiness, records mutual consent, and opens a **witnessed,
bounded A2A channel**. The result is permission to begin a defined conversation — not
a commercial or legal agreement, and never authorization of a business action.

Boundaries (from the requirements doc, binding):
- Consent covers communication with the identified counterparty, for a stated purpose
  and duration. It accepts no proposal, price, or obligation.
- Readiness is "the specified entry conditions passed", not a safety or truth guarantee.
- The witness records what was checked and consented to; it does not adjudicate.
- No funds, no payments, no external business actions — structural invariant, same
  posture as the rest of this repo.

## Decisions made (the doc's open product decisions)

| Decision | Choice |
|---|---|
| V1 readiness checks | (1) ERC-8004 identity verified on-chain, both sides; (2) signed authority statement per side (accountable party + authority to discuss); (3) machine-checkable capability manifest cross-checked by the coordinator |
| Authority evidence | Self-asserted statement, signature verified against the party's registered session key. The receipt records that the signature verified — not that the claim is true |
| Capability compatibility | Exact-match `dataHandlingClass` from the lattice `public < confidential < restricted`; declared purpose on both sides must equal the terms' purpose |
| Initial channel limits | Default duration 3600s; permitted range 60–86400s. Message kinds enum: `question`, `proposal`, `evidence`, `note`. Max message 16 KiB |
| Where it lives | New module `packages/mcp-server/src/standalone-handshake/`, its own credential-light public MCP route `/connect/mcp`. The v2 `agent-handshake` is untouched |
| Ship target | V1 "demo ready": staging-connected, single validator, not scaled |

## Tool surface

Served by its own MCP server (name `clockchain-standalone-handshake`) at `/connect/mcp`,
following the v2 public-server pattern: role-access handles, per-IP rate limits
(invites/hour, calls/minute), per-request transport. No API key required — two
strangers must be able to connect.

| Tool | Read-only | Purpose |
|---|---|---|
| `handshake_invite` | no | Propose terms (reference, purpose, channel limits, identity policy) + initiator readiness package. Returns single-use Responder invitation + role access handle |
| `handshake_accept_invitation` | no | Responder submits their readiness package. Server runs the deterministic checklist |
| `handshake_status` | yes | Progress, checklist results with per-check outcomes, channel state, remaining time, scope |
| `consent_sign` | no | Party signs consent over the exact terms+checklist digest (local signing; server never holds keys) |
| `channel_open` | no | Only from `consented` with both signatures verified. Anchors the opening receipt |
| `channel_send` | no | Typed message; admitted only when open, unexpired, in-scope, from an authenticated participant |
| `channel_read` | yes | Fetch the counterpart's messages addressed to this party, with sequence numbers |
| `channel_status` | yes | State, remaining time, scope, counts (thin variant of handshake_status post-open) |
| `channel_close` | no | Explicit close by either party (records closer) |
| `channel_revoke` | no | One-sided immediate revocation; admission stops at once |

## Flow and state machine

```
invited → readiness_pending → ready | ready_failed
ready → consent_pending → consented → open → closed
                                    open → revoked | expired
```

- `ready_failed` is terminal and carries reason codes (`IDENTITY_UNVERIFIED`,
  `AUTHORITY_INVALID`, `MANIFEST_MISMATCH`, `PURPOSE_MISMATCH`).
- `expired` is entered lazily on first touch after `expiresAtMs` (consensus time) and
  reported identically wherever the session is inspected.
- No transition skips the checklist; an interrupted or failed opening can never become
  an open channel.

## Records (exact-key canonical, v2 style)

Schema family `clockchain.standalone-handshake-*/v1`, canonical bytes + digest via the
existing `handshake/protocol.ts` helpers:

- `terms/v1` — `{reference, purpose, channelLimits{durationSeconds, messageKinds[], maxMessageBytes}, identityPolicy}`
- `readiness/v1` — per party: `{identity{erc8004...}, authorityStatement{accountableParty, statement}, capabilityManifest{dataHandlingClass, purpose}}`
- `consent/v1` — per party, signature over `{termsDigest, checklistDigest, sessionId, party}`
- `message/v1` — `{sessionId, seq, kind, fromRole, toRole, bodyDigest, sentAtMs}`
- `opening/v1` (receipt) — three anchors: `terms-readiness`, `consent`, `open`
- `closure/v1` — `{sessionId, outcome: closed|revoked|expired, by, anchors[1]}`

Message bodies stay in the staging session store only. Every receipt and every
verifiable claim carries digests, never bodies.

## Enforcement (fail-closed)

- All time judgments against **Clockchain consensus time** (ledger timestamps), never
  the server clock. Consent terms carry `expiresAtMs = openedAtMs + durationSeconds`.
- `channel_send` rejection reason codes: `NOT_OPEN`, `EXPIRED`, `REVOKED`,
  `SCOPE_VIOLATION`, `TOO_LARGE`, `UNKNOWN_PARTY`, `MALFORMED`.
  `MALFORMED` is emitted when the body is not a non-empty string; a well-formed
  string over the byte cap is `TOO_LARGE`.
- Revocation by either party is immediate and permanent for the session.
- Rate limits and role-access handles per the v2 broker pattern, instantiated locally
  in this module (v2 files are not modified; extraction into a shared module is
  deferred until a third consumer exists).

## Anchoring and receipts

Anchor through `ClockchainClient` from `@clockchain/core` (the same client and
`readConfigFromEnv` configuration the v2 coordinator uses), with a local anchor helper
per transition: at open, three records (`terms-readiness`, `consent`, `open`); at
close/revoke, one `closure` record. The `consent` and `open` transition records carry
both parties' consent digests (`consentDigests.initiator` / `consentDigests.responder`);
session opening time derives from the open anchor's consensus block time, and each
closure is verifiable against its anchor's consensus block time (the record's
`closedAtMs` is pinned before anchoring so a retry re-anchors the identical digest). The opening receipt carries all three anchors
(blockHeight, blockTimeRaw, digest, ledgerId) and is keylessly verifiable through the
existing public verify path. Anchoring uses the same idempotency/degraded-pool posture
as existing tools.

## Pages (stakeholder-visible update)

- `landing.ts`: new "Standalone Handshake" section — one-paragraph what/why, connect
  command for `/connect/mcp`, link to `/llms.txt` handshake facts.
- `INSTALL_TXT` (llms.txt): same facts in agent-readable text.
- Tool-count line keeps its single source of truth (`CLASSIFIED_TOOLS`).
- New `/.well-known/standalone-handshake.json` discovery entry, mirroring the v2 one.
- Research site untouched.

## Testing

Same suite standard as the repo (`.test.mjs`, no skips, no TODOs):

- Protocol validators: exact-key records reject every extra/missing/mistyped field.
- State machine: every legal and illegal transition edge.
- Enforcement boundaries with an injected clock: send at exactly `expiresAtMs`
  rejects; revocation mid-conversation stops admission; each scope violation reason.
- Checklist matrix: mismatched `dataHandlingClass`, purpose, and invalid authority
  signature each fail with their reason code; passing combinations open.
- Rate limits and role-access handle lifecycle.
- One end-to-end two-party integration test over the HTTP handler with a fake ledger,
  from invite through anchored closure.
- Page tests: landing section renders, llms.txt contains the handshake facts,
  `.well-known` entry served.

## Out of scope (V2 per the requirements doc)

Scaled concurrent sessions, production blockchain, AC Express demo page, marketing
page and launch strategy, registry listing mechanics.
