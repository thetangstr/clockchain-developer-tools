# Clockchain Developer Tools - Implementation Plan

## What We're Building

The developer surface for Clockchain's two core products:

- **Product A**: On-Chain Agent Identity - DID minting, verification, revocation ("birth certificates" for AI agents)
- **Product B**: Agent-SDK - the integration layer that makes Clockchain the default time-trust primitive for AI agent frameworks (LangChain, AutoGPT, CrewAI)

Three npm packages deliver both products through a shared core:

```
@clockchain/core          ← API client, DID operations, receipt generation, types
@clockchain/cli           ← Developer access: identity, logging, proofs, triggers
@clockchain/mcp-server    ← AI agent access: the Agent-SDK's MCP connector
```

The MCP server is not a utility - it IS Product B's primary interface. An AI agent that connects to Clockchain via MCP can mint its own identity, log its actions with tamper-proof timestamps, prove its identity to other agents, and trigger time-conditional smart contracts. This is the "default-import pattern" the assessment identifies as the competitive moat.

## Architecture

```
AI Agent (LangChain, AutoGPT, CrewAI)     Developer
   │                                          │
   ▼                                          ▼
@clockchain/mcp-server                  @clockchain/cli
(Product B: Agent-SDK MCP connector)    (Product A+B dev tooling)
   │                                          │
   └──────────────┬───────────────────────────┘
                  ▼
          @clockchain/core
           (TypeScript)
                  │
                  ▼
       node.clockchain.network
       D4 Node (Spring Boot + CometBFT)
                  │
           ┌──────┼──────┐
           ▼      ▼      ▼
       DynamoDB  Chain  EVM Layer
       (off-chain (Marzullo  (smart
        index)   consensus) contracts)
                  │
           ┌──────┼──────┐
           ▼      ▼      ▼
         NTP   Google  NIST
                NTP
```

### Why TypeScript

- MCP SDK is TypeScript-native (`@modelcontextprotocol/sdk`)
- LangChain.js and Vercel AI SDK are TypeScript - same ecosystem as target developers
- One language across CLI + MCP + core
- `npx` gives zero-install for both CLI and MCP

---

## Live Evaluation (2026-06-02, full write-path test)

A second pass actually exercised the write paths, not just read probes. Results:

| Capability | Verdict | Evidence |
|---|---|---|
| Time oracle (`time`, `timestamp`, `block`) | **Working** | Returns live data; genesis block 1 = `2026-04-30T15:29:16Z`. Single node: `consentedOffset -999.0`, `totalNodes 1.0`, votes 0%. |
| Validation (`getValidationBlock`) | **Working, empty** | 200 for any height; all vote/trust/participation fields are 0 on the single-node testnet. |
| Search (`searchAsset`) | **Working** | 200, returns `[]` (no assets logged under this client). |
| **Logging (`POST /log`)** | **Live, blocked on credits** | Passes structural + hash-type validation, then returns `400 {"message":"No enough tokens to facilitate this logging"}`. The endpoint works; the account has no log credits. |
| Ledger (`GET /ledger/{id}`) | Present, untested | 500 on a bad id; needs a real `ledgerId` from a successful log. |
| **Smart contract (`/schedule`)** | **Not available** | 404 on GET, POST, and `/api/schedule`. Not proxied to the gateway. |
| Twitter logging (`/buyTweets`) | Present, not registered | `400 {"error":"This client ID is not registered with us"}`. |

**Two confirmed corrections to earlier drafts:**

1. **`hashType` must be hyphenated.** Valid set is `MD5 | SHA-1 | SHA-2 | SHA-256`. `"SHA256"` is rejected with `400 Invalid hash type`. The spec has been corrected throughout.
2. **Logging is metered by purchased "tokens" (log credits)**, separate from the API request quota. With zero credits, every `/log` write fails at the token gate even though the request is otherwise valid. This matches the D4 Payment Gateway (Stripe, 10/100/1000 log packs) in the internal docs.

**Operational note - rate limiting is far tighter than documented.** The docs say 50 req/min; in practice 1-2 calls trip `Rate limit exceeded` (HTTP 400) with a ~100s cooldown. Whether this is per-key burst limiting or leftover budget from same-day probing is unclear, but any polling/`watch`/streaming feature must assume a very low effective rate on the current tier and back off aggressively.

**Net:** the entire read surface and the logging endpoint are real and reachable today. To finish the write-path test we need (a) log credits provisioned on a known `clientId`/`walletId`, and (b) the backend to expose `/schedule` for the trigger feature.

---

## Verified API Surface (probed 2026-06-02)

Before building, here is what the public gateway at `node.clockchain.network` actually exposes. This was probed directly with a live API key. Treat the rest of this document as a design against these facts, not a description of finished APIs.

| Endpoint | Status | Live response shape |
|---|---|---|
| `GET /api/time/time` | Confirmed 200 | `{success, data:{latestBlockTime, latestBlockHeight}, meta:{timestamp}}` |
| `GET /api/time/timestamp` | Confirmed 200 | `{success, data:{...Marzullo fields...}, meta}` |
| `GET /api/time/block?height=` | Confirmed 200 | block height, proposer, time |
| `GET /searchAsset?clientId=&assetReferenceId=` | Confirmed 200 | bare JSON array, `[]` when empty. No `{success,data}` envelope. |
| `GET /getValidationBlock/{h}` | Confirmed 200 | `{validationBlockData:{...}}`. No `executionResult`/`faultHandling` wrapper (the internal doc showed those; the gateway does not return them). No `{success,data}` envelope. |
| `GET /ledger/{id}` | Present (500 on bad id) | not verified with a real ledger ID |
| `POST /log` | Present (500 on GET probe) | not verified end-to-end (would write to chain; needs a real walletId) |
| `GET /schedule?...` | **404 — NOT exposed on the gateway** | The smart-contract scheduling endpoint exists only on a raw node (`:8000`) per the internal docs, not through the public gateway |

**Three things this changes:**

1. **The response envelope is inconsistent.** `/api/time/*` wraps results in `{success, data, meta}`; `/searchAsset` and `/getValidationBlock` return raw bodies. The core client must unwrap per-endpoint, not assume a uniform envelope.

2. **Triggers / smart contracts are blocked.** `/schedule` returns 404 on the public gateway. Everything in the "Time-Conditional Triggers" section below (CLI `trigger *`, MCP `schedule_trigger`) cannot be built against the public API today. It stays in the plan as a design target but is **gated on the backend exposing `/schedule` through the gateway** — treat it as Phase 5-adjacent, not P1.

3. **The validation block is sparse on testnet.** Block 100 returns `positiveVotes: 0, negativeVotes: 0, Trust value percentage: 0.0, Node participation percentage: 0.0`. With a single testnet node and `consentedOffset: -999.0`, every proof generated today carries zero votes and 0% trust. See "Evidence Package: testnet reality" below.

### Open assumptions (resolve with the D4 team before/during Phase 1)

- **`walletId` provenance.** `/log` requires `clientId` and `walletId`. The dashboard exposes a Client ID (email) and an API key, but no `walletId`. Where a developer obtains one is unknown. Phase 1 is blocked on this for any write path.
- **`searchAsset` is scoped to the caller's `clientId`.** It cannot list by prefix and cannot see another client's records. This breaks two features as specified (cross-client DID verification and `identity list`) - see the DID section.
- **No per-validator reading endpoint.** The audit doc says individual time-source readings are stored, but no API returns them. Evidence-package layers 1-3 cannot be populated from the live API today (see Evidence Package section).

---

## Product A Surface: Agent Identity (DIDs)

An AI agent's lifecycle on Clockchain:

```
1. MINT        Agent (or its developer) mints a Birth Certificate DID
               → on-chain record: agent name, capabilities, owner, timestamp
               → returns: DID + block height + validator signatures

2. LOG         Agent logs every significant action against its DID
               → each log: DID + action hash + consensus timestamp
               → immutable, tamper-proof action trail

3. PROVE       Agent (or auditor) generates an evidence package
               → 5-layer chain by design (VRF election → time sources →
                 computation → consensus → ledger); today only the
                 consensus + ledger layers are populated from the live API

4. VERIFY      Another agent or service verifies the DID is valid
               → checks on-chain: DID exists, not revoked, owner matches

5. REVOKE      Owner revokes the DID (agent decommissioned, compromised)
               → on-chain revocation record with timestamp
```

### CLI Commands (Product A)

| Command | What it does | Priority |
|---|---|---|
| `clockchain identity mint` | Mint a new agent DID (Birth Certificate) | P0 |
| `clockchain identity verify <DID>` | Check if a DID is valid and unrevoked | P0 |
| `clockchain identity revoke <DID>` | Revoke an agent's DID | P0 |
| `clockchain identity show <DID>` | Display DID details (owner, mint time, capabilities) | P0 |
| `clockchain identity list` | List all DIDs owned by this client | P1 |

```bash
# Mint a birth certificate for an agent
$ clockchain identity mint \
    --name "investor-update-agent" \
    --capabilities "draft,send-email,read-metrics" \
    --owner "yang@clockchain.network"

DID:             did:clockchain:agent:a8f3c2e1...
Block Height:    2734500
Minted At:       2026-06-02T01:06:01.000Z
Trust:           100.0%
Participation:   100.0%
Validator Sigs:  3/3

# Verify an agent's identity
$ clockchain identity verify did:clockchain:agent:a8f3c2e1...
Status:          VALID
Minted:          2026-06-02T01:06:01.000Z
Owner:           yang@clockchain.network
Capabilities:    draft, send-email, read-metrics
Revoked:         No
```

### MCP Tools (Product A)

| Tool | Description |
|---|---|
| `mint_agent_identity` | Mint a new DID for an AI agent. The agent can call this itself on first run to self-register. |
| `verify_agent_identity` | Check if a DID minted by this client is valid. See constraint below. |
| `revoke_agent_identity` | Revoke a DID. Requires owner authorization. |
| `get_agent_identity` | Get full DID details including mint time, capabilities, and owner. |

> **Design constraint (must resolve before Product A is real).** This DID layer is built as a convention on top of `/log` and `/searchAsset` - a mint is a log entry with `assetReferenceId = did:mint:{did}`, a revoke is `did:revoke:{did}`. That works for a client managing its own agents, but two things do **not** work with the live API:
>
> 1. **Cross-client verification is impossible.** `searchAsset` only returns records under the caller's own `clientId`. Agent B cannot verify Agent A's DID if they belong to different clients - which is the entire point of an agent-to-agent handshake. A real DID system needs a **public resolution endpoint** (`GET /did/{did}` with no client scoping) that the D4 team must add. Until then, `verify_agent_identity` only works within a single client.
> 2. **`identity list` cannot be implemented.** `searchAsset` requires an exact `assetReferenceId`; it cannot list by `did:mint:` prefix. Listing a client's DIDs requires either a backend index or a local cache the CLI maintains. As specified against the live API, this command does not work.
>
> Net: ship `mint` + `verify`-within-client + `revoke` as a convention layer for the pilot/dogfood, but flag clearly that production Product A depends on a backend DID-resolution endpoint. Do not present this convention layer as a finished W3C-style DID system.

---

## Product B Surface: Agent-SDK (Logging, Proofs, Triggers)

Product B is the integration layer. The MCP server is the primary interface - an AI agent framework (LangChain, AutoGPT) connects to Clockchain via MCP and gets:

1. **Tamper-proof action logging** - every agent action gets a consensus timestamp
2. **Court-admissible proof generation** - 5-layer evidence chain on demand
3. **Time-conditional triggers** - smart contracts that execute when consensus time crosses a threshold
4. **Time oracle queries** - current consensus time, drift, node health

### Logging: Agent Action Trail

Not "log a generic asset hash." Log an **agent action** tied to the agent's DID.

#### CLI Commands

| Command | What it does | Priority |
|---|---|---|
| `clockchain log action` | Log an agent action (hash + DID + metadata) | P0 |
| `clockchain log file <path>` | Hash a file and log it | P0 |
| `clockchain log search` | Search logged actions by DID or asset reference | P0 |
| `clockchain log get <ledgerId>` | Retrieve a specific log entry | P0 |

```bash
# Log an agent action tied to a DID
$ clockchain log action \
    --did did:clockchain:agent:a8f3c2e1... \
    --asset-ref "investor-update-2026-06-02" \
    --hash sha256:$(echo "Weekly update: testnet reached 2.7M blocks" | shasum -a 256 | cut -d' ' -f1) \
    --info "Drafted weekly investor update from testnet metrics" \
    --wait

Ledger ID:       b9c4d3f2-5a6e-7890-bcde-f01234567890
DID:             did:clockchain:agent:a8f3c2e1...
Block Height:    2734510
Timestamp:       2026-06-02T01:07:15.000Z
Action:          investor-update-2026-06-02
Status:          Confirmed

# Log a file (e.g., the generated investor update PDF)
$ clockchain log file ./investor-update-june-2.pdf \
    --did did:clockchain:agent:a8f3c2e1... \
    --asset-ref "investor-update-2026-06-02-pdf" \
    --wait

# Search an agent's action trail
$ clockchain log search --did did:clockchain:agent:a8f3c2e1... --limit 10
LEDGER ID          BLOCK      TIMESTAMP                    ASSET REF
b9c4d3f2-5a6e...   2734510    2026-06-02T01:07:15.000Z    investor-update-2026-06-02
c0d5e4g3-6b7f...   2734480    2026-06-01T22:15:00.000Z    metrics-fetch-daily
```

#### MCP Tools

| Tool | Description |
|---|---|
| `log_action` | Log an agent action with DID, hash, and metadata. The agent calls this after every significant action to build its auditable trail. |
| `log_file` | Compute SHA-256 of content and log it. Convenience wrapper. |
| `search_actions` | Search logged actions by DID or asset reference. |
| `get_log_entry` | Retrieve a specific log entry by ledger ID. |

The `log_action` tool is the heartbeat of Product B. An AI agent framework integration looks like:

```python
# LangChain integration example
from langchain.callbacks import ClockchainCallback

# Every tool call, LLM response, and chain step is logged to Clockchain
chain = LLMChain(
    llm=ChatAnthropic(model="claude-sonnet-4-6"),
    callbacks=[ClockchainCallback(did="did:clockchain:agent:a8f3c2e1...")]
)
```

### Proofs: Evidence Package

A structured evidence package modelled on the 5-layer chain from the Audit & Proof System document. Read this honestly: of the five layers, only layers 4 and 5 can be populated from the live gateway today.

| Layer | Source | Buildable now? |
|---|---|---|
| 1 - VRF validator election | no endpoint returns the election proof | No - needs backend endpoint |
| 2 - per-validator time-source readings (NTP/Google NTP/NIST) | no endpoint returns raw readings | No - needs backend endpoint |
| 3 - independent computation / threshold | inferred only | Partial - can state the algorithm and 1500ms threshold, cannot show per-validator work |
| 4 - validator consensus (votes, trust %, participation %) | `GET /getValidationBlock/{h}` | Yes |
| 5 - ledger record (block height, proposer, time, event hash) | `GET /ledger/{id}` + `GET /api/time/block` | Yes |

So the deliverable for the pilot is an **honest 2-layer proof (consensus + ledger)** with layers 1-3 marked "requires endpoints not yet exposed." Calling it "court-admissible" is the *destination* per the audit doc's legal analysis, not what a generated package proves today. Use that framing carefully with customers.

**Testnet reality:** the testnet runs a single node. `consentedOffset` is `-999.0` (sentinel: no consensus), and `getValidationBlock` returns `positiveVotes: 0, Trust value percentage: 0.0, Node participation percentage: 0.0`. Every proof generated against the current testnet shows zero votes and 0% trust. The rich multi-validator numbers below are **mainnet illustrations**, not current output - the tooling must render real numbers, including the unflattering testnet ones.

#### CLI Commands

| Command | What it does | Priority |
|---|---|---|
| `clockchain prove <ledgerId>` | Generate a full evidence package for a log entry | P0 |
| `clockchain prove verify <file>` | Verify a previously generated proof package | P1 |
| `clockchain prove agent <DID>` | Generate a proof of an agent's entire action trail | P1 |

```bash
# Generate an evidence package (numbers below are a MAINNET illustration;
# on the current 1-node testnet, votes and trust render as 0).
$ clockchain prove b9c4d3f2-5a6e-7890-bcde-f01234567890 --output proof.json

Clockchain Evidence Package
═══════════════════════════════════════════════════════════════

Layer 1 - Validator Election
  Method:           Verifiable Random Function (VRF)
  Validators:       3 selected from pool of 3
  Election Proof:   0x7a8b9c... (independently verifiable)

Layer 2 - Time Sources
  NTP:              2026-06-02T01:07:14.998Z
  Google NTP:       2026-06-02T01:07:15.001Z
  NIST:             2026-06-02T01:07:14.999Z

Layer 3 - Independent Computation
  Each validator independently computed consensus time
  using the Marzullo fault-tolerant algorithm.
  Threshold:        1500ms
  All readings within threshold: YES

Layer 4 - Validator Consensus
  Positive Votes:   3/3 (100.0%)
  Negative Votes:   0/3
  Consensus Time:   2026-06-02T01:07:15.000Z

Layer 5 - Ledger Record
  Block Height:     2734510
  Block Time:       2026-06-02T01:07:15.000Z
  Proposer:         5E7C4A1E2CED496E...
  Event Hash:       sha256:a1b2c3d4e5f6...

Verification
  Hash Match:       YES (sha256:a1b2c3d4e5f6...)
  Chain Integrity:  Block 2734510 links to 2734509 (valid)

Standards Compliance
  EU eIDAS:         Meets qualified timestamp requirements
  RFC 3161:         Exceeds (multi-validator vs single authority)
  ISO/IEC 18014:    UTC-traceable via GPS + atomic clock sources
  US ESIGN Act:     Validator signatures qualify as electronic signatures

═══════════════════════════════════════════════════════════════
Saved to: proof.json

# Verify a proof package. Offline, this only re-checks the package is internally
# consistent (the hash matches what the package claims). To confirm the entry is
# actually on-chain it re-reads the ledger + block, which needs an API key.
$ clockchain prove verify proof.json --online
Consensus + ledger layers verified against live chain. Layers 1-3 not independently checkable (no public endpoint).
```

#### MCP Tools

| Tool | Description |
|---|---|
| `generate_proof` | Generate a full 5-layer evidence package for a log entry. Returns structured JSON with all verification layers. |
| `verify_proof` | Verify a previously generated proof package against the live ledger. |
| `generate_agent_proof` | Generate a proof covering an agent's entire action trail (all logs under a DID). |

### Time-Conditional Smart Contracts (Triggers)

> **Blocked on the public API.** `GET /schedule` returns 404 on `node.clockchain.network` (probed 2026-06-02). It exists only on a raw node port per the internal docs. This whole section is a design target, not a P1 deliverable - it cannot ship until the gateway proxies `/schedule`. The `--min-trust`/`--min-participation` flags below are also inferred from the audit doc; the documented `/schedule` URL only takes `privateKey`, `smartContractClassName`, `smartContractFileName`, `scheduleOn`, so the threshold parameters need confirmation from the D4 team.

Clockchain's unique primitive: smart contracts that execute when consensus time crosses a threshold. The trigger condition is immutably encoded at deployment.

#### CLI Commands

| Command | What it does | Priority |
|---|---|---|
| `clockchain trigger schedule` | Schedule a smart contract with time + trust conditions | P1 |
| `clockchain trigger status <address>` | Check trigger status and deployment conditions | P1 |
| `clockchain trigger verify <address>` | Verify trigger executed at correct time with correct trust | P1 |

```bash
# Schedule a contract: "release escrow when time > 2026-07-01 AND trust > 67%"
$ clockchain trigger schedule \
    --contract-class EscrowRelease \
    --contract-file EscrowRelease \
    --schedule-on "2026-07-01T00:00:00" \
    --min-trust 67 \
    --min-participation 50 \
    --private-key <KEY>

Trigger Scheduled
Contract:        EscrowRelease
Fires When:      time ≥ 2026-07-01T00:00:00Z
                 AND trust ≥ 67%
                 AND participation ≥ 50%
Status:          Waiting

# After trigger fires:
$ clockchain trigger verify 0xA3F...
Contract:        0xA3F...
Trigger Condition: time ≥ 2026-07-01T00:00:00Z
Actual Time:     2026-07-01T00:00:00.218Z
Trust at Fire:   72.3% (threshold: 67%)
Participation:   85.0% (threshold: 50%)
Block:           4821004
Verdict:         Trigger executed correctly. Condition met.
```

#### MCP Tools

| Tool | Description |
|---|---|
| `schedule_trigger` | Schedule a time-conditional smart contract. Agent can set up automated actions that fire at a future consensus time. |
| `get_trigger_status` | Check if a trigger has fired, is waiting, or was discarded. |
| `verify_trigger` | Prove a trigger executed at the correct time with correct trust thresholds. |

### Time Oracle (Shared Primitive)

The foundation both products build on.

#### CLI Commands

| Command | What it does | Priority |
|---|---|---|
| `clockchain time` | Current consensus time + block height | P0 |
| `clockchain timestamp` | Full node status (Marzullo state, drift, votes, participation) | P0 |
| `clockchain block <height>` | Block details | P0 |
| `clockchain block validate <height>` | Validation data (votes, trust %) for a block | P1 |
| `clockchain benchmark` | Compare consensus time against independent sources (NTP, Google NTP, NIST, TAI) | P1 |
| `clockchain watch` | Stream time updates | P1 |
| `clockchain status` | API key status, quota, plan | P0 |

```bash
$ clockchain time
Block Height:  2734412
Block Time:    2026-06-02T01:04:52.154Z
Server Time:   2026-06-02T01:04:54.206Z

$ clockchain timestamp
Node Status:          Synced
Block Height:         2734446
Marzullo Time:        02-06-2026_01:05:28:090
System Time:          02-06-2026_01:05:28:000
Time Difference:      90ms
Consented Offset:     -999.0 (insufficient nodes for consensus)
Positive Votes:       0.0%
Negative Votes:       0.0%
Node Participation:   0.0%
Total Nodes:          1

$ clockchain benchmark
Source                    Time                          Drift from Consensus
D4 Clockchain (consensus) 2026-06-02T01:05:28.090Z      -
Your System               2026-06-02T01:05:28.000Z      -90ms
UTC (NICT Japan)          2026-06-02T01:05:28.050Z      -40ms
Google NTP                2026-06-02T01:05:28.020Z      -70ms
NIST                      2026-06-02T01:05:28.045Z      -45ms
TAI                       2026-06-02T01:06:05.090Z      +37.000s (TAI = UTC+37s)
```

#### MCP Tools

| Tool | Description |
|---|---|
| `get_time` | Current consensus time. Agents use this as their authoritative clock. |
| `get_timestamp` | Full node status. Agents check this to verify network health before trusting timestamps. |
| `get_block` | Block details by height. |
| `get_validation` | Validation data for a block (votes, trust %, participation). |

---

## Phase 1: @clockchain/core (Week 1-2)

The shared foundation. Every CLI command and MCP tool calls into this.

### API Client

| Method | Endpoint | Notes |
|---|---|---|
| `getTime()` | `GET /api/time/time` | Read-only |
| `getTimestamp()` | `GET /api/time/timestamp` | Read-only |
| `getBlock(height)` | `GET /api/time/block?height={h}` | Read-only |
| `getValidationBlock(height)` | `GET /getValidationBlock/{h}` | Follows faultHandling redirect |
| `log(entry)` | `POST /log` | Write. blockHeight initially null |
| `searchAsset(clientId, assetRef)` | `GET /searchAsset?...` | Read-only |
| `getLedgerEntry(ledgerId)` | `GET /ledger/{ledgerId}` | Read-only |
| `schedule(params)` | `GET /schedule?...` | **Not on gateway (404).** Blocked - see Verified API Surface |

**Envelope handling (confirmed by probe):** `/api/time/*` returns `{success, data, meta}` - unwrap `.data`. `/searchAsset` and `/getValidationBlock` return raw bodies (a bare array and a bare object respectively) with no envelope. The client must normalize per-endpoint; do not assume a uniform `{success,data}` wrapper. Types below describe the unwrapped result.

### DID Operations (Product A)

DID operations build on top of the log and smart contract APIs. A DID mint is a specific log entry type with a defined schema:

```typescript
interface AgentDID {
  did: string                    // did:clockchain:agent:{uuid}
  name: string
  owner: string
  capabilities: string[]
  mintedAt: string               // consensus timestamp
  mintBlock: number
  mintLedgerId: string           // log entry for the mint event
  status: "active" | "revoked"
  revokedAt?: string
  revokeBlock?: number
}

interface MintAgentParams {
  name: string
  capabilities: string[]
  owner: string
}

interface LogActionParams {
  did: string                    // agent's DID
  assetHash: string
  assetReferenceId: string
  hashType?: string              // default: "SHA-256". Valid: MD5 | SHA-1 | SHA-2 | SHA-256 (hyphenated - confirmed by live API)
  versionNumber?: number
  additionalInfo?: string
}
```

### Evidence Package (Product A+B)

Layers 1-3 are descriptive (no public endpoint backs them yet); layers 4-5 carry real on-chain data. The types reflect that honestly.

```typescript
type LayerStatus = "verified" | "described_only" | "not_independently_verifiable"

interface EvidencePackage {
  layer1_election: { method: "VRF"; status: LayerStatus; note: string }
  layer2_sources: { sources: string[]; status: LayerStatus; note: string }
  layer3_computation: { algorithm: "Marzullo"; threshold_ms: number; status: LayerStatus }
  layer4_consensus: {           // real, from getValidationBlock
    positiveVotes: number
    negativeVotes: number
    totalNodes: number
    trustPercentage: number
    participationPercentage: number
    consensusTime: string
    note?: string               // set when node count is too low to be meaningful
  }
  layer5_ledger: {              // real, from ledger + block
    blockHeight: number
    blockTime: string
    proposerAddress: string
    eventHash: string
  }
  verification: { hashMatch: boolean }
  standards_target: { note: string }   // aspiration per the audit doc, not a per-entry claim
}
```

### Utilities

- `computeHash(input: string | Buffer): string` - SHA-256
- `hashFile(path: string): Promise<string>` - SHA-256 of file contents
- `generateDID(): string` - create a `did:clockchain:agent:{uuid}`
- `buildEvidencePackage(ledgerId: string): Promise<EvidencePackage>` - composites log entry + block + validation; layers 4-5 real, 1-3 descriptive
- `waitForConfirmation(ledgerId: string, timeoutMs?: number): Promise<LogResponse>` - poll until blockHeight is non-null

### Configuration

```typescript
interface ClockchainConfig {
  apiKey: string
  clientId: string
  walletId: string
  endpoint: string              // default: https://node.clockchain.network
  nodeEndpoint?: string         // direct node IP:port
  defaultDid?: string           // agent's own DID, used as default for log operations
}
```

Resolution order: constructor args > env vars > `~/.config/clockchain/config.toml`.

### Rate Limit Handling

- Track 50 hits/min IP limit locally
- Detect 429 responses and surface cooldown (100s dead value)
- Track plan quota (e.g., 11/1000 on FREE plan)
- Expose `RateLimitState` for CLI/MCP to display warnings

### Testing

#### Unit Tests (no network, every commit)

```
tests/unit/
├── client.test.ts          # API client methods return correct types
├── did.test.ts             # DID generation, mint/verify/revoke schemas
├── evidence.test.ts        # 5-layer evidence package assembly
├── rate-limiter.test.ts    # 429 detection, cooldown, quota tracking
├── config.test.ts          # Resolution order: args > env > file
├── hash.test.ts            # computeHash, hashFile produce correct SHA-256
└── wait.test.ts            # waitForConfirmation polls correctly
```

| Test | What it proves |
|---|---|
| `getTime()` returns `TimeResponse` | Type mapping from raw API JSON |
| `getTimestamp()` handles `-999.0` offset | Sentinel value surfaces as "insufficient nodes" |
| `log()` returns `blockHeight: null` | Async write model handled |
| `getValidationBlock()` follows `faultHandling` | Redirect pointer works |
| `generateDID()` produces valid format | `did:clockchain:agent:{uuid}` |
| `buildEvidencePackage()` assembles all 5 layers | Composites log + block + validation correctly |
| Rate limiter tracks 50/min | 51st call returns warning |
| Config resolution order | Constructor > env > file |
| `computeHash("hello")` matches known vector | SHA-256 correctness |

```bash
npm test                    # ~2s
```

#### Integration Tests (testnet, manual)

Gated behind `CLOCKCHAIN_INTEGRATION=true`.

| Test | Quota cost |
|---|---|
| `getTime()` returns current data | 1 |
| `getBlock(1)` matches genesis (2026-04-30) | 1 |
| Log roundtrip: `log()` -> `getLedgerEntry()` -> hash matches | 3-5 |
| Search after log: `log()` -> `searchAsset()` finds it | 3 |
| Evidence package for a confirmed log entry | 3-4 |

```bash
CLOCKCHAIN_INTEGRATION=true npm run test:integration    # ~30s, ~15 requests
```

#### Contract Tests (API shape stability)

Snapshot diffs in `tests/contracts/*.snap.json`. Run weekly or after D4 node updates.

```bash
npm run test:contract       # ~5s
```

---

## Phase 2: @clockchain/cli (Week 2-3)

### Tech Stack

- `commander` for arg parsing
- `@clockchain/core` for all operations
- `chalk` + `ora` for output
- Distributed as `@clockchain/cli` on npm

### Command Priority

**P0 (ship first - the TTFL path):**

```bash
# 1. Auth
$ npx @clockchain/cli auth login --api-key <KEY> --client-id <ID> --wallet-id <WID>

# 2. Mint an agent identity
$ npx @clockchain/cli identity mint --name "my-agent" --capabilities "read,write"

# 3. Log an action
$ npx @clockchain/cli log action --did did:clockchain:agent:... --asset-ref "first-action" \
    --hash sha256:abc123... --wait

# 4. Generate a proof
$ npx @clockchain/cli prove <ledgerId>

# 5. Query time
$ npx @clockchain/cli time
```

This is the 5-minute flow. Developer goes from `npx` to a minted agent identity with a logged action and an evidence package.

**P1 (ship next):**
- `identity verify`, `identity revoke`, `identity list`
- `log search`, `log get`
- `prove verify`, `prove agent`
- `trigger schedule`, `trigger status`, `trigger verify`
- `benchmark`, `block validate`, `watch`

**P2 (ship later):**
- `diff`, shell completions, CSV output

### Global Flags

| Flag | Short | Description |
|---|---|---|
| `--json` | `-j` | JSON output |
| `--quiet` | `-q` | Values only, no headers |
| `--field <name>` | `-f` | Single field output |
| `--api-key <key>` | `-k` | Override API key |
| `--did <did>` | `-d` | Override default agent DID |
| `--wait` | `-w` | Poll until blockchain confirmation |
| `--endpoint <url>` | `-e` | Override base URL |
| `--verbose` | `-v` | Show request/response details |

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error |
| 2 | Authentication error |
| 3 | Rate limit exceeded |
| 4 | Network error |
| 5 | Invalid arguments |
| 6 | Node not synced |
| 7 | Blockchain write pending (timeout waiting for confirmation) |
| 8 | Hash mismatch (verification failed) |
| 9 | DID not found or revoked |

### Testing

#### Unit Tests (no network)

```
tests/unit/
├── commands/
│   ├── identity.test.ts    # mint/verify/revoke arg parsing and output
│   ├── log.test.ts         # action logging, --did flag, --wait polling
│   ├── prove.test.ts       # evidence package formatting (all 5 layers)
│   ├── time.test.ts        # output formats (text, json, quiet, field)
│   └── auth.test.ts        # config file writing
├── formatting.test.ts      # table rendering, evidence package display
└── exit-codes.test.ts      # correct code per error type
```

| Test | What it proves |
|---|---|
| `identity mint --json` | JSON output includes DID, block, timestamp, trust |
| `log action --wait` | Polls until blockHeight confirmed |
| `prove <id> --output file.json` | Writes valid evidence package to disk |
| `time --field block_height` | Raw value only |
| Missing API key -> exit 2 | Correct exit code |
| Revoked DID -> exit 9 | Correct exit code |

```bash
npm test                    # ~1s
```

#### Smoke Tests (testnet)

```typescript
test("TTFL < 5 minutes", async () => {
  const start = Date.now()
  await run("clockchain auth login ...")
  await run("clockchain identity mint --name smoke-test --capabilities read")
  await run("clockchain log action --did $DID --asset-ref smoke --hash sha256:abc --wait")
  await run("clockchain prove $LEDGER_ID")
  expect((Date.now() - start) / 1000).toBeLessThan(300)
})
```

```bash
CLOCKCHAIN_INTEGRATION=true npm run test:smoke    # ~30s, ~10 requests
```

---

## Phase 3: @clockchain/mcp-server (Week 3-4)

### Option 1: npm Package (stdio transport)

```json
{
  "mcpServers": {
    "clockchain": {
      "command": "npx",
      "args": ["-y", "@clockchain/mcp-server"],
      "env": {
        "CLOCKCHAIN_API_KEY": "<key>",
        "CLOCKCHAIN_CLIENT_ID": "<client_id>",
        "CLOCKCHAIN_WALLET_ID": "<wallet_id>"
      }
    }
  }
}
```

#### Tools

**Identity (Product A):**

| Tool | Schema | Priority |
|---|---|---|
| `mint_agent_identity` | `{name, capabilities[], owner}` -> `{did, block, timestamp, trust}` | P0 |
| `verify_agent_identity` | `{did}` -> `{valid, owner, capabilities, mintedAt, revoked}` | P0 |
| `revoke_agent_identity` | `{did}` -> `{revoked, revokeBlock, revokeTime}` | P1 |
| `get_agent_identity` | `{did}` -> full DID record | P1 |

**Logging (Product B):**

| Tool | Schema | Priority |
|---|---|---|
| `log_action` | `{did, asset_hash, asset_reference_id, info?}` -> `{ledger_id, block_height}` | P0 |
| `search_actions` | `{did?, asset_reference_id?}` -> `[{ledger_id, block, timestamp, ref}]` | P0 |
| `get_log_entry` | `{ledger_id}` -> full log record | P0 |

**Proofs (Product A+B):**

| Tool | Schema | Priority |
|---|---|---|
| `generate_proof` | `{ledger_id}` -> `EvidencePackage` (all 5 layers) | P0 |
| `verify_proof` | `{evidence_package}` -> `{valid, layers_checked}` | P1 |
| `generate_agent_proof` | `{did, since?, until?}` -> proof of entire action trail | P1 |

**Triggers:**

| Tool | Schema | Priority |
|---|---|---|
| `schedule_trigger` | `{contract_class, schedule_on, min_trust, min_participation}` -> `{status}` | P1 |
| `get_trigger_status` | `{contract_address}` -> `{status, fired_at?, trust_at_fire?}` | P1 |
| `verify_trigger` | `{contract_address}` -> trigger execution proof | P2 |

**Time Oracle:**

| Tool | Schema | Priority |
|---|---|---|
| `get_time` | `{}` -> `{block_height, block_time, server_time}` | P0 |
| `get_timestamp` | `{}` -> full Marzullo state | P0 |
| `get_block` | `{height}` -> `{block_height, proposer, block_time}` | P0 |
| `get_validation` | `{height}` -> `{votes, trust%, participation%}` | P1 |

#### Resources

| URI | Content | Priority |
|---|---|---|
| `clockchain://status` | API key status, plan, quota, node health | P1 |
| `clockchain://agent/{did}` | Full agent identity record + action count | P1 |
| `clockchain://network` | Chain height, node count, avg block time, consensus state | P2 |

#### Prompts

| Prompt | What it guides | Priority |
|---|---|---|
| `onboard_agent` | Walk an AI agent through: mint DID -> log first action -> generate proof. This IS the TTFL flow for agents. | P0 |
| `timestamp_document` | Guide user through hashing + logging + proof for a document. | P1 |
| `audit_agent` | Search an agent's action trail and generate a comprehensive proof. | P1 |

The `onboard_agent` prompt is the Product B activation flow:

```
You are a new AI agent connecting to Clockchain for the first time.

Steps:
1. Call mint_agent_identity with your name and capabilities
2. Save the returned DID - this is your on-chain identity
3. Call log_action with your DID to record your first action
4. Call generate_proof to see your evidence package (consensus + ledger layers)
5. You now have a verifiable identity and an auditable action trail

Every significant action you take should be logged via log_action.
Other agents can verify your identity via verify_agent_identity.
```

#### Testing

##### Unit Tests (no network)

| Test | What it proves |
|---|---|
| Server exposes all tools on `tools/list` | Identity + logging + proof + trigger + time tools registered |
| `mint_agent_identity` validates required fields | Missing `name` returns `isError: true` |
| `log_action` requires `did` | Agent must have an identity before logging |
| `generate_proof` returns all 5 layers | Evidence package is complete |
| `log_action` surfaces `blockHeight: null` | Agent sees async state |
| `verify_agent_identity` on revoked DID | Returns `{valid: false, revoked: true}` |
| Rate limit -> `isError` with retry guidance | Actionable error for agent |

```bash
npm test                    # ~1s
```

##### MCP Protocol Tests (stdio, no network)

```typescript
test("agent onboarding flow via MCP", async () => {
  const client = await connectToMockServer()

  // Mint identity
  const mint = await client.callTool("mint_agent_identity", {
    name: "test-agent", capabilities: ["read"], owner: "test@test.com"
  })
  const did = JSON.parse(mint.content[0].text).did
  expect(did).toMatch(/^did:clockchain:agent:/)

  // Log action
  const log = await client.callTool("log_action", {
    did, asset_hash: "sha256:abc123", asset_reference_id: "test-action"
  })
  expect(JSON.parse(log.content[0].text).ledger_id).toBeTruthy()

  await client.close()
})
```

```bash
npm run test:protocol       # ~3s
```

##### Integration Tests (testnet, through MCP)

Full stack: MCP client -> server -> core -> live D4 node.

```bash
CLOCKCHAIN_INTEGRATION=true npm run test:integration    # ~15s, ~10 requests
```

##### Manual QA Checklist

| Client | Test | Pass? |
|---|---|---|
| Claude Code | Add config, call `mint_agent_identity`, call `log_action`, call `generate_proof` | |
| Claude Code | Use `onboard_agent` prompt to walk through full flow | |
| Cursor | Add config, call `get_time` and `log_action` | |
| ChatGPT Desktop | Add as MCP server, verify tool discovery | |

---

### Option 2: Remote MCP Server (Streamable HTTP)

Ship after Option 1 proves demand.

#### Hosting: ECS Fargate on AWS

```
mcp.clockchain.network
        │
        ▼
┌───────────────────┐
│  AWS ALB           │  TLS termination, path routing
│  /mcp/* → ECS     │
│  /api/* → D4 Node │
└───────┬───────────┘
        ▼
┌───────────────────┐
│  ECS Fargate       │  @clockchain/mcp-server
│  256 MB / 0.25 CPU │  StreamableHTTPServerTransport
└───────┬───────────┘  Same code as Option 1
        ▼
   node.clockchain.network
```

Same code as Option 1. Only the transport differs:

```typescript
const transport = process.env.MCP_TRANSPORT === "http"
  ? new StreamableHTTPServerTransport({ port: 3000 })
  : new StdioServerTransport()
```

Estimated cost: ~$20/month (Fargate + shared ALB).

#### Deployment

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY dist/ ./dist/
ENV MCP_TRANSPORT=http
ENV MCP_PORT=3000
EXPOSE 3000
CMD ["node", "dist/server.js"]
```

#### Testing (Remote)

| Test | What it checks |
|---|---|
| `curl /health` | `{"status": "ok"}` |
| MCP handshake via HTTP | Tools listed, capabilities correct |
| `get_time` via HTTP | Returns live block height |
| No `x-api-key` header | 401 |
| Invalid key | 401 |
| 10 concurrent clients, 5 calls each | All succeed, p99 < 2s |

```bash
CLOCKCHAIN_API_KEY=<key> npm run test:remote    # ~5s
```

---

## Phase 4: Documentation & Developer Experience (Week 4-5)

### Developer Portal

- **Quickstart (CLI)**: `npx` -> auth -> mint identity -> log action -> prove. Under 5 minutes.
- **Agent Onboarding (MCP)**: one-copy-paste config for Claude Code / Cursor / ChatGPT. Agent mints its own DID on first run.
- **LangChain Integration Guide**: `ClockchainCallback` that logs every chain step to Clockchain.
- **Evidence Package Guide**: what each layer means, how to present in court.
- **API Reference**: generated from `@clockchain/core` types.

### MCP Registry

Register `@clockchain/mcp-server` on mcp.run, glama.ai, smithery.ai. Listing description emphasizes: "Give your AI agent a verifiable on-chain identity and a timestamped, tamper-evident action trail."

---

## Phase 5: Subnet Integration (Q3 2026, gated on backend)

When subnets go live, enterprise agents log to dedicated subnets:

```bash
clockchain log action --did did:clockchain:agent:... --subnet <SUBNET_ID> --asset-ref "..."
```

Mainnet sees only the state root per settlement cycle. Agent action trails are private to the customer's subnet but verifiable via the mainnet anchor.

New tools: `log_to_subnet`, `get_subnet_status`, `verify_subnet_anchor`.

---

## Test Strategy Summary

### Test Pyramid

```
              ┌──────────┐
              │  Manual  │  QA checklist per client
             ┌┴──────────┴┐
             │ Integration │  Live testnet, full stack
            ┌┴────────────┴┐
            │   Protocol    │  MCP handshake, stdio, no network
           ┌┴──────────────┴┐
           │   Smoke (CLI)   │  Spawn binary, assert stdout/exit
          ┌┴────────────────┴┐
          │    Unit Tests     │  Mocked core, fast, every commit
          └──────────────────┘
```

### Commands

| Command | Network | Speed | When |
|---|---|---|---|
| `npm test` | No | ~2s | Every commit, CI |
| `npm run test:protocol` | No | ~3s | Every commit, CI |
| `npm run test:smoke` | Yes | ~30s | Pre-release |
| `npm run test:integration` | Yes | ~15s | Pre-release |
| `npm run test:remote` | Yes | ~5s | Post-deploy |
| `npm run test:contract` | Yes | ~5s | Weekly |

### CI (GitHub Actions)

```yaml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci
      - run: npm test
      - run: npm run test:protocol
```

### Testnet Quota

FREE plan: 1,000 requests. ~50 requests per release cycle. Supports ~20 releases before renewal.

---

## Timeline

| Phase | What | When | Dependency |
|---|---|---|---|
| 1 | `@clockchain/core` (API client + DID ops + evidence package) | Week 1-2 | None |
| 2 | `@clockchain/cli` (identity, logging, proofs, time) | Week 2-3 | Phase 1 |
| 3a | `@clockchain/mcp-server` (stdio, npm) | Week 3-4 | Phase 1 |
| 3b | `@clockchain/mcp-server` (remote, ECS) | Week 4-5 | Phase 3a |
| 4 | Docs, MCP registry, LangChain guide | Week 4-5 | Phase 2, 3a |
| 5 | Subnet integration | Q3 2026 | Backend APIs |

Phases 2 and 3a run in parallel once Phase 1 ships.

## Success Metrics

| Metric | Target | Source |
|---|---|---|
| TTFL (time to first log) | < 5 minutes | CLI smoke test |
| Agent TTFL (MCP) | < 2 minutes | Copy config -> agent mints DID -> logs action |
| DID mints on testnet | 50+ by Week 8 | On-chain count |
| npm weekly downloads | 100+ by Week 8 | npm stats |
| MCP registry listing | Live by Week 5 | mcp.run, glama.ai |
| LangChain integration | Working callback | Integration test |
| External developer testers | 5 by Week 4 | Assessment target |

---

## Appendix A: MCP Server Detail Specification

Everything needed to build `@clockchain/mcp-server`. Tool definitions are listed in the order an agent encounters them during onboarding.

### Server Capabilities

```typescript
const server = new McpServer({
  name: "clockchain",
  version: "1.0.0",
  capabilities: {
    tools: {},
    resources: {},
    prompts: {}
  }
})
```

### Tool Definitions

#### `mint_agent_identity`

The first tool an agent calls. Creates an on-chain DID (Birth Certificate).

```typescript
server.tool(
  "mint_agent_identity",
  {
    name: {
      type: "string" as const,
      description: "Human-readable name for this agent (e.g., 'investor-update-agent', 'code-reviewer')."
    },
    capabilities: {
      type: "array" as const,
      items: { type: "string" as const },
      description: "List of capabilities this agent declares (e.g., ['draft', 'send-email', 'read-metrics']). Stored on-chain as part of the identity."
    },
    owner: {
      type: "string" as const,
      description: "Email or identifier of the human owner responsible for this agent."
    }
  },
  async ({ name, capabilities, owner }) => {
    const did = generateDID()
    const logEntry = await core.log({
      clientId: config.clientId,
      walletId: config.walletId,
      assetReferenceId: `did:mint:${did}`,
      assetHash: computeHash(JSON.stringify({ did, name, capabilities, owner })),
      hashType: "SHA-256",
      versionNumber: 1,
      additionalInfo: JSON.stringify({ type: "did:mint", did, name, capabilities, owner })
    })

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          did,
          name,
          owner,
          capabilities,
          ledger_id: logEntry.ledgerId,
          block_height: logEntry.blockHeight,
          minted_at: new Date().toISOString(),
          status: "active"
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance in description:**
> "Mint a new on-chain identity (DID) for an AI agent. Call this once when the agent is first deployed. The returned DID is the agent's permanent identifier on the Clockchain ledger - save it. All subsequent log_action calls require this DID. The identity is immutable once minted; use revoke_agent_identity to decommission."

---

#### `verify_agent_identity`

Used before trusting another agent in an agent-to-agent interaction.

```typescript
server.tool(
  "verify_agent_identity",
  {
    did: {
      type: "string" as const,
      description: "The DID to verify (format: did:clockchain:agent:{uuid})."
    }
  },
  async ({ did }) => {
    const results = await core.searchAsset(config.clientId, `did:mint:${did}`)
    if (!results || results.length === 0) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ valid: false, reason: "DID not found on ledger" })
        }]
      }
    }

    const mintEntry = results[0]
    const revokeResults = await core.searchAsset(config.clientId, `did:revoke:${did}`)
    const revoked = revokeResults && revokeResults.length > 0

    const identity = JSON.parse(mintEntry.additionalInfo)
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          valid: !revoked,
          did: identity.did,
          name: identity.name,
          owner: identity.owner,
          capabilities: identity.capabilities,
          minted_at: mintEntry.blockHeight ? "confirmed" : "pending",
          mint_block: mintEntry.blockHeight,
          revoked,
          revoked_at: revoked ? revokeResults[0].blockHeight : null
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Check if another agent's DID is valid and unrevoked on the Clockchain ledger. Call this before trusting data or actions from another agent. Returns the agent's declared capabilities and owner. A revoked DID means the agent has been decommissioned - do not trust it."

---

#### `revoke_agent_identity`

```typescript
server.tool(
  "revoke_agent_identity",
  {
    did: {
      type: "string" as const,
      description: "The DID to revoke. Must be owned by the current client."
    },
    reason: {
      type: "string" as const,
      description: "Reason for revocation (e.g., 'decommissioned', 'compromised', 'replaced')."
    }
  },
  async ({ did, reason }) => {
    const logEntry = await core.log({
      clientId: config.clientId,
      walletId: config.walletId,
      assetReferenceId: `did:revoke:${did}`,
      assetHash: computeHash(JSON.stringify({ did, reason, revokedAt: new Date().toISOString() })),
      hashType: "SHA-256",
      versionNumber: 1,
      additionalInfo: JSON.stringify({ type: "did:revoke", did, reason })
    })

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          did,
          revoked: true,
          reason,
          revoke_ledger_id: logEntry.ledgerId,
          revoke_block: logEntry.blockHeight
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Permanently revoke an agent's DID. This is irreversible - the DID will show as revoked on all future verify_agent_identity calls. Use when an agent is decommissioned or compromised. Requires the revoking client to be the DID's owner."

---

#### `log_action`

The core Product B tool. Every significant agent action should be logged.

```typescript
server.tool(
  "log_action",
  {
    did: {
      type: "string" as const,
      description: "The agent's DID (from mint_agent_identity). Required - agents must have an identity before logging."
    },
    asset_hash: {
      type: "string" as const,
      description: "SHA-256 hash of the action content or output. Compute this before calling."
    },
    asset_reference_id: {
      type: "string" as const,
      description: "Human-readable reference for this action (e.g., 'investor-update-2026-06-02', 'code-review-pr-42'). Used for searching later."
    },
    hash_type: {
      type: "string" as const,
      description: "Hash algorithm. Valid: MD5, SHA-1, SHA-2, SHA-256 (hyphenated). Default: SHA-256."
    },
    version_number: {
      type: "number" as const,
      description: "Version number. Default: 1. Increment for updated versions of the same action."
    },
    additional_info: {
      type: "string" as const,
      description: "Human-readable description of the action. Stored on-chain alongside the hash."
    }
  },
  async ({ did, asset_hash, asset_reference_id, hash_type, version_number, additional_info }) => {
    const logEntry = await core.log({
      clientId: config.clientId,
      walletId: config.walletId,
      assetReferenceId: asset_reference_id,
      assetHash: asset_hash,
      hashType: hash_type || "SHA-256",
      versionNumber: version_number || 1,
      additionalInfo: JSON.stringify({
        did,
        description: additional_info,
        logged_at: new Date().toISOString()
      })
    })

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          ledger_id: logEntry.ledgerId,
          did,
          asset_reference_id,
          asset_hash,
          block_height: logEntry.blockHeight,
          status: logEntry.blockHeight ? "confirmed" : "pending",
          note: logEntry.blockHeight
            ? undefined
            : "Block height is null - blockchain write is async (~1s). Call get_log_entry with this ledger_id to check confirmation."
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Log an agent action to the Clockchain with a tamper-proof consensus timestamp. Requires a DID from mint_agent_identity. The action is recorded immutably - it cannot be altered or deleted. The block_height will initially be null (the blockchain write is asynchronous, ~1 second). Call get_log_entry with the returned ledger_id after a few seconds to confirm. Use this after every significant action: generating a document, sending a message, making a decision, calling an external API."

**Required fields:** `did`, `asset_hash`, `asset_reference_id`

---

#### `search_actions`

```typescript
server.tool(
  "search_actions",
  {
    asset_reference_id: {
      type: "string" as const,
      description: "Search by asset reference ID (e.g., 'investor-update-2026-06-02')."
    }
  },
  async ({ asset_reference_id }) => {
    const results = await core.searchAsset(config.clientId, asset_reference_id)
    return {
      content: [{
        type: "text",
        text: JSON.stringify(results, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Search for logged actions by asset reference ID. Returns all matching log entries for this client, including ledger IDs, block heights, and timestamps. Use to find a previously logged action, check if a specific action was recorded, or verify that a blockchain confirmation has arrived (block_height non-null = confirmed)."

---

#### `get_log_entry`

```typescript
server.tool(
  "get_log_entry",
  {
    ledger_id: {
      type: "string" as const,
      description: "The ledger ID returned from log_action."
    }
  },
  async ({ ledger_id }) => {
    const entry = await core.getLedgerEntry(ledger_id)
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          ...entry,
          confirmed: entry.blockHeight !== null,
          note: entry.blockHeight
            ? undefined
            : "Not yet confirmed on chain. The leader writes approximately every 1 second. Try again shortly."
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Retrieve a specific log entry by its ledger ID. Use this to check blockchain confirmation status after calling log_action - a non-null block_height means the action is permanently recorded on chain. Also use when building verification proofs."

---

#### `generate_proof`

Composites a log entry, its block, and its validation data into an evidence package. Three API calls: `getLedgerEntry`, `getBlock`, `getValidationBlock` - plus one `getTimestamp` for node count. Fetch each once.

Layers 4 and 5 carry real on-chain data. Layers 1-3 are descriptive only - no public endpoint returns the VRF election proof or per-validator readings, so they describe the protocol rather than prove it for this specific entry. The code says so explicitly rather than emitting confident placeholders.

```typescript
server.tool(
  "generate_proof",
  {
    ledger_id: {
      type: "string" as const,
      description: "Ledger ID of a confirmed log entry (block_height must be non-null)."
    }
  },
  async ({ ledger_id }) => {
    const entry = await core.getLedgerEntry(ledger_id)
    if (!entry.blockHeight) {
      return {
        isError: true,
        content: [{
          type: "text",
          text: "Cannot generate proof: log entry not yet confirmed on chain (block_height is null). Wait ~2s and retry."
        }]
      }
    }

    // Fetch each input exactly once.
    const [block, validation, ts] = await Promise.all([
      core.getBlock(entry.blockHeight),
      core.getValidationBlock(parseInt(entry.blockHeight)),
      core.getTimestamp()
    ])
    const vb = validation.validationBlockData
    const totalNodes = parseInt(ts.totalNodes)

    const evidence: EvidencePackage = {
      // Layers 1-3: protocol description, NOT per-entry proof. No endpoint
      // exposes the election proof or raw readings yet.
      layer1_election: {
        method: "VRF",
        status: "not_independently_verifiable",
        note: "The protocol selects validators by VRF, but the election proof for this block is not exposed by the public API."
      },
      layer2_sources: {
        sources: ["NTP", "Google NTP", "NIST"],
        status: "not_independently_verifiable",
        note: "Per-validator readings are recorded by the protocol but not returned by any public endpoint."
      },
      layer3_computation: {
        algorithm: "Marzullo",
        threshold_ms: 1500,
        status: "described_only"
      },
      // Layers 4-5: real on-chain data for THIS entry.
      layer4_consensus: {
        positiveVotes: parseInt(vb?.positiveVotes || "0"),
        negativeVotes: parseInt(vb?.negativeVotes || "0"),
        totalNodes,
        trustPercentage: parseFloat(vb?.["Trust value percentage"] || "0"),
        participationPercentage: parseFloat(vb?.["Node participation percentage"] || "0"),
        consensusTime: block.blockTime,
        note: totalNodes < 3
          ? "Single/low node count - consensus figures are not meaningful on the current testnet."
          : undefined
      },
      layer5_ledger: {
        blockHeight: parseInt(entry.blockHeight),
        blockTime: block.blockTime,
        proposerAddress: block.proposerAddress,
        eventHash: entry.assetHash
      },
      verification: {
        hashMatch: true   // caller compares entry.assetHash to the original content
      },
      standards_target: {
        note: "Per the Clockchain Audit & Proof System, a full multi-validator proof is designed to meet EU eIDAS / RFC 3161 / ISO-IEC 18014 / US ESIGN Act. This package reaches that bar only once layers 1-3 are exposed and the network runs a real validator set."
      }
    }

    return {
      content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
    }
  }
)
```

**Agent guidance:**
> "Generate an evidence package for a confirmed log entry. Layers 4 (validator consensus: votes, trust %, participation %) and 5 (ledger: block, proposer, time, hash) contain real on-chain data. Layers 1-3 describe the protocol but are not independently verifiable through the public API yet. On the current single-node testnet, consensus figures will be zero - that is expected, not an error. The entry must be confirmed (block_height non-null) before a proof can be generated."

---

#### `get_time`

```typescript
server.tool(
  "get_time",
  {},
  async () => {
    const time = await core.getTime()
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          block_height: time.latestBlockHeight,
          block_time: time.latestBlockTime,
          server_time: new Date().toISOString()
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Get the current blockchain consensus time and latest block height from the Clockchain decentralized time oracle. This is the authoritative clock for the network - it represents the Marzullo-algorithm agreed time across GPS satellites, atomic clocks, and NTP servers queried by independent validators. Use this as the ground truth for time-sensitive decisions."

---

#### `get_timestamp`

```typescript
server.tool(
  "get_timestamp",
  {},
  async () => {
    const ts = await core.getTimestamp()
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          node_status: ts.nodeStatus,
          block_height: ts.blockHeight,
          marzullo_time: ts.madMarzulloTime,
          system_time: ts.systemTime,
          time_difference_ms: parseInt(ts.AbsTimeDifference),
          consented_offset: parseFloat(ts.consentedOffset),
          consented_offset_note: parseFloat(ts.consentedOffset) === -999.0
            ? "Sentinel value: insufficient nodes for Marzullo consensus (testnet has 1 node, minimum 3 needed)"
            : undefined,
          positive_votes_pct: parseFloat(ts.positiveVotesPercentage),
          negative_votes_pct: parseFloat(ts.negativeVotesPercentage),
          node_participation_pct: parseFloat(ts["nodeParticipation%"]),
          total_nodes: parseInt(ts.totalNodes)
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Get detailed node status including Marzullo consensus state. Returns: sync status, consensus time, system time, clock drift, validator vote percentages, and node participation. A consented_offset of -999.0 is a sentinel meaning insufficient nodes for consensus (testnet). Check node_status is 'Synced' before trusting timestamps. Use this to verify network health before critical operations."

---

#### `get_block`

```typescript
server.tool(
  "get_block",
  {
    height: {
      type: "string" as const,
      description: "Block height number, or 'latest' for the most recent block."
    }
  },
  async ({ height }) => {
    let blockHeight = height
    if (height === "latest") {
      const time = await core.getTime()
      blockHeight = time.latestBlockHeight
    }
    const block = await core.getBlock(blockHeight)
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          block_height: block.blockHeight,
          proposer_address: block.proposerAddress,
          block_time: block.blockTime
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Get block details (proposer address, consensus timestamp) for a specific block height. Use 'latest' for the most recent block. The proposer is the CometBFT validator that proposed this block. Block 1 is the genesis block (2026-04-30T15:29:16Z). Average block time is ~1.024 seconds."

---

#### `get_validation`

```typescript
server.tool(
  "get_validation",
  {
    height: {
      type: "string" as const,
      description: "Block height to get validation data for."
    }
  },
  async ({ height }) => {
    const validation = await core.getValidationBlock(parseInt(height))
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          block_height: validation.validationBlockData.blockHeight,
          validation_block: validation.validationBlockData.validationBlock,
          positive_votes: parseInt(validation.validationBlockData.positiveVotes),
          negative_votes: parseInt(validation.validationBlockData.negativeVotes),
          trust_percentage: parseFloat(validation.validationBlockData["Trust value percentage"]),
          participation_percentage: parseFloat(validation.validationBlockData["Node participation percentage"]),
          execution_result: validation.executionResult,
          fault_handling: validation.faultHandling || null,
          fault_handling_note: validation.faultHandling
            ? "Validation data was not on this block. The validation_block field shows where it was found."
            : undefined
        }, null, 2)
      }]
    }
  }
)
```

**Agent guidance:**
> "Get validator vote data for a specific block: positive/negative votes, trust percentage, and node participation. Not all blocks contain validation data - if the requested block is empty, the response includes a fault_handling pointer to the next block that does. Trust percentage = positive votes / total nodes. These metrics are used by smart contract triggers to gate deployment."

---

### Error Handling

Every error returns `isError: true` with an actionable message. The agent should never see a raw stack trace.

```typescript
function mcpError(code: string, message: string, guidance: string) {
  return {
    isError: true,
    content: [{
      type: "text" as const,
      text: JSON.stringify({ error: code, message, guidance }, null, 2)
    }]
  }
}
```

| Code | HTTP Status | Message | Agent Guidance |
|---|---|---|---|
| `AUTH_INVALID` | 401 | Invalid or missing API key | "Ask the user to set CLOCKCHAIN_API_KEY in the MCP server environment configuration." |
| `IDENTITY_MISSING` | - | Client ID or wallet ID not configured | "CLOCKCHAIN_CLIENT_ID and CLOCKCHAIN_WALLET_ID are required for logging. Ask the user to add them to the MCP server env." |
| `RATE_LIMITED_IP` | 429 | IP rate limit exceeded (50/min) | "Rate limit hit. Wait 100 seconds before retrying. The Clockchain node enforces a 50 requests/minute limit per IP." |
| `RATE_LIMITED_PLAN` | 429 | Plan quota exhausted | "API quota exhausted (e.g., 1000/1000 on FREE plan). The user needs to upgrade their plan or wait for renewal." |
| `BLOCK_NOT_FOUND` | 404 | Block height does not exist | "The requested block height exceeds the current chain height. Call get_time to check the latest height." |
| `NODE_UNSYNCED` | 503 | Node is not synced | "The Clockchain node is not synced. Retry in 5-10 seconds. If persistent, the node may be restarting." |
| `WRITE_PENDING` | - | blockHeight is null | "The log entry was accepted but not yet written to the blockchain (~1 second delay). Call get_log_entry with the ledger_id to check confirmation status." |
| `PROOF_NOT_READY` | - | Cannot generate proof for unconfirmed entry | "The log entry has not been confirmed on chain yet (block_height is null). Wait for confirmation before generating a proof." |
| `DID_NOT_FOUND` | 404 | DID does not exist on ledger | "No agent identity found with this DID. It may not have been minted, or may be owned by a different client." |
| `DID_REVOKED` | - | DID has been revoked | "This agent identity has been revoked and should not be trusted. Check revoke details with get_agent_identity." |
| `VALIDATION_REDIRECT` | - | Validation data not on requested block | "Validation data is not stored on every block. The response includes a fault_handling pointer to the next block with data." |

---

### Resources

#### `clockchain://status`

```typescript
server.resource(
  "clockchain://status",
  "API & Node Status",
  async () => {
    const ts = await core.getTimestamp()
    return {
      contents: [{
        uri: "clockchain://status",
        mimeType: "application/json",
        text: JSON.stringify({
          node: {
            status: ts.nodeStatus,
            block_height: ts.blockHeight,
            total_nodes: parseInt(ts.totalNodes),
            consensus: parseFloat(ts.consentedOffset) === -999.0
              ? "insufficient_nodes" : "active"
          },
          api: {
            endpoint: config.endpoint,
            rate_limit: "50 requests/min per IP",
            cooldown: "100 seconds after breach"
          },
          chain: {
            genesis: "2026-04-30T15:29:16Z",
            avg_block_time: "~1.024s",
            blocks_per_minute: "~58.6"
          }
        }, null, 2)
      }]
    }
  }
)
```

#### `clockchain://agent/{did}`

```typescript
server.resourceTemplate(
  "clockchain://agent/{did}",
  "Agent Identity",
  async ({ did }) => {
    const mintResults = await core.searchAsset(config.clientId, `did:mint:${did}`)
    if (!mintResults || mintResults.length === 0) {
      return {
        contents: [{
          uri: `clockchain://agent/${did}`,
          mimeType: "application/json",
          text: JSON.stringify({ error: "DID not found" })
        }]
      }
    }

    const identity = JSON.parse(mintResults[0].additionalInfo)
    const revokeResults = await core.searchAsset(config.clientId, `did:revoke:${did}`)

    return {
      contents: [{
        uri: `clockchain://agent/${did}`,
        mimeType: "application/json",
        text: JSON.stringify({
          did: identity.did,
          name: identity.name,
          owner: identity.owner,
          capabilities: identity.capabilities,
          status: revokeResults?.length > 0 ? "revoked" : "active",
          mint_block: mintResults[0].blockHeight,
          mint_ledger_id: mintResults[0].ledgerId
        }, null, 2)
      }]
    }
  }
)
```

---

### Prompts

#### `onboard_agent`

The TTFL flow for AI agents. This is Product B's activation path.

```typescript
server.prompt(
  "onboard_agent",
  {
    agent_name: {
      type: "string" as const,
      description: "Name for the new agent"
    },
    capabilities: {
      type: "string" as const,
      description: "Comma-separated list of capabilities"
    }
  },
  async ({ agent_name, capabilities }) => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `You are setting up a new AI agent on the Clockchain network. Follow these steps exactly:

1. MINT IDENTITY: Call mint_agent_identity with:
   - name: "${agent_name}"
   - capabilities: [${capabilities.split(",").map(c => `"${c.trim()}"`).join(", ")}]
   - owner: the user's email or identifier

2. SAVE THE DID: The returned 'did' field (format: did:clockchain:agent:...) is this agent's permanent on-chain identity. Report it to the user.

3. LOG FIRST ACTION: Call log_action with:
   - did: the DID from step 1
   - asset_hash: compute SHA-256 of the string "Agent ${agent_name} initialized on Clockchain"
   - asset_reference_id: "${agent_name}-init"
   - additional_info: "Agent initialization - first on-chain action"

4. WAIT FOR CONFIRMATION: The block_height will initially be null. Call get_log_entry with the ledger_id after 2 seconds to check if block_height is populated.

5. GENERATE PROOF: Once confirmed, call generate_proof with the ledger_id. Show the user the evidence package. Be accurate: layers 4-5 (consensus + ledger) are real on-chain data; on the current testnet the vote counts will be zero because only one node is running. Do not claim "court-admissible" - that is the protocol's design goal, not what this single-node testnet proof demonstrates.

6. REPORT TO USER: Summarize what was created:
   - Agent DID (their permanent on-chain identity)
   - First action ledger ID (proof of initialization)
   - Block height and consensus timestamp
   - Explain that every future action logged via log_action builds an immutable, auditable trail under this DID`
      }
    }]
  })
)
```

#### `timestamp_document`

```typescript
server.prompt(
  "timestamp_document",
  {
    content_description: {
      type: "string" as const,
      description: "What the user wants to timestamp"
    }
  },
  async ({ content_description }) => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `The user wants to create a verifiable, tamper-evident timestamp for: ${content_description}

Steps:
1. Ask the user for the file content or text to timestamp
2. Compute SHA-256 hash of the content
3. Call log_action with:
   - did: the configured default DID (or ask the user which agent identity to use)
   - asset_hash: the SHA-256 hash
   - asset_reference_id: a descriptive reference (suggest one based on "${content_description}")
   - additional_info: "${content_description}"
4. Wait for blockchain confirmation (call get_log_entry until block_height is non-null)
5. Call generate_proof with the ledger_id
6. Explain to the user:
   - Their document's hash is now recorded on the Clockchain and cannot be altered without detection
   - The timestamp comes from the Marzullo consensus over NTP, Google NTP, and NIST sources
   - The eIDAS / RFC 3161 / ISO-IEC 18014 / ESIGN bar is the protocol's design goal; a single-node testnet entry does not yet meet it. Say so plainly if asked.
   - To verify later: recompute the SHA-256 hash and compare against the on-chain record
   - Save the ledger_id for future reference`
      }
    }]
  })
)
```

#### `audit_agent`

```typescript
server.prompt(
  "audit_agent",
  {
    did: {
      type: "string" as const,
      description: "The agent's DID to audit"
    }
  },
  async ({ did }) => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `Generate a compliance audit for agent ${did}.

Steps:
1. Call verify_agent_identity with did "${did}" to confirm the agent is valid
2. Call search_actions to find all logged actions (try common asset_reference_id patterns)
3. For each action found, call get_log_entry to get full details
4. For the most critical actions, call generate_proof to get the 5-layer evidence package
5. Compile a report:
   - Agent identity: name, owner, capabilities, mint date, status
   - Total actions logged
   - Action timeline (earliest to latest, with timestamps and references)
   - Any gaps in the trail (periods with no logged actions)
   - Proofs generated for key actions
   - Overall assessment: is the audit trail complete and trustworthy?`
      }
    }]
  })
)
```

---

### Transport Initialization

The same server code handles both local (stdio) and remote (HTTP) transports:

```typescript
// src/server.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"

const server = new McpServer({ name: "clockchain", version: "1.0.0" })

// Register all tools, resources, prompts (as defined above)
registerIdentityTools(server)
registerLoggingTools(server)
registerProofTools(server)
registerTimeTools(server)
registerResources(server)
registerPrompts(server)

// Transport selection
if (process.env.MCP_TRANSPORT === "http") {
  const transport = new StreamableHTTPServerTransport({
    port: parseInt(process.env.MCP_PORT || "3000")
  })
  await server.connect(transport)
  console.log(`Clockchain MCP server listening on port ${process.env.MCP_PORT || 3000}`)
} else {
  const transport = new StdioServerTransport()
  await server.connect(transport)
}
```

### Security

- API keys, client IDs, and wallet IDs come from environment variables - never from tool inputs
- The `/schedule` endpoint's `privateKey` parameter is the only tool that handles cryptographic key material - `schedule_trigger` requires explicit user confirmation before passing it
- Tool responses never include API keys or raw private keys
- DID ownership is enforced by clientId matching - an agent can only verify/revoke DIDs minted by the same client
- Rate limit state is tracked locally; the server never tells the agent how many requests remain on the plan (information leakage)
