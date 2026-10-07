# N7c — `/contract/mcp` SSM parameter contract

Exact contract between SSM Parameter Store and `loadContractConfig`
(`packages/mcp-server/src/agent-contract/config.ts`). This is the authoritative
list of what the orchestrator provisions into SSM and what `compose-up.sh`
reads — derived from the code, not from memory. If a row and the code ever
disagree, the code is right; fix the row.

- **Path:** every parameter lives at `/clockchain/mcp/<NAME>` (single level —
  the name IS the env var name).
- **Region:** `us-west-2`.
- **Fetch:** `compose-up.sh` reads each parameter with
  `aws ssm get-parameter --with-decryption` at container-start time. Nothing is
  cached, echoed, or logged.
- **Absent ⇒ unset:** a parameter that does not exist leaves the env var unset
  on the host; `""` reaching the container is normalized to absent by
  `config.ts`, so *absent* and *empty* are equivalent everywhere below.
- **Route gate:** the `/contract/mcp` route answers 404 unless
  `CONTRACT_MCP_ENABLED=1`. All other parameters may be provisioned while the
  route stays dark; none of them take effect until the flag is set.

## Parameter table

Types: `SecureString` = secret material (tokens, seed). `String` = config.
"Required at L" means `loadContractConfig` misconfigures (route 503s) or the
D20 demo cannot run without it when `CONTRACT_MCP_ENABLED=1`; anything not
marked required falls back to the shown default or stays off.

| Parameter (suffix of `/clockchain/mcp/`) | Type | Required at L | Format / semantics |
|---|---|---|---|
| `CONTRACT_MCP_ENABLED` | String | the gate | `1` enables the route; anything else (or absent) = 404 |
| `CONTRACT_LEVEL` | String | no (default `L`) | `L` \| `S` \| `P`, case-insensitive. S/P additionally REQUIRE `CONTRACT_REQUIRE_BIND_STATEMENT=1`, `TELEMETRY_CLOSE_URL`, production host roots, and a non-ephemeral signer (check-config refuses otherwise) |
| `CONTRACT_AUTH_TOKENS` | SecureString | **yes** | comma-separated `token:role:keyId:agentId:side` entries — see §Tokens |
| `CONTRACT_SERVER_ED25519_SEED` | SecureString | **yes** | canonical base64 of exactly 32 bytes (re-encode check: `b64decode(x).b64encode() == x`), e.g. output of `openssl rand 32 \| base64`. Alternative for dev only: omit and set `CONTRACT_ALLOW_EPHEMERAL_KEY=1` — forbidden for D20 |
| `CONTRACT_SERVER_KEY_ID` | String | recommended | free-form keyId for the published signing key (default `contract-server`); pin a durable id, e.g. `contract-server-v1`. Ignored when the signer is ephemeral (forced to `ephemeral-dev-*`) |
| `CONTRACT_SERVER_KEY_VALID_FROM` | String | **yes** | ISO-8601 timestamp parseable by `Date.parse` — pinned, never boot time |
| `CONTRACT_SERVER_KEY_VALID_UNTIL` | String | no | ISO-8601; absent = no expiry. Boot refuses if already past |
| `CONTRACT_ALLOW_EPHEMERAL_KEY` | String | **do not set** | `1` permits a disposable dev signer when the seed is absent. Never set on the box — check-config refuses it at S/P and D20 wants a pinned key |
| `CONTRACT_POLICY_DIGESTS` | String | **yes** | `buyer:0x<64-hex>,provider:0x<64-hex>` — BOTH required; lowercase hex; `0x00…00` is refused. Each role also takes a `\|`-separated SET (`buyer:0xA\|0xB,provider:0xC`, max 64 per role); an approval is accepted if its digest is any member |
| `CONTRACT_PRINCIPALS` | String | **yes** (demo) | comma-separated `keyId:0x<40-hex-address>` buyer-family pins; the mandate's EIP-191 signature must recover to the pinned address. keyId must equal the keyId in the buyer's token entry |
| `CONTRACT_OBSERVER_TOKEN` | SecureString | no | bearer for the read-only observer receipt feed; if set MUST differ from `CONTRACT_VERIFIER_TOKEN` |
| `CONTRACT_VERIFIER_TOKEN` | SecureString | no | bearer for verifier-scoped run-salt disclosure; if set MUST differ from `CONTRACT_OBSERVER_TOKEN` |
| `CONTRACT_HOST_ROOTS` | String | no | comma-separated `kid:<64-hex-fingerprint>`; absent = the published production root set (`root-2026-08`). A value REPLACES the default list: it must include `root-2026-08` (startup logs a `contract_default_host_root_missing` warning, kid only, when it does not). At S/P every pinned root must be a published production root |
| `CONTRACT_ERC8004_CHAIN_ID` | String | no | `eip155:<n>` (the certificate's wire format) or a bare decimal, normalized to `eip155:<n>`; when either ERC8004 pin is set, certs must attest exactly this deployment. Pair with `CONTRACT_ERC8004_REGISTRY_ADDRESS` (both or neither) |
| `CONTRACT_ERC8004_REGISTRY_ADDRESS` | String | no | `0x<40-hex>`, compared case-insensitively (checksummed or lowercase both work) — Sepolia registry `0x8004A818BFB912233c491871b3d84c89A494BD9e` for D20 |
| `CONTRACT_ANCHOR_ENABLED` | String | no | `1` = anchor agreement digest + terminal chain head via the in-process `tsa_issue` path (no extra secret; uses the server's Clockchain client config) |
| `CONTRACT_SETTLEMENT_RAIL` | String | no | `simulated` (default) \| `stripe_test_mode`. The Stripe rail resolves `agentcontract/travel-stripe-test-key` (Secrets Manager, `us-west-2`) at call time, TEST-mode keys only; absent key ⇒ honest `awaiting_stripe_test_key`, non-test ⇒ refused |
| `CONTRACT_ALLOW_SIM_FAULTS` | String | no | `1` gates `CONTRACT_SIM_FAULTS`; card/keys disclose `simFaultsEnabled` |
| `CONTRACT_SIM_FAULTS` | String | no | JSON `{"<runId>":{"issueMismatch":"fare"\|"travellers"}}`, runIds 1..128 chars; requires `CONTRACT_ALLOW_SIM_FAULTS=1` |
| `CONTRACT_REQUIRE_BIND_STATEMENT` | String | yes iff any `*` token | `1` mandates the bind-statement possession proof. REQUIRED at S/P and at ANY level when a token uses late-binding `agentId=*` |
| `CONTRACT_TRUST_PROXY` | String | no | `1` trusts `X-Forwarded-For` for evidence `sourceIp` (edge = Caddy only) |
| `CONTRACT_STATE_DIR` | String | no | run/receipt/binding state dir. Container default is `cwd/state/contract` = `/app/state/contract` (the `mcp_state` volume); pin it anyway for clarity |
| `CONTRACT_CALLS_PER_MINUTE` | String | no | integer, default `120` |
| `CONTRACT_OBSERVER_PER_MINUTE` | String | no | observer feed limiter, integer, default `30` (read in `http.ts`, not `config.ts`) |
| `CONTRACT_MAX_RUNS` | String | no | integer, default `1024` |
| `CONTRACT_MAX_RECEIPTS_PER_RUN` | String | no | integer, default `4096` |
| `CONTRACT_MAX_RECEIPTS_PER_PRINCIPAL` | String | no | integer, default `512` |
| `CONTRACT_RUN_TTL_MS` | String | no | integer ms, default `86400000` |
| `CONTRACT_CERT_GRACE_MS` | String | no | integer ms, default `600000` |
| `CONTRACT_SESSION_TTL_MS` | String | no | integer ms, default `1800000` |
| `TELEMETRY_CLOSE_URL` | String | no at L; **yes at S/P** | `http(s)://…` — the sink's close-only listener, a compose DNS name (never a public route). D20 (L): no sink yet — leave absent |
| `TELEMETRY_CLOSE_BACKOFF_MS` | String | no | comma list of ms delays, each 0..120000 |
| `TELEMETRY_CLOSE_ATTEMPT_TIMEOUT_MS` | String | no | integer ms, 100..120000 (default 10000) |
| `TELEMETRY_CLOSE_DEADLINE_MS` | String | no | integer ms, 1000..600000 (default 90000) |

### CDT features (track-b/cdt-wiring) — all default-off

Every row below is optional. Absent (or `""`, which compose injects for an
unset host variable) gives exactly the b04059e surface and behaviour —
`infra/clockchain-mcp/compose-up.sh` reads each with `read_optional_env` and
`docker-compose.yml` passes `"${NAME:-}"`. A malformed value is a boot-time
misconfiguration (route 503s); run `check-config-from-ssm.mjs` first.

| Parameter (suffix of `/clockchain/mcp/`) | Type | Required | Format / semantics |
|---|---|---|---|
| `TELEMETRY_LANES` | String | no | `0` \| `1`. `1` serves `telemetry_open`, links runs to provider lanes and uses the v2 close. REQUIRES `TELEMETRY_CLOSE_URL` and `TELEMETRY_SINK_KEY_ID`; the sink's `TELEMETRY_CONTRACT_KEYS` must carry this server's signer keyId |
| `TELEMETRY_SINK_KEY_ID` | String | iff lanes on | the sink's signing keyId (public; the lane-open audience), `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Read it off the sink's ready line / `/telemetry/keys`. Ignored (check-config warns) while lanes are off |
| `CONTRACT_DIRECTORY` | String | no | comma list `name:providerKeyId`; each keyId must have a provider token in `CONTRACT_AUTH_TOKENS`. Append-only like the principal pins |
| `CONTRACT_MAX_RUNS_PER_KEY` | String | no (default `1`) | integer `1..64` — live runs per keyId. `1` = b04059e routing |
| `CONTRACT_POLICY_REGISTRATION` | String | no | `0` \| `1`. `1` serves `contract_register_policy` (principal-signed buyer policy registrations, persisted in `registered-policies.json`) |
| `CONTRACT_SERVER_ANCHORS` | String | no | `0` \| `1`. `1` fires the server-side terms / brief / final anchors — a no-op unless `CONTRACT_ANCHOR_ENABLED=1` (check-config warns) |
| `CONTRACT_EXPIRE_AT_TTL` | String | no | `0` \| `1`. `1` ends a run non-terminal at its TTL as `expired` / `expired_unbound` through the full terminal path (receipt, close, anchor) instead of dropping it |
| `CONTRACT_BRIEFS` | String | no | comma list `name:0x<64 lower hex sha256>`; each text is `CONTRACT_BRIEFS_DIR/<name>.md` and must hash to its pin at boot. Serves `contract_get_brief` |
| `CONTRACT_BRIEFS_DIR` | String | iff briefs | ABSOLUTE path **inside the mcp container** (e.g. `/app/state/briefs` on the `mcp_state` volume — the files must be put there before the restart; the image does not ship them) |
| `CONTRACT_ROLE_BRIEFS` | String | no | `buyer:<brief>,provider:<brief>` — names from `CONTRACT_BRIEFS`. REQUIRES `CONTRACT_SERVER_ANCHORS=1` and `CONTRACT_BRIEFS` |

### Telemetry sink parameters (read by `telemetry-sink/sink-up.sh up`)

These are the sink container's environment, not the mcp's. `compose-up.sh`
never reads them.

| Parameter (suffix of `/clockchain/mcp/`) | Type | Required | Format / semantics |
|---|---|---|---|
| `TELEMETRY_CONTRACT_KEYS` | String | **yes** for the sink | non-empty JSON `{keyId: public key}` (no private JWK member) — the contract server's PUBLIC keys, the only close authority. `sink-up.sh` refuses to build without it |
| `TELEMETRY_RUN_SET_HEAD` | String | no | `0` \| `1` (no decryption needed). `1` = per-run run-set head (CDT-GAPS gap 4). Absent leaves it unset (compose passes `""` = off = the pre-wiring sink). Any other value, or a read error other than ParameterNotFound, makes `sink-up.sh` refuse BEFORE building. It prints `runSetHead flag: on\|off\|absent`, never the value |

The contract public-key pin is `TELEMETRY_CONTRACT_KEYS` above. Enrollment
and lane state live in the sink's `TELEMETRY_STATE_DIR` (`/telemetry/state`,
the `telemetry_state` volume) — no parameter.

## §Tokens — `CONTRACT_AUTH_TOKENS` for the D20 pairing

Format per entry: `token:role:keyId:agentId:side` — five non-empty,
colon-free fields, entries comma-separated, whitespace around entries ignored.
Duplicates refused. `buyer` ≡ `initiator`, `provider` ≡ `responder` (the
parser refuses a mismatched role/side pin).

One entry per company — one buyer and three providers:

```text
<secret>:buyer:family-travel:<agentId>:initiator,
<secret>:provider:rome-agency-a:<agentId>:responder,
<secret>:provider:rome-agency-b:<agentId>:responder,
<secret>:provider:rome-agency-c:<agentId>:responder
```

- `token` — the business bearer the company presents on `/contract/mcp`.
  Generated by the orchestrator (≥32 random bytes, e.g. `openssl rand -hex 32`),
  delivered to each company out-of-band, never stored anywhere but SSM and the
  company's own credential store.
- `keyId` — the company's principal id, used in receipts and as the
  `CONTRACT_PRINCIPALS` map key. Convention: `family-travel`, `rome-agency-a`,
  `rome-agency-b`, `rome-agency-c` (the provisioner's pairing names are
  `agentdash-travel-pairing-buyer` / `-rome-a` / `-rome-b` / `-rome-c`; the
  contract keyIds above are the wire ids and must match `mcp_servers`
  principal entries exactly).
- `agentId` — the company's ERC-8004 agent id as a **decimal** string (from
  its Sepolia registration), or `*` for late binding. Late binding requires
  `CONTRACT_REQUIRE_BIND_STATEMENT=1` (fail-closed at every level — an
  unproven `*` entry can otherwise claim any certificate party's agentId).
  Prefer concrete ids once the four registrations exist.

## `CONTRACT_PRINCIPALS`

```text
family-travel:0x<40-hex-EIP-191-recovered-address>
```

Buyer keyIds → family-principal addresses. Required for the demo (the
mandate's EIP-191 signature recovers to the pinned address). Provider
principals are not pinned here — this map is buyer-side only.

## `CONTRACT_POLICY_DIGESTS`

```text
buyer:0x<64-hex-sha256>,provider:0x<64-hex-sha256>
```

The §13 policy digest each role's approvals must carry. Both entries
required; each role may list several digests joined by `|`
(`buyer:0xA|0xB,provider:0xC`, at most 64 per role) — the buyer digest changes
every run, so a pre-pinned batch avoids an SSM write per run. An approval is
accepted when its digest is ANY member of its role's set; a single value per
role keeps working; lowercase `0x`-prefixed sha256; the all-zero digest is refused.
Values come from the policy document the orchestrator ships with the demo —
compute them out-of-band and provision verbatim.

## Server seed — `CONTRACT_SERVER_ED25519_SEED`

Canonical base64 of exactly 32 bytes. `loadContractConfig` verifies the
round-trip (`b64encode(b64decode(x)) === x`), so no whitespace/newline is
tolerated — SSM `SecureString`, value is the single 44-char line.

Pair it with `CONTRACT_SERVER_KEY_ID` (a stable human id, e.g.
`contract-server-v1`) and `CONTRACT_SERVER_KEY_VALID_FROM` (pinned ISO-8601 —
the published key window, never boot-derived). Derive `publicKeyHex`
out-of-band and hand it to the harness so agents pin `/contract/keys` before
any run.

## Checking what SSM will do — before touching the route

```sh
# on the box, or anywhere with ssm:GetParameter on /clockchain/mcp/*
node packages/mcp-server/scripts/agent-contract/check-config-from-ssm.mjs \
  --region us-west-2
```

Reads the same parameters `compose-up.sh` will read, loads them into the
process environment only, and prints the same redacted verdict as
`check-config.mjs` plus a `present`/`absent` map per parameter. The report
also carries `features` (on/off/configured verdicts and entry counts for the
CDT rows), `limits.maxRunsPerKey`, `warnings` (settings that load but do
nothing as combined) and a `sink` block for the two sink parameters
(`runSetHead: on|off|absent|invalid`, `contractKeys: valid|invalid|absent`,
whether the signer keyId is published). An invalid sink value is a refusal
(exit 1). Values are never printed. Exit codes: `0` ready, `1` misconfigured/refused, `2` disabled
(route flag absent — expected until the enable step of D20).

The contract route ships **disabled**: `CONTRACT_MCP_ENABLED` is itself an SSM
parameter — the safe bring-up is to provision every other parameter first, run
the checker (expect exit 2), then write `CONTRACT_MCP_ENABLED=1` and re-run
(expect exit 0) before restarting the service.
