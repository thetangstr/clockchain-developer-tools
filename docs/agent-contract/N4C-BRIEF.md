# Brief N4c: `ac-telemetry-sink` and `ac-otlp-forward` (third travel Devin)

**From:** orchestrator, 2026-09-28. **Design of record:** LLD rev 6.3
(`/Volumes/mac_studio_ssd/Projects/travel_mvp/ac_travel_mvp/docs/travel-mvp/design/AGENT-PAIRING-HARNESS-LLD.md`)
§9 ("Telemetry sink", R13(d), E10), E12, §6 (pf per uid) and D2 in the GOAL-GRAPH. The per-runtime telemetry facts are in
`ac_travel_mvp/docs/travel-mvp/reports/agent-pairing/2026-09-28-runtime-research.md`. Read those first.

## Where
- **Worktree:** `/Volumes/mac_studio_ssd/Projects/handshake/.worktrees/telemetry-sink-n4c`, branch
  `feat/telemetry-sink-n4c`, off `main` c30b9d9. `node_modules` is symlinked.
- **Your paths only:** a **new** package, `packages/telemetry-sink/**`, plus this `docs/agent-contract/` folder.
- **Don't touch** `packages/mcp-server/**`: N4b-1, N4b-2 and the sim lanes are working there.
- If the workspace root needs an entry for the new package, report it rather than editing the root.

## Build
1. **Sink (`src/sink.ts`, `src/server.ts`)**, an OTLP/HTTP ingest service with its own ed25519 signing key (a
   TEST-ONLY seed in tests).
   - **Ingest:** `POST /v1/traces` and `POST /v1/logs`. Accept **`application/json` (OTLP/JSON)** at minimum. Accept
     protobuf only if a protobuf decoder is **already** a dependency somewhere in the workspace; otherwise document
     that exporters must use `http/json` (Claude: `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`; report what Codex supports).
   - **Auth:** a **write-only** ingest token per `(runId, role)`. An ingest token can never read, and an unknown or
     revoked token gets 401 and writes nothing.
   - **Storage:** an append-only **hash-chained** span/log record per run (`prevHash`, `recordDigest`, `receivedAt`,
     `tokenId → role`). The raw OTLP body digest is kept, and records are never rewritten.
   - **Head:** the chain head is **signed** by the sink key. The anchor call (`tsa_issue`) is an interface only;
     no network in this slice.
   - **Query:** `GET /v1/runs/:runId/records` and `GET /v1/runs/:runId/head` with a **read-only** query token. It
     returns the records, the signed head, and a `verifyChain` result.
2. **Token minting and sealing (`src/tokens.ts`).**
   - The sink mints ingest tokens and returns each one **sealed** to the role's local-services X25519 public key.
   - Use this scheme **exactly**; it's shared with the N5 signer's `seal.ts`: an ephemeral X25519 key; HKDF-SHA256
     with an empty salt and info `"agent-contract seal v1" ‖ epk ‖ recipientPub`; AES-256-GCM with a 12-byte IV,
     a 16-byte tag and the context as AAD. The output is `{v:1, epk, iv, ct, tag}` in 0x-hex.
   - The plaintext token is never logged or returned unsealed.
3. **Forwarder (`src/forward.ts`, `bin/ac-otlp-forward`)**, run by the role's services uid.
   - It listens on **loopback** (`127.0.0.1:<port>`, no Unix socket, since the runtimes can't use one). It reads the
     sealed token, unseals it with the services key, attaches `Authorization: Bearer`, and relays the **request body
     byte-for-byte** to the sink.
   - It adds nothing and alters nothing: a test must show that the body digest the sink records equals the digest of
     what the forwarder received.
   - It refuses non-loopback binds.
4. **Extraction helper (`src/extract.ts`).** This turns stored OTLP records into `TelemetrySpan`-shaped rows
   `{role, runtime, ts, tool, serverNonce?, argsDigest?, sinkRef}` for R13(d), using the attribute names from the
   research note:
   - Claude `claude_code.mcp.rpc` + `tool.output`;
   - Codex `codex.tool_result` (arguments/output);
   - Gemini `gemini_cli.tool_call`.

   Pull `serverNonce` out of tool-result content when present. Use **hand-made OTLP/JSON fixtures** that follow
   those attribute names, clearly labelled SYNTHETIC. Real captures come later.

## Tests (red first)
Cover all of the following:
- ingest/query auth separation (an ingest token can't read; a query token can't write);
- a single-byte tamper, a deleted record or a reordering breaks `verifyChain`;
- a head signature under the wrong key fails;
- records are per-run (another run's token can't write here);
- a sealed token round-trips, and a wrong key or tampered tag fails;
- forwarder byte-for-byte digest equality; non-loopback refused;
- extraction finds the nonce in each runtime fixture;
- no plaintext token in any log or response (scan them).

## Hard limits
No deploys, no compose or Caddy edits, no network beyond loopback in tests, no real keys or tokens, no pushes. Commit
per piece.

## Report back with
Commits, raw test tails, the protocol finding (json vs protobuf, and what Codex supports), and any disagreements with
the LLD. Then idle.
