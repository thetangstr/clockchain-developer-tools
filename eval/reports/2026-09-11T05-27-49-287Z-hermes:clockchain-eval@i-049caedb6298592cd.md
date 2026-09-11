# Clockchain MCP — agent test report: PASS

| | |
|---|---|
| Agent | `hermes:clockchain-eval@i-049caedb6298592cd` (Clark — Hermes 0.17.0 on AWS (i-049caedb6298592cd), Bedrock us.amazon.nova-2-lite-v1:0) |
| Endpoint | https://mcp.clockchain.network/mcp |
| Run | `04469287` · 2026-09-11T05:27:49.287Z → 2026-09-11T05:39:00.828Z |
| Tasks | **24 / 24 passed** (on-chain checks, no LLM judge); tool selection 24 / 24 |
| Tools | 50 on the live surface: **35 exercised OK**, 5 exercised with an error result, 10 not single-agent testable (covered elsewhere), 0 not exercised |

## Tasks

| Task | Result | Tools | Calls | Evidence |
|---|---|---|---|---|
| `time-read` | ✅ PASS | as expected | 1 | live height 611; called get_time=true |
| `notarize` | ✅ PASS | as expected | 1 | reference found on-chain |
| `attest-verify` | ✅ PASS | as expected | 2 | verify_receipt called=true, match=true |
| `identity-valid-at` | ✅ PASS | as expected | 2 | verify_identity_at called=true, authorized=false (expect false) |
| `cross-party-verify` | ✅ PASS | as expected | 2 | verify_cross_party called=true, has on-chain result=true |
| `block-read` | ✅ PASS | as expected | 2 | live block 623; called block/time=true |
| `audit-trail` | ✅ PASS | as expected | 2 | ref on-chain=true, generate_audit_trail called=true |
| `async-attest` | ✅ PASS | as expected | 2 | complete_attestation calls=1, confirmed=true |
| `tsa-commitment` | ✅ PASS | as expected | 2 | tsa_attest called=true, verdict=kept (expect kept) |
| `stopwatch` | ✅ PASS | as expected | 4 | stopwatch_verify called=true, verified=true, elapsedOnChainMs=4734 |
| `hosted-timer` | ✅ PASS | as expected | 11 | fired: ledger bba1f257-203e-4f35-be9a-c0c873df2818 block 636 |
| `timestamp-detail` | ✅ PASS | as expected | 1 | madMarzulloTime 2026-09-11T05:33:08.946Z, participation 100 |
| `validation-read` | ✅ PASS | as expected | 2 | called=true; real=false; reported-unavailable=true |
| `search-and-verify` | ✅ PASS | as expected | 3 | found=true, verify_asset match=true |
| `resolve-agent` | ✅ PASS | as expected | 1 | status=unknown |
| `scheduler-reads` | ✅ PASS | as expected | 3 | called types=true list=true; real=false; reported-unavailable=true |
| `compliance-report` | ✅ PASS | as expected | 2 | report for eval-04469287-compliance: reportHash 1d975d77f85cbbfc…, n/a event(s) |
| `evidence-package` | ✅ PASS | as expected | 3 | verify_package called=true, valid=true |
| `identity-lifecycle` | ✅ PASS | as expected | 4 | history events: mint,revoke; delegation record found=true |
| `tsa-lifecycle` | ✅ PASS | as expected | 4 | commitment 4d6548b27cc292f4f4adf492: 3 event(s) on record (issue+checkpoint+settle expected) |
| `hosted-alarm-cancel` | ✅ PASS | as expected | 5 | alarm b590b198-c7d8-4f48-ab7d-6e9017112e04 status=cancelled |
| `handshake-status-read` | ✅ PASS | as expected | 2 | handshake_status=true, agent_handshake_status=true |
| `adversarial-unknown-ledger` | ✅ PASS | as expected | 1 | get_log_entry called=true, reported-absent=true |
| `adversarial-no-write` | ✅ PASS | as expected | 1 | no write tools used (correct) |

## Tool coverage (live `tools/list`)

| Tool | Status | Calls | Note |
|---|---|---|---|
| `get_time` | ✅ exercised-ok | 5 |  |
| `get_timestamp` | ✅ exercised-ok | 1 |  |
| `get_block` | ✅ exercised-ok | 1 |  |
| `get_validation` | ⚠️ exercised-error | 1 | error result in: `validation-read` |
| `log_action` | ✅ exercised-ok | 5 |  |
| `search_actions` | ✅ exercised-ok | 1 |  |
| `get_log_entry` | ⚠️ exercised-error | 1 | error result in: `adversarial-unknown-ledger` |
| `verify_asset` | ✅ exercised-ok | 1 |  |
| `stopwatch_start` | ✅ exercised-ok | 1 |  |
| `stopwatch_stop` | ✅ exercised-ok | 1 |  |
| `stopwatch_verify` | ✅ exercised-ok | 1 |  |
| `timer_set` | ✅ exercised-ok | 1 |  |
| `alarm_set` | ✅ exercised-ok | 1 |  |
| `timer_status` | ✅ exercised-ok | 9 |  |
| `timer_cancel` | ✅ exercised-ok | 1 |  |
| `timer_list` | ✅ exercised-ok | 2 |  |
| `resolve_agent` | ✅ exercised-ok | 1 |  |
| `attest_action` | ✅ exercised-ok | 3 |  |
| `verify_receipt` | ✅ exercised-ok | 1 |  |
| `complete_attestation` | ✅ exercised-ok | 1 |  |
| `get_contract_types` | ⚠️ exercised-error | 1 | error result in: `scheduler-reads` |
| `estimate_schedule` | ⚠️ exercised-error | 1 | error result in: `scheduler-reads` |
| `create_schedule` | ◻️ not-single-agent | 0 | needs the caller's EVM wallet signature (non-custodial; the server never fabricates one) — covered by tools.test.mjs + the protocol team's signing spec |
| `list_schedules` | ✅ exercised-ok | 1 |  |
| `generate_audit_trail` | ✅ exercised-ok | 1 |  |
| `generate_compliance_report` | ✅ exercised-ok | 1 |  |
| `build_evidence_package` | ✅ exercised-ok | 1 |  |
| `verify_package` | ✅ exercised-ok | 1 |  |
| `mint_identity` | ✅ exercised-ok | 2 |  |
| `revoke_identity` | ✅ exercised-ok | 1 |  |
| `delegate_authority` | ✅ exercised-ok | 1 |  |
| `get_identity_history` | ✅ exercised-ok | 1 |  |
| `verify_identity_at` | ✅ exercised-ok | 1 |  |
| `verify_cross_party` | ✅ exercised-ok | 2 |  |
| `tsa_issue` | ✅ exercised-ok | 2 |  |
| `tsa_checkpoint` | ✅ exercised-ok | 1 |  |
| `tsa_attest` | ✅ exercised-ok | 1 |  |
| `tsa_settle` | ✅ exercised-ok | 1 |  |
| `tsa_status` | ✅ exercised-ok | 1 |  |
| `handshake_status` | ⚠️ exercised-error | 1 | error result in: `handshake-status-read` |
| `handshake_join` | ◻️ not-single-agent | 0 | bilateral protocol: a counterparty must join — covered by handshake-*.test.mjs and the M3 live demo |
| `handshake_next` | ◻️ not-single-agent | 0 | bilateral protocol step — covered by handshake-*.test.mjs and the M3 live demo |
| `handshake_submit` | ◻️ not-single-agent | 0 | requires a party-produced EIP-191 signature — covered by handshake-*.test.mjs and the M3 live demo |
| `handshake_get_certificate` | ◻️ not-single-agent | 0 | issued only after both parties complete — covered by handshake-*.test.mjs and the M3 live demo |
| `agent_handshake_invite` | ◻️ not-single-agent | 0 | creates a live single-use stakeholder invitation on the public surface; not something an eval should mint — covered by agent-handshake-v2-*.test.mjs and the M3 live demo |
| `agent_handshake_status` | ✅ exercised-ok | 1 |  |
| `agent_handshake_join` | ◻️ not-single-agent | 0 | two-stakeholder protocol with local signing — covered by agent-handshake-v2-*.test.mjs and the M3 live demo |
| `agent_handshake_next` | ◻️ not-single-agent | 0 | two-stakeholder protocol step — covered by agent-handshake-v2-*.test.mjs |
| `agent_handshake_submit` | ◻️ not-single-agent | 0 | requires a stakeholder-produced signature — covered by agent-handshake-v2-*.test.mjs |
| `agent_handshake_get_certificate` | ◻️ not-single-agent | 0 | issued only after both stakeholders complete — covered by agent-handshake-v2-*.test.mjs |

Legend: ✅ called and returned the server's JSON success payload · ⚠️ called, returned an error/text result (see the task's evidence — expected where the substrate lacks the API) · ◻️ cannot be completed by one agent; covered by the named suites · ❌ not exercised in this run.

Verdict rule: PASS = every task's on-chain check passed AND every single-agent-testable tool was exercised.
