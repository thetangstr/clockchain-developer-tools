# Clockchain MCP — agent test report: FAIL

| | |
|---|---|
| Agent | `hermes:clockchain-eval@i-049caedb6298592cd` (Clark — Hermes 0.17.0 on AWS (i-049caedb6298592cd), Bedrock us.amazon.nova-2-lite-v1:0) |
| Endpoint | https://mcp.clockchain.network/mcp |
| Run | `02653097` · 2026-09-11T04:57:33.098Z → 2026-09-11T05:08:19.504Z |
| Tasks | **18 / 24 passed** (on-chain checks, no LLM judge); tool selection 20 / 24 |
| Tools | 50 on the live surface: **27 exercised OK**, 8 exercised with an error result, 10 not single-agent testable (covered elsewhere), 5 not exercised |

## Tasks

| Task | Result | Tools | Calls | Evidence |
|---|---|---|---|---|
| `time-read` | ✅ PASS | as expected | 1 | live height 502; called get_time=true |
| `notarize` | ✅ PASS | as expected | 1 | reference found on-chain |
| `attest-verify` | ❌ FAIL | as expected | 9 | verify_receipt called=true, match=undefined |
| `identity-valid-at` | ✅ PASS | as expected | 2 | verify_identity_at called=true, authorized=false (expect false) |
| `cross-party-verify` | ❌ FAIL | missed: verify_cross_party | 9 | verify_cross_party called=false, has on-chain result=false |
| `block-read` | ✅ PASS | as expected | 2 | live block 514; called block/time=true |
| `audit-trail` | ✅ PASS | as expected | 2 | ref on-chain=true, generate_audit_trail called=true |
| `async-attest` | ❌ FAIL | as expected | 5 | complete_attestation calls=4, confirmed=false |
| `tsa-commitment` | ✅ PASS | as expected | 2 | tsa_attest called=true, verdict=kept (expect kept) |
| `stopwatch` | ✅ PASS | as expected | 3 | stopwatch_verify called=true, verified=true, elapsedOnChainMs=966 |
| `hosted-timer` | ✅ PASS | as expected | 10 | fired: ledger 083b3fe2-5a6f-4d7f-babb-a6d3f63136c1 block 525 |
| `timestamp-detail` | ✅ PASS | as expected | 1 | madMarzulloTime 2026-09-11T05:02:45.330Z, participation 100 |
| `validation-read` | ✅ PASS | as expected | 2 | called=true; real=false; reported-unavailable=true |
| `search-and-verify` | ✅ PASS | as expected | 3 | found=true, verify_asset match=true |
| `resolve-agent` | ✅ PASS | as expected | 1 | status=unknown |
| `scheduler-reads` | ✅ PASS | missed: estimate_schedule | 2 | called types=true list=true; real=false; reported-unavailable=true |
| `compliance-report` | ✅ PASS | as expected | 2 | report for eval-02653097-compliance: reportHash ee412f966008f0c9…, n/a event(s) |
| `evidence-package` | ❌ FAIL | as expected | 6 | verify_package called=true, valid=undefined |
| `identity-lifecycle` | ❌ FAIL | missed: delegate_authority, revoke_identity, get_identity_history | 1 | history events: mint; delegation record found=false |
| `tsa-lifecycle` | ✅ PASS | as expected | 4 | commitment 28962458492da5e382bcb150: 3 event(s) on record (issue+checkpoint+settle expected) |
| `hosted-alarm-cancel` | ❌ FAIL | missed: alarm_set | 3 | no alarm id from alarm_set |
| `handshake-status-read` | ✅ PASS | as expected | 2 | handshake_status=true, agent_handshake_status=true |
| `adversarial-unknown-ledger` | ✅ PASS | as expected | 1 | get_log_entry called=true, reported-absent=true |
| `adversarial-no-write` | ✅ PASS | as expected | 1 | no write tools used (correct) |

## Tool coverage (live `tools/list`)

| Tool | Status | Calls | Note |
|---|---|---|---|
| `get_time` | ✅ exercised-ok | 5 |  |
| `get_timestamp` | ✅ exercised-ok | 1 |  |
| `get_block` | ✅ exercised-ok | 1 |  |
| `get_validation` | ⚠️ exercised-error | 1 |  |
| `log_action` | ✅ exercised-ok | 5 |  |
| `search_actions` | ✅ exercised-ok | 1 |  |
| `get_log_entry` | ⚠️ exercised-error | 1 |  |
| `verify_asset` | ✅ exercised-ok | 1 |  |
| `stopwatch_start` | ✅ exercised-ok | 1 |  |
| `stopwatch_stop` | ✅ exercised-ok | 1 |  |
| `stopwatch_verify` | ✅ exercised-ok | 1 |  |
| `timer_set` | ✅ exercised-ok | 2 |  |
| `alarm_set` | ❌ not-exercised | 0 |  |
| `timer_status` | ✅ exercised-ok | 8 |  |
| `timer_cancel` | ✅ exercised-ok | 1 |  |
| `timer_list` | ⚠️ exercised-error | 1 |  |
| `resolve_agent` | ✅ exercised-ok | 1 |  |
| `attest_action` | ✅ exercised-ok | 6 |  |
| `verify_receipt` | ⚠️ exercised-error | 11 |  |
| `complete_attestation` | ⚠️ exercised-error | 5 |  |
| `get_contract_types` | ⚠️ exercised-error | 1 |  |
| `estimate_schedule` | ❌ not-exercised | 0 |  |
| `create_schedule` | ◻️ not-single-agent | 0 | needs the caller's EVM wallet signature (non-custodial; the server never fabricates one) — covered by tools.test.mjs + the protocol team's signing spec |
| `list_schedules` | ✅ exercised-ok | 1 |  |
| `generate_audit_trail` | ✅ exercised-ok | 1 |  |
| `generate_compliance_report` | ✅ exercised-ok | 1 |  |
| `build_evidence_package` | ✅ exercised-ok | 1 |  |
| `verify_package` | ⚠️ exercised-error | 4 |  |
| `mint_identity` | ✅ exercised-ok | 2 |  |
| `revoke_identity` | ❌ not-exercised | 0 |  |
| `delegate_authority` | ❌ not-exercised | 0 |  |
| `get_identity_history` | ❌ not-exercised | 0 |  |
| `verify_identity_at` | ✅ exercised-ok | 1 |  |
| `verify_cross_party` | ✅ exercised-ok | 1 |  |
| `tsa_issue` | ✅ exercised-ok | 2 |  |
| `tsa_checkpoint` | ✅ exercised-ok | 1 |  |
| `tsa_attest` | ✅ exercised-ok | 1 |  |
| `tsa_settle` | ✅ exercised-ok | 1 |  |
| `tsa_status` | ✅ exercised-ok | 1 |  |
| `handshake_status` | ⚠️ exercised-error | 1 |  |
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
