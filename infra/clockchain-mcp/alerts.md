# Clockchain MCP: what to watch, and when to act

Nothing here is configured. No alert fires today, and `GET /metrics` answers 404 on production until the token below is
set. The thresholds are starting points, not measurements: there is no real traffic to set them from yet. Revisit them
after the first month.

## Reading the numbers

`GET /metrics` is Prometheus text. It needs `Authorization: Bearer <MCP_METRICS_TOKEN>`, and without a token set the route
doesn't exist. Set `/clockchain/mcp/MCP_METRICS_TOKEN` as a SecureString, then deploy. Caddy forwards the path, so it
is reachable from outside once the token is set; only the token protects it.

```bash
curl -s -H "Authorization: Bearer $MCP_METRICS_TOKEN" https://mcp.clockchain.network/metrics | grep -E '^clockchain_(log_budget|oauth|shadow)'
```

The series below are totals. They carry no owner, session, account, key, token or link (`test/shadow-metrics.test.mjs`
checks). They are read from memory, so a scrape doesn't walk the disk.

## Thresholds

| Watch | Series | Warn | Act now | What it means at the limit |
|---|---|---|---|---|
| Ledger writes | `clockchain_log_budget_used` / `clockchain_log_budget_limit` | 80% | 95% | Anchors stop: steps are still recorded, marked `over_limit`, with no block or ledger ID. `/mcp` writes are refused too. |
| Shadow storage | `clockchain_shadow_state_bytes` / `clockchain_shadow_state_bytes_cap` | 70% | 90% | At 100% no new session starts. At 125% no new step is recorded. Existing sessions can still close. |
| Accounts | `clockchain_oauth_accounts` / `clockchain_oauth_accounts_cap` | 80% | 95% | At 100% sign-up is refused. Accounts already made keep working. |
| New accounts | rise in `clockchain_oauth_accounts` | over 100 in an hour | over 180 in an hour | The server-wide limit is 200 an hour by default. Accounts are free and have no email, so a spike is probably abuse. |
| Anchors waiting | rise in `clockchain_shadow_anchors_owed{state="queued"}` plus `{state="pending"}` | over 20 in 15 minutes | over 100 in 15 minutes | Clockchain is slow or down. Steps stay safe and anchor later. |
| Anchors given up | rise in `clockchain_shadow_anchors_owed{state="failed"}` | any | over 5 in 15 minutes | Those checkpoints will never anchor. Later checkpoints still cover the steps. |
| Retention | `clockchain_shadow_last_sweep_age_seconds` | over 2 hours | over 6 hours, or the series has no value while Shadow should be on | Nothing is being deleted, and the 30-day promise is at risk. |
| The gateway | `clockchain_dependency_up{dep="gateway_pool"}`, set when `/status.json` is computed | 0 for 5 minutes | 0 for 15 minutes | See "The anchoring gateway" in `RUNBOOK.md`. |

## What to know before acting

**Ledger writes.** `MCP_LOG_BUDGET` is 5000, set in `compose-up.sh`. It counts per process, so a restart or deploy sets the
count back to 0. That makes it a brake, not a monthly budget. Shadow's anchors and `/mcp`'s writes share it. With logging
on by default, each step is one write, so a few active preview users can use it up. To get writes moving again, restart
`mcp`, which resets the count, or raise the number in `compose-up.sh` and deploy. Before doing either, check that the use is
real and not abuse.

**Shadow storage.** The number is measured at each hourly sweep and kept current by appended steps. Between sweeps it
leaves out session metadata, so it can read a little low. `SHADOW_MAX_BYTES` is 1 GB by default. Shadow refuses to start if
the cap is more than half the free space on the state filesystem, so check `df` before raising it. To free space, use
`scripts/shadow-purge.mjs` (RUNBOOK, "Hosted Shadow"). The count catches up at the next sweep or restart.

**Anchors waiting.** Nothing retries in the background. A queued anchor is retried only when that session is next used, so
one left by an agent that never came back stays queued until the session expires at 30 days. The absolute number can sit
above 0 for a long time and mean nothing, so watch the rise. After a restart, the count reads 0 until the boot sweep, which
runs at start-up.

**Anchors given up.** A failed row stays counted until its session expires, so this series only tells you something when
it rises.

**Retention.** The series has no value when `SHADOW_ENABLED` is off or Shadow failed to start. Both stop the sweep. Records
then outlive the 30 days we promise until someone runs the purge script (RUNBOOK, "Hosted Shadow").

## Not covered

- Requests that fail before they reach Shadow, and box health (disk, memory). Use the existing HTTP series and the box itself.
- Whether an agent logged every step. The server can't see inside the chat.
- Whether the listed paths still carry no default-on logging. Check that after any deploy (RUNBOOK, "Hosted Shadow").
