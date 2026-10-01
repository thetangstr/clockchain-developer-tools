# @clockchain/telemetry-sink — N4c

OTLP/HTTP-JSON telemetry sink for the agent-pairing harness: append-only
hash-chained records per run, capability-separated tokens (ingest / query /
global-query — close authority belongs to the SINK via signed contract-server
terminal receipts or window expiry, never a bearer token), sealed token
delivery, an immutable signed final head plus a signed refusal annex per run,
and a loopback-only per-role forwarder.

## Ports: write, read, and close are separate listeners

`createTelemetrySinkServer()` returns THREE servers — `{ write, read, close }`:

- **write** — `POST /v1/traces`, `POST /v1/logs`, `GET /v1/health`. Only the
  per-role services uids (the forwarders) ever connect here. `/close` is NOT
  served on this port — a compromised forwarder can never deliver one.
- **read** — `GET /v1/runs/:runId/records`, `GET /v1/runs/:runId/head` (each
  response carries the latest refusal annex), `GET /v1/health`. Only the
  harness / verifier uids ever connect here.
- **close** — `POST /v1/runs/:runId/close` and NOTHING else (not even
  `/v1/health`). Only the contract server's uid/address ever connects here;
  the terminal receipt's signature is the only credential.

Bind them on distinct loopback ports and firewall them separately.

## pf rules the harness MUST install (probe item)

The forwarder binds a literal loopback port per role. Loopback alone is NOT
sufficient isolation — any local uid can connect to `127.0.0.1:<port>`. The
harness must install `pf` rules so that:

- **Only the role's agent uid** may open a TCP connection to that role's
  forwarder port — over BOTH IPv4 (`127.0.0.1`) and IPv6 (`::1`) loopback.
- The harness uid and the OTHER role's agent uid are blocked.
- The sink **write** port is reachable only by the per-role services uids
  running the forwarders — never by agent uids or the harness.
- The sink **read** (query) port is reachable only by the harness and the
  verifier uids — never by agent uids or the services uids.
- The sink **close** port is reachable only by the contract-server uid (if it
  is a remote host instead, restrict by source address — `pf` `from <addr>` —
  and bind the listener off loopback; the loopback rules below cover the
  co-located case).

On macOS `pf`, filtering happens on the **outbound** rules — `user` on an
`out` rule matches the uid of the *connecting process*, which is exactly the
distinction needed here. `pass` must come BEFORE `block` (`quick` makes the
first match terminal). Do NOT add `set skip on lo0` — it disables filtering
on the loopback interface entirely.

Example anchor file `/etc/pf.anchors/ac-telemetry` (adjust uids/ports):

```
# uids:  buyer agent 501 · provider agent 502 · harness 505 · verifier 506
#        contract server 507
#        buyer services 601 · provider services 602
# ports: sink write 9400 · sink query 9401 · sink close 9402
#        buyer forwarder 9418 · provider forwarder 9419

# 1. Each role's agent may reach ONLY its own forwarder (v4 + v6).
pass  out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9418 user 501
pass  out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9419 user 502
block out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port { 9418, 9419 }

# 2. Sink write port: services uids only.
pass  out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9400 user { 601, 602 }
block out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9400

# 3. Sink query port: harness + verifier uids only.
pass  out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9401 user { 505, 506 }
block out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9401

# 4. Sink close port: the contract-server uid only.
pass  out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9402 user 507
block out quick on lo0 proto tcp to { 127.0.0.1, ::1 } port 9402
```

Load it from the main ruleset and enable pf (pf is off by default on macOS):

```
# /etc/pf.conf — inside the existing filter section, after the pass rules:
anchor "ac-telemetry"
load anchor "ac-telemetry" from "/etc/pf.anchors/ac-telemetry"
```

```sh
sudo pfctl -f /etc/pf.conf   # load ruleset + anchors
sudo pfctl -E                # ENABLE pf (required — loading alone leaves it off)
sudo pfctl -sr | grep lo0    # verify the pass rules precede the blocks
sudo pfctl -a ac-telemetry -s rules   # confirm the anchor itself loaded
```

Probe the rules as each uid (expect timeout/refused where blocked):

```sh
sudo -u 505 nc -w 2 -vz 127.0.0.1 9418   # harness uid  -> buyer forwarder  (BLOCKED)
sudo -u 502 nc -w 2 -vz ::1 9418         # provider uid -> buyer forwarder  (BLOCKED, v6)
sudo -u 501 nc -w 2 -vz 127.0.0.1 9400   # buyer agent  -> sink write port  (BLOCKED)
sudo -u 501 nc -w 2 -vz 127.0.0.1 9401   # buyer agent  -> sink query port  (BLOCKED)
sudo -u 601 nc -w 2 -vz 127.0.0.1 9401   # services uid -> sink query port  (BLOCKED)
sudo -u 505 nc -w 2 -vz 127.0.0.1 9402   # harness uid  -> sink close port  (BLOCKED)
sudo -u 601 nc -w 2 -vz 127.0.0.1 9402   # services uid -> sink close port  (BLOCKED)

sudo -u 501 nc -w 2 -vz 127.0.0.1 9418   # buyer agent  -> own forwarder    (connects)
sudo -u 601 nc -w 2 -vz 127.0.0.1 9400   # services uid -> sink write port  (connects)
sudo -u 506 nc -w 2 -vz 127.0.0.1 9401   # verifier     -> sink query port  (connects)
sudo -u 507 nc -w 2 -vz 127.0.0.1 9402   # contract srv -> sink close port  (connects)
```

**Residual (LLD E10):** `pf` matches on uid, not executable — any process
running under the agent's uid can reach that uid's forwarder port, so the
sudoers entry for each agent uid must be restricted to the pinned agent
binary. The same caveat means the query-port `user` clause trusts that only
the harness/verifier binaries run under those uids.

## Runtime wire shapes the extractor consumes

Verified against live captures (N4e, `5a7a679` on `feat/hermes-telemetry-n4d`):

- **Codex 0.154.0** — `codex.tool_result` log records; `tool_name`,
  `arguments`, `output`. `output` is exec-wrapped
  (`"Wall time: <s> seconds\nOutput:\n<json>"`, or
  `"Script completed\n…\nOutput:\n\n<jsonl>"` for script runs). The extractor
  strips only that exact anchored preamble, then applies the one-structural-
  nonce rule; a multi-JSON-body remainder is `nonce_ambiguous` and an
  unrecognized wrapper is flagged `codex_output_unrecognized` — never a
  substring scan.
- **Claude Code 2.1.284** — `claude_code.tool` SPANS (traces signal): span
  attribute `tool_name` (`mcp__<server>__<tool>`), result in the span event
  `tool.output` → attribute `output` (clean JSON). The older
  `claude_code.mcp.rpc` shape (`tool.name`) is still accepted alongside.
- **Hermes 0.21.2** — `hermes.tool_call` log records from the N4d plugin.
- **Gemini** — `gemini_cli.tool_call` log records.

## Claude Code identity attributes (N4e finding)

Claude stamps `user.id`, `session.id`, `organization.id`, `user.email`,
`user.account_uuid`, `user.account_id` onto EVERY log record AND every span
(observed: 51/51 log records and 14/14 spans in the N4e run). The sink stores
bodies byte-for-byte, so that identity lands in evidence. Source-side levers:

- **There is no knob that strips identity from logs or spans.** The
  `OTEL_METRICS_INCLUDE_*` gates (`_ACCOUNT_UUID`, `_SESSION_ID`, …) are
  metrics-scoped only. Per the docs, `organization.id` and `user.email` are
  "always included when available"; `OTEL_RESOURCE_ATTRIBUTES` can never
  override built-in keys.
- `OTEL_LOGS_EXPORTER=none` removes the whole `resourceLogs` signal — in the
  N4e run that drops all 51 identity-bearing event records while keeping
  every `claude_code.tool` span, and **the nonce path (R13(d)) lives entirely
  in spans** (`tool.output` events), so nothing needed is lost.
- The account attributes are emitted only "when authenticated" — a runtime
  authenticated via `ANTHROPIC_API_KEY` or a third-party provider (the
  deployed P4 provider shape, GLM/z.ai) emits no `organization.id` /
  `user.email` / `user.account_*`. `user.id` (install/device id) and
  `session.id` remain — per-run, not account PII.

Recommended export set for a signed-in run: `OTEL_TRACES_EXPORTER=otlp`,
`OTEL_LOGS_EXPORTER=none`, `OTEL_METRICS_EXPORTER=none`,
`OTEL_LOG_TOOL_CONTENT=1` (the nonce-carrying `tool.output` span event is
gated on it).
