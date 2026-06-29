#!/usr/bin/env bash
# Clockchain — verified-time ALARM via the hosted MCP, ZERO creds (self-serve demo token).
#
# Mints ONE demo token (cached), checks validator-pool health, arms an alarm, fires +
# anchors with wait=true, ASSERTS it actually anchored, then keyless-verifies against the
# immutable on-chain block. No gateway creds, no SDK build — just bash, curl, jq.
#
#   curl -fsSL https://raw.githubusercontent.com/thetangstr/clockchain-developer-tools/main/packages/clock-sdk/examples/try-alarm-mcp.sh | bash
#
# Hard-won robustness (see commit history): mint once + cache (the /token endpoint is
# IP-rate-limited with no Retry-After); fail FAST on 401/403 (auth isn't transient);
# wait=true so the reply carries blockHeight directly; snake_case tool args.
#
# Degraded testnet pool: on testnet the gateway often reports participation 0% / a single
# node. Blocks are still advancing, so anchoring WORKS — but the default pool-health guard
# refuses. Rather than dead-end a 0-context user, this script auto-fires with
# allow_degraded:true (with a LOUD single-validator-testnet caveat). Override via
# CC_ALLOW_DEGRADED (1=always allow, 0=never). The HARD failure is kept for the ONE case
# that matters: a genuinely null/empty blockHeight = no real anchor → die (truthful only).
set -uo pipefail
BASE="https://mcp.clockchain.network"
TKFILE="${CC_TOKEN_FILE:-/tmp/cc_demo_token}"
WAIT_S="${CC_WAIT_S:-30}"
say(){ printf "\n\033[1;36m▶ %s\033[0m\n" "$*"; }
die(){ printf "\n\033[1;31m✗ %s\033[0m\n" "$*" >&2; exit 1; }
command -v jq   >/dev/null || die "jq is required (brew install jq / apt-get install jq)."
command -v curl >/dev/null || die "curl is required."

# Mint once and cache. The /token endpoint is IP-hard-capped; do NOT mint per call.
get_token(){
  if [ -s "$TKFILE" ] && [ "$(cat "$TKFILE")" != "null" ]; then return 0; fi
  local r t
  r=$(curl -fsS -X POST "$BASE/token" 2>/dev/null) || die "/token request failed (network)."
  t=$(printf '%s' "$r" | jq -r '.token // empty')
  [ -n "$t" ] || die "/token returned no token — likely IP rate-limited ($r). Wait, switch network, or reuse a cached token via \$CC_TOKEN_FILE. Mint once, never per call."
  printf '%s' "$t" > "$TKFILE"
}

# JSON-RPC call over HTTP+SSE. 200 → data; 401/403 → fail fast; 429/5xx → short backoff.
cc(){
  local body="$1" out code clean attempt
  for attempt in 1 2 3; do
    out=$(curl -sN -w $'\n__H__%{http_code}' -X POST "$BASE/mcp" \
      -H "x-api-key: $(cat "$TKFILE")" -H "content-type: application/json" \
      -H "accept: application/json, text/event-stream" -d "$body" 2>/dev/null) || true
    code=$(printf '%s' "$out" | sed -n 's/^__H__//p' | tail -1)
    clean=$(printf '%s' "$out" | sed '/^__H__/d' | grep '^data:' | tail -1 | sed 's/^data: //')
    case "$code" in
      200) printf '%s' "$clean"; return 0 ;;
      401|403) die "auth $code — token bad/expired (not retrying). Run: rm $TKFILE && re-run." ;;
      *) sleep $((attempt*8)) ;;
    esac
  done
  die "call failed after retries (http=${code:-empty})."
}
tool(){ cc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" | jq -r '.result.content[0].text // empty'; }

say "Minting demo token (once → $TKFILE)…"; get_token

say "Pool-health pre-check…"
TS=$(tool get_timestamp '{}')
T0=$(printf '%s' "$TS" | jq -r '.madMarzulloTime'); BH0=$(printf '%s' "$TS" | jq -r '.blockHeight')
NODES=$(printf '%s' "$TS" | jq -r '.totalNodes // "?"'); PART=$(printf '%s' "$TS" | jq -r '."nodeParticipation%" // "?"')
echo "  T0=$T0  block=$BH0  totalNodes=$NODES  participation=$PART%"

# Detect a degraded pool: participation 0% or a single node. On testnet this is the norm —
# blocks keep advancing (block=$BH0 above) and anchoring still works, but the default guard
# refuses. CC_ALLOW_DEGRADED: 1=always allow, 0=never; unset → auto-allow iff degraded.
DEGRADED=0
case "$PART" in 0|0.0|0.00) DEGRADED=1 ;; esac
case "$NODES" in 1|1.0) DEGRADED=1 ;; esac
ALLOW_DEGRADED="${CC_ALLOW_DEGRADED:-$DEGRADED}"

FIRE_ARGS='{"action":"alarm.fire","asset_reference_id":"alarm-demo","content":"verified-time alarm fired","wait":true,"wait_ms":30000}'
if [ "$ALLOW_DEGRADED" = "1" ]; then
  printf '\033[1;33m'
  echo "  ████████████████████████████████████████████████████████████████████"
  echo "  ██  SINGLE-VALIDATOR TESTNET — DEGRADED POOL (participation=$PART% nodes=$NODES)"
  echo "  ██  Blocks ARE advancing (current block=$BH0) so anchoring works; the default"
  echo "  ██  pool-health guard would refuse, so firing with allow_degraded:true."
  echo "  ██  The receipt ANCHORS on-chain and is keyless-verifiable, but it is"
  echo "  ██  single-validator testnet — anchored, NOT court-grade."
  echo "  ██  (Set CC_ALLOW_DEGRADED=0 to refuse a degraded pool instead.)"
  echo "  ████████████████████████████████████████████████████████████████████"
  printf '\033[0m'
  FIRE_ARGS='{"action":"alarm.fire","asset_reference_id":"alarm-demo","content":"verified-time alarm fired","wait":true,"wait_ms":30000,"allow_degraded":true}'
fi

say "Arming alarm for T0 + ${WAIT_S}s; waiting…"; sleep "$WAIT_S"
T1=$(tool get_timestamp '{}' | jq -r '.madMarzulloTime'); echo "  consensus now T1=$T1 (≥ scheduled T) — firing"

say "Fire = anchor on-chain (wait=true → blockHeight returned directly)…"
FIRE=$(tool log_action "$FIRE_ARGS")
LID=$(printf '%s' "$FIRE" | jq -r '.ledgerId'); BH=$(printf '%s' "$FIRE" | jq -r '.blockHeight // empty'); HASH=$(printf '%s' "$FIRE" | jq -r '.assetHash')
echo "  ledgerId=$LID  blockHeight=${BH:-null}  assetHash=$HASH"
# HARD failure ONLY on a genuinely null/empty blockHeight (no real anchor). A degraded pool
# that still lands a block is fine — that is a real, keyless-verifiable anchor. A null means
# the fire never anchored and the receipt is cache-only; refuse to claim success (truthful).
{ [ -n "$BH" ] && [ "$BH" != "null" ]; } || die "FIRE NOT ANCHORED (blockHeight null) — the receipt is cache-only and unverifiable (no real anchor). The pool produced no block for this fire; re-run when blocks are advancing."

say "Keyless verify against the immutable on-chain block…"
# verify_cross_party returns { onChain, advisoryHashCheck }; the authoritative on-chain
# fields live under .onChain (verifiedAgainst / keyless / blockHeight / anchoredHash).
V=$(tool verify_cross_party "{\"ledger_id\":\"$LID\",\"block_height\":$BH}")
printf '%s' "$V" | jq '.onChain | {verifiedAgainst,keyless,blockHeight,anchoredHash}' 2>/dev/null || echo "$V"
[ "$(printf '%s' "$V" | jq -r '.onChain.verifiedAgainst // "?"')" = "on-chain block" ] \
  && say "✓ Alarm fired on neutral time, anchored at block $BH, keyless-verified." \
  || die "verify did not resolve to an on-chain block."
