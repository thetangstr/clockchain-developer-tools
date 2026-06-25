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
# wait=true so the reply carries blockHeight directly; refuse to claim success on a
# null blockHeight (a degraded pool silently drops fires); snake_case tool args.
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
case "$PART/$NODES" in 0.0/*|*/1.0) echo "  ⚠ pool looks degraded — fires may NOT anchor. Will assert anchoring before claiming success." >&2 ;; esac

say "Arming alarm for T0 + ${WAIT_S}s; waiting…"; sleep "$WAIT_S"
T1=$(tool get_timestamp '{}' | jq -r '.madMarzulloTime'); echo "  consensus now T1=$T1 (≥ scheduled T) — firing"

say "Fire = anchor on-chain (wait=true → blockHeight returned directly)…"
FIRE=$(tool log_action '{"action":"alarm.fire","asset_reference_id":"alarm-demo","content":"verified-time alarm fired","wait":true,"wait_ms":30000}')
LID=$(printf '%s' "$FIRE" | jq -r '.ledgerId'); BH=$(printf '%s' "$FIRE" | jq -r '.blockHeight // empty'); HASH=$(printf '%s' "$FIRE" | jq -r '.assetHash')
echo "  ledgerId=$LID  blockHeight=${BH:-null}  assetHash=$HASH"
{ [ -n "$BH" ] && [ "$BH" != "null" ]; } || die "FIRE NOT ANCHORED (blockHeight null) — the receipt is cache-only and unverifiable (degraded pool). Re-run when participation > 0."

say "Keyless verify against the immutable on-chain block…"
V=$(tool verify_cross_party "{\"ledger_id\":\"$LID\",\"block_height\":$BH}")
printf '%s' "$V" | jq '{verifiedAgainst,keyless,blockHeight,anchoredHash}' 2>/dev/null || echo "$V"
[ "$(printf '%s' "$V" | jq -r '.verifiedAgainst // "?"')" = "on-chain block" ] \
  && say "✓ Alarm fired on neutral time, anchored at block $BH, keyless-verified." \
  || die "verify did not resolve to an on-chain block."
