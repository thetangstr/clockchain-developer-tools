#!/usr/bin/env bash
# Clockchain verified-time tools through the hosted MCP — the 60-second first experience.
#
#   curl -fsSL https://raw.githubusercontent.com/thetangstr/clockchain-developer-tools/main/packages/clock-sdk/examples/try-clock-tools-mcp.sh | bash
#
# ZERO credentials: mints one self-serve demo token (cached), then runs a STOPWATCH end to end —
# start marker, ~3 s, stop marker, keyless verification that recomputes the elapsed time from the
# two sealed blocks. Spends two log credits on the shared demo account (nothing of yours).
#
# With a tester token (export CC_MCP_TOKEN=...): ALSO sets a hosted TIMER that fires server-side
# while this script only polls, and verifies its fire. Timer/alarm are account-gated because the
# keeper spends credits unattended — a demo token gets a clear 402, not a failure.
#
# Field notes shared with try-alarm-mcp.sh: mint once + cache; fail fast on 401/403; every result
# is checked against the immutable block — a null blockHeight is a failure, never "pending".
set -uo pipefail
BASE="${CC_MCP_URL:-https://mcp.clockchain.network}"
TKFILE="${CC_TOKEN_FILE:-/tmp/cc_demo_token}"
HOLD_S="${CC_HOLD_S:-3}"
TIMER_S="${CC_TIMER_S:-5}"
say(){ printf "\n\033[1;36m▶ %s\033[0m\n" "$*"; }
die(){ printf "\n\033[1;31m✗ %s\033[0m\n" "$*" >&2; exit 1; }
command -v jq >/dev/null || die "jq is required (brew install jq / apt-get install jq)."
command -v curl >/dev/null || die "curl is required."

if [ -n "${CC_MCP_TOKEN:-}" ]; then
  TOKEN="$CC_MCP_TOKEN"; MODE="tester token"
else
  if [ -s "$TKFILE" ] && [ "$(cat "$TKFILE")" != "null" ]; then TOKEN=$(cat "$TKFILE"); else
    r=$(curl -fsS -X POST "$BASE/token" 2>/dev/null) || die "/token request failed (network)."
    TOKEN=$(printf '%s' "$r" | jq -r '.token // empty'); [ -n "$TOKEN" ] || die "/token returned no token (IP rate-limited?). Reuse a cached one via \$CC_TOKEN_FILE."
    printf '%s' "$TOKEN" > "$TKFILE"
  fi
  MODE="demo token (cached at $TKFILE)"
fi

# JSON-RPC over HTTP+SSE; 200 → data, 401/403 → fail fast, 429 → back off.
cc(){
  local body="$1" out code clean attempt
  for attempt in 1 2 3; do
    out=$(curl -sN -w $'\n__H__%{http_code}' -X POST "$BASE/mcp" -H "x-api-key: $TOKEN" -H "content-type: application/json" \
      -H "accept: application/json, text/event-stream" -d "$body" 2>/dev/null) || true
    code=$(printf '%s' "$out" | sed -n 's/^__H__//p' | tail -1)
    clean=$(printf '%s' "$out" | sed '/^__H__/d' | grep '^data:' | tail -1 | sed 's/^data: //')
    case "$code" in
      200) printf '%s' "$clean"; return 0 ;;
      401|403) die "auth $code — token bad/expired. Run: rm $TKFILE && re-run." ;;
      *) sleep $((attempt*8)) ;;
    esac
  done
  die "call failed after retries (http=${code:-empty})."
}
tool(){ cc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"; }
text(){ jq -r '.result.content[0].text // empty'; }
is_error(){ jq -e '.result.isError == true' >/dev/null 2>&1; }

say "Using $MODE against $BASE"
LABEL="try-$(date +%s)"

say "Stopwatch: start marker…"
S=$(tool stopwatch_start "{\"label\":\"$LABEL\"}"); printf '%s' "$S" | is_error && die "stopwatch_start: $(printf '%s' "$S" | text)"
START_ID=$(printf '%s' "$S" | text | jq -r '.start.ledgerId'); START_BH=$(printf '%s' "$S" | text | jq -r '.start.blockHeight')
[ "$START_BH" != "null" ] && [ -n "$START_BH" ] || die "start marker did not anchor (blockHeight null)."
echo "  start ledgerId=$START_ID block=$START_BH — holding ${HOLD_S}s"; sleep "$HOLD_S"

say "Stopwatch: stop marker…"
P=$(tool stopwatch_stop "{\"label\":\"$LABEL\",\"start_ledger_id\":\"$START_ID\"}"); printf '%s' "$P" | is_error && die "stopwatch_stop: $(printf '%s' "$P" | text)"
STOP_ID=$(printf '%s' "$P" | text | jq -r '.stop.ledgerId'); STOP_BH=$(printf '%s' "$P" | text | jq -r '.stop.blockHeight'); EL=$(printf '%s' "$P" | text | jq -r '.elapsedMs')
[ "$STOP_BH" != "null" ] && [ -n "$STOP_BH" ] || die "stop marker did not anchor."
echo "  stop ledgerId=$STOP_ID block=$STOP_BH — recorded elapsed ${EL} ms"

say "Stopwatch: keyless verify (elapsed recomputed from the two sealed blocks)…"
V=$(tool stopwatch_verify "{\"start_ledger_id\":\"$START_ID\",\"stop_ledger_id\":\"$STOP_ID\",\"start_block_height\":$START_BH,\"stop_block_height\":$STOP_BH}")
printf '%s' "$V" | text | jq '{verified, elapsedOnChainMs, elapsedRecordedMs, start: .start.verifiedAgainst, stop: .stop.verifiedAgainst}'
[ "$(printf '%s' "$V" | text | jq -r '.verified')" = "true" ] && say "✓ Stopwatch: ${EL} ms, both markers verified against the immutable blocks." || die "stopwatch_verify did not verify."

say "Hosted timer: timer_set ${TIMER_S}s (fires server-side; this script only polls)…"
T=$(tool timer_set "{\"delay_ms\":$((TIMER_S*1000)),\"label\":\"$LABEL\"}")
if printf '%s' "$T" | is_error; then
  MSG=$(printf '%s' "$T" | text)
  case "$MSG" in *account_required*|*keeper_action*) echo "  (timer/alarm need an account-backed tester token — the keeper spends credits unattended. Set CC_MCP_TOKEN to try them.)"; exit 0 ;; esac
  die "timer_set: $MSG"
fi
TID=$(printf '%s' "$T" | text | jq -r '.id'); echo "  armed id=$TID fires at $(printf '%s' "$T" | text | jq -r '.fireAtIso')"
for i in $(seq 1 20); do
  sleep 3
  ST=$(tool timer_status "{\"id\":\"$TID\"}" | text)
  STATUS=$(printf '%s' "$ST" | jq -r '.status'); [ "$STATUS" = "done" ] && break
done
[ "$STATUS" = "done" ] || die "timer ended in state '$STATUS'."
FL=$(printf '%s' "$ST" | jq -r '.fires[0].anchor.ledgerId'); FB=$(printf '%s' "$ST" | jq -r '.fires[0].anchor.blockHeight'); LATE=$(printf '%s' "$ST" | jq -r '(.fires[0].firedAtMs - .fires[0].scheduledForMs)')
echo "  fired ${LATE} ms after target — anchored ledgerId=$FL block=$FB"
VF=$(tool verify_cross_party "{\"ledger_id\":\"$FL\",\"block_height\":$FB}" | text)
[ "$(printf '%s' "$VF" | jq -r '.onChain.verifiedAgainst')" = "on-chain block" ] && say "✓ Timer fired on verified time while you were away; fire verified keylessly at block $FB." || die "timer fire did not verify."
