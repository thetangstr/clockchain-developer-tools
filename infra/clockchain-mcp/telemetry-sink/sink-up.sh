#!/usr/bin/env bash
# Box-side half of the D22 telemetry-sink deploy. Runs on the MCP box
# (i-0d6765d143da7e1ea) as root over SSM, from the checkout deploy-box.sh left
# at /opt/clockchain-mcp/app. See infra/clockchain-mcp/telemetry-sink/RUNBOOK.md.
#
#   sink-up.sh preflight          read-only: checkout, running-vs-checkout Caddyfile, capacity
#   sink-up.sh up                 build + start ONLY telemetry-sink (--no-deps); refuses if running
#   sink-up.sh reload-caddy [rev] docker cp the checkout's (or <rev>'s) Caddyfile into the RUNNING
#                                 caddy and `caddy reload` it — caddy is never recreated
#   sink-up.sh status             sink state + its ready line (public keyIds only)
#   sink-up.sh stop               stop the sink; telemetry_state (sink key, tokens, ledger) is kept
#
# Never: compose down, --full-restart, systemctl, or any up/recreate of caddy, host or mcp.
# Prints no secrets: the only SSM value read is the PUBLIC contract-key set, and it is not echoed.
set -euo pipefail

APP_ROOT="${CLOCKCHAIN_MCP_APP_ROOT:-/opt/clockchain-mcp/app}"
AWS_REGION="${AWS_REGION:-us-west-2}"
KEYS_PARAM="${TELEMETRY_CONTRACT_KEYS_PARAM:-/clockchain/mcp/TELEMETRY_CONTRACT_KEYS}"
WAIT_TIMEOUT="${SINK_WAIT_TIMEOUT:-180}"
CADDYFILE=infra/clockchain-mcp/Caddyfile

usage() { echo "usage: $0 preflight|up|reload-caddy [rev]|status|stop" >&2; exit 64; }
[[ $# -ge 1 ]] || usage
MODE="$1"
shift

cd "$APP_ROOT"
OWNER=$(stat -c %U .)
G=(sudo -u "$OWNER" git -c "safe.directory=$APP_ROOT")
DC=(docker compose -f infra/clockchain-mcp/docker-compose.yml)
SDC=("${DC[@]}" --profile telemetry)

# created/started of the long-lived containers; compose warns about every unset
# interpolation variable (this shell has no compose env), so stderr is dropped.
container_times() {
  local id
  for id in $("${DC[@]}" ps -aq caddy host mcp </dev/null 2>/dev/null); do
    docker inspect -f '{{.Name}} created={{.Created}} started={{.State.StartedAt}}' "$id" </dev/null
  done
  for id in $(docker ps -aq --filter name=acm4 </dev/null 2>/dev/null); do
    docker inspect -f '{{.Name}} created={{.Created}} started={{.State.StartedAt}}' "$id" </dev/null
  done
}

ready_line() {
  "${SDC[@]}" logs --no-log-prefix telemetry-sink </dev/null 2>/dev/null | grep '"telemetry-sink-ready"' | tail -1 || true
}

sink_running() {
  [[ -n "$("${SDC[@]}" ps -q telemetry-sink </dev/null 2>/dev/null)" ]]
}

caddy_id() {
  local id
  id=$("${DC[@]}" ps -q caddy </dev/null 2>/dev/null)
  [[ -n "$id" ]] || { echo "REFUSING: caddy is not running"; exit 2; }
  printf '%s\n' "$id"
}

case "$MODE" in
  preflight)
    echo "checkout: $("${G[@]}" rev-parse HEAD) dirty=[$("${G[@]}" status --short | tr '\n' ' ')]"
    CID=$(caddy_id)
    echo "Caddyfile checkout: $(sha256sum "$CADDYFILE" | cut -d' ' -f1)"
    echo "Caddyfile running:  $(docker exec "$CID" sha256sum /etc/caddy/Caddyfile </dev/null | cut -d' ' -f1)  (bind mount; equal before the first reload)"
    container_times
    free -m | sed -n 1,2p
    df -h /var/lib/docker | tail -1
    docker image inspect -f 'base image present: {{.Id}}' \
      node@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 </dev/null 2>/dev/null \
      || echo "base image NOT cached (build will pull node:24-alpine by digest)"
    if sink_running; then echo "telemetry-sink: RUNNING"; else echo "telemetry-sink: not running"; fi
    ;;

  up)
    if sink_running; then
      echo "REFUSING: telemetry-sink is already running — a restart marks every open run RUN_LOST. Stop it deliberately first (sink-up.sh stop) when no run is open."
      exit 3
    fi
    if ! KEYS=$(aws --region "$AWS_REGION" ssm get-parameter --name "$KEYS_PARAM" \
        --query Parameter.Value --output text </dev/null); then
      echo "REFUSING: cannot read $KEYS_PARAM (create it first: public contract-server JWK set)"
      exit 4
    fi
    # Same rules the sink enforces at boot, checked BEFORE anything is built or started, so a
    # bad value never becomes a restart loop: a non-empty JSON object, no private JWK member.
    if ! jq -e 'type == "object" and length > 0
        and all(.[]; (type == "string") or (type == "object" and (has("d") | not)))' \
        >/dev/null 2>&1 <<<"$KEYS"; then
      echo "REFUSING: $KEYS_PARAM is not a non-empty {keyId: public key} object (or carries private material)"
      exit 4
    fi
    echo "contract keyIds: $(jq -r 'keys | join(",")' <<<"$KEYS")"
    export TELEMETRY_CONTRACT_KEYS="$KEYS"
    # Production runs with TELEMETRY_PEER_ENV=none (compose): no staging peer set may be passed.
    unset TELEMETRY_CONTRACT_KEYS_STAGING
    BEFORE=$(container_times)
    echo "box: sink build $(date -u +%FT%TZ)"
    "${SDC[@]}" build telemetry-sink </dev/null 2>&1 | tail -3
    echo "box: sink up $(date -u +%FT%TZ)"
    "${SDC[@]}" up -d --no-deps --wait --wait-timeout "$WAIT_TIMEOUT" telemetry-sink </dev/null
    AFTER=$(container_times)
    printf '%s\n' "$AFTER"
    if [[ "$BEFORE" != "$AFTER" ]]; then
      echo "WARNING: caddy/host/mcp/acm4 container times CHANGED — investigate"
      exit 1
    fi
    echo "caddy/host/mcp unchanged"
    "${SDC[@]}" ps telemetry-sink </dev/null 2>/dev/null
    echo "ready: $(ready_line)"
    MCP=$("${DC[@]}" ps -q mcp </dev/null 2>/dev/null)
    if [[ -n "$MCP" ]]; then
      docker exec "$MCP" node -e "fetch('http://telemetry-sink:8081/v1/health').then(r=>{console.log('mcp -> telemetry-sink:8081/v1/health', r.status);process.exit(r.ok?0:1)}).catch(e=>{console.log('mcp -> sink FAILED', String(e));process.exit(1)})" </dev/null
    fi
    ;;

  reload-caddy)
    REV="${1:-}"
    CID=$(caddy_id)
    SRC="$CADDYFILE"
    if [[ -n "$REV" ]]; then
      SRC=$(mktemp /tmp/Caddyfile.rev.XXXXXX)
      "${G[@]}" show "$REV:$CADDYFILE" > "$SRC" </dev/null
    fi
    BEFORE=$(docker inspect -f '{{.Created}} {{.State.StartedAt}}' "$CID" </dev/null)
    echo "reloading caddy from ${REV:-checkout} sha256=$(sha256sum "$SRC" | cut -d' ' -f1)"
    docker cp "$SRC" "$CID:/tmp/Caddyfile.next" </dev/null
    docker exec "$CID" caddy validate --config /tmp/Caddyfile.next --adapter caddyfile </dev/null 2>&1 | tail -1
    docker exec "$CID" caddy reload --config /tmp/Caddyfile.next --adapter caddyfile </dev/null 2>&1 | tail -1
    AFTER=$(docker inspect -f '{{.Created}} {{.State.StartedAt}}' "$CID" </dev/null)
    if [[ "$BEFORE" != "$AFTER" ]]; then
      echo "WARNING: caddy container times changed: $BEFORE -> $AFTER"
      exit 1
    fi
    echo "caddy not recreated ($AFTER)"
    ;;

  status)
    "${SDC[@]}" ps telemetry-sink </dev/null 2>/dev/null || true
    echo "ready: $(ready_line)"
    container_times
    ;;

  stop)
    "${SDC[@]}" stop telemetry-sink </dev/null
    echo "telemetry-sink stopped; volume telemetry_state kept (deleting it mints a NEW sink key)"
    ;;

  *) usage ;;
esac
