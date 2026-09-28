#!/usr/bin/env bash
# Deploy a commit of this repo to the PRODUCTION MCP box (mcp.clockchain.network) over AWS SSM.
#
# This is RUNBOOK step 3 (infra/clockchain-mcp/RUNBOOK.md) as one command, with the guard rails
# learned on 2026-09-11: the box is the AWS EC2 instance running Caddy + docker-compose; the GitHub
# "Deploy MCP to Cloud Run" workflow is NOT production.
#
#   scripts/deploy-box.sh <commit-sha> [--yes] [--full-restart]      (flags in any order)
#
# Two modes. The DEFAULT is CODE-ONLY; the full-unit restart needs --full-restart.
#
#   code-only (default): recreates ONLY the mcp container. caddy (so /acm4/*, /mcp anchoring and
#     TLS) and the v2 host keep running. On the box it runs the checked-out repo copy
#     `infra/clockchain-mcp/compose-up.sh --only mcp`, which does the same SSM/env preparation the
#     systemd unit does and then `docker compose up -d --no-deps --build --wait --wait-timeout 180 mcp`.
#     Beforehand it refreshes the installed wrapper + unit WITHOUT restarting
#     (install-clockchain-mcp-deploy-assets.sh --no-restart), so a later reboot or full restart runs
#     the same compose-up.sh that just deployed mcp. In-memory mcp state (ccra_/csha_ handles) is
#     still lost: the notice/freeze rule still applies (spec, "Deploy blast radius").
#     Changes to the Caddyfile, docker-compose.yml, the unit or the installer are NOT applied to
#     caddy/host by this mode; it warns when the deploy diff touches them.
#
#   --full-restart: the previous behaviour, for infra/config changes. The installer refreshes the
#     wrapper + unit and `systemctl restart clockchain-mcp`, whose ExecStop is `docker compose down`:
#     mcp, host AND caddy are recreated (/mcp, /acm4/*, the handshake surface and anchoring drop
#     for ~seconds). Notify the travel_mvp orchestrator and the ACM4 production owner first.
#
# What it does, on the box, as root via SSM Run Command:
#   1. refuses to run if the checkout at /opt/clockchain-mcp/app has local changes (prints them) —
#      a blind checkout once nearly reverted production's gateway wiring; commit the box's edits to
#      the repo instead (they are in git since PR "D8")
#   2. git fetch + checkout --detach <sha> as the checkout owner
#   3. pre-builds the mcp image (no downtime), then either (code-only) installs the deploy assets
#      without restart and recreates mcp alone, or (--full-restart) runs the installer, which
#      restarts the whole unit
#   4. prints container status, and in code-only mode the caddy/host/mcp container created/started
#      times before and after, so you can see caddy and host were not recreated
# Then, from this machine: the runbook canaries and the read-only clock gates G0.1–G0.5
# (needs CC_MCP_TOKEN for the gates; skipped if unset).
#
# Requires: aws CLI with SSM access to the instance (user Yang works), jq. Never prints secrets.
set -euo pipefail

INSTANCE_ID="${CLOCKCHAIN_BOX_INSTANCE_ID:-i-0d6765d143da7e1ea}"
AWS_REGION="${AWS_REGION:-us-west-2}"
APP_ROOT="${CLOCKCHAIN_MCP_APP_ROOT:-/opt/clockchain-mcp/app}"
BASE_URL="${CLOCKCHAIN_MCP_URL:-https://mcp.clockchain.network}"

usage() { echo "usage: $0 <full-commit-sha> [--yes] [--full-restart]   (flags in any order)" >&2; exit 64; }

SHA=""
CONFIRM=0
MODE=code-only
for arg in "$@"; do
  case "$arg" in
    --yes) CONFIRM=1 ;;
    --full-restart) MODE=full-restart ;;
    -*) usage ;;
    *) [[ -z "$SHA" ]] || usage; SHA="$arg" ;;
  esac
done
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || usage

# Print the mode loudly (also used by the tests: `DEPLOY_BOX_PARSE_ONLY=1` stops here).
if [[ "$MODE" == "full-restart" ]]; then
  cat <<'BANNER'
==============================================================================
 MODE: FULL RESTART (--full-restart)
 systemctl restart clockchain-mcp => docker compose down + up: mcp, host AND caddy are
 recreated. /mcp, /acm4/* (frozen ACM4 path), the handshake surface and anchoring all drop.
 REMINDER: the travel_mvp orchestrator AND the ACM4 production owner must have been
 notified (notice/freeze rule) before you continue.
==============================================================================
BANNER
else
  cat <<'BANNER'
==============================================================================
 MODE: CODE-ONLY (default)
 Recreates ONLY the mcp container (compose up --no-deps mcp). caddy and host keep running.
 mcp in-memory state (ccra_/csha_ handles) is still lost: the notice/freeze rule still applies.
 Infra/config changes (Caddyfile, compose file, unit) need --full-restart.
==============================================================================
BANNER
fi
[[ "${DEPLOY_BOX_PARSE_ONLY:-0}" == "1" ]] && { echo "mode=$MODE sha=$SHA confirm=$CONFIRM"; exit 0; }

command -v aws >/dev/null || { echo "aws CLI required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

# The commit must exist on origin/main (deploy what was reviewed, not a local branch).
git fetch -q origin main
git merge-base --is-ancestor "$SHA" origin/main || { echo "$SHA is not on origin/main — merge it first." >&2; exit 1; }
echo "deploying $(git log -1 --format='%h %s' "$SHA") to $INSTANCE_ID ($BASE_URL), mode=$MODE"
if [[ "$CONFIRM" != 1 ]]; then
  if [[ "$MODE" == "full-restart" ]]; then
    read -r -p "FULL RESTART of production (mcp + host + caddy; /mcp, /acm4/*, handshake down ~seconds). travel_mvp orchestrator and ACM4 owner notified? Continue? [y/N] " ans
  else
    read -r -p "CODE-ONLY deploy: recreates the mcp container (/mcp + handshake surface blip; caddy and host untouched). Continue? [y/N] " ans
  fi
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted"; exit 1; }
fi

REMOTE_SCRIPT=$(cat <<EOF
set -euo pipefail
MODE="$MODE"
cd "$APP_ROOT"
OWNER=\$(stat -c %U .)
G="sudo -u \$OWNER git -c safe.directory=$APP_ROOT"
DC="docker compose -f infra/clockchain-mcp/docker-compose.yml"
BEFORE=\$(\$G rev-parse HEAD)
echo "box: mode=\$MODE before=\$(\$G rev-parse --short HEAD) \$(date -u +%FT%TZ)"
DIRTY=\$(\$G status --short)
if [[ -n "\$DIRTY" ]]; then
  echo "REFUSING: the box checkout has local changes. Commit them to the repo (or preserve them on a local branch) first:"
  echo "\$DIRTY"
  exit 3
fi
\$G fetch --quiet origin main
\$G checkout --quiet --detach "$SHA"
echo "box: after=\$(\$G rev-parse --short HEAD)"
echo "box: pre-build \$(date -u +%FT%TZ)"
\$DC build mcp 2>&1 | tail -1
container_times() {
  local id
  for id in \$(\$DC ps -aq caddy host mcp); do
    docker inspect -f '{{.Name}} created={{.Created}} started={{.State.StartedAt}}' "\$id"
  done
}
if [[ "\$MODE" == "full-restart" ]]; then
  echo "box: FULL RESTART: install + systemctl restart (mcp, host, caddy recreated) \$(date -u +%FT%TZ)"
  infra/scripts/install-clockchain-mcp-deploy-assets.sh
else
  INFRA=\$(\$G diff --name-only "\$BEFORE" HEAD -- infra/clockchain-mcp/Caddyfile infra/clockchain-mcp/docker-compose.yml infra/clockchain-mcp/clockchain-mcp.service infra/scripts/install-clockchain-mcp-deploy-assets.sh)
  if [[ -n "\$INFRA" ]]; then
    echo "WARNING: this deploy changes infra files that CODE-ONLY mode does NOT apply to caddy/host:"
    echo "\$INFRA"
    echo "WARNING: run a --full-restart (after the notices) to apply them."
  fi
  echo "box: container times BEFORE (code-only):"
  container_times
  echo "box: CODE-ONLY: install deploy assets without restart, then compose-up.sh --only mcp \$(date -u +%FT%TZ)"
  infra/scripts/install-clockchain-mcp-deploy-assets.sh --no-restart
  infra/clockchain-mcp/compose-up.sh --only mcp
  echo "box: container times AFTER (code-only; caddy and host created= must be unchanged):"
  container_times
fi
echo "box: up \$(date -u +%FT%TZ) mode=\$MODE systemd=\$(systemctl is-active clockchain-mcp)"
docker ps --format '{{.Names}} {{.Status}}'
EOF
)

PARAMS=$(jq -cn --arg s "bash -s <<'EOS'
$REMOTE_SCRIPT
EOS
" '{commands: [$s], executionTimeout: ["1800"]}')
CMD_ID=$(aws --region "$AWS_REGION" ssm send-command --instance-ids "$INSTANCE_ID" --document-name AWS-RunShellScript \
  --comment "deploy clockchain-mcp $SHA $MODE (scripts/deploy-box.sh)" --parameters "$PARAMS" --query 'Command.CommandId' --output text)
echo "ssm command $CMD_ID"
STATUS=InProgress
while [[ "$STATUS" == "InProgress" || "$STATUS" == "Pending" || "$STATUS" == "Delayed" ]]; do
  sleep 10
  STATUS=$(aws --region "$AWS_REGION" ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" --query Status --output text 2>/dev/null || echo Pending)
done
aws --region "$AWS_REGION" ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" \
  --query '[StandardOutputContent,StandardErrorContent]' --output text
[[ "$STATUS" == "Success" ]] || { echo "deploy FAILED ($STATUS) — production may be on the previous build; see the runbook rollback." >&2; exit 1; }

echo "--- canaries (RUNBOOK)"
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"deploy-box","version":"0"}}}'
H=$(code "$BASE_URL/health"); echo "health $H"; [[ "$H" == 200 ]]
M=$(code "$BASE_URL/.well-known/agent-handshake.json"); echo "handshake manifest $M"; [[ "$M" == 200 ]]
# While the ACM4 demo pin is live, /handshake/mcp serves the frozen 2.1.6
# instance and the deployed build's handshake surface is /next/handshake/mcp.
HS=$(code -X POST "$BASE_URL/next/handshake/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT"); echo "handshake initialize /next (no creds) $HS"; [[ "$HS" == 200 ]]
PIN=$(code -X POST "$BASE_URL/handshake/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT"); echo "handshake initialize pinned demo (no creds) $PIN (expect 200 while the ACM4 pin is live)"
A=$(code -X POST "$BASE_URL/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT"); echo "mcp without creds $A (expect 401)"; [[ "$A" == 401 ]]

if [[ -n "${CC_MCP_TOKEN:-}" ]]; then
  echo "--- clock gates G0 (surface checks; the guard probe spends 1 credit)"
  [[ -f packages/clock-sdk/dist/index.js ]] || npm run build -w @clockchain/core -w @clockchain/clock-sdk >/dev/null
  CC_LIVE_GATES=1 CC_MCP_URL="$BASE_URL/mcp" node --test --test-name-pattern 'G0\.[0-9]' packages/clock-sdk/test/gates-live.test.mjs
else
  echo "(set CC_MCP_TOKEN to also run the G0 clock gates; full suite: CC_LIVE_GATES=1 node --test packages/clock-sdk/test/gates-live.test.mjs)"
fi
echo "deployed $SHA (mode=$MODE)"
