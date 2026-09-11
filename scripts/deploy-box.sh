#!/usr/bin/env bash
# Deploy a commit of this repo to the PRODUCTION MCP box (mcp.clockchain.network) over AWS SSM.
#
# This is RUNBOOK step 3 (infra/clockchain-mcp/RUNBOOK.md) as one command, with the guard rails
# learned on 2026-09-11: the box is the AWS EC2 instance running Caddy + docker-compose; the GitHub
# "Deploy MCP to Cloud Run" workflow is NOT production.
#
#   scripts/deploy-box.sh <commit-sha> [--yes]
#
# What it does, on the box, as root via SSM Run Command:
#   1. refuses to run if the checkout at /opt/clockchain-mcp/app has local changes (prints them) —
#      a blind checkout once nearly reverted production's gateway wiring; commit the box's edits to
#      the repo instead (they are in git since PR "D8")
#   2. git fetch + checkout --detach <sha> as the checkout owner
#   3. pre-builds the mcp image (no downtime), then runs the installer which refreshes the systemd
#      wrapper + unit and restarts the stack (~seconds of downtime for /mcp and the handshake surface)
#   4. prints container status
# Then, from this machine: the runbook canaries and the read-only clock gates G0.1–G0.5
# (needs CC_MCP_TOKEN for the gates; skipped if unset).
#
# Requires: aws CLI with SSM access to the instance (user Yang works), jq. Never prints secrets.
set -euo pipefail

INSTANCE_ID="${CLOCKCHAIN_BOX_INSTANCE_ID:-i-0d6765d143da7e1ea}"
AWS_REGION="${AWS_REGION:-us-west-2}"
APP_ROOT="${CLOCKCHAIN_MCP_APP_ROOT:-/opt/clockchain-mcp/app}"
BASE_URL="${CLOCKCHAIN_MCP_URL:-https://mcp.clockchain.network}"
SHA="${1:-}"
CONFIRM="${2:-}"

usage() { echo "usage: $0 <full-commit-sha> [--yes]" >&2; exit 64; }
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || usage
command -v aws >/dev/null || { echo "aws CLI required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

# The commit must exist on origin/main (deploy what was reviewed, not a local branch).
git fetch -q origin main
git merge-base --is-ancestor "$SHA" origin/main || { echo "$SHA is not on origin/main — merge it first." >&2; exit 1; }
echo "deploying $(git log -1 --format='%h %s' "$SHA") to $INSTANCE_ID ($BASE_URL)"
if [[ "$CONFIRM" != "--yes" ]]; then
  read -r -p "This restarts production (/mcp + handshake surface, ~seconds). Continue? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted"; exit 1; }
fi

REMOTE_SCRIPT=$(cat <<EOF
set -euo pipefail
cd "$APP_ROOT"
OWNER=\$(stat -c %U .)
G="sudo -u \$OWNER git -c safe.directory=$APP_ROOT"
echo "box: before=\$(\$G rev-parse --short HEAD) \$(date -u +%FT%TZ)"
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
docker compose -f infra/clockchain-mcp/docker-compose.yml build mcp 2>&1 | tail -1
echo "box: install + restart \$(date -u +%FT%TZ)"
infra/scripts/install-clockchain-mcp-deploy-assets.sh
echo "box: up \$(date -u +%FT%TZ) systemd=\$(systemctl is-active clockchain-mcp)"
docker ps --format '{{.Names}} {{.Status}}'
EOF
)

PARAMS=$(jq -cn --arg s "bash -s <<'EOS'
$REMOTE_SCRIPT
EOS
" '{commands: [$s], executionTimeout: ["1800"]}')
CMD_ID=$(aws --region "$AWS_REGION" ssm send-command --instance-ids "$INSTANCE_ID" --document-name AWS-RunShellScript \
  --comment "deploy clockchain-mcp $SHA (scripts/deploy-box.sh)" --parameters "$PARAMS" --query 'Command.CommandId' --output text)
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
HS=$(code -X POST "$BASE_URL/handshake/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT"); echo "handshake initialize (no creds) $HS"; [[ "$HS" == 200 ]]
A=$(code -X POST "$BASE_URL/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT"); echo "mcp without creds $A (expect 401)"; [[ "$A" == 401 ]]

if [[ -n "${CC_MCP_TOKEN:-}" ]]; then
  echo "--- clock gates G0 (surface checks; the guard probe spends 1 credit)"
  [[ -f packages/clock-sdk/dist/index.js ]] || npm run build -w @clockchain/core -w @clockchain/clock-sdk >/dev/null
  CC_LIVE_GATES=1 CC_MCP_URL="$BASE_URL/mcp" node --test --test-name-pattern 'G0' packages/clock-sdk/test/gates-live.test.mjs
else
  echo "(set CC_MCP_TOKEN to also run the G0 clock gates; full suite: CC_LIVE_GATES=1 node --test packages/clock-sdk/test/gates-live.test.mjs)"
fi
echo "deployed $SHA"
