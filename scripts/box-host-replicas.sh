#!/usr/bin/env bash
# Run N parallel Agent Handshake v2 generic hosts on the PRODUCTION MCP box, over AWS SSM,
# WITHOUT editing docker-compose.yml and WITHOUT recreating caddy, mcp or host-1.
#
#   scripts/box-host-replicas.sh <N> [--yes] [--force]        N in 1..3
#
# Each generic host opens its own ~120 s invitation window on the shared relay (its own random
# session id), so N hosts = N sessions that can be invited into at the same time. The mcp
# coordinator picks a free one (agent-handshake-v2 multi-session invite; needs that mcp build —
# with an older mcp the extra hosts are harmless but unused except as "current").
#
# N > 1: creates clockchain-mcp-host-2..N as exact clones of clockchain-mcp-host-1 — same image ID,
#   env (copied through a 0600 file on /run, never printed, deleted on exit), user, workdir,
#   command, secret bind mount (ro), host_runs volume, network and restart policy — plus ALL of
#   host-1's compose labels with com.docker.compose.container-number=k, so compose treats them as
#   scale replicas of `host`: `docker compose down` (systemctl stop/restart) removes them, and a
#   later full `compose up` scales back to 1. Each replica is started at an offset of
#   k-1 / N of the ~121 s rotation after host-1's current session, so windows (and their ~30 s
#   dead tails) are staggered. Existing replicas are left alone.
# N = 1: removes clockchain-mcp-host-2/3. REFUSES unless the relay shows no session from the last
#   12 minutes with any message on it (a stopped host kills its live session); --force skips that.
#
# Not persistent across a full restart / reboot-time compose up (that is by design: compose only
# knows one host). Make it permanent with a compose `scale:` after the demo, with the usual notices.
# Requires: aws CLI with SSM access (user Yang), jq. Never prints secrets or env values.
set -euo pipefail

INSTANCE_ID="${CLOCKCHAIN_BOX_INSTANCE_ID:-i-0d6765d143da7e1ea}"
AWS_REGION="${AWS_REGION:-us-west-2}"

usage() { echo "usage: $0 <N 1..3> [--yes] [--force]" >&2; exit 64; }
N=""; CONFIRM=0; FORCE=0
for arg in "$@"; do
  case "$arg" in
    --yes) CONFIRM=1 ;;
    --force) FORCE=1 ;;
    -*) usage ;;
    *) [[ -z "$N" ]] || usage; N="$arg" ;;
  esac
done
[[ "$N" =~ ^[1-3]$ ]] || usage

REMOTE_BODY=$(cat <<'EOF'
set -euo pipefail
H1=clockchain-mcp-host-1
CYCLE=121
docker inspect "$H1" >/dev/null
[[ "$(docker inspect -f '{{.State.Running}}' "$H1")" == true ]] || { echo "REFUSING: $H1 is not running"; exit 3; }

relay_busy_count() {
  # Sessions opened in the last 12 min that have ANY relay message (an invitation or later).
  # Runs inside mcp-1 (node + the same relay URL); prints a single integer, never the URL.
  docker exec clockchain-mcp-mcp-1 node -e '
    const relay = (process.env.HANDSHAKE_RELAY || "").replace(/\/+$/, "");
    (async () => {
      const runs = (await (await fetch(relay + "/v1/runs")).json()).runs || [];
      const recent = runs.filter((r) => Date.now() - r.startedAtMs < 12 * 60_000);
      let busy = 0;
      for (const r of recent) {
        const m = await (await fetch(relay + "/v1/sessions/" + encodeURIComponent(r.sessionId) + "/messages?after=0&waitMs=0")).json();
        if ((m.messages || []).length > 0) busy += 1;
      }
      console.log(busy);
    })().catch(() => { console.log("unknown"); });'
}

relay_recent() {
  docker exec clockchain-mcp-mcp-1 node -e '
    const relay = (process.env.HANDSHAKE_RELAY || "").replace(/\/+$/, "");
    fetch(relay + "/v1/runs").then((r) => r.json()).then((b) => {
      for (const r of (b.runs || []).slice(0, 6)) console.log(r.sessionId.slice(0, 8), new Date(r.startedAtMs).toISOString(), r.stage);
    }).catch(() => console.log("relay unreachable"));'
}

echo "box: target N=$N $(date -u +%FT%TZ)"
docker ps -a --filter "name=^clockchain-mcp-host-" --format '{{.Names}} {{.Status}}'

if [[ "$N" == 1 ]]; then
  if [[ "$FORCE" != 1 ]]; then
    BUSY=$(relay_busy_count)
    if [[ "$BUSY" != 0 ]]; then
      echo "REFUSING: relay shows $BUSY recent session(s) with messages (live or just-finished runs); wait or use --force"
      exit 4
    fi
  fi
  for k in 2 3; do
    if docker inspect "clockchain-mcp-host-$k" >/dev/null 2>&1; then
      docker rm -f "clockchain-mcp-host-$k" >/dev/null && echo "removed clockchain-mcp-host-$k"
    fi
  done
else
  IMG=$(docker inspect -f '{{.Image}}' "$H1")
  USER_=$(docker inspect -f '{{.Config.User}}' "$H1")
  WD=$(docker inspect -f '{{.Config.WorkingDir}}' "$H1")
  SECRETS=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/keys"}}{{.Source}}{{end}}{{end}}' "$H1")
  RUNS=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/runs"}}{{.Name}}{{end}}{{end}}' "$H1")
  NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$H1")
  [[ -n "$IMG" && -n "$SECRETS" && -n "$RUNS" && -n "$NET" ]] || { echo "REFUSING: could not read host-1 config"; exit 5; }
  [[ -d "$SECRETS" ]] || { echo "REFUSING: host secret dir missing (needs a full compose-up first)"; exit 5; }
  umask 077
  ENVF=$(mktemp /run/clockchain-host-replica-env.XXXXXX)
  LABF=$(mktemp /run/clockchain-host-replica-labels.XXXXXX)
  trap 'rm -f "$ENVF" "$LABF"' EXIT
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$H1" | sed '/^$/d' > "$ENVF"
  for k in $(seq 2 "$N"); do
    NAME="clockchain-mcp-host-$k"
    if docker inspect "$NAME" >/dev/null 2>&1; then
      echo "$NAME exists ($(docker inspect -f '{{.State.Status}}' "$NAME")), left alone"
      continue
    fi
    # Stagger: start when host-1's current session is (k-1)/N of a cycle old.
    STARTED=$(date -d "$(docker inspect -f '{{.State.StartedAt}}' "$H1")" +%s)
    AGE=$(( $(date +%s) - STARTED ))
    OFFSET=$(( CYCLE * (k - 1) / N ))
    WAIT=$(( ((OFFSET - AGE) % CYCLE + CYCLE) % CYCLE ))
    echo "$NAME: host-1 session age ${AGE}s, target offset ${OFFSET}s, waiting ${WAIT}s"
    sleep "$WAIT"
    docker inspect -f '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}' "$H1" \
      | grep '^com\.docker\.compose\.' | grep -v '^com\.docker\.compose\.container-number=' > "$LABF"
    echo "com.docker.compose.container-number=$k" >> "$LABF"
    docker run -d --name "$NAME" --restart unless-stopped --network "$NET" --network-alias "$NAME" \
      --user "$USER_" --workdir "$WD" --memory 256m \
      --env-file "$ENVF" --label-file "$LABF" \
      -v "$SECRETS:/app/keys:ro" -v "$RUNS:/app/runs" \
      "$IMG" node bin/agent-handshake-host.mjs >/dev/null
    echo "started $NAME"
  done
  sleep 8
fi

echo "--- host containers"
docker ps -a --filter "name=^clockchain-mcp-host-" --format '{{.Names}} {{.Status}} {{.Image}}'
docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' | grep -E 'host-|mcp-mcp-1' || true
free -m 2>/dev/null | sed -n 1,3p || true
echo "--- relay: newest sessions (each host opens one every ~2 min; with N hosts expect N in each ~2 min)"
relay_recent
EOF
)

REMOTE_SCRIPT="N=$(printf %q "$N")
FORCE=$(printf %q "$FORCE")
$REMOTE_BODY"

if [[ "${BOX_REPLICAS_RENDER_ONLY:-0}" == "1" ]]; then
  printf '%s\n' "$REMOTE_SCRIPT"; exit 0
fi
command -v aws >/dev/null || { echo "aws CLI required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
if [[ "$CONFIRM" != 1 ]]; then
  read -r -p "Set generic v2 hosts on $INSTANCE_ID to N=$N (caddy/mcp/host-1 untouched)? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted"; exit 1; }
fi
PARAMS=$(jq -cn --arg s "bash -s <<'EOS'
$REMOTE_SCRIPT
EOS
" '{commands: [$s], executionTimeout: ["900"]}')
CMD_ID=$(aws --region "$AWS_REGION" ssm send-command --instance-ids "$INSTANCE_ID" --document-name AWS-RunShellScript \
  --comment "generic v2 hosts N=$N (scripts/box-host-replicas.sh)" --parameters "$PARAMS" --query 'Command.CommandId' --output text)
echo "ssm command $CMD_ID"
STATUS=InProgress
while [[ "$STATUS" == "InProgress" || "$STATUS" == "Pending" || "$STATUS" == "Delayed" ]]; do
  sleep 10
  STATUS=$(aws --region "$AWS_REGION" ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" --query Status --output text 2>/dev/null || echo Pending)
done
aws --region "$AWS_REGION" ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" --output json \
  | jq -r '.StandardOutputContent // "", .StandardErrorContent // ""'
[[ "$STATUS" == "Success" ]] || { echo "box-host-replicas FAILED ($STATUS)" >&2; exit 1; }
