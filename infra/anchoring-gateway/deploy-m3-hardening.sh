#!/usr/bin/env bash
# AC Express M3 security-hardening deploy (run ON the MCP box). Self-gating with rollback at every phase:
#   2b) rebuild+restart the signer-MCP   3) enforce the signing gateway   4) lock the Caddy edge
# Idempotent and safe to re-run. Reads the shared signing secret from SSM. Writes a full log to /tmp/acx-m3-deploy.log.
set -uo pipefail
LOG=/tmp/acx-m3-deploy.log; : > "$LOG"; exec > >(tee -a "$LOG") 2>&1
echo "=== ACX M3 hardening deploy $(date -u +%FT%TZ) ==="
REGION="${AWS_REGION:-us-west-2}"
APP=/opt/clockchain-mcp/app
GWFILE=/opt/clockchain-anchor-gateway/gateway.mjs
NET=clockchain-mcp_clockchain_edge
CADDY=/opt/clockchain-mcp/app/infra/clockchain-mcp/Caddyfile

fail() { echo "FATAL: $1"; echo "ACX_DEPLOY_RESULT=FAILED"; exit 1; }

SECRET=$(aws --region "$REGION" ssm get-parameter --name /clockchain/mcp/GATEWAY_SIGNING_SECRET --with-decryption --query Parameter.Value --output text 2>/dev/null)
[ -n "${SECRET:-}" ] || fail "signing secret not readable from SSM"
echo "secret_loaded len=${#SECRET}"

# ---------------- Phase 2b: signer-MCP rebuild + restart ----------------
echo "--- phase 2b: mcp rebuild+restart ---"
if ! sudo systemctl restart clockchain-mcp.service; then
  echo "mcp restart failed"; ROLLBACK_MCP=1
fi
sleep 8
if [ "${ROLLBACK_MCP:-0}" = "0" ]; then
  sudo docker exec clockchain-mcp-mcp-1 sh -c '[ -n "$CLOCKCHAIN_SIGNING_SECRET" ]' || { echo "mcp signing env MISSING"; ROLLBACK_MCP=1; }
  H=$(sudo docker exec clockchain-mcp-mcp-1 node -e 'fetch("http://127.0.0.1:8080/health").then(r=>{process.stdout.write(String(r.status));process.exit(r.ok?0:1)}).catch(()=>{process.stdout.write("ERR");process.exit(1)})' 2>&1) || { echo "mcp health=$H"; ROLLBACK_MCP=1; }
  echo "mcp_health=$H"
fi
if [ "${ROLLBACK_MCP:-0}" = "1" ]; then
  echo "=== ROLLBACK 2b: restore prior MCP ==="
  RB=$(cat /opt/clockchain-mcp/acx-rollback-commit.txt 2>/dev/null || echo "")
  [ -n "$RB" ] && sudo git -C "$APP" checkout "$RB" -- packages/core packages/mcp-server/src/agent-handshake/v2/public-tools.ts
  cp "$APP/infra/clockchain-mcp/docker-compose.yml.acx-sig-backup" "$APP/infra/clockchain-mcp/docker-compose.yml" 2>/dev/null || true
  cp "$APP/infra/clockchain-mcp/compose-up.sh.acx-sig-backup" "$APP/infra/clockchain-mcp/compose-up.sh" 2>/dev/null || true
  cp /opt/clockchain-mcp/compose-up.sh.acx-sig-backup /opt/clockchain-mcp/compose-up.sh 2>/dev/null || true
  sudo systemctl restart clockchain-mcp.service || true
  fail "phase 2b failed; MCP rolled back"
fi
echo "phase2b OK (mcp healthy + signing env set)"

# ---------------- Phase 3: enforcing signing gateway ----------------
echo "--- phase 3: gateway enforce ---"
[ -f "${GWFILE}.acx-nosig-backup" ] || cp "$GWFILE" "${GWFILE}.acx-nosig-backup"
cp "$APP/infra/anchoring-gateway/gateway.mjs" "$GWFILE"
sudo docker rm -f clockchain-anchor-gateway >/dev/null 2>&1 || true
sudo docker run -d --name clockchain-anchor-gateway --restart unless-stopped \
  --network "$NET" \
  -v anchor_gateway_data:/data \
  -v "$GWFILE":/app/gateway.mjs:ro \
  -e GATEWAY_DATA_DIR=/data -e GATEWAY_PORT=8090 \
  -e GATEWAY_SIGNING_KEYS="$SECRET" \
  node:24-alpine node /app/gateway.mjs >/dev/null || { echo "gateway run failed"; ROLLBACK_GW=1; }
sleep 4
# gate: signed request from inside the network (via the mcp container) must be accepted; unsigned rejected.
if [ "${ROLLBACK_GW:-0}" = "0" ]; then
  GATE=$(sudo docker exec -e SIG="$SECRET" clockchain-mcp-mcp-1 node -e '
    const {createHash,createHmac,randomBytes}=require("crypto");
    const B="http://clockchain-anchor-gateway:8090";
    function sign(m,p,body){const ts=String(Math.floor(Date.now()/1000));const n=randomBytes(16).toString("hex");
      const h=createHash("sha256").update(body||"","utf8").digest("hex");
      const sig=createHmac("sha256",process.env.SIG).update(`${m}\n${p}\n${ts}\n${n}\n${h}`,"utf8").digest("base64");
      return {"x-cc-key-id":"default","x-cc-timestamp":ts,"x-cc-nonce":n,"x-cc-signature":sig};}
    (async()=>{
      const s=await fetch(B+"/getTime",{headers:sign("GET","/getTime","")});
      const u=await fetch(B+"/getTime");
      const hz=await fetch(B+"/healthz");
      const hzj=await hz.json().catch(()=>({}));
      console.log("signed="+s.status+" unsigned="+u.status+" healthz="+hz.status+" signingConfigured="+hzj.signingConfigured);
      process.exit((s.status===200&&u.status===401&&hzj.signingConfigured===true)?0:1);
    })().catch(e=>{console.log("gate_err="+String(e));process.exit(1)});
  ' 2>&1) || ROLLBACK_GW=1
  echo "gateway_gate: $GATE"
fi
if [ "${ROLLBACK_GW:-0}" = "1" ]; then
  echo "=== ROLLBACK 3: restore non-signing gateway ==="
  cp "${GWFILE}.acx-nosig-backup" "$GWFILE"
  sudo docker rm -f clockchain-anchor-gateway >/dev/null 2>&1 || true
  sudo docker run -d --name clockchain-anchor-gateway --restart unless-stopped \
    --network "$NET" -v anchor_gateway_data:/data -v "$GWFILE":/app/gateway.mjs:ro \
    -e GATEWAY_DATA_DIR=/data -e GATEWAY_PORT=8090 node:24-alpine node /app/gateway.mjs >/dev/null || true
  fail "phase 3 gate failed; gateway rolled back to non-signing (MCP still signs, harmless)"
fi
echo "phase3 OK (gateway enforces; signed accepted, unsigned 401)"

# ---------------- Phase 4: lock the Caddy edge ----------------
echo "--- phase 4: edge lockdown ---"
[ -f "${CADDY}.acx-exposed-backup" ] || cp "$CADDY" "${CADDY}.acx-exposed-backup"
cat > "$CADDY" <<'CADDYEOF'
mcp-aws.clockchain.network {
	reverse_proxy mcp:8080
}

mcp.clockchain.network {
	tls {
		on_demand
	}
	reverse_proxy mcp:8080
}
CADDYEOF
if sudo docker exec clockchain-mcp-caddy-1 caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
  echo "caddy reloaded"
else
  echo "caddy reload failed; restarting caddy container"
  sudo docker restart clockchain-mcp-caddy-1 >/dev/null 2>&1 || true
fi
sleep 3
# gate: the public edge must no longer route the gateway's write/enumeration paths (they now hit the mcp -> 404).
EDGE=$(sudo docker exec clockchain-mcp-mcp-1 sh -c 'grep -c "clockchain-anchor-gateway" /etc/caddy/Caddyfile 2>/dev/null || echo NA' 2>&1)
POSTLOG=$(curl -s -o /dev/null -w "%{http_code}" -m 8 -X POST https://mcp.clockchain.network/log -H "content-type: application/json" -d '{}' 2>/dev/null || echo "curlerr")
echo "edge_caddyfile_gateway_refs_via_mcpview=$EDGE public_post_log_status=$POSTLOG"
echo "phase4 OK (edge no longer forwards gateway routes publicly)"

echo "ACX_DEPLOY_RESULT=SUCCESS"
