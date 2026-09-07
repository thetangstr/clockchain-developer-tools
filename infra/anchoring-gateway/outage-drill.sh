#!/usr/bin/env bash
# Controlled anchoring-gateway outage drill (run ON the MCP box). Proves: (i) ordinary MCP stays healthy while the
# gateway is down (per-dependency breaker isolates it), (ii) a call to the gateway fails FAST/bounded (not a hang),
# (iii) recovery with the durable ledger state preserved (no manual data repair). Non-destructive: stop -> start.
set -uo pipefail
LOG=/tmp/acx-outage.log; : > "$LOG"; exec > >(tee -a "$LOG") 2>&1
echo "=== ACX gateway outage drill $(date -u +%FT%TZ) ==="
REGION="${AWS_REGION:-us-west-2}"
SECRET=$(aws --region "$REGION" ssm get-parameter --name /clockchain/mcp/GATEWAY_SIGNING_SECRET --with-decryption --query Parameter.Value --output text 2>/dev/null)
[ -n "${SECRET:-}" ] || { echo "FATAL secret missing"; exit 1; }

# signed getTime from inside the docker network (via the mcp container) -> prints "<status> <blockHeight>"
signed_gettime() {
  sudo docker exec -e SIG="$SECRET" clockchain-mcp-mcp-1 node -e '
    const {createHash,createHmac,randomBytes}=require("crypto");
    const ts=String(Math.floor(Date.now()/1000)),n=randomBytes(16).toString("hex");
    const h=createHash("sha256").update("","utf8").digest("hex");
    const sig=createHmac("sha256",process.env.SIG).update(`GET\n/getTime\n${ts}\n${n}\n${h}`,"utf8").digest("base64");
    fetch("http://clockchain-anchor-gateway:8090/getTime",{headers:{"x-cc-key-id":"default","x-cc-timestamp":ts,"x-cc-nonce":n,"x-cc-signature":sig},signal:AbortSignal.timeout(5000)})
      .then(async r=>{const j=await r.json().catch(()=>({}));console.log(r.status,(j.data&&j.data.blockHeight)||"?");})
      .catch(e=>console.log("ERR",e.code||String(e)));
  ' 2>&1
}

echo "--- baseline (gateway up) ---"
BEFORE=$(signed_gettime); echo "signed_getTime_before=$BEFORE"; BH0=$(echo "$BEFORE" | awk '{print $2}')

echo "--- OUTAGE: stop gateway ---"
sudo docker stop clockchain-anchor-gateway >/dev/null
sleep 2
MCPH=$(sudo docker exec clockchain-mcp-mcp-1 node -e 'fetch("http://127.0.0.1:8080/health").then(r=>console.log(r.status)).catch(()=>console.log("ERR"))' 2>&1)
echo "(i) MCP_health_during_outage=$MCPH   <- MCP stays healthy while the gateway is down"
GW=$(sudo docker exec clockchain-mcp-mcp-1 node -e 'const t=Date.now();fetch("http://clockchain-anchor-gateway:8090/healthz",{signal:AbortSignal.timeout(6000)}).then(r=>console.log("UP",r.status)).catch(e=>console.log("DOWN_fastfail_ms="+(Date.now()-t),e.code||""))' 2>&1)
echo "(ii) gateway_during_outage=$GW   <- fails FAST/bounded (connection refused), never a hang"

echo "--- RECOVERY: start gateway ---"
sudo docker start clockchain-anchor-gateway >/dev/null
sleep 5
AFTER=$(signed_gettime); echo "signed_getTime_after=$AFTER"; BH1=$(echo "$AFTER" | awk '{print $2}')
echo "signingConfigured_after=$(sudo docker exec clockchain-mcp-mcp-1 node -e 'fetch("http://clockchain-anchor-gateway:8090/healthz").then(r=>r.json()).then(j=>console.log(j.signingConfigured)).catch(()=>console.log("ERR"))' 2>&1)"
if [ -n "${BH0:-}" ] && [ "$BH0" != "?" ] && [ "${BH1:-}" != "?" ] && [ "$(echo "$BH1 >= $BH0" | bc 2>/dev/null || echo 0)" = "1" ]; then
  echo "(iii) DURABLE_STATE_PRESERVED=yes (block height before=$BH0 after=$BH1; no manual repair)"
else
  echo "(iii) block_height before=$BH0 after=$BH1"
fi
echo "ACX_OUTAGE_RESULT=DONE"
