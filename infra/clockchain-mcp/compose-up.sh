#!/usr/bin/env bash
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
APP_ROOT="${CLOCKCHAIN_MCP_APP_ROOT:-/opt/clockchain-mcp/app}"
DEPLOY_DIR="${CLOCKCHAIN_MCP_DEPLOY_DIR:-${APP_ROOT}/infra/clockchain-mcp}"
COMPOSE_FILE="${CLOCKCHAIN_MCP_COMPOSE_FILE:-${DEPLOY_DIR}/docker-compose.yml}"
SECRET_SENTINEL=$'\001clockchain-mcp-secret-end\001'

fetch_secret() {
  local parameter_name="$1"

  aws --region "$AWS_REGION" ssm get-parameter \
    --name "$parameter_name" \
    --with-decryption \
    --output json |
    jq -j --arg sentinel "$SECRET_SENTINEL" '.Parameter.Value, $sentinel'
}

read_secret() {
  local env_name="$1"
  local parameter_name="$2"
  local payload value
  if ! payload="$(fetch_secret "$parameter_name")"; then
    printf 'failed to fetch required SSM parameter: %s\n' "$parameter_name" >&2
    return 1
  fi
  if [[ "$payload" != *"$SECRET_SENTINEL" ]]; then
    printf 'missing secret sentinel for required SSM parameter: %s\n' "$parameter_name" >&2
    return 1
  fi
  value="${payload%"$SECRET_SENTINEL"}"
  printf -v "$env_name" '%s' "$value"
  export "$env_name"
}

read_secret CLOCKCHAIN_API_KEY /clockchain/mcp/CLOCKCHAIN_API_KEY
read_secret MCP_AUTH_TOKENS /clockchain/mcp/MCP_AUTH_TOKENS
read_secret MCP_TOKEN_SIGNING_SECRET /clockchain/mcp/MCP_TOKEN_SIGNING_SECRET

export PORT=8080
export MCP_TRANSPORT=http
export MCP_REQUIRE_AUTH=1
export MCP_RATE_PER_MIN=30
export MCP_LOG_BUDGET=5000
export MCP_TOKEN_MINT_PER_HOUR=10
export CLOCKCHAIN_CLIENT_ID=thetangstr@gmail.com
export CLOCKCHAIN_WALLET_ID=thetangstr@gmail.com
export CLOCKCHAIN_ENDPOINT=https://node.clockchain.network
export ERC8004_REGISTRY_ADDRESS=0x8004A818BFB912233c491871b3d84c89A494BD9e

cd "$DEPLOY_DIR"
exec docker compose -f "$COMPOSE_FILE" up -d --build --wait --wait-timeout 180
