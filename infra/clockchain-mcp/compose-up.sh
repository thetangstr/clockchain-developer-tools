#!/usr/bin/env bash
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
APP_ROOT="${CLOCKCHAIN_MCP_APP_ROOT:-/opt/clockchain-mcp/app}"
DEPLOY_DIR="${CLOCKCHAIN_MCP_DEPLOY_DIR:-${APP_ROOT}/infra/clockchain-mcp}"
COMPOSE_FILE="${CLOCKCHAIN_MCP_COMPOSE_FILE:-${DEPLOY_DIR}/docker-compose.yml}"
HANDSHAKE_APP_ROOT="${HANDSHAKE_APP_ROOT:-/opt/clockchain-host/app}"
HANDSHAKE_RELAY="${HANDSHAKE_RELAY:-http://44.249.47.220:8080}"
HANDSHAKE_KIT_REPO="${HANDSHAKE_KIT_REPO:-https://github.com/thetangstr/clockchain-handshake-v2.git}"
CLOCKCHAIN_HOST_SECRET_DIR="${CLOCKCHAIN_HOST_SECRET_DIR:-/run/clockchain-host-secrets}"
CLOCKCHAIN_HOST_UID="${CLOCKCHAIN_HOST_UID:-1000}"
CLOCKCHAIN_HOST_GID="${CLOCKCHAIN_HOST_GID:-1000}"
CLOCKCHAIN_HOST_FUNDING_WALLET_JSON_PARAM="${CLOCKCHAIN_HOST_FUNDING_WALLET_JSON_PARAM:-/clockchain/host/FUNDING_WALLET_JSON}"
CLOCKCHAIN_HOST_FUNDING_WALLET_PUBLIC_JSON_PARAM="${CLOCKCHAIN_HOST_FUNDING_WALLET_PUBLIC_JSON_PARAM:-/clockchain/host/FUNDING_WALLET_PUBLIC_JSON}"
CLOCKCHAIN_HOST_FUNDING_PASSWORD_PARAM="${CLOCKCHAIN_HOST_FUNDING_PASSWORD_PARAM:-/clockchain/host/FUNDING_PASSWORD}"
CLOCKCHAIN_HOST_CLOCKCHAIN_TOKEN_PARAM="${CLOCKCHAIN_HOST_CLOCKCHAIN_TOKEN_PARAM:-/clockchain/host/CLOCKCHAIN_TOKEN}"
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

fetch_host_secret_value() {
  local env_name="$1" parameter_name="$2" payload value
  if ! payload="$(fetch_secret "$parameter_name")"; then
    printf 'failed to fetch required SSM parameter: %s\n' "$parameter_name" >&2
    return 1
  fi
  if [[ "$payload" != *"$SECRET_SENTINEL" ]]; then
    printf 'missing secret sentinel for required SSM parameter: %s\n' "$parameter_name" >&2
    return 1
  fi
  value="${payload%"$SECRET_SENTINEL"}"
  if [[ -z "$value" ]]; then
    printf 'required SSM parameter is empty: %s\n' "$parameter_name" >&2
    return 1
  fi
  printf -v "$env_name" '%s' "$value"
}

stage_secret_file() {
  local stage_dir="$1" file_name="$2" value="$3" target

  target="${stage_dir}/${file_name}"
  install -m 0600 /dev/null "$target"
  printf '%s' "$value" > "$target"
  chmod 0600 "$target"
  if [[ "$(id -u)" == "0" ]]; then
    chown "${CLOCKCHAIN_HOST_UID}:${CLOCKCHAIN_HOST_GID}" "$target"
  fi
}

require_nonempty() {
  local name="$1" value="$2"
  if [[ -z "$value" ]]; then
    printf 'missing required configuration: %s\n' "$name" >&2
    return 1
  fi
}

validate_handshake_checkout() {
  require_nonempty HANDSHAKE_APP_ROOT "$HANDSHAKE_APP_ROOT"
  require_nonempty HANDSHAKE_RELAY "$HANDSHAKE_RELAY"
  require_nonempty HANDSHAKE_KIT_REPO "$HANDSHAKE_KIT_REPO"

  local actual_sha status
  if ! git -C "$HANDSHAKE_APP_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'handshake app root is not a git checkout: %s\n' "$HANDSHAKE_APP_ROOT" >&2
    return 1
  fi
  actual_sha="$(git -C "$HANDSHAKE_APP_ROOT" rev-parse HEAD)"
  HANDSHAKE_SHA="${HANDSHAKE_SHA:-$actual_sha}"
  if [[ ! "$actual_sha" =~ ^[0-9a-f]{40}$ || ! "$HANDSHAKE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'handshake checkout SHA is not a 40-character lowercase hex value\n' >&2
    return 1
  fi
  if [[ "$actual_sha" != "$HANDSHAKE_SHA" ]]; then
    printf 'handshake checkout SHA mismatch: expected %s, got %s\n' "$HANDSHAKE_SHA" "$actual_sha" >&2
    return 1
  fi
  status="$(git -C "$HANDSHAKE_APP_ROOT" status --porcelain)"
  if [[ -n "$status" ]]; then
    printf 'handshake checkout has uncommitted changes: %s\n' "$HANDSHAKE_APP_ROOT" >&2
    return 1
  fi

  export HANDSHAKE_APP_ROOT
  export HANDSHAKE_RELAY
  export HANDSHAKE_KIT_REPO
  export HANDSHAKE_SHA
}

materialize_host_secrets() {
  local funding_wallet_json funding_wallet_public_json funding_password clockchain_token
  local stage_dir

  fetch_host_secret_value funding_wallet_json "$CLOCKCHAIN_HOST_FUNDING_WALLET_JSON_PARAM"
  fetch_host_secret_value funding_wallet_public_json "$CLOCKCHAIN_HOST_FUNDING_WALLET_PUBLIC_JSON_PARAM"
  fetch_host_secret_value funding_password "$CLOCKCHAIN_HOST_FUNDING_PASSWORD_PARAM"
  fetch_host_secret_value clockchain_token "$CLOCKCHAIN_HOST_CLOCKCHAIN_TOKEN_PARAM"

  mkdir -p "$CLOCKCHAIN_HOST_SECRET_DIR"
  chmod 0700 "$CLOCKCHAIN_HOST_SECRET_DIR"
  if [[ "$(id -u)" == "0" ]]; then
    chown "${CLOCKCHAIN_HOST_UID}:${CLOCKCHAIN_HOST_GID}" "$CLOCKCHAIN_HOST_SECRET_DIR"
  fi

  stage_dir="$(mktemp -d "${CLOCKCHAIN_HOST_SECRET_DIR}/.stage.XXXXXX")"
  trap 'rm -rf "$stage_dir"' RETURN
  chmod 0700 "$stage_dir"
  stage_secret_file "$stage_dir" funding-wallet.json "$funding_wallet_json"
  stage_secret_file "$stage_dir" funding-wallet.public.json "$funding_wallet_public_json"
  stage_secret_file "$stage_dir" funding.password "$funding_password"
  stage_secret_file "$stage_dir" clockchain.token "$clockchain_token"

  mv -f "${stage_dir}/funding-wallet.json" "${CLOCKCHAIN_HOST_SECRET_DIR}/funding-wallet.json"
  mv -f "${stage_dir}/funding-wallet.public.json" "${CLOCKCHAIN_HOST_SECRET_DIR}/funding-wallet.public.json"
  mv -f "${stage_dir}/funding.password" "${CLOCKCHAIN_HOST_SECRET_DIR}/funding.password"
  mv -f "${stage_dir}/clockchain.token" "${CLOCKCHAIN_HOST_SECRET_DIR}/clockchain.token"
  rm -rf "$stage_dir"
  trap - RETURN

  export CLOCKCHAIN_HOST_SECRET_DIR
  export CLOCKCHAIN_FUNDING_PASSWORD_FILE=/app/keys/funding.password
}

read_secret CLOCKCHAIN_API_KEY /clockchain/mcp/CLOCKCHAIN_API_KEY
read_secret MCP_AUTH_TOKENS /clockchain/mcp/MCP_AUTH_TOKENS
read_secret MCP_TOKEN_SIGNING_SECRET /clockchain/mcp/MCP_TOKEN_SIGNING_SECRET
validate_handshake_checkout
materialize_host_secrets

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
