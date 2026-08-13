#!/usr/bin/env bash
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-west-2}"
APP_ROOT="${CLOCKCHAIN_MCP_APP_ROOT:-/opt/clockchain-mcp/app}"
DEPLOY_DIR="${CLOCKCHAIN_MCP_DEPLOY_DIR:-${APP_ROOT}/infra/clockchain-mcp}"
COMPOSE_FILE="${CLOCKCHAIN_MCP_COMPOSE_FILE:-${DEPLOY_DIR}/docker-compose.yml}"
HANDSHAKE_APP_ROOT="${HANDSHAKE_APP_ROOT:-/opt/clockchain-host/app}"
HANDSHAKE_RELAY="${HANDSHAKE_RELAY:-http://44.249.47.220:8080}"
MCP_HANDSHAKE_FILE=/app/state/handshake.json
HANDSHAKE_ALLOW_DEGRADED="${HANDSHAKE_ALLOW_DEGRADED:-false}"
EVM_RPC_URL="${EVM_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
HANDSHAKE_KIT_REPO="${HANDSHAKE_KIT_REPO:-https://github.com/thetangstr/clockchain-handshake-v2.git}"
CLOCKCHAIN_HOST_SECRET_DIR="${CLOCKCHAIN_HOST_SECRET_DIR:-/run/clockchain-host-secrets}"
CLOCKCHAIN_HOST_UID="${CLOCKCHAIN_HOST_UID:-1000}"
CLOCKCHAIN_HOST_GID="${CLOCKCHAIN_HOST_GID:-1000}"
CLOCKCHAIN_HOST_FUNDING_WALLET_JSON_PARAM="${CLOCKCHAIN_HOST_FUNDING_WALLET_JSON_PARAM:-/clockchain/host/FUNDING_WALLET_JSON}"
CLOCKCHAIN_HOST_FUNDING_WALLET_PUBLIC_JSON_PARAM="${CLOCKCHAIN_HOST_FUNDING_WALLET_PUBLIC_JSON_PARAM:-/clockchain/host/FUNDING_WALLET_PUBLIC_JSON}"
CLOCKCHAIN_HOST_FUNDING_PASSWORD_PARAM="${CLOCKCHAIN_HOST_FUNDING_PASSWORD_PARAM:-/clockchain/host/FUNDING_PASSWORD}"
CLOCKCHAIN_HOST_CLOCKCHAIN_TOKEN_PARAM="${CLOCKCHAIN_HOST_CLOCKCHAIN_TOKEN_PARAM:-/clockchain/host/CLOCKCHAIN_TOKEN}"
CLOCKCHAIN_HOST_ROOT_KEY_PARAM="${CLOCKCHAIN_HOST_ROOT_KEY_PARAM:-/clockchain/host/AGENT_HANDSHAKE_V2_HOST_ROOT_KEY}"
CLOCKCHAIN_HOST_ROOT_KEY_ID="${CLOCKCHAIN_HOST_ROOT_KEY_ID:-root-2026-08}"
AGENT_HANDSHAKE_V2_FUNDING_MAX_HOURLY_ETH="${AGENT_HANDSHAKE_V2_FUNDING_MAX_HOURLY_ETH:-0.20}"
AGENT_HANDSHAKE_RELEASE_PIN_PARAM="${AGENT_HANDSHAKE_RELEASE_PIN_PARAM:-/clockchain/mcp/AGENT_HANDSHAKE_RELEASE_PIN}"
AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE_PARAM="${AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE_PARAM:-/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE}"
AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS_PARAM="${AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS_PARAM:-/clockchain/mcp/AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS}"
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

handshake_git() {
  git -c "safe.directory=${HANDSHAKE_APP_ROOT}" -C "$HANDSHAKE_APP_ROOT" "$@"
}

validate_handshake_checkout() {
  require_nonempty HANDSHAKE_APP_ROOT "$HANDSHAKE_APP_ROOT"
  require_nonempty HANDSHAKE_RELAY "$HANDSHAKE_RELAY"
  require_nonempty HANDSHAKE_KIT_REPO "$HANDSHAKE_KIT_REPO"

  local actual_sha status
  if ! handshake_git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'handshake app root is not a git checkout: %s\n' "$HANDSHAKE_APP_ROOT" >&2
    return 1
  fi
  actual_sha="$(handshake_git rev-parse HEAD)"
  HANDSHAKE_SHA="${HANDSHAKE_SHA:-$actual_sha}"
  if [[ ! "$actual_sha" =~ ^[0-9a-f]{40}$ || ! "$HANDSHAKE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'handshake checkout SHA is not a 40-character lowercase hex value\n' >&2
    return 1
  fi
  if [[ "$actual_sha" != "$HANDSHAKE_SHA" ]]; then
    printf 'handshake checkout SHA mismatch: expected %s, got %s\n' "$HANDSHAKE_SHA" "$actual_sha" >&2
    return 1
  fi
  status="$(handshake_git status --porcelain)"
  if [[ -n "$status" ]]; then
    printf 'handshake checkout has uncommitted changes: %s\n' "$HANDSHAKE_APP_ROOT" >&2
    return 1
  fi

  export HANDSHAKE_APP_ROOT
  export HANDSHAKE_RELAY
  export HANDSHAKE_KIT_REPO
  export HANDSHAKE_SHA
}

validate_mcp_runtime_config() {
  require_nonempty HANDSHAKE_RELAY "$HANDSHAKE_RELAY"
  require_nonempty MCP_HANDSHAKE_FILE "$MCP_HANDSHAKE_FILE"
  require_nonempty EVM_RPC_URL "$EVM_RPC_URL"
  require_nonempty CLOCKCHAIN_HOST_ROOT_KEY_ID "$CLOCKCHAIN_HOST_ROOT_KEY_ID"
  case "$HANDSHAKE_ALLOW_DEGRADED" in
    true|false) ;;
    *)
      printf 'HANDSHAKE_ALLOW_DEGRADED must be true or false\n' >&2
      return 1
      ;;
  esac

  export HANDSHAKE_RELAY
  export MCP_HANDSHAKE_FILE
  export HANDSHAKE_ALLOW_DEGRADED
  export EVM_RPC_URL
  export CLOCKCHAIN_HOST_ROOT_KEY_ID
  export AGENT_HANDSHAKE_V2_FUNDING_MAX_HOURLY_ETH
}

validate_v2_server_config() {
  local release_filter access_filter active_kid previous_kid
  release_filter='type == "object" and (keys | sort) == ["allowedAssetPrefix","hostRoots","manifestDigest","sourceCommit","version"] and .version == "2.1.2" and (.sourceCommit | test("^[0-9a-f]{40}$")) and (.manifestDigest | test("^[0-9a-f]{64}$")) and .allowedAssetPrefix == "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/" and (.hostRoots | type == "array" and length >= 1 and length <= 2 and all(.[]; type == "object" and (keys | sort) == ["fingerprint","kid"] and (.kid | test("^[a-z0-9][a-z0-9-]{0,63}$")) and (.fingerprint | test("^[0-9a-f]{64}$"))))'
  access_filter='type == "object" and (keys | sort) == ["kid","secretBase64"] and (.kid | test("^[a-z0-9][a-z0-9-]{0,63}$")) and (.secretBase64 | @base64d | length >= 32)'

  if ! jq -e "$release_filter" >/dev/null 2>&1 <<<"$AGENT_HANDSHAKE_RELEASE_PIN"; then
    printf 'invalid AGENT_HANDSHAKE_RELEASE_PIN configuration\n' >&2
    return 1
  fi
  if ! jq -e "$access_filter" >/dev/null 2>&1 <<<"$AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE"; then
    printf 'invalid active role-access key configuration\n' >&2
    return 1
  fi
  if ! jq -e "$access_filter" >/dev/null 2>&1 <<<"$AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS"; then
    printf 'invalid previous role-access key configuration\n' >&2
    return 1
  fi
  active_kid="$(jq -r '.kid' <<<"$AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE")"
  previous_kid="$(jq -r '.kid' <<<"$AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS")"
  if [[ "$active_kid" == "$previous_kid" ]]; then
    printf 'active and previous role-access keys must be distinct\n' >&2
    return 1
  fi
}

materialize_host_secrets() {
  local funding_wallet_json funding_wallet_public_json funding_password clockchain_token host_root_key
  local stage_dir

  fetch_host_secret_value funding_wallet_json "$CLOCKCHAIN_HOST_FUNDING_WALLET_JSON_PARAM"
  fetch_host_secret_value funding_wallet_public_json "$CLOCKCHAIN_HOST_FUNDING_WALLET_PUBLIC_JSON_PARAM"
  fetch_host_secret_value funding_password "$CLOCKCHAIN_HOST_FUNDING_PASSWORD_PARAM"
  fetch_host_secret_value clockchain_token "$CLOCKCHAIN_HOST_CLOCKCHAIN_TOKEN_PARAM"
  fetch_host_secret_value host_root_key "$CLOCKCHAIN_HOST_ROOT_KEY_PARAM"

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
  stage_secret_file "$stage_dir" agent-handshake-v2-host-root.pem "$host_root_key"

  mv -f "${stage_dir}/funding-wallet.json" "${CLOCKCHAIN_HOST_SECRET_DIR}/funding-wallet.json"
  mv -f "${stage_dir}/funding-wallet.public.json" "${CLOCKCHAIN_HOST_SECRET_DIR}/funding-wallet.public.json"
  mv -f "${stage_dir}/funding.password" "${CLOCKCHAIN_HOST_SECRET_DIR}/funding.password"
  mv -f "${stage_dir}/clockchain.token" "${CLOCKCHAIN_HOST_SECRET_DIR}/clockchain.token"
  mv -f "${stage_dir}/agent-handshake-v2-host-root.pem" "${CLOCKCHAIN_HOST_SECRET_DIR}/agent-handshake-v2-host-root.pem"
  rm -rf "$stage_dir"
  trap - RETURN

  export CLOCKCHAIN_HOST_SECRET_DIR
  export CLOCKCHAIN_FUNDING_PASSWORD_FILE=/app/keys/funding.password
}

validate_mcp_runtime_config
read_secret CLOCKCHAIN_API_KEY /clockchain/mcp/CLOCKCHAIN_API_KEY
read_secret MCP_AUTH_TOKENS /clockchain/mcp/MCP_AUTH_TOKENS
read_secret MCP_TOKEN_SIGNING_SECRET /clockchain/mcp/MCP_TOKEN_SIGNING_SECRET
read_secret AGENT_HANDSHAKE_RELEASE_PIN "$AGENT_HANDSHAKE_RELEASE_PIN_PARAM"
read_secret AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE "$AGENT_HANDSHAKE_ROLE_ACCESS_ACTIVE_PARAM"
read_secret AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS "$AGENT_HANDSHAKE_ROLE_ACCESS_PREVIOUS_PARAM"
validate_v2_server_config
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
