#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${CLOCKCHAIN_MCP_APP_ROOT:-/opt/clockchain-mcp/app}"
INSTALL_ROOT="${CLOCKCHAIN_MCP_INSTALL_ROOT:-/opt/clockchain-mcp}"
SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASSET_ROOT="${SOURCE_ROOT}/infra/clockchain-mcp"

if [[ ! -d "$APP_ROOT" || "$(cd "$SOURCE_ROOT" && pwd)" != "$(cd "$APP_ROOT" && pwd)" ]]; then
  printf 'Expected repo checkout at %s; current source is %s\n' "$APP_ROOT" "$SOURCE_ROOT" >&2
  exit 1
fi

install -d -m 0755 "$INSTALL_ROOT"
install -m 0755 "${ASSET_ROOT}/compose-up.sh" "${INSTALL_ROOT}/compose-up.sh"
install -m 0644 "${ASSET_ROOT}/clockchain-mcp.service" /etc/systemd/system/clockchain-mcp.service

systemctl daemon-reload
systemctl enable clockchain-mcp.service
systemctl restart clockchain-mcp.service
