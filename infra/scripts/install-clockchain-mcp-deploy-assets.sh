#!/usr/bin/env bash
set -euo pipefail

# Default: install the out-of-checkout wrapper + unit, then restart the whole stack (full restart).
# --no-restart: install + daemon-reload + enable only, so the installed copies match the checkout
# without touching running containers (used by the code-only deploy in scripts/deploy-box.sh).
# deploy-box: supports --no-restart (scripts/deploy-box.sh checks for this line before a code-only deploy)
usage() { printf 'usage: %s [--no-restart]\n' "$0" >&2; exit 64; }
[[ $# -le 1 ]] || usage
RESTART=1
case "${1:-}" in
  "") ;;
  --no-restart) RESTART=0 ;;
  *) usage ;;
esac

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
install -m 0644 "${ASSET_ROOT}/clockchain-mcp.service" "${CLOCKCHAIN_MCP_SYSTEMD_DIR:-/etc/systemd/system}/clockchain-mcp.service"

systemctl daemon-reload
systemctl enable clockchain-mcp.service
if [[ "$RESTART" == 1 ]]; then
  systemctl restart clockchain-mcp.service
else
  printf 'deploy assets installed; clockchain-mcp.service NOT restarted (--no-restart)\n'
fi
