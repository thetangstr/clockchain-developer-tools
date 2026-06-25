#!/usr/bin/env bash
# Clockchain — verified-time ALARM: zero-to-demo in a fresh terminal.
#
# Clones the repo (if needed), installs dependencies, builds, and runs a live
# testnet alarm end-to-end:
#   sync (NTP-style) → arm → fire on the disciplined clock → anchor → keyless on-chain verify.
#
# Usage (from an empty directory):
#   export CLOCKCHAIN_API_KEY=...  CLOCKCHAIN_CLIENT_ID=...  CLOCKCHAIN_WALLET_ID=...
#   curl -fsSL https://raw.githubusercontent.com/thetangstr/clockchain-developer-tools/main/packages/clock-sdk/examples/try-alarm.sh | bash
# or, if you've already cloned the repo, from its root:
#   bash packages/clock-sdk/examples/try-alarm.sh
set -euo pipefail

REPO="https://github.com/thetangstr/clockchain-developer-tools.git"
DIR="${CLOCKCHAIN_DEMO_DIR:-clockchain-developer-tools}"

say(){ printf "\n\033[1;36m▶ %s\033[0m\n" "$*"; }
die(){ printf "\n\033[1;31m✗ %s\033[0m\n" "$*" >&2; exit 1; }

# 1) Node 18+
command -v node >/dev/null || die "Node.js not found — install Node 18+ and re-run."
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ] || die "Need Node 18+ (found $(node -v))."
command -v git >/dev/null || die "git not found."

# 2) Get the code — use the current checkout if we're in it, else clone.
if [ -d "packages/clock-sdk" ]; then
  say "Using current checkout: $(pwd)"
elif [ -d "$DIR/.git" ]; then
  say "Updating existing checkout: $DIR"; cd "$DIR"; git pull --ff-only || true
else
  say "Cloning $REPO"; git clone --depth 1 "$REPO" "$DIR"; cd "$DIR"
fi

# 3) Install + build
say "Installing dependencies (npm install)…"; npm install
say "Building workspaces (npm run build)…"; npm run build

# 4) Credentials — the one thing not self-serve (testnet gateway creds).
missing=()
for v in CLOCKCHAIN_API_KEY CLOCKCHAIN_CLIENT_ID CLOCKCHAIN_WALLET_ID; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -ne 0 ]; then
  cat >&2 <<EOF

$(printf '\033[1;31m✗ Missing testnet gateway creds: %s\033[0m' "${missing[*]}")

The SDK alarm talks to the Clockchain gateway directly, which needs an account's
testnet creds. Set all three and re-run:

  export CLOCKCHAIN_API_KEY=...
  export CLOCKCHAIN_CLIENT_ID=...
  export CLOCKCHAIN_WALLET_ID=...

No creds handy? You can instead try the zero-setup MCP flow (a demo token, no
account): see packages/clock-sdk/README.md → "Try it with no creds".
EOF
  exit 1
fi

# 5) Run the live alarm
say "Running the verified-time alarm on testnet…"
node packages/clock-sdk/examples/alarm-live.mjs
say "Done — that fire is anchored and keyless-verifiable on-chain."
