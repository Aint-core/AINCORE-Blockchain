#!/usr/bin/env bash
#
# testnet-join.sh — join the AINCORE public testnet as an OBSERVER in one shot.
#
# It bootstraps from a state snapshot (because the seed prunes old blocks, a
# fresh node CANNOT replay from genesis — see docs/PUBLIC-TESTNET-JOIN.md), then
# syncs the small recent delta from the seed automatically.
#
# Prereqs the joiner provides:
#   - a node binary built for THIS machine's arch (x86_64 or aarch64). Get it
#     from the project release, or build: `cargo build --release -p node`.
#   - network reachability to the public seed (Tailscale Funnel addr or seed IP).
#
# Usage:
#   testnet-join.sh \
#     --binary ./node \
#     --genesis ./genesis.json \
#     --snapshot-url https://<host>/aincore-testnet-snapshot.tar.gz \
#     --seed /ip4/<seed-host>/tcp/9022 \
#     --datadir ~/.aincore-observer \
#     [--port 9032 --rpc-port 8032]
#
# This runs an OBSERVER (AINCORE_P2P_LISTEN=0, never in the validator set).
set -euo pipefail

BINARY=""; GENESIS=""; SNAPSHOT_URL=""; SNAPSHOT_FILE=""; SEED=""
DATADIR="$HOME/.aincore-observer"; PORT=9032; RPC_PORT=8032
CHAIN_ID="AINCORE-LATEST-FRESH-1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)       BINARY="$2"; shift 2 ;;
    --genesis)      GENESIS="$2"; shift 2 ;;
    --snapshot-url) SNAPSHOT_URL="$2"; shift 2 ;;
    --snapshot)     SNAPSHOT_FILE="$2"; shift 2 ;;
    --seed)         SEED="$2"; shift 2 ;;
    --datadir)      DATADIR="$2"; shift 2 ;;
    --port)         PORT="$2"; shift 2 ;;
    --rpc-port)     RPC_PORT="$2"; shift 2 ;;
    --chain-id)     CHAIN_ID="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

for req in BINARY GENESIS SEED; do
  [[ -n "${!req}" ]] || { echo "ERROR: --${req,,} is required" >&2; exit 2; }
done
[[ -x "$BINARY" ]] || { echo "ERROR: binary not executable: $BINARY" >&2; exit 2; }
[[ -f "$GENESIS" ]] || { echo "ERROR: genesis not found: $GENESIS" >&2; exit 2; }
[[ -n "$SNAPSHOT_URL" || -n "$SNAPSHOT_FILE" ]] || { echo "ERROR: --snapshot-url or --snapshot required" >&2; exit 2; }

echo "==> Preparing datadir: $DATADIR"
mkdir -p "$DATADIR"

# Fetch snapshot if a URL was given.
if [[ -n "$SNAPSHOT_URL" ]]; then
  SNAPSHOT_FILE="$DATADIR/snapshot.tar.gz"
  echo "==> Downloading snapshot..."
  curl -fL --retry 3 -o "$SNAPSHOT_FILE" "$SNAPSHOT_URL"
fi

# Extract snapshot and rename the DB to THIS node's port. The snapshot is
# pre-sanitised by the operator (no DA key, no peer table) so nothing else to do.
echo "==> Installing snapshot state..."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar xzf "$SNAPSHOT_FILE" -C "$TMP"
SNAP_DB_DIR="$(find "$TMP" -maxdepth 1 -type d -name 'validator_*.db' | head -1)"
[[ -n "$SNAP_DB_DIR" ]] || { echo "ERROR: snapshot has no validator_*.db dir" >&2; exit 2; }
rm -rf "$DATADIR/validator_${PORT}.db"
mv "$SNAP_DB_DIR" "$DATADIR/validator_${PORT}.db"

# genesis.json must match the seed's lineage.
cp "$GENESIS" "$DATADIR/genesis.json"

echo "==> Starting OBSERVER (chain_id=$CHAIN_ID, seed=$SEED)..."
echo "    (node.key auto-generates on first boot if absent; this node is an"
echo "     observer — its address is not in the validator set, so it will not mine.)"
echo ""
echo "    Run it (foreground shown; wrap in systemd/tmux for production):"
echo ""
cat <<EOF
  AINCORE_CHAIN_ID=$CHAIN_ID AINCORE_P2P_LISTEN=0 RUST_LOG=info \\
    $BINARY --port $PORT --rpc-port $RPC_PORT \\
      --datadir $DATADIR --bootnodes $SEED

  # then verify it is catching up (height should climb toward the seed):
  curl -s localhost:$RPC_PORT/rpc -H 'content-type: application/json' \\
    -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}'
EOF
echo ""
echo "✅ Bootstrap prepared in $DATADIR. Start the node with the command above."
