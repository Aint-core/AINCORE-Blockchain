#!/usr/bin/env bash
#
# testnet-make-snapshot.sh — produce a CLEAN, joiner-ready state snapshot of an
# AINCORE node's chain DB so new nodes can bootstrap without replaying from
# genesis (which is impossible once the seed prunes old blocks).
#
# WHY THIS EXISTS
#   A fresh node at height 0 cannot catch up to a far-ahead network: the seed
#   prunes old blocks, so block_1..N no longer exist to replay, and the
#   anti-jump guards reject a 0->current leap. The fix is state-snapshot
#   bootstrap: a new node starts from a recent snapshot and only syncs the small
#   (still-present) delta. (See docs/PUBLIC-TESTNET-JOIN.md.)
#
# WHAT THIS DOES (operator runs this on the SEED/validator host)
#   1. Cleanly stop the node (consistent on-disk DB) — brief downtime.
#   2. Copy the chain DB aside.
#   3. Restart the node immediately (minimise downtime).
#   4. SANITISE the copy so it is safe to hand to ANY joiner:
#        - delete the per-identity DA signing key (sys:da:signing_key*) so the
#          joiner generates its own (otherwise the node panics on boot:
#          da/src/lib.rs "failed to decrypt DA signing key").
#        - clear the seed's peer table (peer:/peer_ip:/peer_addr:) so joiners
#          don't inherit + hammer the seed's dead peers.
#   5. Tar it as a publishable artifact.
#
# Joiners then just extract it; they need NO ldb and NO key surgery.
#
# Usage:
#   testnet-make-snapshot.sh \
#       --container aincore-latest-fresh-node \
#       --db /home/alpha/aincore-latest-fresh-run/fresh_data/validator_9022.db \
#       --out /home/alpha/snapshot/aincore-testnet-snapshot.tar.gz
#
# Requires: docker (or set --no-docker + --stop-cmd/--start-cmd), ldb
# (rocksdb-tools), tar.
set -euo pipefail

CONTAINER="aincore-latest-fresh-node"
DB=""
OUT="./aincore-testnet-snapshot.tar.gz"
USE_DOCKER=1
STOP_CMD=""
START_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --container) CONTAINER="$2"; shift 2 ;;
    --db)        DB="$2"; shift 2 ;;
    --out)       OUT="$2"; shift 2 ;;
    --no-docker) USE_DOCKER=0; shift ;;
    --stop-cmd)  STOP_CMD="$2"; shift 2 ;;
    --start-cmd) START_CMD="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$DB" ]] || { echo "ERROR: --db <path to validator_*.db> is required" >&2; exit 2; }
[[ -d "$DB" ]] || { echo "ERROR: DB dir not found: $DB" >&2; exit 2; }
command -v ldb >/dev/null || { echo "ERROR: ldb not found (apt install rocksdb-tools)" >&2; exit 2; }

WORK="$(mktemp -d)"
SNAP_DB="$WORK/validator_snapshot.db"
trap 'rm -rf "$WORK"' EXIT

stop_node()  { if [[ "$USE_DOCKER" == 1 ]]; then docker stop -t 30 "$CONTAINER" >/dev/null; else eval "$STOP_CMD"; fi; }
start_node() { if [[ "$USE_DOCKER" == 1 ]]; then docker start "$CONTAINER" >/dev/null;     else eval "$START_CMD"; fi; }

echo "==> Stopping node for a consistent copy (brief downtime)..."
stop_node
echo "==> Copying chain DB aside..."
cp -a "$DB" "$SNAP_DB"
echo "==> Restarting node (downtime ends here)..."
start_node
echo "    node restarted."

echo "==> Sanitising snapshot (strip per-identity DA key + seed peer table)..."
ldb --db="$SNAP_DB" delete "sys:da:signing_key_enc_v1"  >/dev/null 2>&1 || true
ldb --db="$SNAP_DB" delete "sys:da:signing_key"         >/dev/null 2>&1 || true
# Clear the peer table so joiners don't inherit the seed's peers.
for pfx in "peer:" "peer_ip:" "peer_addr:"; do
  ldb --db="$SNAP_DB" deleterange "$pfx" "${pfx}~" >/dev/null 2>&1 || true
done

echo "==> Packing snapshot -> $OUT"
mkdir -p "$(dirname "$OUT")"
# Pack as a generic name so joiners can rename to their own port.
tar czf "$OUT" -C "$WORK" "$(basename "$SNAP_DB")"
SIZE="$(du -h "$OUT" | cut -f1)"

echo ""
echo "✅ Snapshot ready: $OUT ($SIZE)"
echo "   Publish it (GitHub release / object storage / served over the seed)"
echo "   and point joiners at it via testnet-join.sh --snapshot-url <URL>."
