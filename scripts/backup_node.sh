#!/usr/bin/env bash
#
# backup_node.sh — take a CONSISTENT disaster-recovery backup of an AINCORE
# node's full identity + chain state (audit #16, DR drill + runbook).
#
# WHAT THIS BACKS UP (everything needed to restore THIS exact node):
#   - {datadir}/validator_{port}.db   the RocksDB chain state (height, blocks,
#                                     validator set, consensus cursors, balances)
#   - {datadir}/node.key              the root secret (re-derives the Ed25519
#                                     consensus identity + DA signing key)
#   - genesis.json (optional, via --genesis) so the restore is self-describing
#
# It writes a timestamped tar.gz PLUS a sibling .sha256 file. The sha256 is the
# value you feed AINCORE_BOOTSTRAP_SHA256 if you restore via the observer
# bootstrap path (see docs/DR_RUNBOOK.md).
#
# UNLIKE scripts/testnet-make-snapshot.sh (which SANITISES the DB to hand to
# *other* joiners), this is a *self-restore* backup: it keeps node.key and the
# per-identity DA key intact so the node resumes its OWN identity untouched.
#
# CONSISTENCY: RocksDB is only crash-consistent on a live copy. For a clean
# backup either (a) STOP the node first (recommended — pass --assume-stopped to
# acknowledge), or (b) accept a hot copy (--hot), which relies on RocksDB WAL
# recovery on restore and may capture an in-flight write. Stopped is safest.
#
# Usage:
#   backup_node.sh --datadir ./data --port 9001 [--out-dir ./backups] \
#                  [--genesis ./genesis.json] [--assume-stopped | --hot] \
#                  [--keep N]
#
# Exit codes: 0 ok, 2 usage error, 3 precondition failed.
set -euo pipefail

DATADIR=""
PORT=""
OUT_DIR="./backups"
GENESIS=""
MODE="" # "stopped" or "hot" — must be chosen explicitly
KEEP=0  # 0 = keep all; N>0 = prune to newest N backups

usage() {
  sed -n '2,40p' "$0" >&2
  exit "${1:-2}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --datadir)        DATADIR="${2:-}"; shift 2 ;;
    --port)           PORT="${2:-}"; shift 2 ;;
    --out-dir)        OUT_DIR="${2:-}"; shift 2 ;;
    --genesis)        GENESIS="${2:-}"; shift 2 ;;
    --assume-stopped) MODE="stopped"; shift ;;
    --hot)            MODE="hot"; shift ;;
    --keep)           KEEP="${2:-}"; shift 2 ;;
    -h|--help)        usage 0 ;;
    *) echo "ERROR: unknown arg: $1" >&2; usage 2 ;;
  esac
done

[[ -n "$DATADIR" ]] || { echo "ERROR: --datadir is required" >&2; usage 2; }
[[ -n "$PORT" ]] || { echo "ERROR: --port is required" >&2; usage 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "ERROR: --port must be numeric, got '$PORT'" >&2; exit 2; }
[[ "$KEEP" =~ ^[0-9]+$ ]] || { echo "ERROR: --keep must be numeric, got '$KEEP'" >&2; exit 2; }

DB_NAME="validator_${PORT}.db"
DB_PATH="${DATADIR%/}/${DB_NAME}"
KEY_PATH="${DATADIR%/}/node.key"

[[ -d "$DB_PATH" ]] || { echo "ERROR: chain DB not found: $DB_PATH" >&2; exit 3; }

if [[ -z "$MODE" ]]; then
  echo "ERROR: choose --assume-stopped (recommended: stop the node first) or --hot" >&2
  echo "       a hot copy relies on RocksDB WAL recovery and may catch an in-flight write" >&2
  exit 3
fi

if [[ "$MODE" == "stopped" ]]; then
  # Best-effort warning if a process still holds the DB LOCK (Linux only; no-op
  # elsewhere). We do not abort — operator asserted stopped — but we surface it.
  if command -v fuser >/dev/null 2>&1; then
    if fuser "$DB_PATH/LOCK" >/dev/null 2>&1; then
      echo "WARNING: $DB_PATH/LOCK still held by a running process — node may NOT be stopped." >&2
      echo "         The backup may be inconsistent. Stop the node and retry." >&2
    fi
  fi
fi

command -v tar >/dev/null || { echo "ERROR: tar not found" >&2; exit 3; }
SHA_CMD=""
if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD="shasum -a 256"
else
  echo "ERROR: need sha256sum or shasum for integrity hash" >&2
  exit 3
fi

mkdir -p "$OUT_DIR"
# UTC timestamp — stable, sortable, tz-independent.
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="aincore-backup-port${PORT}-${TS}"
ARCHIVE="${OUT_DIR%/}/${BASE}.tar.gz"

# Stage a manifest + the genesis copy (if given) so the tarball is portable
# regardless of where genesis lived on the source host.
STAGING="$(mktemp -d)"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

{
  echo "aincore_backup_version=1"
  echo "created_utc=${TS}"
  echo "source_port=${PORT}"
  echo "db_name=${DB_NAME}"
  echo "includes_node_key=$([[ -f "$KEY_PATH" ]] && echo yes || echo no)"
  echo "includes_genesis=$([[ -n "$GENESIS" ]] && echo yes || echo no)"
  echo "mode=${MODE}"
} > "$STAGING/MANIFEST"

if [[ ! -f "$KEY_PATH" ]]; then
  echo "WARNING: $KEY_PATH not found — backup will NOT contain node identity." >&2
  echo "         Restoring it will produce a node with a DIFFERENT identity." >&2
fi

if [[ -n "$GENESIS" ]]; then
  [[ -f "$GENESIS" ]] || { echo "ERROR: --genesis file not found: $GENESIS" >&2; exit 3; }
  cp "$GENESIS" "$STAGING/genesis.json"
fi

echo "==> Packing backup -> $ARCHIVE (mode=$MODE)"
# Layout inside the tarball (flat, matches what restore_node.sh + the node's
# AINCORE_BOOTSTRAP_SNAPSHOT path expect): validator_{port}.db/, node.key,
# genesis.json, MANIFEST. -C into each source dir so paths are not absolute.
TAR_ARGS=(-C "$DATADIR" "$DB_NAME")
[[ -f "$KEY_PATH" ]] && TAR_ARGS+=(-C "$DATADIR" "node.key")
TAR_ARGS+=(-C "$STAGING" "MANIFEST")
[[ -n "$GENESIS" ]] && TAR_ARGS+=(-C "$STAGING" "genesis.json")

tar czf "$ARCHIVE" "${TAR_ARGS[@]}"

# Integrity hash for AINCORE_BOOTSTRAP_SHA256 (and for tamper detection at rest).
HASH="$($SHA_CMD "$ARCHIVE" | awk '{print $1}')"
echo "${HASH}  ${BASE}.tar.gz" > "${ARCHIVE}.sha256"

SIZE="$(du -h "$ARCHIVE" | cut -f1)"
echo ""
echo "✅ Backup ready: $ARCHIVE ($SIZE)"
echo "   sha256: $HASH"
echo "   sha256 file: ${ARCHIVE}.sha256"
echo ""
echo "   Restore with:   scripts/restore_node.sh --backup '$ARCHIVE' --datadir <fresh> --port $PORT"
echo "   Observer boot:  export AINCORE_BOOTSTRAP_SNAPSHOT='$ARCHIVE'"
echo "                   export AINCORE_BOOTSTRAP_SHA256='$HASH'"

# Optional retention: keep only the newest N backups for this port.
if [[ "$KEEP" -gt 0 ]]; then
  echo ""
  echo "==> Retention: keeping newest $KEEP backup(s) for port $PORT"
  # Newest-first; delete archives (and their .sha256) beyond the keep window.
  # Portable to bash 3.2 (macOS) — no mapfile; read NUL-free lines in a loop.
  ls -1t "${OUT_DIR%/}"/aincore-backup-port"${PORT}"-*.tar.gz 2>/dev/null \
    | tail -n +"$((KEEP + 1))" \
    | while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        echo "    pruning $f"
        rm -f "$f" "${f}.sha256"
      done
fi
