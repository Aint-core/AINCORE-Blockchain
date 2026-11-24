#!/usr/bin/env bash
#
# backup_node.sh — take a CONSISTENT disaster-recovery backup of the database
# of an AINCORE node that is NOT a validator: an RPC or observer node (audit
# #16, DR drill + runbook; B467).
#
# A VALIDATOR NEVER BACKS UP OR RESTORES ITS DATABASE (G1 SA-4, B459, B467).
# The database holds the validator's signing guards and
# consensus:guard_origin, the G1 RC-3 row that says those guards are this
# key's own unbroken record. A restored copy brings both back older than what
# the validator signed after the backup was taken, and the key still matches
# the row, so the node counts its guards as continuous, does not abstain,
# and can sign those rounds again: equivocation, jailed for good and slashed
# with its delegators (G5 SL-4). RC-3 protects an EMPTY datadir, not a
# restored one. A validator backs up only node.key, offline and encrypted,
# and recovers from an empty datadir with that key and a fresh sync
# (docs/DR_RUNBOOK.md §4). This script refuses to run without
# --not-a-validator.
#
# WHAT THIS BACKS UP:
#   - {datadir}/validator_{port}.db   the RocksDB chain state (height, blocks,
#                                     validator set, consensus cursors, balances)
#   - genesis.json (optional, via --genesis) so the restore is self-describing
#   - a MANIFEST
# It never packs node.key (B467): scripts/restore_node.sh always runs a new
# key on a restored database, so the backed-up key has no use in the archive.
#
# It writes a timestamped tar.gz PLUS a sibling .sha256 file, which
# scripts/restore_node.sh verifies before it restores.
#
# CONSISTENCY: STOP the observer and fence automatic restarts first. The copy
# holds RocksDB's POSIX LOCK until tar finishes. Raw live copying is NOT a
# consistent snapshot: --hot is refused. A live backup needs a coordinated
# RocksDB Checkpoint/BackupEngine implementation, not an ordinary tar of a DB.
# Requires Python 3 on a POSIX host and a local filesystem supporting locks.
#
# Usage:
#   backup_node.sh --datadir ./data --port 9001 --not-a-validator \
#                  [--out-dir ./backups] [--genesis ./genesis.json] \
#                  --assume-stopped [--keep N]
#
#   --not-a-validator  required: you confirm this node's key is not a
#                      validator's (its address is not in /get_validators).
#
# Exit codes: 0 ok, 2 usage error, 3 precondition failed.
set -euo pipefail

DATADIR=""
PORT=""
OUT_DIR="./backups"
GENESIS=""
MODE="" # "stopped" must be acknowledged explicitly
KEEP=0  # 0 = keep all; N>0 = prune to newest N backups
NOT_A_VALIDATOR=0

usage() {
  sed -n '2,44p' "$0" >&2
  exit "${1:-2}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --datadir)        DATADIR="${2:-}"; shift 2 ;;
    --port)           PORT="${2:-}"; shift 2 ;;
    --out-dir)        OUT_DIR="${2:-}"; shift 2 ;;
    --genesis)        GENESIS="${2:-}"; shift 2 ;;
    --assume-stopped) MODE="stopped"; shift ;;
    --hot)
      echo "ERROR: --hot is unsupported: raw copying a live RocksDB is not a consistent backup." >&2
      echo "       Stop and fence the observer, then use --assume-stopped." >&2
      exit 3 ;;
    --keep)           KEEP="${2:-}"; shift 2 ;;
    --not-a-validator) NOT_A_VALIDATOR=1; shift ;;
    -h|--help)        usage 0 ;;
    *) echo "ERROR: unknown arg: $1" >&2; usage 2 ;;
  esac
done

[[ -n "$DATADIR" ]] || { echo "ERROR: --datadir is required" >&2; usage 2; }
[[ -n "$PORT" ]] || { echo "ERROR: --port is required" >&2; usage 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "ERROR: --port must be numeric, got '$PORT'" >&2; exit 2; }
[[ "$KEEP" =~ ^[0-9]+$ ]] || { echo "ERROR: --keep must be numeric, got '$KEEP'" >&2; exit 2; }

# --- B467: a validator's database is never backed up -------------------------
# Before, this script packed a validator's database with its node.key as a
# "self-restore" backup, the input of a restore that can sign twice (B459).
if [[ "$NOT_A_VALIDATOR" != 1 ]]; then
  echo "ERROR: refusing to back up a database without --not-a-validator (B467)." >&2
  echo "       A validator never backs up or restores its database (G1 SA-4, B459):" >&2
  echo "       restored, its older signing guards and guard_origin come back, its" >&2
  echo "       key still matches them, and it can sign rounds it already signed:" >&2
  echo "       equivocation, jailed for good, its stake and its delegators' slashed." >&2
  echo "       A validator backs up only node.key (offline, encrypted) and recovers" >&2
  echo "       from an empty datadir with that key (docs/DR_RUNBOOK.md §4)." >&2
  echo "       Pass --not-a-validator only for an RPC or observer node." >&2
  exit 3
fi

DB_NAME="validator_${PORT}.db"
DB_PATH="${DATADIR%/}/${DB_NAME}"

[[ -d "$DB_PATH" ]] || { echo "ERROR: chain DB not found: $DB_PATH" >&2; exit 3; }

if [[ -z "$MODE" ]]; then
  echo "ERROR: stop and fence the observer, then acknowledge with --assume-stopped" >&2
  exit 3
fi

command -v python3 >/dev/null || { echo "ERROR: Python 3 is required to hold the RocksDB lock" >&2; exit 3; }
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
  echo "aincore_backup_version=2"
  echo "created_utc=${TS}"
  echo "source_port=${PORT}"
  echo "db_name=${DB_NAME}"
  echo "includes_node_key=no"
  echo "not_a_validator=yes"
  echo "includes_genesis=$([[ -n "$GENESIS" ]] && echo yes || echo no)"
  echo "mode=${MODE}"
} > "$STAGING/MANIFEST"

if [[ -n "$GENESIS" ]]; then
  [[ -f "$GENESIS" ]] || { echo "ERROR: --genesis file not found: $GENESIS" >&2; exit 3; }
  cp "$GENESIS" "$STAGING/genesis.json"
fi

echo "==> Packing backup -> $ARCHIVE (mode=$MODE)"
# Layout inside the tarball (flat, what restore_node.sh expects):
# validator_{port}.db/, MANIFEST, genesis.json. Never node.key (B467). -C into
# each source dir so paths are not absolute.
TAR_ARGS=(-C "$DATADIR" "$DB_NAME")
TAR_ARGS+=(-C "$STAGING" "MANIFEST")
[[ -n "$GENESIS" ]] && TAR_ARGS+=(-C "$STAGING" "genesis.json")

# RocksDB's POSIX environment uses F_SETLK, not flock. Keep this parent alive
# while tar runs so a concurrent DB opener cannot acquire the same file lock.
python3 - "$DB_PATH/LOCK" "$ARCHIVE" "${TAR_ARGS[@]}" <<'PY'
import fcntl
import os
import stat
import subprocess
import sys

lock_path, archive, *tar_args = sys.argv[1:]
try:
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, "r+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise OSError("LOCK is not a regular file")
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Exclusive creation also prevents overwriting a same-second backup.
        with open(archive, "xb") as output:
            try:
                subprocess.run(["tar", "czf", "-", *tar_args], stdout=output, check=True)
            except BaseException:
                os.unlink(archive)
                raise
except (OSError, subprocess.CalledProcessError) as error:
    print(f"ERROR: backup refused or copy failed: {error}", file=sys.stderr)
    print("Stop and fence the observer; retain its existing LOCK file.", file=sys.stderr)
    sys.exit(3)
PY

# Integrity hash, checked by restore_node.sh (tamper detection at rest).
HASH="$($SHA_CMD "$ARCHIVE" | awk '{print $1}')"
echo "${HASH}  ${BASE}.tar.gz" > "${ARCHIVE}.sha256"

SIZE="$(du -h "$ARCHIVE" | cut -f1)"
echo ""
echo "✅ Backup ready: $ARCHIVE ($SIZE)"
echo "   sha256: $HASH"
echo "   sha256 file: ${ARCHIVE}.sha256"
echo "   node.key is not in it (B467): a restored node runs a new key."
echo ""
echo "   Restore with:   scripts/restore_node.sh --backup '$ARCHIVE' --datadir <fresh> --port $PORT --not-a-validator"

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
