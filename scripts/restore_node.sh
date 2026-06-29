#!/usr/bin/env bash
#
# restore_node.sh — restore an AINCORE node from a backup_node.sh tar.gz into a
# FRESH datadir (audit #16, DR drill + runbook).
#
# It is the inverse of scripts/backup_node.sh. It:
#   1. (optionally) verifies the archive sha256 against the sibling .sha256 file
#      or an explicit --sha256 value (same hash you'd use for
#      AINCORE_BOOTSTRAP_SHA256).
#   2. extracts validator_*.db -> {datadir}/validator_{port}.db
#   3. restores node.key into {datadir}/node.key (unless --new-identity).
#   4. restores genesis.json next to the datadir if --genesis-out is given.
#
# SAFETY: it NEVER overwrites a non-empty existing chain DB. If
# {datadir}/validator_{port}.db already exists and is non-empty, it aborts
# unless you pass --force (which moves the old DB aside to a .pre-restore copy,
# it does not delete it).
#
# NODE IDENTITY:
#   default        restore node.key from the backup → node resumes its OWN
#                  identity (correct for restoring the SAME validator).
#   --new-identity drop node.key → the node generates a fresh keypair on first
#                  boot. Use this to spin up an OBSERVER from a validator's state
#                  without impersonating the validator's consensus identity.
#
# Usage:
#   restore_node.sh --backup <archive.tar.gz> --datadir <dir> --port <p> \
#                   [--sha256 <hex> | --no-verify] \
#                   [--new-identity] [--force] [--genesis-out <path>]
#
# Exit codes: 0 ok, 2 usage error, 3 precondition failed, 4 integrity failed.
set -euo pipefail

BACKUP=""
DATADIR=""
PORT=""
EXPECT_SHA=""
VERIFY=1
NEW_IDENTITY=0
FORCE=0
GENESIS_OUT=""

usage() {
  sed -n '2,38p' "$0" >&2
  exit "${1:-2}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backup)        BACKUP="${2:-}"; shift 2 ;;
    --datadir)       DATADIR="${2:-}"; shift 2 ;;
    --port)          PORT="${2:-}"; shift 2 ;;
    --sha256)        EXPECT_SHA="${2:-}"; shift 2 ;;
    --no-verify)     VERIFY=0; shift ;;
    --new-identity)  NEW_IDENTITY=1; shift ;;
    --force)         FORCE=1; shift ;;
    --genesis-out)   GENESIS_OUT="${2:-}"; shift 2 ;;
    -h|--help)       usage 0 ;;
    *) echo "ERROR: unknown arg: $1" >&2; usage 2 ;;
  esac
done

[[ -n "$BACKUP" ]] || { echo "ERROR: --backup is required" >&2; usage 2; }
[[ -n "$DATADIR" ]] || { echo "ERROR: --datadir is required" >&2; usage 2; }
[[ -n "$PORT" ]] || { echo "ERROR: --port is required" >&2; usage 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "ERROR: --port must be numeric, got '$PORT'" >&2; exit 2; }
[[ -f "$BACKUP" ]] || { echo "ERROR: backup not found: $BACKUP" >&2; exit 3; }

command -v tar >/dev/null || { echo "ERROR: tar not found" >&2; exit 3; }

SHA_CMD=""
if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD="shasum -a 256"
fi

# --- integrity verification -------------------------------------------------
if [[ "$VERIFY" == 1 ]]; then
  if [[ -z "$EXPECT_SHA" && -f "${BACKUP}.sha256" ]]; then
    # sidecar format: "<hash>  <basename>" — take the first field.
    EXPECT_SHA="$(awk '{print $1}' "${BACKUP}.sha256" | head -n1)"
  fi
  if [[ -n "$EXPECT_SHA" ]]; then
    [[ -n "$SHA_CMD" ]] || { echo "ERROR: --sha256 given but no sha256sum/shasum available" >&2; exit 3; }
    GOT="$($SHA_CMD "$BACKUP" | awk '{print $1}')"
    EXPECT_LC="$(echo "$EXPECT_SHA" | tr '[:upper:]' '[:lower:]')"
    GOT_LC="$(echo "$GOT" | tr '[:upper:]' '[:lower:]')"
    if [[ "$GOT_LC" != "$EXPECT_LC" ]]; then
      echo "🚨 INTEGRITY FAILURE: sha256 mismatch" >&2
      echo "   expected: $EXPECT_LC" >&2
      echo "   got:      $GOT_LC" >&2
      exit 4
    fi
    echo "🔒 sha256 verified: $GOT_LC"
  else
    echo "WARNING: no sha256 to verify against (no --sha256, no ${BACKUP}.sha256)." >&2
    echo "         Re-run with --sha256 <hex> or --no-verify to acknowledge." >&2
    exit 3
  fi
else
  echo "WARNING: integrity verification SKIPPED (--no-verify)." >&2
fi

DB_NAME="validator_${PORT}.db"
DEST_DB="${DATADIR%/}/${DB_NAME}"
DEST_KEY="${DATADIR%/}/node.key"

# --- never clobber a non-empty existing DB ----------------------------------
if [[ -d "$DEST_DB" ]] && [[ -n "$(ls -A "$DEST_DB" 2>/dev/null)" ]]; then
  if [[ "$FORCE" != 1 ]]; then
    echo "ERROR: target DB already exists and is non-empty: $DEST_DB" >&2
    echo "       Refusing to overwrite. Use a fresh --datadir, or pass --force" >&2
    echo "       (which moves the existing DB aside, never deletes it)." >&2
    exit 3
  fi
  ASIDE="${DEST_DB}.pre-restore.$(date -u +%Y%m%dT%H%M%SZ)"
  echo "==> --force: moving existing DB aside -> $ASIDE"
  mv "$DEST_DB" "$ASIDE"
fi

mkdir -p "$DATADIR"

# --- extract into staging, then place deliberately --------------------------
STAGING="$(mktemp -d)"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

echo "==> Extracting backup into staging..."
tar xzf "$BACKUP" -C "$STAGING"

# Locate the single validator_*.db inside the archive (name may differ from our
# target port — we always place it at validator_{--port}.db).
SRC_DB=""
for d in "$STAGING"/validator_*.db; do
  [[ -d "$d" ]] || continue
  SRC_DB="$d"
  break
done
[[ -n "$SRC_DB" ]] || { echo "ERROR: no validator_*.db inside backup" >&2; exit 3; }

echo "==> Installing chain DB -> $DEST_DB"
mv "$SRC_DB" "$DEST_DB"

# --- node.key handling ------------------------------------------------------
if [[ "$NEW_IDENTITY" == 1 ]]; then
  echo "==> --new-identity: NOT restoring node.key (node will generate a fresh keypair on boot)."
  # If a key happens to pre-exist in the target datadir, leave it untouched;
  # the operator chose new-identity so we simply don't import the backup's key.
else
  if [[ -f "$STAGING/node.key" ]]; then
    if [[ -f "$DEST_KEY" ]]; then
      echo "WARNING: $DEST_KEY already exists — keeping the EXISTING key, not the backup's." >&2
      echo "         (Pass --new-identity to keep existing, or remove it first to import.)" >&2
    else
      echo "==> Restoring node.key -> $DEST_KEY"
      cp "$STAGING/node.key" "$DEST_KEY"
      chmod 600 "$DEST_KEY" 2>/dev/null || true
    fi
  else
    echo "WARNING: backup contains no node.key — node will generate a fresh identity." >&2
  fi
fi

# --- genesis ----------------------------------------------------------------
if [[ -n "$GENESIS_OUT" ]]; then
  if [[ -f "$STAGING/genesis.json" ]]; then
    echo "==> Restoring genesis.json -> $GENESIS_OUT"
    cp "$STAGING/genesis.json" "$GENESIS_OUT"
  else
    echo "WARNING: --genesis-out given but backup has no genesis.json — skipped." >&2
  fi
fi

if [[ -f "$STAGING/MANIFEST" ]]; then
  echo ""
  echo "==> Backup manifest:"
  sed 's/^/    /' "$STAGING/MANIFEST"
fi

echo ""
echo "✅ Restore complete into: $DATADIR"
echo "   chain DB: $DEST_DB"
[[ "$NEW_IDENTITY" == 1 ]] && echo "   identity: NEW (fresh keypair on boot)" || echo "   identity: restored from backup (if node.key present)"
echo "   Start the node pointed at this datadir + --port $PORT."
