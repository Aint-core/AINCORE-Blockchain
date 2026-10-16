#!/usr/bin/env bash
#
# restore_node.sh — restore the database of an AINCORE node that is NOT a
# validator (an RPC or observer node) from a backup_node.sh tar.gz into a
# FRESH datadir, under a NEW key (audit #16, DR drill + runbook; B467).
#
# A VALIDATOR NEVER RESTORES ITS DATABASE (G1 SA-4, B459, B467). A restored
# database carries the backed-up node's signing guards and its
# consensus:guard_origin. Under that node's key the row still matches, so
# G1 RC-3 counts the guards as continuous: the node does not abstain, and it
# can sign again rounds it signed after the backup was taken (equivocation:
# jailed for good, its stake and its delegators' slashed, G5 SL-4). RC-3
# protects an EMPTY datadir, not a restored one. A validator recovers from an
# empty datadir with its node.key and a fresh sync (docs/DR_RUNBOOK.md §4).
#
# It:
#   1. refuses to run without --not-a-validator: you confirm the restored node
#      is not a validator and will never run a validator's node.key, above
#      all not the key of the node the backup was taken from.
#   2. verifies the archive sha256 against the sibling .sha256 file or an
#      explicit --sha256 value.
#   3. extracts validator_*.db -> {datadir}/validator_{port}.db
#   4. never restores node.key: the node generates a new keypair on first
#      boot. An archive taken before B467 may hold the backed-up node's key;
#      it stays in staging and is removed. If {datadir}/node.key already
#      exists, it refuses (exit 3): that key on an older database can sign a
#      slot it already signed (B373).
#   5. writes {datadir}/RESTORED_FROM_BACKUP, a warning beside where a key
#      would go (the node does not read it).
#   6. restores genesis.json if --genesis-out is given.
#
# SAFETY: it NEVER overwrites a non-empty existing chain DB. If
# {datadir}/validator_{port}.db already exists and is non-empty, it aborts
# unless you pass --force (which moves the old DB aside to a .pre-restore copy,
# it does not delete it).
#
# REMOVED: --restore-validator-key (B467) is refused (exit 2). --new-identity
# is accepted for compatibility: a new identity is the only mode.
#
# Usage:
#   restore_node.sh --backup <archive.tar.gz> --datadir <dir> --port <p> \
#                   --not-a-validator [--sha256 <hex> | --no-verify] \
#                   [--force] [--genesis-out <path>]
#
# Exit codes: 0 ok, 2 usage error, 3 precondition failed, 4 integrity failed.
set -euo pipefail

BACKUP=""
DATADIR=""
PORT=""
EXPECT_SHA=""
VERIFY=1
NOT_A_VALIDATOR=0
FORCE=0
GENESIS_OUT=""

usage() {
  sed -n '2,45p' "$0" >&2
  exit "${1:-2}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backup)        BACKUP="${2:-}"; shift 2 ;;
    --datadir)       DATADIR="${2:-}"; shift 2 ;;
    --port)          PORT="${2:-}"; shift 2 ;;
    --sha256)        EXPECT_SHA="${2:-}"; shift 2 ;;
    --no-verify)     VERIFY=0; shift ;;
    --not-a-validator) NOT_A_VALIDATOR=1; shift ;;
    --new-identity)  shift ;;
    --restore-validator-key)
      echo "ERROR: --restore-validator-key was removed (B467): a validator never" >&2
      echo "       restores its database (G1 SA-4, B459). Recover it from an empty" >&2
      echo "       datadir with its node.key and a fresh sync (docs/DR_RUNBOOK.md §4)." >&2
      exit 2 ;;
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

# --- B467: only a node that is not a validator restores a database ----------
# Before, the default restore (no key) still installed a validator's database
# with its guard_origin, and the runbook then had the operator move the
# validator's node.key in "to resume its identity": continuous guards older
# than what the key had signed, a double-sign.
if [[ "$NOT_A_VALIDATOR" != 1 ]]; then
  echo "ERROR: refusing to restore without --not-a-validator (B467)." >&2
  echo "       A validator never restores its database (G1 SA-4, B459): the restored" >&2
  echo "       guard_origin matches its key, so RC-3 counts its older guards as" >&2
  echo "       continuous and it can sign rounds it already signed: equivocation," >&2
  echo "       jailed for good, its stake and its delegators' slashed. Recover a" >&2
  echo "       validator from an empty datadir with its node.key (docs/DR_RUNBOOK.md §4)." >&2
  echo "       Pass --not-a-validator only for a node that will never run a" >&2
  echo "       validator's node.key, above all not the backed-up node's." >&2
  exit 3
fi

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
DB_NONEMPTY=0
if [[ -d "$DEST_DB" ]] && [[ -n "$(ls -A "$DEST_DB" 2>/dev/null)" ]]; then
  DB_NONEMPTY=1
  if [[ "$FORCE" != 1 ]]; then
    echo "ERROR: target DB already exists and is non-empty: $DEST_DB" >&2
    echo "       Refusing to overwrite. Use a fresh --datadir, or pass --force" >&2
    echo "       (which moves the existing DB aside, never deletes it)." >&2
    exit 3
  fi
fi

# --- B373: a new identity needs an empty key slot -----------------------------
# Before, the default mode left an existing node.key in place and still said
# "fresh keypair on boot": the node then booted that key on an older database
# whose signing records predate what the key already signed, a double-sign
# (G1 SA-4). Now it refuses before touching anything.
if [[ -e "$DEST_KEY" || -L "$DEST_KEY" ]]; then
  echo "ERROR: $DEST_KEY already exists. Refusing to restore." >&2
  echo "       The node would boot THIS key on the restored, older database, and a" >&2
  echo "       key on an older database can sign a slot it already signed: a" >&2
  echo "       double-sign, jailed and slashed. A restore runs a new key: move this" >&2
  echo "       one away first (mv, never cp). A validator's key never goes onto a" >&2
  echo "       restored database (B459, B467)." >&2
  exit 3
fi

if [[ "$DB_NONEMPTY" == 1 ]]; then
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

# --- node.key: never restored (B467) -----------------------------------------
# Reached only with no node.key in the datadir (B373, refused above), so the
# node really does generate a new keypair.
if [[ -f "$STAGING/node.key" ]]; then
  echo "WARNING: this archive holds the backed-up node's node.key (a backup taken" >&2
  echo "         before B467). It is NOT restored, and it must never be put into" >&2
  echo "         $DATADIR: the restored database's guard_origin matches it." >&2
fi
echo "==> NOT restoring node.key: the node generates a fresh keypair on boot."

# --- B467: a warning where a key would go -------------------------------------
# The restored database keeps the backed-up node's guard_origin: that node's
# key put here later would count its older guards as continuous (G1 RC-3) and
# could sign rounds again. The node does not read this file; an operator
# about to copy a node.key in finds it beside the database.
MARKER="${DATADIR%/}/RESTORED_FROM_BACKUP"
{
  echo "This datadir's database was restored from $(basename "$BACKUP") by"
  echo "scripts/restore_node.sh at $(date -u +%Y%m%dT%H%M%SZ), for a node that is not a validator."
  echo "Never put a validator's node.key here, above all the key of the node the"
  echo "backup was taken from: this database holds that node's consensus:guard_origin,"
  echo "so under its key the node would count its older signing guards as continuous"
  echo "(G1 RC-3) and could sign again rounds it signed after the backup: equivocation,"
  echo "jailed for good, its stake and its delegators' slashed (G1 SA-4, B459, B467)."
  echo "A validator recovers from an empty datadir with its node.key (docs/DR_RUNBOOK.md §4)."
  if [[ -f "$STAGING/MANIFEST" ]]; then
    echo "--- backup MANIFEST ---"
    cat "$STAGING/MANIFEST"
  fi
} > "$MARKER"

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
echo "   identity: NEW (fresh keypair on boot); see $MARKER"
echo "   Start the node pointed at this datadir + --port $PORT."
