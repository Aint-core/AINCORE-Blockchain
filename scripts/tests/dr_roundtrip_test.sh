#!/usr/bin/env bash
#
# dr_roundtrip_test.sh — automated DR drill for audit #16.
#
# Proves scripts/backup_node.sh + scripts/restore_node.sh faithfully round-trip
# a node datadir (DB + node.key + genesis), that the sha256 integrity sidecar
# verifies, that integrity tampering is caught, and that restore refuses to
# clobber a non-empty existing DB. Needs NO running node — it fabricates a
# RocksDB-shaped datadir.
#
# Run:  scripts/tests/dr_roundtrip_test.sh
# Exit: 0 all pass, non-zero on first failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SH="$SCRIPT_DIR/../backup_node.sh"
RESTORE_SH="$SCRIPT_DIR/../restore_node.sh"

[[ -x "$BACKUP_SH" ]] || { echo "FATAL: $BACKUP_SH not executable" >&2; exit 1; }
[[ -x "$RESTORE_SH" ]] || { echo "FATAL: $RESTORE_SH not executable" >&2; exit 1; }

# Pick an available sha256 verifier for the integrity assertions.
if command -v sha256sum >/dev/null 2>&1; then
  SHA_VERIFY() { ( cd "$1" && sha256sum -c "$2" ); }
elif command -v shasum >/dev/null 2>&1; then
  SHA_VERIFY() { ( cd "$1" && shasum -a 256 -c "$2" ); }
else
  echo "FATAL: need sha256sum or shasum" >&2; exit 1
fi

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0
fail() { echo "❌ FAIL: $1" >&2; exit 1; }
ok()   { echo "✅ $1"; PASS=$((PASS + 1)); }

PORT=9001
DATA="$WORK/data"
mkdir -p "$DATA/validator_${PORT}.db"

# Fabricate deterministic-ish DB contents + identity.
printf 'CURRENT-marker\n' > "$DATA/validator_${PORT}.db/CURRENT"
head -c 256 /dev/urandom > "$DATA/validator_${PORT}.db/000001.sst"
mkdir -p "$DATA/validator_${PORT}.db/sub"
printf 'nested\n' > "$DATA/validator_${PORT}.db/sub/data.log"
head -c 32 /dev/urandom > "$DATA/node.key"
printf '{"chain_id":"AINCORE-MAINNET-1"}\n' > "$WORK/genesis.json"

# --- 1. backup --------------------------------------------------------------
"$BACKUP_SH" --datadir "$DATA" --port "$PORT" --out-dir "$WORK/backups" \
  --genesis "$WORK/genesis.json" --assume-stopped >/dev/null
ARCHIVE="$(ls "$WORK"/backups/aincore-backup-port${PORT}-*.tar.gz)"
[[ -f "$ARCHIVE" ]] || fail "backup did not produce an archive"
[[ -f "${ARCHIVE}.sha256" ]] || fail "backup did not produce a .sha256 sidecar"
ok "backup produced archive + sha256 sidecar"

# --- 2. integrity sidecar verifies ------------------------------------------
SHA_VERIFY "$WORK/backups" "$(basename "$ARCHIVE").sha256" >/dev/null \
  || fail "sha256 sidecar did not verify against archive"
ok "sha256 sidecar verifies"

# --- 3. restore into a fresh datadir ----------------------------------------
"$RESTORE_SH" --backup "$ARCHIVE" --datadir "$WORK/restored" --port "$PORT" \
  --genesis-out "$WORK/genesis-restored.json" >/dev/null
ok "restore completed"

# --- 4. byte-for-byte round-trip --------------------------------------------
diff "$DATA/node.key" "$WORK/restored/node.key" >/dev/null \
  || fail "node.key did not round-trip"
diff "$DATA/validator_${PORT}.db/CURRENT" \
     "$WORK/restored/validator_${PORT}.db/CURRENT" >/dev/null \
  || fail "DB CURRENT did not round-trip"
diff "$DATA/validator_${PORT}.db/000001.sst" \
     "$WORK/restored/validator_${PORT}.db/000001.sst" >/dev/null \
  || fail "DB sst did not round-trip"
diff "$DATA/validator_${PORT}.db/sub/data.log" \
     "$WORK/restored/validator_${PORT}.db/sub/data.log" >/dev/null \
  || fail "nested DB file did not round-trip"
diff "$WORK/genesis.json" "$WORK/genesis-restored.json" >/dev/null \
  || fail "genesis did not round-trip"
ok "DB + node.key + genesis round-trip byte-for-byte"

# --- 5. restore refuses to clobber a non-empty existing DB ------------------
if "$RESTORE_SH" --backup "$ARCHIVE" --datadir "$WORK/restored" --port "$PORT" \
     >/dev/null 2>&1; then
  fail "restore overwrote an existing non-empty DB (should have refused)"
fi
ok "restore refuses to clobber existing non-empty DB"

# --- 6. --new-identity drops the key ----------------------------------------
"$RESTORE_SH" --backup "$ARCHIVE" --datadir "$WORK/observer" --port 9101 \
  --new-identity >/dev/null
[[ -d "$WORK/observer/validator_9101.db" ]] || fail "--new-identity did not install DB"
[[ ! -f "$WORK/observer/node.key" ]] || fail "--new-identity should NOT restore node.key"
ok "--new-identity installs DB without node.key"

# --- 7. integrity tampering is caught ---------------------------------------
TAMPERED="$WORK/tampered.tar.gz"
cp "$ARCHIVE" "$TAMPERED"
printf 'corruption' >> "$TAMPERED" # append garbage -> hash changes
GOOD_SHA="$(awk '{print $1}' "${ARCHIVE}.sha256")"
if "$RESTORE_SH" --backup "$TAMPERED" --datadir "$WORK/tamper-restore" \
     --port "$PORT" --sha256 "$GOOD_SHA" >/dev/null 2>&1; then
  fail "restore accepted a tampered archive (sha256 mismatch not caught)"
fi
ok "restore rejects tampered archive (sha256 mismatch caught)"

echo ""
echo "✅ DR ROUND-TRIP TEST PASSED ($PASS checks)"
