#!/usr/bin/env bash
#
# dr_roundtrip_test.sh — automated DR drill (audit #16; B373, B391, B467).
#
# Proves scripts/backup_node.sh + scripts/restore_node.sh round-trip the
# database of a node that is NOT a validator (DB + genesis, never node.key),
# that the sha256 sidecar verifies and tampering is caught, and that a restore
# refuses to clobber a non-empty DB or a datadir holding a node.key (B373).
#
# B467 witnesses: a validator never backs up or restores its database (G1
# SA-4, B459), so both scripts refuse (exit 3) without --not-a-validator; an
# archive holds no node.key; a restore never installs one, not even from an
# archive taken before B467 that holds one; --restore-validator-key is
# refused (exit 2); a restored datadir carries the RESTORED_FROM_BACKUP
# warning; and the DR runbook, the operator guide and both scripts no longer
# tell a validator to back up or restore its database.
#
# Needs NO running node: it fabricates a RocksDB-shaped datadir. Portable to
# bash 3.2 (macOS).
#
# Run:  bash scripts/dr/dr_roundtrip_test.sh
# Exit: 0 all pass, non-zero on first failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKUP_SH="$ROOT/scripts/backup_node.sh"
RESTORE_SH="$ROOT/scripts/restore_node.sh"

[[ -f "$BACKUP_SH" ]] || { echo "FATAL: $BACKUP_SH not found" >&2; exit 1; }
[[ -f "$RESTORE_SH" ]] || { echo "FATAL: $RESTORE_SH not found" >&2; exit 1; }

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
# run CMD...: runs it with its output in $WORK/out and its exit code in RC,
# without tripping set -e.
RC=0
run() { RC=0; "$@" >"$WORK/out" 2>&1 || RC=$?; }

PORT=9001
DATA="$WORK/data"
DB="$DATA/validator_${PORT}.db"
mkdir -p "$DB/sub"

# Fabricate deterministic-ish DB contents + identity.
printf 'CURRENT-marker\n' > "$DB/CURRENT"
head -c 256 /dev/urandom > "$DB/000001.sst"
printf 'nested\n' > "$DB/sub/data.log"
head -c 32 /dev/urandom > "$DATA/node.key"
printf '{"chain_id":"AINCORE-MAINNET-1"}\n' > "$WORK/genesis.json"

# --- 1. B467: a backup without --not-a-validator is refused -----------------
run bash "$BACKUP_SH" --datadir "$DATA" --port "$PORT" --out-dir "$WORK/refused" \
  --genesis "$WORK/genesis.json" --assume-stopped
[[ "$RC" == 3 ]] || fail "a backup without --not-a-validator exited $RC, want 3 (B467)"
if ls "$WORK"/refused/aincore-backup-*.tar.gz >/dev/null 2>&1; then
  fail "a refused backup still wrote an archive"
fi
ok "backup refuses (exit 3) without --not-a-validator: a validator backs up node.key only (B467)"

# --- 2. backup of a node that is not a validator ----------------------------
run bash "$BACKUP_SH" --datadir "$DATA" --port "$PORT" --out-dir "$WORK/backups" \
  --genesis "$WORK/genesis.json" --assume-stopped --not-a-validator
[[ "$RC" == 0 ]] || { cat "$WORK/out" >&2; fail "backup --not-a-validator exited $RC, want 0"; }
ARCHIVE="$(ls "$WORK"/backups/aincore-backup-port${PORT}-*.tar.gz)"
[[ -f "$ARCHIVE" ]] || fail "backup did not produce an archive"
[[ -f "${ARCHIVE}.sha256" ]] || fail "backup did not produce a .sha256 sidecar"
ok "backup --not-a-validator produced archive + sha256 sidecar"

# --- 3. B467: the archive holds no node.key; its MANIFEST says why ----------
tar tzf "$ARCHIVE" > "$WORK/listing"
if grep -q 'node\.key' "$WORK/listing"; then
  fail "the archive holds node.key (B467: a backup never packs the key)"
fi
mkdir -p "$WORK/peek"
tar xzf "$ARCHIVE" -C "$WORK/peek" MANIFEST
grep -qx 'includes_node_key=no' "$WORK/peek/MANIFEST" \
  || fail "the MANIFEST does not say includes_node_key=no"
grep -qx 'not_a_validator=yes' "$WORK/peek/MANIFEST" \
  || fail "the MANIFEST does not say not_a_validator=yes"
ok "the archive holds no node.key; MANIFEST includes_node_key=no, not_a_validator=yes (B467)"

# --- 4. integrity sidecar verifies ------------------------------------------
SHA_VERIFY "$WORK/backups" "$(basename "$ARCHIVE").sha256" >/dev/null \
  || fail "sha256 sidecar did not verify against archive"
ok "sha256 sidecar verifies"

# --- 5. B467: a restore without --not-a-validator is refused ----------------
run bash "$RESTORE_SH" --backup "$ARCHIVE" --datadir "$WORK/noflag" --port "$PORT"
[[ "$RC" == 3 ]] || fail "a restore without --not-a-validator exited $RC, want 3 (B467)"
[[ ! -e "$WORK/noflag/validator_${PORT}.db" ]] || fail "a refused restore installed a DB"
ok "restore refuses (exit 3) without --not-a-validator (B467)"

# --- 6. B467: --restore-validator-key is removed ----------------------------
run bash "$RESTORE_SH" --backup "$ARCHIVE" --datadir "$WORK/keymode" --port "$PORT" \
  --not-a-validator --restore-validator-key
[[ "$RC" == 2 ]] || fail "--restore-validator-key exited $RC, want 2 (removed, B467)"
grep -q 'restore-validator-key was removed' "$WORK/out" \
  || fail "--restore-validator-key was refused without saying it was removed"
[[ ! -e "$WORK/keymode/validator_${PORT}.db" ]] || fail "--restore-validator-key installed a DB"
[[ ! -e "$WORK/keymode/node.key" ]] || fail "--restore-validator-key installed a node.key"
ok "--restore-validator-key is refused (exit 2) and installs nothing (B467)"

# --- 7. restore into a fresh datadir: byte-for-byte, no key, a warning ------
run bash "$RESTORE_SH" --backup "$ARCHIVE" --datadir "$WORK/restored" --port "$PORT" \
  --genesis-out "$WORK/genesis-restored.json" --not-a-validator
[[ "$RC" == 0 ]] || { cat "$WORK/out" >&2; fail "restore --not-a-validator exited $RC, want 0"; }
diff "$DB/CURRENT" "$WORK/restored/validator_${PORT}.db/CURRENT" >/dev/null \
  || fail "DB CURRENT did not round-trip"
diff "$DB/000001.sst" "$WORK/restored/validator_${PORT}.db/000001.sst" >/dev/null \
  || fail "DB sst did not round-trip"
diff "$DB/sub/data.log" "$WORK/restored/validator_${PORT}.db/sub/data.log" >/dev/null \
  || fail "nested DB file did not round-trip"
diff "$WORK/genesis.json" "$WORK/genesis-restored.json" >/dev/null \
  || fail "genesis did not round-trip"
[[ ! -e "$WORK/restored/node.key" ]] || fail "the restore installed a node.key (B467)"
[[ -f "$WORK/restored/RESTORED_FROM_BACKUP" ]] \
  || fail "the restore left no RESTORED_FROM_BACKUP warning (B467)"
grep -q "Never put a validator" "$WORK/restored/RESTORED_FROM_BACKUP" \
  || fail "RESTORED_FROM_BACKUP does not warn against a validator's node.key"
grep -qx 'not_a_validator=yes' "$WORK/restored/RESTORED_FROM_BACKUP" \
  || fail "RESTORED_FROM_BACKUP does not carry the backup's MANIFEST"
ok "DB + genesis round-trip byte-for-byte; no node.key; RESTORED_FROM_BACKUP written"

# --- 8. restore refuses to clobber a non-empty existing DB ------------------
run bash "$RESTORE_SH" --backup "$ARCHIVE" --datadir "$WORK/restored" --port "$PORT" \
  --not-a-validator
[[ "$RC" == 3 ]] || fail "restore over a non-empty DB exited $RC, want 3"
ok "restore refuses to clobber existing non-empty DB"

# --- 9. B467: an archive taken before B467 holds the node's key; a restore
#        installs its DB, never its key, and needs --not-a-validator too ----
mkdir -p "$WORK/v1/stage"
cp -R "$DB" "$WORK/v1/stage/validator_${PORT}.db"
cp "$DATA/node.key" "$WORK/v1/stage/node.key"
printf 'aincore_backup_version=1\nincludes_node_key=yes\n' > "$WORK/v1/stage/MANIFEST"
tar czf "$WORK/v1/old.tar.gz" -C "$WORK/v1/stage" "validator_${PORT}.db" node.key MANIFEST
run bash "$RESTORE_SH" --backup "$WORK/v1/old.tar.gz" --datadir "$WORK/v1-noflag" \
  --port "$PORT" --no-verify
[[ "$RC" == 3 ]] || fail "a pre-B467 archive restored without --not-a-validator (exit $RC, want 3)"
[[ ! -e "$WORK/v1-noflag/node.key" ]] || fail "a refused restore installed a node.key"
run bash "$RESTORE_SH" --backup "$WORK/v1/old.tar.gz" --datadir "$WORK/v1-restored" \
  --port "$PORT" --no-verify --not-a-validator
[[ "$RC" == 0 ]] || { cat "$WORK/out" >&2; fail "restore of a pre-B467 archive exited $RC, want 0"; }
[[ -d "$WORK/v1-restored/validator_${PORT}.db" ]] || fail "the pre-B467 archive's DB was not installed"
[[ ! -e "$WORK/v1-restored/node.key" ]] || fail "the pre-B467 archive's node.key was installed (B467)"
grep -q 'must never be put' "$WORK/out" \
  || fail "no warning that the archive's node.key must never be put into the datadir"
ok "a pre-B467 archive with a node.key restores its DB only, with a warning (B467)"

# --- 10. integrity tampering is caught --------------------------------------
TAMPERED="$WORK/tampered.tar.gz"
cp "$ARCHIVE" "$TAMPERED"
printf 'corruption' >> "$TAMPERED" # append garbage -> hash changes
GOOD_SHA="$(awk '{print $1}' "${ARCHIVE}.sha256")"
run bash "$RESTORE_SH" --backup "$TAMPERED" --datadir "$WORK/tamper-restore" \
  --port "$PORT" --sha256 "$GOOD_SHA" --not-a-validator
[[ "$RC" == 4 ]] || fail "restore of a tampered archive exited $RC, want 4 (sha256 mismatch)"
ok "restore rejects tampered archive (sha256 mismatch caught)"

# --- 11. B373: a restore refuses a datadir that already holds a node.key
#         (that key on an older database can double-sign) --------------------
HASKEY="$WORK/haskey"
mkdir -p "$HASKEY"
head -c 32 /dev/urandom > "$HASKEY/node.key"
cp "$HASKEY/node.key" "$WORK/haskey.node.key.orig"
for extra in "" "--new-identity"; do
  # shellcheck disable=SC2086 # $extra is empty or one flag on purpose
  run bash "$RESTORE_SH" --backup "$ARCHIVE" --datadir "$HASKEY" --port 9103 \
    --not-a-validator $extra
  [[ "$RC" == 3 ]] || fail "restore ${extra:-(default)} with an existing node.key exited $RC, want 3"
  cmp -s "$HASKEY/node.key" "$WORK/haskey.node.key.orig" \
    || fail "restore ${extra:-(default)} changed the existing node.key"
  [[ ! -e "$HASKEY/validator_9103.db" ]] \
    || fail "restore ${extra:-(default)} installed a DB next to an existing node.key"
  [[ ! -e "$HASKEY/RESTORED_FROM_BACKUP" ]] \
    || fail "restore ${extra:-(default)} wrote a marker although it refused"
  if grep -q "fresh keypair" "$WORK/out"; then
    fail "restore ${extra:-(default)} printed 'fresh keypair' while a node.key is present"
  fi
done
ok "restore refuses (exit 3) a datadir with a node.key, key untouched (B373)"

# --- 12. B467: no DR document or script tells a validator to back up or
#         restore its database, or calls RC-3 its protection --------------
#         (each phrase is one the round-30 review found false: G1 SA-4, B459;
#         G5 SL-4 slashes an isolated equivocation 9 (Q/T)^2, from 1 %)
STALE_PHRASES=(
  'resume your identity'
  'resumes its own identity'
  'backup keeps your identity'
  '12h for validators'
  'makes validator recovery safe'
  'built yet'
  'import `node.key` and restart'
  'slashed 100%'
)
for f in docs/DR_RUNBOOK.md docs/NODE_OPERATOR_GUIDE.md scripts/backup_node.sh scripts/restore_node.sh; do
  [[ -f "$ROOT/$f" ]] || fail "$f is missing"
  for phrase in "${STALE_PHRASES[@]}"; do
    if grep -q -i -F -- "$phrase" "$ROOT/$f"; then
      fail "$f still says \"$phrase\" (B467: a validator never restores its database)"
    fi
  done
done
for f in docs/DR_RUNBOOK.md docs/NODE_OPERATOR_GUIDE.md; do
  grep -q -F 'A validator never restores its database' "$ROOT/$f" \
    || fail "$f does not state that a validator never restores its database (B459, B467)"
  # In the launch hour the flag lets an empty database take a guard origin at
  # once, so a validator recovering then must start without it.
  grep -q -F 'without `AINCORE_GUARD_ORIGIN_INIT`' "$ROOT/$f" \
    || fail "$f does not say to recover without AINCORE_GUARD_ORIGIN_INIT (B467)"
done
ok "the DR runbook, the operator guide and both scripts agree with G1 SA-4 and B459 (B467)"

echo ""
echo "✅ DR ROUND-TRIP TEST PASSED ($PASS checks)"
