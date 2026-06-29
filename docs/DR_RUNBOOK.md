# AINCORE Disaster Recovery (DR) Runbook

> Audit #16 — backup/restore DR drill + runbook.
> Scope: recovering a single AINCORE validator/observer node's state and
> identity after disk loss, host failure, or corruption. Pairs with
> `scripts/backup_node.sh` and `scripts/restore_node.sh`.

This is the *self-restore* path (recover **your own** node). It is distinct from
`scripts/testnet-make-snapshot.sh`, which produces a **sanitised** snapshot for
handing to *other* joiners (it strips `node.key` and the peer table). Do not
confuse the two: a DR backup keeps your identity; a joiner snapshot removes it.

---

## 1. What to back up

A node's complete recoverable state lives in three things:

| Artifact | Path | Why it matters |
|---|---|---|
| Chain DB | `{datadir}/validator_{port}.db` (RocksDB) | Height, blocks, validator set, consensus cursors (`consensus:committed_rounds`, `consensus:committed_sequence`), balances, DAG checkpoints. |
| Node key | `{datadir}/node.key` | The root secret. Re-derives the Ed25519 consensus identity **and** the DA signing key. Lose it → the node boots with a **different** identity (different validator). **Never** commit it; back it up encrypted. |
| Genesis | `genesis.json` | Chain genesis. Identical across all nodes of a network; back it up once. |

`node.key` is the single most important secret. If you lose the DB but keep
`node.key`, you can re-sync from a snapshot and resume your identity. If you
lose `node.key`, you have lost the validator identity even if the DB survives.

---

## 2. Backup cadence (recommendation)

| Tier | Cadence | Retention |
|---|---|---|
| `node.key` (cold, encrypted) | Once at provisioning, re-export on any rotation | Forever (offline, e.g. HSM / sealed envelope / encrypted vault) |
| Chain DB snapshot | Every 6–12h for validators; daily for observers | `--keep 7` (newest 7), plus 1 weekly offsite |
| `genesis.json` | Once per network | Forever |

Backups must land on **separate failure domain** storage (different host / object
store / region), not the node's own disk.

---

## 3. Taking a backup

Recommended: stop the node for a fully consistent RocksDB copy (brief downtime).

```bash
# 1. Stop the node (whatever your process manager uses), e.g.:
#    systemctl stop aincore-node   |   docker stop aincore-node   |   kill <pid>

# 2. Back up DB + node.key + genesis, with a sha256 sidecar, keeping newest 7.
scripts/backup_node.sh \
  --datadir ./data \
  --port 9001 \
  --out-dir ./backups \
  --genesis ./genesis.json \
  --assume-stopped \
  --keep 7

# 3. Restart the node.
#    systemctl start aincore-node  |  docker start aincore-node  |  ...
```

Output: `./backups/aincore-backup-port9001-<UTC>.tar.gz` plus a sibling
`.tar.gz.sha256`. **Copy both off-box.**

### Hot backup (no downtime)

If you cannot stop the node, use `--hot`. The copy relies on RocksDB WAL
recovery at restore time and may capture an in-flight write — acceptable for an
observer or a best-effort safety net, but a **stopped** backup is the gold copy.

```bash
scripts/backup_node.sh --datadir ./data --port 9001 --hot
```

### Snapshot integrity (sha256)

Every backup writes `<archive>.sha256` containing the SHA-256 of the tarball.
This is the same value consumed by `AINCORE_BOOTSTRAP_SHA256` (see §5). Verify
at any time:

```bash
sha256sum -c ./backups/aincore-backup-port9001-<UTC>.tar.gz.sha256   # Linux
shasum -a 256 -c ./backups/aincore-backup-port9001-<UTC>.tar.gz.sha256  # macOS
```

---

## 4. Restoring a node (full DR)

Restore into a **fresh** datadir. The script refuses to clobber a non-empty
existing DB unless `--force` (which moves the old DB aside, never deletes it).

```bash
# Restore the SAME validator (keeps its identity from the backup's node.key):
scripts/restore_node.sh \
  --backup ./backups/aincore-backup-port9001-<UTC>.tar.gz \
  --datadir ./data-restored \
  --port 9001 \
  --genesis-out ./genesis.json
# sha256 is auto-verified against the sidecar .sha256 file.

# Then start the node pointed at the restored datadir:
./target/release/node --port 9001 --datadir ./data-restored
```

The node boots, reads its restored height, and ChainSyncs only the small delta
that elapsed since the backup. Do **not** run two nodes with the same `node.key`
simultaneously — that is equivocation and will get the validator slashed. Ensure
the failed node is truly down before bringing the restored one online.

### Restoring as a fresh OBSERVER (no identity)

To stand up an observer from a validator's state without impersonating its
consensus identity, drop the key:

```bash
scripts/restore_node.sh \
  --backup ./backups/aincore-backup-port9001-<UTC>.tar.gz \
  --datadir ./observer-data \
  --port 9101 \
  --new-identity
```

---

## 5. Observer bootstrap flow (`AINCORE_BOOTSTRAP_SNAPSHOT`)

A fresh node at height 0 **cannot** replay from genesis once the network has
pruned old blocks. Instead of `restore_node.sh`, you can hand the node the
backup tarball directly via the built-in bootstrap path
(`core/node/src/main.rs::maybe_extract_bootstrap_snapshot`). It acts **only**
when the target `validator_{port}.db` does not yet exist — it never overwrites a
live DB.

```bash
export AINCORE_BOOTSTRAP_SNAPSHOT="/path/to/aincore-backup-port9001-<UTC>.tar.gz"
# Strongly recommended: pin the integrity hash (supply-chain protection).
export AINCORE_BOOTSTRAP_SHA256="$(awk '{print $1}' \
  /path/to/aincore-backup-port9001-<UTC>.tar.gz.sha256)"

./target/release/node --port 9001 --datadir ./fresh-data
```

Notes on the bootstrap path:

- `AINCORE_BOOTSTRAP_SNAPSHOT` may be a **local path** or an **https://** URL.
  Plain `http://` is rejected; https fetches allow **no redirects** (SSRF
  protection).
- If `AINCORE_BOOTSTRAP_SHA256` is set, the downloaded/used tarball must match
  or the node refuses to bootstrap. Always set it for remote snapshots.
- The bootstrap path extracts the single `validator_*.db` from the tarball and
  installs it as `validator_{port}.db`. It then sanitises per-identity keys via
  the storage API, so the bootstrapped node uses **its own** `node.key`, not the
  snapshot author's. (This is why the observer bootstrap is identity-safe even
  from a full backup.)

---

## 6. DR drill (verify backup → restore round-trips)

Run this drill on a non-production copy at least once per quarter and after any
change to the backup/restore scripts. It needs **no running node** — it proves
the scripts faithfully round-trip a datadir.

```bash
set -e
DRILL="$(mktemp -d)"
mkdir -p "$DRILL/data/validator_9001.db"
# Simulate chain DB contents + identity.
printf 'CURRENT\n' > "$DRILL/data/validator_9001.db/CURRENT"
head -c 32 /dev/urandom > "$DRILL/data/validator_9001.db/000001.sst"
head -c 32 /dev/urandom > "$DRILL/data/node.key"
printf '{"chain_id":"AINCORE-MAINNET-1"}\n' > "$DRILL/genesis.json"

# 1. BACK UP
scripts/backup_node.sh --datadir "$DRILL/data" --port 9001 \
  --out-dir "$DRILL/backups" --genesis "$DRILL/genesis.json" --assume-stopped

ARCHIVE="$(ls "$DRILL"/backups/aincore-backup-port9001-*.tar.gz)"

# 2. INTEGRITY CHECK
( cd "$DRILL/backups" && sha256sum -c "$(basename "$ARCHIVE").sha256" ) \
  2>/dev/null || ( cd "$DRILL/backups" && shasum -a 256 -c "$(basename "$ARCHIVE").sha256" )

# 3. RESTORE into a FRESH datadir
scripts/restore_node.sh --backup "$ARCHIVE" --datadir "$DRILL/restored" \
  --port 9001 --genesis-out "$DRILL/genesis-restored.json"

# 4. ASSERT round-trip
diff "$DRILL/data/node.key" "$DRILL/restored/node.key"
diff "$DRILL/data/validator_9001.db/CURRENT" "$DRILL/restored/validator_9001.db/CURRENT"
diff "$DRILL/data/validator_9001.db/000001.sst" "$DRILL/restored/validator_9001.db/000001.sst"
diff "$DRILL/genesis.json" "$DRILL/genesis-restored.json"
echo "✅ DR DRILL PASSED: backup → verify → restore round-trips byte-for-byte"

# 5. NEGATIVE CHECK — restore must refuse to clobber a non-empty DB
if scripts/restore_node.sh --backup "$ARCHIVE" --datadir "$DRILL/restored" \
     --port 9001 >/dev/null 2>&1; then
  echo "❌ DR DRILL FAILED: restore overwrote an existing DB"; exit 1
else
  echo "✅ DR DRILL PASSED: restore refused to clobber existing DB"
fi

rm -rf "$DRILL"
```

A test harness runs an equivalent automated round-trip:
`scripts/tests/dr_roundtrip_test.sh`.

---

## 7. Recovery checklist (incident)

1. Confirm the failed node is **fully down** (no process holding `node.key`).
   Two live nodes sharing `node.key` = equivocation = slashing.
2. Provision a clean host + fresh datadir.
3. Pull the latest backup tarball **and** its `.sha256` from offsite storage.
4. `restore_node.sh` (auto-verifies sha256). If only `node.key` survived, use the
   observer bootstrap path (§5) against the network's published snapshot, then
   import `node.key` and restart.
5. Restore `genesis.json` if the host doesn't already have it.
6. Start the node; watch logs for height advancing and ChainSync closing the
   delta. Confirm it is **not** jailed (`validator:jailed:{addr}`).
7. Once healthy and caught up, resume the normal backup cadence.
