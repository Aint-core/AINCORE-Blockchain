# AINCORE Disaster Recovery (DR) Runbook

> Audit #16 — backup/restore DR drill + runbook. Aligned with G1 SA-4 and
> B459 in B467 (round 30).
> Scope: recovering an AINCORE node after disk loss, host failure, or
> corruption. Pairs with `scripts/backup_node.sh` and
> `scripts/restore_node.sh`.

**A validator never restores its database.** A validator backs up only
`node.key` and recovers from an empty data directory with that key and a fresh
sync (§4). A database backup and restore is only for a node that is not a
validator: an RPC or observer node (§3, §5), and the restored node runs a new
key.

Why. A node's database holds its signing guards (`consensus:vattest:*`,
`consensus:vproposed:*`, `consensus:qc_signing:*`, `latest_proposed_round`)
and `consensus:guard_origin`, the G1 RC-3 row that says those guards are this
key's own unbroken record. A restored database brings both back as they were
when the backup was taken, older than what the validator signed afterwards.
The key still matches the restored `guard_origin`, so the node counts its
guards as continuous, does not abstain, and can sign again a round it already
signed after the backup, with different contents: equivocation. G1 SA-4 calls
a restore from backup Byzantine; the node cannot tell it from its own
continuous history. The validator is jailed for good and slashed with its
delegators (G5 SL-4: 9·(Q/T)² of the stake, Q the weight that equivocated
within a day of it and T the committee's; at least 1 %, all of it from a
third; a validator with a quarter of the weight alone loses 56 %).

G1 RC-3 protects an **empty** data directory, not a restored one: with no
`guard_origin`, the node abstains until a block holds its proof of boot, and
signs again from the activation after the first epoch boundary above it.
Production chains treat signing state the same way (Ethereum
slashing-protection databases, CometBFT `priv_validator_state.json`, Aptos
SafetyRules): it is never rolled back.

---

## 1. What to back up

| Artifact | Path | Validator | Not a validator (RPC, observer) |
|---|---|---|---|
| Node key | `{datadir}/node.key` | **The only backup**: once, offline and encrypted | Optional: a restored node runs a new key |
| Chain DB | `{datadir}/validator_{port}.db` (RocksDB) | **Never** | `scripts/backup_node.sh --not-a-validator` (§3) |
| Genesis | `genesis.json` | Once per network | Once per network |

`node.key` is the root secret: it derives the node's Ed25519 identity and its
BLS consensus key. **Never** commit it. Lose it and the validator identity is
lost, whatever else survives; keep it and a validator can recover (§4).

---

## 2. Backup cadence (recommendation)

| What | Cadence | Retention |
|---|---|---|
| `node.key` (every node; a validator's only backup) | Once at provisioning, again after any rotation | Forever, offline (HSM, sealed envelope, encrypted vault) |
| Chain DB snapshot, a node that is **not a validator** only | Daily | `--keep 7` (newest 7), plus 1 weekly offsite |
| `genesis.json` | Once per network | Forever |

Why daily: a restored node syncs the blocks after its backup from its peers,
and a full node keeps only the newest 100,000 (`AINCORE_BLOCK_RETENTION`;
`AINCORE_STORAGE_MODE=archive` keeps all). That is 7.7 days at 6.65 s a block
(the block time measured on the testnet) and 28 hours at 1 s. The newest daily
backup is at most a day old, under 100,000 blocks at any block time of 0.87 s
or more (86,400 s / 100,000), so full-node peers can close its gap if it is
restored promptly. An older backup needs an archive peer.

Backups must land on **separate failure domain** storage (different host / object
store / region), not the node's own disk.

---

## 3. Taking a backup (a node that is not a validator)

A validator does not use this section. Its backup is its key, once:

```bash
# A validator: back up node.key only (offline, encrypted storage)
sudo cp /data/aincore/node.key /secure/offline/location/node.key
```

For an RPC or observer node, stop the node for a fully consistent RocksDB copy
(brief downtime). `backup_node.sh` refuses (exit 3) without `--not-a-validator`.

```bash
# 1. Stop the node (whatever your process manager uses), e.g.:
#    systemctl stop aincore-node   |   docker stop aincore-node   |   kill <pid>

# 2. Back up DB + genesis, with a sha256 sidecar, keeping newest 7.
scripts/backup_node.sh \
  --datadir ./data \
  --port 9001 \
  --not-a-validator \
  --out-dir ./backups \
  --genesis ./genesis.json \
  --assume-stopped \
  --keep 7

# 3. Restart the node.
#    systemctl start aincore-node  |  docker start aincore-node  |  ...
```

Output: `./backups/aincore-backup-port9001-<UTC>.tar.gz` plus a sibling
`.tar.gz.sha256`. **Copy both off-box.** The archive holds the database, a
`MANIFEST` (`not_a_validator=yes`, `includes_node_key=no`) and `genesis.json`;
it never holds `node.key` (B467).

### Hot backup (no downtime)

If you cannot stop the node, use `--hot`. The copy relies on RocksDB WAL
recovery at restore time and may capture an in-flight write. A **stopped**
backup is the gold copy.

```bash
scripts/backup_node.sh --datadir ./data --port 9001 --not-a-validator --hot
```

### Snapshot integrity (sha256)

Every backup writes `<archive>.sha256` containing the SHA-256 of the tarball;
`restore_node.sh` checks it before it restores. Verify at any time:

```bash
sha256sum -c ./backups/aincore-backup-port9001-<UTC>.tar.gz.sha256   # Linux
shasum -a 256 -c ./backups/aincore-backup-port9001-<UTC>.tar.gz.sha256  # macOS
```

---

## 4. Recovering a validator

A validator recovers from its key alone. The same steps move a validator to a
new machine.

1. **Fence the old machine.** Power it off, or remove its disk or its
   `node.key` (`mv`, never `cp`), and confirm it physically. A stopped process
   is not enough: two running copies of one `node.key` sign twice.
2. **Start from an empty data directory** on the new host, and put only
   `node.key` in it: moved from the old machine, or from the offline backup.
   Nothing else from the old node: no database, no backup archive, no `*.bak`
   or `*.pre-restore.*` copy, no joiner snapshot.
3. **Start the node without `AINCORE_GUARD_ORIGIN_INIT`** (remove it from the
   unit if the launch set it). Up to one hour after the network's
   `genesis_time` that flag makes an empty database take a guard origin at
   once, so a validator wiped in that hour would sign again over what it had
   signed. Without it the node finds no `consensus:guard_origin`, abstains
   (G1 RC-3) and syncs blocks from its peers from genesis. That needs a peer
   that still holds every block from genesis: an archive node
   (`AINCORE_STORAGE_MODE=archive`) once the chain is past a full node's
   100,000 blocks. State sync (`AINCORE_STATE_SYNC_CHECKPOINT`) is not a
   validator's path: it refuses a key the restored state records as a
   validator (G3 SN-6).
4. **Keep it running until it signs.** Once synced, the node sends a proof of
   boot about once a minute, a transfer of a random amount to itself (the
   account needs a little AIN for its gas). When a block holds one it logs
   `[RC-3] a block after this boot holds a proof transaction: signing resumes
   at the first boundary above height N`, and it signs again from the
   activation that follows the first epoch boundary above N. A restart before
   then clears the noted proof, and a fresh one is needed
   (`docs/NODE_OPERATOR_GUIDE.md`, "Stake Tokens and Join").
5. **Check.** Its address is in `curl -s http://localhost:8002/get_validators`,
   and its logs show it signing again.

The cost is rewards, never a slash: downtime is not slashed. While it abstains
the node makes no vertices and takes no leader slots, so it earns no leader
bonus (its stake-weighted share of emission and fees is still paid). That
lasts while it syncs, then up to one epoch after its proof is noted (I blocks,
`epoch_blocks` in `aincore_getEconomics`). A launch operator's bootstrap score
(G5 BW-6) also counts the leader slots it misses: an epoch with none committed
lowers it by 1/128 of itself, and it forfeits only below half, about 88 such
epochs in a row.

`restore_node.sh` is never part of this: it refuses `--restore-validator-key`
(removed, B467) and restores only with `--not-a-validator`.

---

## 5. Restoring a node that is not a validator

Restore into a **fresh** datadir. The script:

- refuses (exit 3) without `--not-a-validator`: you confirm the restored node
  is not a validator and will never run a validator's `node.key`, above all not
  the key of the node the backup was taken from;
- refuses to clobber a non-empty existing DB unless `--force` (which moves the
  old DB aside, never deletes it);
- never restores a `node.key`: the node generates a new keypair on first boot.
  It refuses (exit 3) a datadir that already holds a `node.key` (B373), since
  that key would boot on the older database;
- leaves `RESTORED_FROM_BACKUP` in the datadir, a warning beside where a key
  would go (the node does not read it).

```bash
scripts/restore_node.sh \
  --backup ./backups/aincore-backup-port9001-<UTC>.tar.gz \
  --datadir ./data-restored \
  --port 9001 \
  --not-a-validator \
  --genesis-out ./genesis.json
# sha256 is auto-verified against the sidecar .sha256 file.

# Then start the node pointed at the restored datadir:
./target/release/node --port 9001 --datadir ./data-restored
```

The node boots, reads its restored height, and ChainSyncs only the small delta
that elapsed since the backup.

**Never copy a validator's `node.key` into a restored datadir.** The restored
database keeps the backed-up node's `guard_origin`: under that node's key the
guards count as continuous, which is the equivocation above. An archive taken
before B467 holds the backed-up node's `node.key`; `restore_node.sh` restores
its database only and warns. Keep such archives offline: one taken from a
validator holds both halves of the hazard.

---

## 6. Observer bootstrap (`AINCORE_BOOTSTRAP_SNAPSHOT`): removed

> **Removed in G3 (SN-5), branch `g3/activation` onward.** The bootstrap path
> installed a downloaded database without verifying its state: no state root,
> no consensus signature. A G3 node refuses to start with the variable set.

A node that is not a validator starts from its own backup (§5), syncs from
genesis, or restores state from peers at a checkpoint the operator pins (G3
S6: `AINCORE_STATE_SYNC_CHECKPOINT` with `AINCORE_STATE_SYNC_PEERS` and
`AINCORE_EXPECTED_GENESIS_HASH`; see `docs/G3_STATE_AUTHENTICATION_CONTRACT.md`).

---

## 7. DR drill (verify backup → restore round-trips)

Run this drill on a non-production copy at least once per quarter and after any
change to the backup/restore scripts. It needs **no running node** — it proves
the scripts faithfully round-trip a datadir of a node that is not a validator.

```bash
set -e
DRILL="$(mktemp -d)"
mkdir -p "$DRILL/data/validator_9001.db"
# Simulate chain DB contents + identity.
printf 'CURRENT\n' > "$DRILL/data/validator_9001.db/CURRENT"
head -c 32 /dev/urandom > "$DRILL/data/validator_9001.db/000001.sst"
head -c 32 /dev/urandom > "$DRILL/data/node.key"
printf '{"chain_id":"AINCORE-MAINNET-1"}\n' > "$DRILL/genesis.json"

# 1. BACK UP (B467: the archive never holds node.key)
scripts/backup_node.sh --datadir "$DRILL/data" --port 9001 --not-a-validator \
  --out-dir "$DRILL/backups" --genesis "$DRILL/genesis.json" --assume-stopped

ARCHIVE="$(ls "$DRILL"/backups/aincore-backup-port9001-*.tar.gz)"
if tar tzf "$ARCHIVE" | grep -q 'node\.key'; then
  echo "❌ DR DRILL FAILED: the archive holds node.key"; exit 1
fi

# 2. INTEGRITY CHECK
( cd "$DRILL/backups" && sha256sum -c "$(basename "$ARCHIVE").sha256" ) \
  2>/dev/null || ( cd "$DRILL/backups" && shasum -a 256 -c "$(basename "$ARCHIVE").sha256" )

# 3. RESTORE into a FRESH datadir
scripts/restore_node.sh --backup "$ARCHIVE" --datadir "$DRILL/restored" \
  --port 9001 --not-a-validator --genesis-out "$DRILL/genesis-restored.json"

# 4. ASSERT round-trip. The restore runs a new identity (§5), so the restored
#    datadir holds no node.key (B391) and carries the B467 warning.
if [ -e "$DRILL/restored/node.key" ]; then
  echo "❌ DR DRILL FAILED: the restore installed a node.key"; exit 1
fi
if [ ! -f "$DRILL/restored/RESTORED_FROM_BACKUP" ]; then
  echo "❌ DR DRILL FAILED: no RESTORED_FROM_BACKUP warning"; exit 1
fi
diff "$DRILL/data/validator_9001.db/CURRENT" "$DRILL/restored/validator_9001.db/CURRENT"
diff "$DRILL/data/validator_9001.db/000001.sst" "$DRILL/restored/validator_9001.db/000001.sst"
diff "$DRILL/genesis.json" "$DRILL/genesis-restored.json"
echo "✅ DR DRILL PASSED: backup → verify → restore round-trips byte-for-byte (no key)"

# 5. NEGATIVE CHECKS — the restore refuses to clobber a non-empty DB, and
#    refuses to run without --not-a-validator (B467)
if scripts/restore_node.sh --backup "$ARCHIVE" --datadir "$DRILL/restored" \
     --port 9001 --not-a-validator >/dev/null 2>&1; then
  echo "❌ DR DRILL FAILED: restore overwrote an existing DB"; exit 1
fi
if scripts/restore_node.sh --backup "$ARCHIVE" --datadir "$DRILL/no-flag" \
     --port 9001 >/dev/null 2>&1; then
  echo "❌ DR DRILL FAILED: restore ran without --not-a-validator"; exit 1
fi
echo "✅ DR DRILL PASSED: restore refused to clobber, and refused without --not-a-validator"
```

Then remove the drill directory:

```bash
rm -rf "$DRILL"
```

A test harness runs an equivalent automated round-trip, with every refusal
above, the pre-B467 archive case and the B373 key check:
`bash scripts/dr/dr_roundtrip_test.sh`.

---

## 8. Recovery checklist (incident)

1. Is the failed node a validator (its address in `/get_validators`)? Then
   follow §4 and nothing else: never restore its database.
2. Confirm the failed node is **fully down** (powered off, or its disk or
   `node.key` moved away). Two live nodes sharing `node.key` = equivocation.
3. Provision a clean host + a fresh, empty datadir.
4. A validator: put `node.key` from the offline backup in the empty datadir
   and start the node (§4). A node that is not a validator: pull the latest
   backup tarball **and** its `.sha256` from offsite storage and run
   `restore_node.sh --not-a-validator` (auto-verifies sha256; §5).
5. Restore `genesis.json` if the host doesn't already have it.
6. Start the node; watch logs for height advancing and ChainSync closing the
   gap. A validator: watch for the `[RC-3]` proof line, then confirm its
   address is still in `/get_validators` and it signs again.
7. Once healthy and caught up, resume the normal backup cadence (§2).
