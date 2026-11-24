# Operating the AINCORE indexer

Set `NODE_RPC_URL` to the trusted node RPC. The node must expose its boot-verified `chain_id` and `genesis_identity` in `aincore_getStatus`. Use `AINCORE_EXPECTED_GENESIS_HASH` to pin a known genesis before first startup. Otherwise the first successful connection establishes the local pin. This indexer relies on the upstream node for block execution and finality.

The default SQLite database is `indexer.db` in the working directory. Set `AINCORE_INDEXER_DB_PATH` to select a different file. Each batch stores its height, block hash, chain ID and genesis identity in the same transaction as its history. A changed cursor, mismatched parent or missing block stops that batch. A valid prefix can commit before a later invalid block. The existing tail bootstrap indexes up to the last 5,000 blocks on a fresh database. Set `AINCORE_INDEXER_BOOTSTRAP_BACKFILL=0` with an archive node to index from height 1.

A populated legacy database needs an independently recorded checkpoint identifying the history it already holds. Stop earlier indexer versions, take a consistent SQLite backup and set `AINCORE_INDEXER_LEGACY_CHECKPOINT` to a JSON file with the following fields.

| Field | Value |
| --- | --- |
| `chain_id` | Chain ID of the original index |
| `genesis_identity` | 64 hexadecimal characters from the original genesis |
| `height` | Unsigned integer equal to the saved SQLite cursor |
| `block_hash` | 64 hexadecimal characters for the block at that height |

The indexer compares the checkpoint with the database height, the node identity and the block at that height before binding the existing rows. The checkpoint attests to the origin of those rows. A value copied from a replacement upstream cannot establish their origin. If the checkpoint is unavailable or the legacy database uses the retired integer-amount schema, keep the old database and rebuild using a new `AINCORE_INDEXER_DB_PATH`. The checkpoint file is optional on subsequent starts after a successful migration.

`GET /health` reports process liveness. `GET /ready` returns 200 when the last successful reconciliation reached the observed upstream height. During startup, catch-up, database errors or upstream failures it returns 503 with the reason, indexed height, last observed upstream height and most recent commit time in this process. An observation expires after 65 seconds. While caught up on a nonzero height, the indexer rechecks the stored tip hash at least once every 30 seconds of successful polling.
