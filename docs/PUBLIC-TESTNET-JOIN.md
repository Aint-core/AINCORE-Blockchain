# AINCORE Public Testnet — Join Guide & Bootstrap Design

Status: working procedure, codified from the 2026-06-15 multi-node bring-up
(NAS validator + Pi + laptop observers, synced over Tailscale/LAN).

## TL;DR

A new node **cannot replay the chain from genesis** — the seed prunes old blocks
(`block_1` no longer exists) and anti-jump guards reject a `0 -> current` leap.
So joining = **state-snapshot bootstrap**: start from a recent snapshot, then
sync the small (still-present) delta automatically.

- Operator publishes a sanitised snapshot:  `scripts/testnet-make-snapshot.sh`
- Joiner bootstraps in one shot:             `scripts/testnet-join.sh`

## Why replay-from-0 fails (root cause, confirmed via ldb)

```
block_1     -> MISSING (pruned)
block_100   -> MISSING (pruned)
block_50000 -> exists
```

The seed keeps only recent history (anti-bloat). A fresh node requests
`block_1..500`, gets an empty response, and stalls at height 0 forever. Wiping
state makes it worse. The only fix is to hand the joiner recent **state**, not
make it replay history.

## Architecture

```
            (public internet / Tailscale)
 joiner ──────────────► PUBLIC SEED (NAS validator, exposed) ──► produces blocks + QC
   │  1. download snapshot + genesis + binary
   │  2. load snapshot state (≈ current height)
   └─ 3. ChainSync the small delta from the seed  ──► tracking, healthy observer
```

Observers run with `AINCORE_P2P_LISTEN=0` and are **never** in the validator set
(their address ≠ a genesis validator), so they follow the chain but never mine.

## Operator: publish a snapshot + run the public seed

1. **Make a clean snapshot** (brief seed downtime; sanitises per-identity DA key
   + peer table so any joiner can use it):
   ```bash
   scripts/testnet-make-snapshot.sh \
     --container aincore-latest-fresh-node \
     --db /home/alpha/aincore-latest-fresh-run/fresh_data/validator_9022.db \
     --out /home/alpha/snapshot/aincore-testnet-snapshot.tar.gz
   ```
2. **Publish** the snapshot + `genesis.json` + prebuilt binaries (x86_64 +
   aarch64) where joiners can fetch them (GitHub release, object storage, or
   served from the seed host).
3. **Expose the seed publicly** — pick one:
   - **Tailscale Funnel** (free, no VPS): enable Funnel in the tailnet admin,
     then `tailscale funnel --bg --tcp 443 127.0.0.1:9022`. Seed addr becomes
     `/dns4/<node>.<tailnet>.ts.net/tcp/443`.
   - **Public VPS seed**: run a node with the public IP; seed addr
     `/ip4/<vps-ip>/tcp/9022`.

Refresh the published snapshot periodically (e.g. daily) so new joiners start
within the seed's prune window.

## Joiner: one command

```bash
# 1. get a node binary for your arch (release artifact, or build it):
#      cargo build --release -p node   # -> target/release/node
# 2. bootstrap:
scripts/testnet-join.sh \
  --binary ./node \
  --genesis ./genesis.json \
  --snapshot-url https://<host>/aincore-testnet-snapshot.tar.gz \
  --seed /dns4/<node>.<tailnet>.ts.net/tcp/443 \
  --datadir ~/.aincore-observer
# then run the printed command; height should climb toward the seed.
```

## What must still be set up (admin prerequisites — not code)

1. **A reachable public seed** (Tailscale Funnel enabled, or a VPS). Today the
   internal nodes reach the seed over Tailscale/LAN; public-internet join needs
   one of the above live.
2. **A public host for the join package** (snapshot + genesis + binaries). The
   old VPS that hosted this is expired.

## Honest limitations / the durable fix

This snapshot flow is a **repeatable manual bootstrap**, not yet automatic:

- If a node is offline longer than the seed's prune window, it falls too far
  behind and must re-bootstrap from a fresh snapshot.
- The snapshot must be re-published periodically.

The durable "perfect" fix is **automated peer state-sync**: a node booting with
empty/far-behind data requests a verified state snapshot from its trusted
bootnode over the wire and loads it, with no manual snapshot publishing. That is
a protocol feature (a `SNAPSHOT_REQ/RESP` exchange in `sync/`), and it also
unblocks multi-validator onboarding (same bootstrap gap). Sequence it after this
manual flow is in use.

## Field notes (gotchas already hit + handled)

- **DA key panic** (`da/src/lib.rs`: "failed to decrypt DA signing key"): a raw
  copy of the seed DB carries the seed's per-identity DA key. The snapshot
  script strips `sys:da:signing_key*` so the joiner generates its own.
- **Inherited peer table**: a raw copy makes the joiner hammer the seed's dead
  peers. The snapshot script clears `peer:/peer_ip:/peer_addr:`.
- **Stale binary**: a node binary older than the genesis reset cannot follow the
  current consensus format — rebuild from the current source for the node's arch.
- **node.key**: preserve per-node identity across reseeds; never copy one node's
  `node.key` to another.
