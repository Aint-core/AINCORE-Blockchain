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
3. **Let participants reach the seed — via the Tailscale tailnet (recommended).**
   The seed is the validator's Tailscale IP (e.g. `100.111.32.83:9022`). This is
   exactly how the existing observers connect — raw TCP over Tailscale, NAT
   handled, zero cost. To onboard a participant: admin console → Settings → Keys
   → generate an **auth key** (reusable, optionally tagged), and share it. They
   `tailscale up --auth-key=<key>` to join your tailnet, then run the join script
   pointed at the seed's Tailscale IP. "Invite-based public": anyone you give a
   key can join from anywhere.

   > **Why not Tailscale Funnel?** Funnel fronts everything with TLS/SNI (it's
   > built for HTTPS). AINCORE P2P is raw TCP with its own encryption, not TLS,
   > so a node cannot traverse Funnel without a joiner-side TLS tunnel
   > (socat/stunnel) — fragile, and bandwidth-limited through Funnel relays. For
   > a fully-open seed (no Tailscale on the joiner) use a **public-IP VPS**
   > running a node (`/ip4/<vps-ip>/tcp/9022`) instead. Tailnet-invite is the
   > robust path until then.

Refresh the published snapshot periodically (e.g. daily) so new joiners start
within the seed's prune window.

## Joiner: steps

```bash
# 1. join the tailnet (one-time) with the auth key the operator gave you:
sudo tailscale up --auth-key=<KEY-FROM-OPERATOR>

# 2. get a node binary for your arch (release artifact, or build it):
#      cargo build --release -p node   # -> target/release/node

# 3. bootstrap (seed = the validator's Tailscale IP):
scripts/testnet-join.sh \
  --binary ./node \
  --genesis ./genesis.json \
  --snapshot-url https://<host>/aincore-testnet-snapshot.tar.gz \
  --seed /ip4/100.111.32.83/tcp/9022 \
  --datadir ~/.aincore-observer
# then run the printed command; height should climb toward the seed.
```

## Node-native auto-bootstrap (no script — for systemd/docker)

The node can bootstrap itself. On a **fresh datadir**, set
`AINCORE_BOOTSTRAP_SNAPSHOT` to a local path or http(s) URL of the snapshot
tarball; the node extracts it before opening the DB, then self-sanitises
(regenerates its own DA key, clears the seed's inherited peer table) — so no ldb
and no manual key surgery on the joiner.

```bash
AINCORE_CHAIN_ID=AINCORE-LATEST-FRESH-1 AINCORE_P2P_LISTEN=0 \
AINCORE_BOOTSTRAP_SNAPSHOT=https://<host>/aincore-testnet-snapshot.tar.gz \
  ./node --port 9032 --rpc-port 8032 --datadir ~/.aincore-observer \
         --bootnodes /ip4/100.111.32.83/tcp/9022
```

It is a strict no-op once a chain DB exists, so it is safe to leave set across
restarts (re-deploying a fresh observer auto-recovers). Use this in an
observer's systemd unit / docker-compose env.

## What must still be set up (admin prerequisites — not code)

1. **Onboard participants to the tailnet.** Generate a Tailscale auth key
   (admin → Settings → Keys) and share it; participants `tailscale up
   --auth-key=<key>` then reach the seed at its Tailscale IP. This works today
   (the existing observers use exactly this path). Funnel was evaluated and
   rejected for P2P (TLS mismatch — see the operator note above); a public-IP
   VPS is the only fully-open alternative.
2. **A public host for the join package** (snapshot + genesis + binaries) so
   joiners can fetch them — e.g. a GitHub release. The old VPS that hosted this
   is expired.

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
