# AINCORE Testnet — Join as an Observer (copy‑paste guide)

This gets a brand‑new machine syncing the AINCORE testnet as an **observer** (it
never mines; its address is never in the validator set). Follow it top to
bottom — every command is paste‑ready.

> **One step is not pasteable:** the testnet is reached over a private
> [Tailscale](https://tailscale.com) tailnet (the seed has no public IP yet), so
> the operator sends you a **Tailscale auth key** out of band. That's Step 1.
> Everything after it is pure copy‑paste.

---

## Network facts (constants)

| Field | Value |
|---|---|
| Chain ID | `AINCORE-LATEST-FRESH-1` |
| Seed multiaddr | `/ip4/100.111.32.83/tcp/9022` (seed's Tailscale IP) |
| Seed / genesis validator id | `64fff6085ad266e3fee5001e6b46f24e` |
| Observer ports (default) | P2P `9032`, RPC `8032` |
| Bootstrap | state snapshot + delta sync (the seed prunes old blocks, so a height‑0 node cannot replay from genesis) |

### Package contents + checksums

```
node-x86_64-linux                61b25a517b8e4be358e54d8661cfdbcc2e28264b8e7a85a0a32a61174b3c65aa
node-aarch64-linux               8bf51a466d6a475feb8515365b75b47d63b3469b68c534ddbd48b23af1817e19
aincore-testnet-snapshot.tar.gz  a24faf69f246e33978f9b83967d056eae74f60ee9ae0e81306344b81850e6a43
genesis.json                     abf599cbbf98b0ef67bfc351dff797e1ff08ac88d04e7051e6999482c55b7507
```

> Current binaries: QC‑verified finality, unified serving path, near‑realtime
> 3 s sync. Different hash ⇒ you have an old package; ask the operator for the latest.

---

## Prerequisites

- **glibc‑based Linux** (Ubuntu/Debian) on **x86_64** or **aarch64 (ARM64)**. The
  shipped binaries are dynamically linked against glibc — on Alpine/musl or a very
  old glibc, build from source (`cargo build --release -p node`) instead.
- Install the base tools first (fresh cloud images often lack `curl`):
  ```bash
  sudo apt-get update && sudo apt-get install -y curl tar coreutils
  ```
- The **join package** (this directory) and a **Tailscale auth key** from the operator.

---

## Step 1 — Join the tailnet (needs the operator's auth key)

Install Tailscale, bring it up with your key, and confirm you can reach the seed:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --auth-key="<AUTH-KEY-FROM-OPERATOR>"
tailscale ping 100.111.32.83        # MUST succeed before continuing
```

**Do not continue until `tailscale ping 100.111.32.83` succeeds** — if it doesn't,
you're not on the tailnet (re‑run `tailscale up` with a valid key). The seed is
only reachable over the tailnet; a node pointed at it without Tailscale will log
`Secure Handshake Failed … TCP connect timeout` and never sync.

---

## Step 2 — Bootstrap + run (pure paste)

**Get the package** from the testnet release (public, no auth needed), extract,
and `cd` in:

```bash
curl -fL -o aincore-testnet-join-package.tar.gz \
  https://github.com/Aint-core/AINCORE-Blockchain/releases/download/testnet-join-v1/aincore-testnet-join-package.tar.gz
tar xzf aincore-testnet-join-package.tar.gz
cd aincore-testnet-join-package
```

(If the operator handed you the folder directly, just `cd` into it. The package
is a *directory* named `aincore-testnet-join-package`.)

Now paste this whole block. It verifies integrity (incl. the script itself),
auto‑detects your CPU arch, and installs the snapshot:

```bash
set -e
# 1. integrity check (fails loudly on a corrupt/old file)
sha256sum -c SHA256SUMS

# 2. auto-pick the binary for THIS machine
case "$(uname -m)" in
  x86_64|amd64)  cp node-x86_64-linux  ./node ;;
  aarch64|arm64) cp node-aarch64-linux ./node ;;
  *) echo "unsupported arch $(uname -m) — build from source" >&2; exit 1 ;;
esac
chmod +x ./node testnet-join.sh

# 3. load snapshot state + prepare datadir
./testnet-join.sh \
  --binary ./node \
  --genesis ./genesis.json \
  --snapshot ./aincore-testnet-snapshot.tar.gz \
  --seed /ip4/100.111.32.83/tcp/9022 \
  --datadir "$HOME/.aincore-observer"
```

Then start the node. **Durable systemd service (recommended).** Paste this block
**as your normal user** — it calls `sudo` itself; do **NOT** prefix the whole
block with `sudo` (that would set the datadir to `/root/...` where there's no
snapshot, and the node would silently start empty at height 0):

```bash
NODE="$(pwd)/node"; DD="$HOME/.aincore-observer"
sudo tee /etc/systemd/system/aincore-observer.service >/dev/null <<UNIT
[Unit]
Description=AINCORE testnet observer
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
User=$USER
Environment=AINCORE_CHAIN_ID=AINCORE-LATEST-FRESH-1
Environment=AINCORE_P2P_LISTEN=0
Environment=AINCORE_SYNC_INTERVAL_MS=3000
Environment=RUST_LOG=info
ExecStart=$NODE --port 9032 --rpc-port 8032 --datadir $DD --bootnodes /ip4/100.111.32.83/tcp/9022
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now aincore-observer.service
```

Or **foreground** (quick test, no sudo):

```bash
AINCORE_CHAIN_ID=AINCORE-LATEST-FRESH-1 AINCORE_P2P_LISTEN=0 AINCORE_SYNC_INTERVAL_MS=3000 RUST_LOG=info \
  ./node --port 9032 --rpc-port 8032 \
    --datadir "$HOME/.aincore-observer" \
    --bootnodes /ip4/100.111.32.83/tcp/9022
```

---

## Step 3 — Verify (paste)

The node takes a few seconds to open its DB and bind the RPC, so the first
samples may print `Connection refused` — **that is normal**; keep watching until
`latest_height` appears and climbs:

```bash
for i in $(seq 1 10); do
  curl -s --retry 5 --retry-connrefused --max-time 5 \
    localhost:8032/rpc -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}'
  echo; sleep 4
done
```

Healthy = `latest_height` climbs each sample and tracks the seed within ~1 block;
`finalized_round` advances. Finality is **QC‑gated**: your node only advances its
finalized round after verifying the validators' >2/3‑stake BLS quorum
certificate — a forged finality hint can never move it.

systemd logs: `journalctl -u aincore-observer.service -f`
(look for `✅ [ChainSync] Applied QC-verified finality: round=…`).

---

## Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `tailscale ping 100.111.32.83` fails | Not on the tailnet → redo Step 1 with a valid key. |
| `sha256sum: … did NOT match` | Corrupt/old file → re‑get the package. |
| `cannot execute binary file` | Wrong arch → Step 2 auto‑picks; if copied by hand, match `uname -m`. |
| Height stuck at the snapshot value | Can't reach the seed → check `tailscale ping`; ensure `9032` is free. |
| Log: `peer pruned below us … bootstrap from a state snapshot` | You fell behind the seed's retention window → get a **fresh** snapshot, redo Step 2. |
| `Address already in use` | `9032`/`8032` taken → pass free `--port`/`--rpc-port` (update the systemd `ExecStart` too). |
| Boot panic re: DA signing key | Un‑sanitised snapshot → use the operator's packaged snapshot (pre‑sanitised). |

**Realtime tuning:** `AINCORE_SYNC_INTERVAL_MS` = pull cadence (default `3000` ms ≈
block time → ~1‑block lag; floor `500`).

---

## Why snapshot bootstrap (not replay‑from‑genesis)

The seed prunes old blocks (`block_1` is gone; confirmed via ldb), and a fresh
node requesting `block_1..500` gets empty replies and stalls at height 0. So a
joiner loads recent **state** from a snapshot and syncs only the still‑present
delta. Observers run `AINCORE_P2P_LISTEN=0` and are never in the validator set.

---

## Operator — onboard a new joiner (Tailscale invite)

The seed has no public IP (the home line is behind ISP CGNAT), so joiners reach it
over the operator's Tailscale tailnet. To bring someone on:

1. Tailscale admin console → **Settings → Keys → Generate auth key**:
   - **Reusable** (one key for many joiners) or one‑off per joiner.
   - Recommended: tag it (e.g. `tag:aincore-observer`) + set an expiry.
2. Send the joiner **two things** (privately — the key is like a password):
   - the **Tailscale auth key**, and
   - the release link: <https://github.com/Aint-core/AINCORE-Blockchain/releases/tag/testnet-join-v1>
3. The joiner runs Step 1–3 above (`tailscale up --auth-key=<key>` → download the
   package → paste the bootstrap → synced). They need nothing else from you.

Revoke access anytime: delete the key or remove the node in the Tailscale admin.

## For operators

- **Make/refresh the snapshot** (run on the seed host; ~15–30 s validator downtime):
  ```bash
  scripts/testnet-make-snapshot.sh \
    --container aincore-latest-fresh-node \
    --db /home/alpha/aincore-latest-fresh-run/fresh_data/validator_9022.db \
    --out ./aincore-testnet-snapshot.tar.gz
  ```
  Stops the node for a consistent copy, restarts immediately, then **sanitises**
  it (strips per‑identity DA key `sys:da:signing_key*` + the seed's peer table) so
  it's safe for any joiner. Re‑cut periodically so joiners sync a small delta.
- **Refresh the package** when binaries change: drop new `node-x86_64-linux` /
  `node-aarch64-linux` in, regenerate the checksums (`sha256sum …`), re‑tar.
- **Node‑native auto‑bootstrap (advanced, most paste‑paste):** instead of
  `testnet-join.sh`, a fresh datadir self‑bootstraps from the release snapshot URL
  (https‑only; the node extracts + self‑sanitises before opening the DB, then
  no‑ops once a DB exists):
  ```bash
  AINCORE_CHAIN_ID=AINCORE-LATEST-FRESH-1 AINCORE_P2P_LISTEN=0 \
  AINCORE_BOOTSTRAP_SNAPSHOT=https://github.com/Aint-core/AINCORE-Blockchain/releases/download/testnet-join-v1/aincore-testnet-snapshot.tar.gz \
    ./node --port 9032 --rpc-port 8032 --datadir ~/.aincore-observer \
           --bootnodes /ip4/100.111.32.83/tcp/9022
  ```
- **Cut a new release** when binaries/snapshot change: re‑tag (e.g. `testnet-join-v2`),
  upload the refreshed `aincore-testnet-join-package.tar.gz` + `aincore-testnet-snapshot.tar.gz`
  + `SHA256SUMS` as assets, and bump the URLs above.
- **Going truly public (no invite):** the home seed line is behind **ISP CGNAT**
  (WAN IP is private `10.x`), so router port‑forward cannot expose it — confirmed.
  To drop the invite step, run a seed on a **public‑IP VPS** (or get a static
  public IP from the ISP) and publish `/ip4/<vps-ip>/tcp/9022`. Add a **second
  validator** before advertising it as decentralized — the testnet is
  single‑validator today.
