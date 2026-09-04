#!/usr/bin/env bash
# AINCORE — join the network as an independent validator.
#
#   ./join-validator.sh prepare   # build, make your key, print your address
#   ./join-validator.sh start     # run the node and sync
#   ./join-validator.sh join      # stake 1000 AIN and enter the validator set
#   ./join-validator.sh verify    # confirm you are validating
#
# Configure with environment variables (see README.md):
#   AINCORE_CHAIN_ID              chain id, must match the network exactly
#   AINCORE_EXPECTED_GENESIS_HASH genesis identity pin — REFUSES TO BOOT on mismatch
#   AINCORE_GENESIS_PATH          path to the network's genesis.json
#   AINCORE_BOOTNODES             comma-separated /ip4/<host>/tcp/<p2p-port>
#   AINCORE_P2P_PORT              default 9201   (RPC is this minus 1000)
#   AINCORE_DATADIR               default ./data-validator
set -euo pipefail

CHAIN_ID="${AINCORE_CHAIN_ID:-}"
GENESIS_PATH="${AINCORE_GENESIS_PATH:-./genesis.json}"
BOOTNODES="${AINCORE_BOOTNODES:-}"
P2P_PORT="${AINCORE_P2P_PORT:-9201}"
RPC_PORT=$((P2P_PORT - 1000))
DATADIR="${AINCORE_DATADIR:-./data-validator}"
KEY="$DATADIR/node.key"
RPC="http://127.0.0.1:$RPC_PORT/rpc"
MIN_STAKE_AIN=1000

die() { echo "❌ $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "butuh '$1' — install dulu"; }

# Alamat dari node.key. `keygen` MEMUAT kunci yang ada (load_or_create) dan hanya
# membuat baru kalau file belum ada -- tidak pernah menimpa. Ambil baris
# "Address:" saja: baris "Public Key:" juga 64 hex dan tertangkap regex polos.
my_address() {
  ./target/release/aincore-cli --keyfile "$KEY" --rpc "$RPC" --chain-id "$CHAIN_ID" keygen 2>/dev/null \
    | awk '/^Address:/{print $2; exit}'
}

rpc_call() {
  curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}"
}

require_config() {
  [ -n "$CHAIN_ID" ] || die "AINCORE_CHAIN_ID belum diset"
  [ -f "$GENESIS_PATH" ] || die "genesis.json tidak ditemukan di $GENESIS_PATH"
  [ -n "${AINCORE_EXPECTED_GENESIS_HASH:-}" ] || die \
    "AINCORE_EXPECTED_GENESIS_HASH belum diset. Tanpa ini kamu bisa diam-diam
   menjalankan chain BERBEDA. Minta nilainya dari operator jaringan."
}

cmd_prepare() {
  need cargo; need curl; need python3
  require_config
  echo "== 1/4 PREPARE =="
  echo "  build node + cli (butuh beberapa menit)..."
  cargo build --release -p node -p aincore-cli
  mkdir -p "$DATADIR"
  if [ -f "$KEY" ]; then
    echo "  node.key sudah ada — dipakai ulang (JANGAN dihapus, itu identitasmu)"
  else
    # 32 byte acak, hex — format ini dipakai node DAN wallet CLI.
    python3 -c "import secrets;print(secrets.token_hex(32),end='')" > "$KEY"
    chmod 600 "$KEY"
    echo "  node.key dibuat (chmod 600)"
  fi
  ADDR=$(my_address)
  echo
  echo "  ALAMAT KAMU: $ADDR"
  echo
  echo "  Kirim alamat itu ke operator jaringan dan minta $MIN_STAKE_AIN AIN."
  echo "  Lanjut: ./join-validator.sh start"
}

cmd_start() {
  require_config
  [ -f "$KEY" ] || die "jalankan 'prepare' dulu"
  echo "== 2/4 START =="
  echo "  chain=$CHAIN_ID p2p=$P2P_PORT rpc=$RPC_PORT datadir=$DATADIR"
  [ -n "$BOOTNODES" ] || die "AINCORE_BOOTNODES belum diset — node tidak akan menemukan siapa pun"
  echo "  Node akan MENOLAK BOOT kalau genesis-mu berbeda dari jaringan."
  echo
  exec env \
    AINCORE_CHAIN_ID="$CHAIN_ID" \
    AINCORE_GENESIS_PATH="$GENESIS_PATH" \
    AINCORE_EXPECTED_GENESIS_HASH="$AINCORE_EXPECTED_GENESIS_HASH" \
    ./target/release/node --port "$P2P_PORT" --datadir "$DATADIR" --bootnodes "$BOOTNODES"
}

cmd_join() {
  require_config
  [ -f "$KEY" ] || die "jalankan 'prepare' dulu"
  echo "== 3/4 JOIN =="
  STATUS=$(rpc_call aincore_getStatus '[]')
  echo "$STATUS" | grep -q latest_height || die "node lokal tidak menjawab di $RPC — jalankan 'start' di terminal lain"
  H=$(echo "$STATUS" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['latest_height'])")
  echo "  tinggi lokal: $H"
  [ "$H" -gt 0 ] || die "node belum sinkron (height 0). Tunggu sampai menyusul jaringan."

  ADDR=$(my_address)
  BAL=$(rpc_call aincore_getCoinBalance "[\"$ADDR\",\"AIN\"]" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['balance'])" 2>/dev/null || echo 0)
  NEED=$(python3 -c "print($MIN_STAKE_AIN*10**18)")
  echo "  saldo AIN: $BAL (butuh >= $NEED)"
  python3 -c "import sys;sys.exit(0 if int('$BAL')>=int('$NEED') else 1)" \
    || die "saldo kurang dari $MIN_STAKE_AIN AIN — minta operator mengirim ke $ADDR"

  echo "  mengirim join_validator_set (stake $MIN_STAKE_AIN AIN)..."
  ./target/release/aincore-cli --keyfile "$KEY" --rpc "$RPC" --chain-id "$CHAIN_ID" register-validator
  echo "  terkirim. Lanjut: ./join-validator.sh verify"
}

cmd_verify() {
  require_config
  echo "== 4/4 VERIFY =="
  ADDR=$(my_address)
  echo "  alamat: $ADDR"
  V=$(curl -s --max-time 10 "http://127.0.0.1:$RPC_PORT/get_validators")
  echo "$V" | python3 -c "
import sys,json
d=json.load(sys.stdin); vs=d.get('validators',[]) or []
me='$ADDR'
hit=[v for v in vs if str(v.get('address','')).lower()==me.lower()]
print('  validator aktif di jaringan:', d.get('active_validators_count'))
print('  kamu di dalam set        :', 'YA' if hit else 'BELUM')
if hit: print('  stake kamu               :', hit[0].get('stake'))
" 2>/dev/null || echo "  (tidak bisa membaca /get_validators)"
  echo
  echo "  Kalau 'BELUM': tunggu beberapa blok, lalu jalankan verify lagi."
  echo "  Kalau sudah YA: node-mu ikut memproduksi blok. Selamat datang."
}

case "${1:-}" in
  prepare) cmd_prepare ;;
  start)   cmd_start ;;
  join)    cmd_join ;;
  verify)  cmd_verify ;;
  *) echo "pakai: $0 {prepare|start|join|verify}"; exit 1 ;;
esac
