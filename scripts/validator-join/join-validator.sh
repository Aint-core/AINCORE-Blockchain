#!/usr/bin/env bash
# AINCORE — join the network as an independent validator.
#
#   ./join-validator.sh prepare   # build, make your key, print your address
#   ./join-validator.sh start     # run the node and sync
#   ./join-validator.sh join      # stake 1000 AIN and enter the validator set
#   ./join-validator.sh verify    # confirm you are validating
#
# B441 (G1 RC-3 "Joining"): a validator that joins after launch signs only
# once its node has proved its boot: while its key is in the live set, the
# node sends about once a minute a transfer to itself, and notes the height N
# it holds when a block carries one. The epoch E the join lands in closes at
# H_E, and C_{E+1} is taken from the live set there: with N below H_E, E+1's
# activation lets the node sign; with N at or above H_E (a join late in E, or
# a restart), it abstains for its whole first member epoch. Every start of a
# node that does not sign yet clears a noted proof, so keep it running and
# synced until it signs, fund it with the stake plus a little AIN for gas, and
# join in the first half of an epoch (`join` checks both). A join sent late
# that lands only after its epoch's boundary is not late: it lands in the next
# epoch, and its proof has all of that epoch to land.
# docs/NODE_OPERATOR_GUIDE.md, "Stake Tokens and Join".
#
# Configure with environment variables (see README.md):
#   AINCORE_CHAIN_ID              chain id, must match the network exactly
#   AINCORE_EXPECTED_GENESIS_HASH genesis identity pin — REFUSES TO BOOT on mismatch
#   AINCORE_GENESIS_PATH          path to the network's genesis.json
#   AINCORE_BOOTNODES             comma-separated /ip4/<host>/tcp/<p2p-port>
#   AINCORE_P2P_PORT              default 9201   (RPC is this minus 1000)
#   AINCORE_DATADIR               default ./data-validator
#   AINCORE_JOIN_LATE             1 = join even in the second half of an epoch
#   AINCORE_REFERENCE_RPC         JSON-RPC URL of another node of the network
#                                 (ask the operator): `join` refuses while this
#                                 node trails it by more than 3 blocks, and times
#                                 the epoch from the higher of the two heights
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
# Di atas stake: gas transaksi join dan bukti boot (B441), seperti default
# fund-validator.sh (1010 AIN).
GAS_HEADROOM_AIN=10
# Batas yang diperiksa `join`: stake + 1 AIN. Lebih kecil dari yang dikirim
# operator, supaya join yang batal (ECHURN_LIMIT; gasnya tetap terbayar) masih
# bisa diulang di epoch berikutnya tanpa minta saldo tambahan.
JOIN_MARGIN_AIN=1
# B441: node rujukan untuk tinggi jaringan (opsional). Node yang sudah di ujung
# bisa tertinggal satu-dua blok dari node lain selama blok menyebar.
REF_RPC="${AINCORE_REFERENCE_RPC:-}"
SYNC_SLACK_BLOCKS=3

die() { echo "❌ $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "butuh '$1' — install dulu"; }

# Alamat dari node.key. `keygen` MEMUAT kunci yang ada (load_or_create) dan hanya
# membuat baru kalau file belum ada -- tidak pernah menimpa. Ambil baris
# "Address (hex):" (B349): baris "Address:" adalah bentuk A1n, yang ditolak
# fund-validator.sh dan tidak cocok dengan alamat 64-hex di /get_validators;
# baris "Public Key:" juga 64 hex dan tertangkap regex polos.
my_address() {
  ./target/release/aincore-cli --keyfile "$KEY" --rpc "$RPC" --chain-id "$CHAIN_ID" keygen 2>/dev/null \
    | awk '/^Address \(hex\):/{print $3; exit}'
}

rpc_call() {
  curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}"
}

# B441: "I H_E SISA" untuk blok berikutnya. Epoch E memuat blok E*I+1 sampai
# blok batasnya H_E = (E+1)*I; blok berikutnya (tinggi+1) ada di epoch
# tinggi // I. I = epoch_blocks dari aincore_getEconomics. Tinggi yang dipakai
# adalah yang lebih tinggi dari tinggi lokal dan $1 (tinggi rujukan; 0 = tidak
# ada).
epoch_position() {
  rpc_call aincore_getEconomics '[]' | python3 -c "
import sys,json
r=json.load(sys.stdin)['result']
i=int(r['epoch_blocks']); h=max(int(r['block_height']), int(sys.argv[1]))
assert i > 0
he=(h//i+1)*i
print(i, he, he-h)
" "${1:-0}" 2>/dev/null
}

# B441: tinggi node rujukan (AINCORE_REFERENCE_RPC); gagal kalau tidak terbaca.
ref_height() {
  curl -s --max-time 10 -X POST "$REF_RPC" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"aincore_getStatus","params":[],"id":1}' \
    | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result']['latest_height']))" 2>/dev/null
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
  echo "  Kirim alamat itu ke operator jaringan dan minta $((MIN_STAKE_AIN + GAS_HEADROOM_AIN)) AIN"
  echo "  ($MIN_STAKE_AIN stake + $GAS_HEADROOM_AIN untuk gas join dan bukti boot)."
  echo "  Lanjut: ./join-validator.sh start"
}

cmd_start() {
  require_config
  [ -f "$KEY" ] || die "jalankan 'prepare' dulu"
  echo "== 2/4 START =="
  echo "  chain=$CHAIN_ID p2p=$P2P_PORT rpc=$RPC_PORT datadir=$DATADIR"
  [ -n "$BOOTNODES" ] || die "AINCORE_BOOTNODES belum diset — node tidak akan menemukan siapa pun"
  echo "  Node akan MENOLAK BOOT kalau genesis-mu berbeda dari jaringan."
  echo "  Biarkan node ini TERUS JALAN dari join sampai ia ikut menandatangani"
  echo "  (biasanya sejak aktivasi epoch pertamamu sebagai anggota). Setiap start"
  echo "  node yang belum menandatangani menghapus bukti boot yang sudah dicatatnya:"
  echo "  restart sebelum aktivasi itu, termasuk setelah blok batas H_E, membuang"
  echo "  bukti tersebut, dan bukti baru yang tercatat di H_E atau di atasnya"
  echo "  menunda tanda tanganmu paling sedikit satu epoch."
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
  NEED=$(python3 -c "print(($MIN_STAKE_AIN+$JOIN_MARGIN_AIN)*10**18)")
  echo "  saldo AIN: $BAL (butuh >= $NEED: stake + gas join dan bukti boot)"
  python3 -c "import sys;sys.exit(0 if int('$BAL')>=int('$NEED') else 1)" \
    || die "saldo kurang dari $((MIN_STAKE_AIN + JOIN_MARGIN_AIN)) AIN (stake $MIN_STAKE_AIN + gas) — minta operator mengirim ke $ADDR"

  # B441: pemeriksaan epoch di bawah membaca tinggi LOKAL, tapi join masuk di
  # tinggi JARINGAN: node yang masih menyusul lolos padahal jaringan sudah di paruh
  # kedua epoch, atau di epoch berikutnya. Dengan AINCORE_REFERENCE_RPC, tolak
  # node yang tertinggal dan hitung dari tinggi yang lebih tinggi.
  REF_H=0
  if [ -n "$REF_RPC" ]; then
    REF_H=$(ref_height) || die "AINCORE_REFERENCE_RPC ($REF_RPC) tidak menjawab aincore_getStatus"
    echo "  tinggi jaringan: $REF_H (dari $REF_RPC)"
    [ $((REF_H - H)) -le "$SYNC_SLACK_BLOCKS" ] || die "node lokal tertinggal $((REF_H - H)) blok dari $REF_RPC.
   Tunggu sampai node menyusul, lalu jalankan 'join' lagi."
  else
    echo "  ⚠️  AINCORE_REFERENCE_RPC belum diset: pemeriksaan epoch di bawah memakai"
    echo "     tinggi LOKAL ($H) dan menganggap node-mu sudah di ujung jaringan."
    echo "     Pastikan tingginya sama dengan node lain sebelum join."
  fi

  # B441: node-mu harus mencatat bukti boot-nya di bawah H_E, blok batas epoch
  # tempat join masuk; di paruh kedua epoch sisa bloknya bisa tidak cukup.
  POS=$(epoch_position "$REF_H") || die "aincore_getEconomics tidak terbaca di $RPC (epoch_blocks)"
  read -r EPOCH_BLOCKS BOUNDARY LEFT <<<"$POS"
  echo "  epoch: $EPOCH_BLOCKS blok; blok batas H_E = $BOUNDARY ($LEFT blok lagi)"
  if [ $((LEFT * 2)) -lt "$EPOCH_BLOCKS" ] && [ "${AINCORE_JOIN_LATE:-0}" != 1 ]; then
    die "epoch ini sudah lewat separuh. Kalau join-mu masuk sebelum blok batas
   H_E = $BOUNDARY, node-mu harus mencatat bukti boot-nya di bawah $BOUNDARY; kalau
   tercatat di $BOUNDARY atau di atasnya, node-mu tidak ikut menandatangani
   selama seluruh epoch pertamanya sebagai anggota (tanpa vertex dan bonus
   leader; bagian reward menurut stake tetap dibayar). Tunggu sampai tinggi
   $BOUNDARY lewat, lalu jalankan 'join' lagi di awal epoch berikutnya
   (AINCORE_JOIN_LATE=1 untuk tetap join sekarang; join yang baru masuk setelah
   $BOUNDARY tidak terlambat: node-mu menjadi anggota satu epoch kemudian)."
  fi

  echo "  mengirim join_validator_set (stake $MIN_STAKE_AIN AIN)..."
  ./target/release/aincore-cli --keyfile "$KEY" --rpc "$RPC" --chain-id "$CHAIN_ID" register-validator
  echo "  terkirim. Jangan kirim transaksi lain dari akun ini sampai bukti boot"
  echo "  tercatat (bukti itu memakai nomor urut akun berikutnya)."
  echo "  Kalau verify tetap BELUM dan receipt transaksi ini gagal dengan abort code"
  echo "  589836 (ECHURN_LIMIT): jatah stake baru epoch ini habis; join lagi di awal"
  echo "  epoch berikutnya."
  echo "  Lanjut: ./join-validator.sh verify"
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
  VREF=0
  if [ -n "$REF_RPC" ]; then VREF=$(ref_height) || VREF=0; fi
  if POS=$(epoch_position "$VREF"); then
    read -r _ BOUNDARY LEFT <<<"$POS"
    echo "  blok batas epoch ini     : $BOUNDARY ($LEFT blok lagi)"
  fi
  echo
  echo "  Kalau 'BELUM': tunggu beberapa blok, lalu jalankan verify lagi."
  echo "  Kalau sudah YA: kuncimu ada di live set, dan node-mu mengirim bukti boot"
  echo "  sekitar sekali semenit. Saat bukti itu masuk blok, log node mencetak:"
  echo "    [RC-3] ... signing resumes at the first boundary above height N"
  echo "  Node-mu menjadi anggota komite pada aktivasi epoch setelah blok batas"
  echo "  epoch tempat join-mu masuk, dan ikut menandatangani sejak itu kalau N"
  echo "  di bawah blok batas tersebut; kalau tidak, satu epoch kemudian atau lebih."
  echo "  Jangan restart node sebelum ia ikut menandatangani: setiap start menghapus"
  echo "  bukti yang sudah tercatat, dan node mengirim bukti baru."
  echo "  Log '[RC-3] no proof-of-boot transaction this time (ALASAN)' yang berulang:"
  echo "  baca ALASAN di dalam kurung (baris itu selalu diakhiri saran soal gas)."
  echo "    Insufficient balance for gas / no CoinStore: akun kurang AIN untuk gas."
  echo "    Duplicate pending nonce: bukti sebelumnya masih menunggu blok; wajar,"
  echo "      kecuali masih berulang menjelang blok batas (periksa peer dan sinkron)."
  echo "    Mempool full: mempool node penuh; node mencoba lagi semenit kemudian."
}

case "${1:-}" in
  prepare) cmd_prepare ;;
  start)   cmd_start ;;
  join)    cmd_join ;;
  verify)  cmd_verify ;;
  *) echo "pakai: $0 {prepare|start|join|verify}"; exit 1 ;;
esac
