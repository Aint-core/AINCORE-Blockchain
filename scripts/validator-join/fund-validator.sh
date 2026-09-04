#!/usr/bin/env bash
# AINCORE — operator side: send a newcomer the stake they need to join.
#
#   ./fund-validator.sh <alamat-64-hex> [jumlah-AIN]
#
# Runs ON a validator host: it signs with that node's own node.key, which never
# leaves the machine. Default 1010 AIN = MIN_STAKE (1000) plus gas headroom.
set -euo pipefail
ADDR="${1:-}"
AMOUNT="${2:-1010}"
KEY="${AINCORE_FUNDER_KEY:-data-r1/node.key}"
RPC="${AINCORE_RPC:-http://127.0.0.1:8201/rpc}"
CHAIN_ID="${AINCORE_CHAIN_ID:-}"

die() { echo "❌ $*" >&2; exit 1; }
[ -n "$ADDR" ] || die "pakai: $0 <alamat-64-hex> [jumlah-AIN]"
[ "${#ADDR}" -eq 64 ] || die "alamat harus 64 hex char (dapat 32 = format lama, tolak)"
echo "$ADDR" | grep -qE '^[0-9a-f]{64}$' || die "alamat bukan hex huruf kecil"
[ -n "$CHAIN_ID" ] || die "AINCORE_CHAIN_ID belum diset"
[ -f "$KEY" ] || die "keyfile pendana tidak ada: $KEY"

bal() {
  curl -s --max-time 10 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"aincore_getCoinBalance\",\"params\":[\"$1\",\"AIN\"],\"id\":1}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['balance'])" 2>/dev/null || echo "?"
}

echo "== danai calon validator =="
echo "  tujuan : $ADDR"
echo "  jumlah : $AMOUNT AIN"
echo "  saldo tujuan sebelum: $(bal "$ADDR")"
./target/release/aincore-cli --keyfile "$KEY" --rpc "$RPC" --chain-id "$CHAIN_ID" \
  transfer "$ADDR" "$AMOUNT"
echo "  menunggu blok..."
sleep 12
echo "  saldo tujuan sesudah: $(bal "$ADDR")"
echo
echo "  Minta dia jalankan: ./join-validator.sh join"
