#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SOAK_SECONDS="${AINCORE_PHASE4_SECONDS:-45}"
P2P_PORT="${AINCORE_PHASE4_P2P_PORT:-19100}"
RPC_PORT="${AINCORE_PHASE4_RPC_PORT:-18100}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$ROOT_DIR/.soak/phase4-localnet-$RUN_ID"
LOG_DIR="$RUN_DIR/logs"
NODE_LOG="$LOG_DIR/node.log"
GENESIS_PATH="$RUN_DIR/genesis.json"
KEEP_LOGS="${AINCORE_SOAK_KEEP_LOGS:-0}"
NODE_PID=""

mkdir -p "$LOG_DIR"

stop_node() {
    if [ -n "${NODE_PID:-}" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID" 2>/dev/null || true
        local deadline=$((SECONDS + 10))
        while kill -0 "$NODE_PID" 2>/dev/null; do
            if [ "$SECONDS" -ge "$deadline" ]; then
                kill -9 "$NODE_PID" 2>/dev/null || true
                break
            fi
            sleep 1
        done
        wait "$NODE_PID" 2>/dev/null || true
    fi
    NODE_PID=""
}

cleanup() {
    stop_node

    if [ "$KEEP_LOGS" != "1" ]; then
        rm -rf "$RUN_DIR"
    else
        echo "Phase 4 localnet logs kept at: $RUN_DIR"
    fi
}
trap cleanup EXIT

rpc() {
    local method="$1"
    local params="${2:-[]}"
    curl -fsS \
        --connect-timeout 2 \
        --max-time 5 \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        "http://127.0.0.1:${RPC_PORT}/rpc"
}

json_get() {
    local expr="$1"
    python3 -c "import json,sys; obj=json.load(sys.stdin); print($expr)"
}

wait_health() {
    local deadline=$((SECONDS + 45))
    until curl -fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:${RPC_PORT}/health" >/dev/null 2>&1; do
        if [ "$SECONDS" -gt "$deadline" ]; then
            echo "Node health timeout on RPC port $RPC_PORT"
            tail -n 120 "$NODE_LOG" || true
            return 1
        fi
        sleep 1
    done
}

assert_rpc_ok() {
    local method="$1"
    local out
    out="$(rpc "$method")"
    if echo "$out" | grep -q '"error":null'; then
        return 0
    fi
    echo "RPC method $method failed:"
    echo "$out"
    return 1
}

start_node() {
    echo "Starting isolated local node (p2p=$P2P_PORT rpc=$RPC_PORT)"
    AINCORE_ENABLE_FAUCET=1 AINCORE_GENESIS_PATH="$GENESIS_PATH" ./target/release/node \
        --port "$P2P_PORT" \
        --rpc-port "$RPC_PORT" \
        --datadir "$RUN_DIR/node" \
        > "$NODE_LOG" 2>&1 &
    NODE_PID=$!
    wait_health
    assert_rpc_ok "aincore_getStatus"
    assert_rpc_ok "aincore_getFinalityStatus"
}

wallet_keygen() {
    local keyfile="$1"
    AINCORE_ALLOW_PLAINTEXT_WALLET=1 ./target/release/aincore-cli \
        --rpc "http://127.0.0.1:${RPC_PORT}/rpc" \
        --keyfile "$keyfile" \
        keygen
}

wallet_address() {
    awk '/^Address:/ {print $2}'
}

wallet_pubkey() {
    awk '/^Public Key:/ {print $3}'
}

balance_of() {
    local address="$1"
    rpc "aincore_getBalance" "[\"$address\"]" \
        | json_get 'obj.get("result", {}).get("move_balance", "0")'
}

wait_balance_at_least() {
    local address="$1"
    local minimum="$2"
    local label="$3"
    local deadline=$((SECONDS + 45))
    while true; do
        local balance
        balance="$(balance_of "$address")"
        if python3 - "$balance" "$minimum" <<'PY'
import sys
sys.exit(0 if int(sys.argv[1]) >= int(sys.argv[2]) else 1)
PY
        then
            echo "$label balance=$balance"
            return 0
        fi
        if [ "$SECONDS" -gt "$deadline" ]; then
            echo "Timed out waiting for $label balance >= $minimum, last=$balance"
            tail -n 160 "$NODE_LOG" || true
            return 1
        fi
        sleep 2
    done
}

echo "== AINCORE Phase 4 Localnet TX Gate =="
echo "duration=${SOAK_SECONDS}s run_dir=$RUN_DIR"

cargo build --release --bin node --bin aincore-cli

mkdir -p "$RUN_DIR/node"
VALIDATOR_INFO="$(wallet_keygen "$RUN_DIR/node/node.key")"
VALIDATOR_ADDR="$(echo "$VALIDATOR_INFO" | wallet_address)"
VALIDATOR_PUB="$(echo "$VALIDATOR_INFO" | wallet_pubkey)"
if [ -z "$VALIDATOR_ADDR" ] || [ -z "$VALIDATOR_PUB" ]; then
    echo "Failed to create local validator key"
    echo "$VALIDATOR_INFO"
    exit 1
fi

python3 - "$GENESIS_PATH" "$VALIDATOR_ADDR" "$VALIDATOR_PUB" <<'PY'
import json
import sys

path, address, public_key = sys.argv[1:4]
with open(path, "w", encoding="utf-8") as fh:
    json.dump({
        "chain_id": "AINCORE-MAINNET-1",
        "validators": [{
            "address": address,
            "public_key": public_key,
            "stake": "1000000000000000000000000",
        }],
        "treasury_reserve": "50000000000000000000000",
        "epoch_duration": 10,
    }, fh, indent=2)
PY

start_node

ALICE_INFO="$(wallet_keygen "$RUN_DIR/alice.key")"
BOB_INFO="$(wallet_keygen "$RUN_DIR/bob.key")"
ALICE="$(echo "$ALICE_INFO" | wallet_address)"
ALICE_PUB="$(echo "$ALICE_INFO" | wallet_pubkey)"
BOB="$(echo "$BOB_INFO" | wallet_address)"
BOB_PUB="$(echo "$BOB_INFO" | wallet_pubkey)"

if [ -z "$ALICE" ] || [ -z "$ALICE_PUB" ] || [ -z "$BOB" ] || [ -z "$BOB_PUB" ]; then
    echo "Failed to create local wallets"
    echo "$ALICE_INFO"
    echo "$BOB_INFO"
    exit 1
fi

FAUCET_AMOUNT="5000000000000000000"
echo "Crediting local faucet: $ALICE"
FAUCET_RESP="$(rpc "aincore_faucet" "[\"$ALICE\",\"$FAUCET_AMOUNT\",\"$ALICE_PUB\"]")"
if ! echo "$FAUCET_RESP" | grep -q '"error":null'; then
    echo "Faucet failed:"
    echo "$FAUCET_RESP"
    exit 1
fi
wait_balance_at_least "$ALICE" "$FAUCET_AMOUNT" "alice-after-faucet"

echo "Registering recipient CoinStore: $BOB"
BOB_REGISTER_RESP="$(rpc "aincore_faucet" "[\"$BOB\",\"0\",\"$BOB_PUB\"]")"
if ! echo "$BOB_REGISTER_RESP" | grep -q '"error":null'; then
    echo "Recipient CoinStore registration failed:"
    echo "$BOB_REGISTER_RESP"
    exit 1
fi

TRANSFER_AMOUNT="12345"
echo "Submitting CLI transfer: $ALICE -> $BOB amount=$TRANSFER_AMOUNT"
./target/release/aincore-cli \
    --rpc "http://127.0.0.1:${RPC_PORT}/rpc" \
    --keyfile "$RUN_DIR/alice.key" \
    transfer "$BOB" "$TRANSFER_AMOUNT" \
    --gas-limit 10000

wait_balance_at_least "$BOB" "$TRANSFER_AMOUNT" "bob-after-transfer"

started_at="$SECONDS"
restarted=0
while [ $((SECONDS - started_at)) -lt "$SOAK_SECONDS" ]; do
    assert_rpc_ok "aincore_getStatus"
    assert_rpc_ok "aincore_getFinalityStatus"
    if [ "$restarted" -eq 0 ] && [ $((SECONDS - started_at)) -ge $((SOAK_SECONDS / 2)) ]; then
        echo "Restarting local node to verify DB replay"
        stop_node
        start_node
        wait_balance_at_least "$BOB" "$TRANSFER_AMOUNT" "bob-after-restart"
        restarted=1
    fi
    sleep 3
done

wait_balance_at_least "$BOB" "$TRANSFER_AMOUNT" "bob-final"

if grep -q "seed.aincore.network\\|p2p.aincore.network" "$NODE_LOG"; then
    echo "Unexpected public seed connection attempt found in localnet log"
    tail -n 160 "$NODE_LOG" || true
    exit 1
fi

echo "Phase 4 localnet TX gate PASSED."
