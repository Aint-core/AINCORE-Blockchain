#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SOAK_SECONDS="${AINCORE_SOAK_SECONDS:-180}"
NODE_COUNT="${AINCORE_SOAK_NODES:-2}"
BASE_P2P_PORT="${AINCORE_SOAK_BASE_P2P_PORT:-19000}"
BASE_RPC_PORT="${AINCORE_SOAK_BASE_RPC_PORT:-18000}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$ROOT_DIR/.soak/phase2-$RUN_ID"
LOG_DIR="$RUN_DIR/logs"
PID_FILE="$RUN_DIR/pids"
KEEP_LOGS="${AINCORE_SOAK_KEEP_LOGS:-0}"
SKIP_PREFLIGHT="${AINCORE_SOAK_SKIP_PREFLIGHT:-0}"

if [ "$NODE_COUNT" -lt 1 ]; then
    echo "AINCORE_SOAK_NODES must be >= 1"
    exit 1
fi

mkdir -p "$LOG_DIR"
: > "$PID_FILE"

cleanup() {
    if [ -f "$PID_FILE" ]; then
        while read -r pid; do
            terminate_pid "$pid" 5
        done < "$PID_FILE"
    fi

    if [ "$KEEP_LOGS" != "1" ]; then
        rm -rf "$RUN_DIR"
    else
        echo "Soak logs kept at: $RUN_DIR"
    fi
}
trap cleanup EXIT

terminate_pid() {
    local pid="${1:-}"
    local timeout="${2:-20}"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
        return 0
    fi

    kill "$pid" 2>/dev/null || true
    local deadline=$((SECONDS + timeout))
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
        sleep 1
    done
    wait "$pid" 2>/dev/null || true
}

rpc() {
    local rpc_port="$1"
    local method="$2"
    local params="${3:-[]}"
    curl -fsS \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        "http://127.0.0.1:${rpc_port}/rpc"
}

wait_health() {
    local rpc_port="$1"
    local deadline=$((SECONDS + 30))
    until curl -fsS "http://127.0.0.1:${rpc_port}/health" >/dev/null 2>&1; do
        if [ "$SECONDS" -gt "$deadline" ]; then
            echo "Node RPC health timeout on port $rpc_port"
            return 1
        fi
        sleep 1
    done
}

start_node() {
    local index="$1"
    local p2p_port=$((BASE_P2P_PORT + index - 1))
    local rpc_port=$((BASE_RPC_PORT + index - 1))
    local datadir="$RUN_DIR/node_$index"
    local log="$LOG_DIR/node_$index.log"
    local bootnode="127.0.0.1:${BASE_P2P_PORT}"

    mkdir -p "$datadir"
    echo "Starting node $index (p2p=$p2p_port rpc=$rpc_port)"
    ./target/release/node \
        --port "$p2p_port" \
        --rpc-port "$rpc_port" \
        --datadir "$datadir" \
        --bootnodes "$bootnode" \
        > "$log" 2>&1 &
    local pid=$!
    echo "$pid" >> "$PID_FILE"
    wait_health "$rpc_port"
}

assert_rpc_ok() {
    local rpc_port="$1"
    local label="$2"
    local status
    status="$(rpc "$rpc_port" "aincore_getStatus")"
    if ! echo "$status" | grep -q '"error":null'; then
        echo "RPC status failed for $label on port $rpc_port"
        echo "$status"
        return 1
    fi

    local finality
    finality="$(rpc "$rpc_port" "aincore_getFinalityStatus")"
    if ! echo "$finality" | grep -q '"error":null'; then
        echo "Finality RPC failed for $label on port $rpc_port"
        echo "$finality"
        return 1
    fi
}

restart_node() {
    local index="$1"
    local rpc_port=$((BASE_RPC_PORT + index - 1))
    local old_pid
    old_pid="$(sed -n "${index}p" "$PID_FILE" || true)"

    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
        echo "Restarting node $index (pid=$old_pid)"
        terminate_pid "$old_pid" 20
        sleep 2
    fi

    # Preserve the datadir and append a new pid. Future cleanup kills all pids in the file.
    start_node "$index"
    assert_rpc_ok "$rpc_port" "node-$index-after-restart"
}

echo "== AINCORE Phase 2 Soak Gate =="
echo "duration=${SOAK_SECONDS}s nodes=${NODE_COUNT} run_dir=$RUN_DIR"

if [ "$SKIP_PREFLIGHT" != "1" ]; then
    ./scripts/phase2_hardening_gate.sh
fi

cargo build --release --bin node

for i in $(seq 1 "$NODE_COUNT"); do
    start_node "$i"
done

for i in $(seq 1 "$NODE_COUNT"); do
    assert_rpc_ok "$((BASE_RPC_PORT + i - 1))" "node-$i-initial"
done

restart_at=$((SOAK_SECONDS / 2))
if [ "$restart_at" -lt 5 ]; then
    restart_at=5
fi

started_at="$SECONDS"
did_restart=0
while [ $((SECONDS - started_at)) -lt "$SOAK_SECONDS" ]; do
    elapsed=$((SECONDS - started_at))
    for i in $(seq 1 "$NODE_COUNT"); do
        assert_rpc_ok "$((BASE_RPC_PORT + i - 1))" "node-$i-elapsed-${elapsed}"
    done

    if [ "$NODE_COUNT" -gt 1 ] && [ "$did_restart" -eq 0 ] && [ "$elapsed" -ge "$restart_at" ]; then
        restart_node 2
        did_restart=1
    fi

    sleep 5
done

for i in $(seq 1 "$NODE_COUNT"); do
    assert_rpc_ok "$((BASE_RPC_PORT + i - 1))" "node-$i-final"
done

echo "Phase 2 soak gate PASSED."
echo "For long soak: AINCORE_SOAK_SECONDS=604800 AINCORE_SOAK_KEEP_LOGS=1 ./scripts/phase2_soak_gate.sh"
