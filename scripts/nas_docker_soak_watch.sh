#!/bin/bash
set -euo pipefail

RPC_URL="${AINCORE_NAS_RPC_URL:-http://127.0.0.1:8002}"
CONTAINER="${AINCORE_NAS_CONTAINER:-aincore-validator}"
INTERVAL_SECONDS="${AINCORE_NAS_SOAK_INTERVAL:-60}"
STALL_INTERVALS="${AINCORE_NAS_STALL_INTERVALS:-3}"
LOG_DIR="${AINCORE_NAS_SOAK_LOG_DIR:-$HOME/aincore-soak}"
SUDO_PASSWORD="${AINCORE_SUDO_PASSWORD:-}"

mkdir -p "$LOG_DIR"
SUMMARY_LOG="$LOG_DIR/summary.log"
ERROR_LOG="$LOG_DIR/errors.log"
STATE_FILE="$LOG_DIR/state.env"

rpc() {
    local method="$1"
    curl -fsS \
        --connect-timeout 3 \
        --max-time 8 \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}" \
        "$RPC_URL/rpc"
}

docker_cmd() {
    if docker ps >/dev/null 2>&1; then
        docker "$@"
        return
    fi

    if [ -n "$SUDO_PASSWORD" ]; then
        printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' docker "$@"
        return
    fi

    sudo -p '' docker "$@"
}

json_field() {
    local field="$1"
    python3 -c '
import json
import sys

field = sys.argv[1]
try:
    obj = json.load(sys.stdin)
    value = obj.get("result", {}).get(field, "")
    print(value)
except Exception:
    print("")
' "$field"
}

last_height=""
last_finalized=""
height_stall_count=0
finality_stall_count=0
if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
fi

echo "AINCORE NAS soak watch started at $(date -Is)" >> "$SUMMARY_LOG"
echo "rpc=$RPC_URL container=$CONTAINER interval=${INTERVAL_SECONDS}s stall_intervals=$STALL_INTERVALS" >> "$SUMMARY_LOG"

while true; do
    ts="$(date -Is)"
    health="FAIL"
    if curl -fsS --connect-timeout 3 --max-time 8 "$RPC_URL/health" >/dev/null 2>&1; then
        health="OK"
    fi

    status_json="$(rpc "aincore_getStatus" 2>>"$ERROR_LOG" || true)"
    finality_json="$(rpc "aincore_getFinalityStatus" 2>>"$ERROR_LOG" || true)"

    height="$(printf '%s' "$status_json" | json_field latest_height)"
    round="$(printf '%s' "$status_json" | json_field current_round)"
    finalized="$(printf '%s' "$status_json" | json_field finalized_round)"
    peers="$(printf '%s' "$status_json" | json_field peers_count)"
    digest="$(printf '%s' "$finality_json" | json_field finality_digest)"

    container_status="$(docker_cmd ps --filter "name=$CONTAINER" --format '{{.Status}}' 2>>"$ERROR_LOG" | head -n 1 || true)"
    bad_logs="$(docker_cmd logs --since "${INTERVAL_SECONDS}s" "$CONTAINER" 2>&1 \
        | grep -E 'panic|ERROR|MISSING_DEPENDENCY|Observer Mode|seed\.aincore\.network|p2p\.aincore\.network' || true)"

    if [ -n "$bad_logs" ]; then
        {
            echo "[$ts] suspicious logs:"
            printf '%s\n' "$bad_logs"
        } >> "$ERROR_LOG"
    fi

    if [[ "$height" =~ ^[0-9]+$ && "$last_height" =~ ^[0-9]+$ ]]; then
        if [ "$height" -le "$last_height" ]; then
            height_stall_count=$((height_stall_count + 1))
        else
            height_stall_count=0
        fi
    else
        height_stall_count=0
    fi

    if [[ "$finalized" =~ ^[0-9]+$ && "$last_finalized" =~ ^[0-9]+$ ]]; then
        if [ "$finalized" -le "$last_finalized" ]; then
            finality_stall_count=$((finality_stall_count + 1))
        else
            finality_stall_count=0
        fi
    else
        finality_stall_count=0
    fi

    stalled=""
    if [ "$height_stall_count" -ge "$STALL_INTERVALS" ]; then
        stalled="${stalled} height_stalled=${height_stall_count}x(last=${last_height:-n/a},current=${height:-n/a})"
    fi
    if [ "$finality_stall_count" -ge "$STALL_INTERVALS" ]; then
        stalled="${stalled} finality_stalled=${finality_stall_count}x(last=${last_finalized:-n/a},current=${finalized:-n/a})"
    fi
    if [ -n "$stalled" ]; then
        echo "[$ts] STALL$stalled" >> "$ERROR_LOG"
    fi

    if [ "$health" != "OK" ] || [ -z "$height" ] || [ -z "$finalized" ] || [ -n "$bad_logs" ] || [ -n "$stalled" ]; then
        echo "[$ts] FAIL health=$health height=${height:-n/a} finalized=${finalized:-n/a} round=${round:-n/a} peers=${peers:-n/a} container=${container_status:-n/a}" >> "$ERROR_LOG"
    fi

    echo "[$ts] health=$health height=${height:-n/a} finalized=${finalized:-n/a} round=${round:-n/a} peers=${peers:-n/a} digest=${digest:-n/a} height_stall=${height_stall_count} finality_stall=${finality_stall_count} container=${container_status:-n/a}" >> "$SUMMARY_LOG"

    {
        printf 'last_height=%q\n' "${height:-}"
        printf 'last_finalized=%q\n' "${finalized:-}"
        printf 'last_digest=%q\n' "${digest:-}"
        printf 'last_seen=%q\n' "$ts"
        printf 'height_stall_count=%q\n' "$height_stall_count"
        printf 'finality_stall_count=%q\n' "$finality_stall_count"
    } > "$STATE_FILE"

    last_height="$height"
    last_finalized="$finalized"

    sleep "$INTERVAL_SECONDS"
done
