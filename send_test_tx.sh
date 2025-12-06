#!/bin/bash

# Simple script to send a dummy transaction to the node
# JSON-RPC method: aincore_sendTransaction

echo "🚀 Sending test transaction..."

TIMESTAMP=$(date +%s)
TX_JSON="{\"from\":\"AddrA_${TIMESTAMP}\",\"to\":\"AddrB_${TIMESTAMP}\",\"amount\":10,\"timestamp\":${TIMESTAMP},\"signature\":\"mock_sig\"}"

curl -X POST -H "Content-Type: application/json" \
     -d "{\"jsonrpc\":\"2.0\",\"method\":\"aincore_sendTransaction\",\"params\":[\"${TX_JSON}\"],\"id\":1}" \
     http://localhost:8000/rpc

echo -e "\n✅ Logic: Transaction sent to Mempool -> Will be included in next block!"
