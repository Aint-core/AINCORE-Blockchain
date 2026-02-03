#!/bin/bash

# Simple script to send a dummy transaction to the node
# JSON-RPC method: aincore_sendTransaction

echo "🚀 Sending test transaction..."

TIMESTAMP=$(date +%s)

# Construct inner JSON first (escaped for the outer JSON string)
# The inner JSON must be a STRING because our specific RPC handler (aincore_sendTransaction) 
# expects params[0] to be a JSON string OR an object. Let's send an object for safety.

curl -X POST -H "Content-Type: application/json" \
     -d "{
           \"jsonrpc\": \"2.0\",
           \"method\": \"aincore_sendTransaction\",
           \"params\": [{
               \"from\": \"AddrA_${TIMESTAMP}\",
               \"to\": \"AddrB_${TIMESTAMP}\",
               \"amount\": 10,
               \"timestamp\": ${TIMESTAMP},
               \"signature\": \"mock_sig\"
           }],
           \"id\": 1
         }" \
     http://localhost:8000/rpc

echo -e "\n✅ Logic: Transaction sent to Mempool -> Will be included in next block!"
