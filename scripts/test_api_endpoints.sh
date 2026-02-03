#!/bin/bash
# scripts/test_api_endpoints.sh
# Tests all AINCORE API endpoints to verify functionality

RPC_PORT=${1:-8002}
BASE_URL="http://127.0.0.1:$RPC_PORT"

echo "🔍 Testing AINCORE API on $BASE_URL ..."

echo "1. Testing /health..."
curl -s -v "$BASE_URL/health"
echo "--------------------------------"

echo "2. Testing /get_network_info..."
curl -s "$BASE_URL/get_network_info" | jq .
echo "--------------------------------"

echo "3. Testing /get_validators..."
curl -s "$BASE_URL/get_validators" | jq .
echo "--------------------------------"

echo "4. Testing /get_latest_blocks..."
curl -s "$BASE_URL/get_latest_blocks?limit=1" | jq .
echo "--------------------------------"

echo "5. Testing JSON-RPC aincore_getMiningStats..."
curl -s -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0", "method": "aincore_getMiningStats", "params": [], "id":1}' \
     "$BASE_URL/rpc" | jq .
echo "--------------------------------"

echo "6. Testing JSON-RPC aincore_getDaStatus..."
curl -s -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0", "method": "aincore_getDaStatus", "params": [], "id":1}' \
     "$BASE_URL/rpc" | jq .
echo "--------------------------------"

echo "✅ Test Complete."
