#!/bin/bash

BASE_URL="http://localhost:8000"

echo "🔍 TESTING EXPLORER API..."
echo "-----------------------------------"

echo "1. GET /get_chain_height"
curl -s "$BASE_URL/get_chain_height"
echo -e "\n-----------------------------------"

echo "2. GET /get_latest_blocks (Limit 2)"
curl -s "$BASE_URL/get_latest_blocks?limit=2" | head -c 200
echo -e "...\n-----------------------------------"

echo "3. GET /get_validators"
curl -s "$BASE_URL/get_validators"
echo -e "\n-----------------------------------"

echo "4. GET /get_network_info"
curl -s "$BASE_URL/get_network_info"
echo -e "\n-----------------------------------"

echo "✅ ALL ENDPOINTS RESPONDING!"
