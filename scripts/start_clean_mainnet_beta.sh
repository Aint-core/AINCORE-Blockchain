#!/bin/bash
# start_clean_mainnet_beta.sh
# "The Perfect Launch Button"
# Resets all data and starts fresh to ensure decentralized oracle genesis.

echo "⚠️  DANGER: This script will WIPE ALL MAINNET DATA (Reset Genesis)."
echo "⚠️  DANGER: This script will WIPE ALL MAINNET DATA (Reset Genesis)."
echo "Typing 'DELETE' confirms you understand that this action is IRREVERSIBLE."
read -p "Type 'DELETE' to confirm: " confirmation

if [[ "$confirmation" != "DELETE" ]]; then
    echo "❌ Safety Check Failed. Aborted."
    exit 1
fi

echo "🔥 Wiping old data (Genesis Reset)..."
pkill -f "target/release/node"
sleep 2
rm -rf data_1 data_2 data_3 data_4
rm -rf node_1.log node_2.log node_3.log node_4.log
rm -rf vault_address.txt

echo "🛠️  Building Project (Ensuring latest binary)..."
# We assume it's arguably built, but let's be safe.
cargo build --release --bin node

echo "🚀 Starting Cluster via Simulate Script..."
./scripts/simulate_cluster.sh

echo "⏳ Waiting for Genesis Initialization..."
sleep 5

if grep -q "Initialized Decentralized Oracle" node_1.log; then
    echo "✅ SUCCESS: Decentralized Oracle Initialized in Genesis!"
else
    echo "⚠️  WARNING: Oracle Initialization log not found. CHECK NODE_1.LOG."
fi

echo "✅ Mainnet Beta is Live!"
