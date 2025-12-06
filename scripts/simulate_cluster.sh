#!/bin/bash

# Kill previous instances
pkill -f "target/release/node"
sleep 2

# Ensure binary exists
if [ ! -f "./target/release/node" ]; then
    echo "❌ Node binary not found! Please run 'cargo build --release --bin node'"
    exit 1
fi

# Setup Data Directories and Keys
setup_node() {
    ID=$1
    KEY=$2
    DATADIR="data_$ID"
    mkdir -p $DATADIR
    if [ ! -f "$DATADIR/node_identity.key" ]; then
        echo $KEY | xxd -r -p > $DATADIR/node_identity.key
        echo "🔑 Key created for Node $ID"
    else
        echo "🔑 Key exists for Node $ID"
    fi
}

echo "🛠️  Setting up Validator Keys..."
# Key 1
setup_node 1 "8721d8bf414f27cac0e11e92ebac68bb64aa4ccdbae68b145318e69cdb7822c0"
# Key 2
setup_node 2 "fa26110d3a14e793f07fbf15b2ba85b90a219535f52cbfd61e188dbf0b8f6797"
# Key 3
setup_node 3 "2847ed43485380633d445a7397f056ca4925a51e5c8f5ba5b9d4461c529c1040"
# Key 4
setup_node 4 "ecd6af9d7b37d2b39582dcfd36ff6cdd6f00d37e7a98f03b9ad1ae633ea46816"

# Launch Nodes
echo "🚀 Launching Node 1 (Genesis)..."
./target/release/node --port 9000 --rpc-port 8000 --datadir data_1 > node_1.log 2>&1 &
PID1=$!
echo "Node 1 PID: $PID1"
sleep 3 # Wait for boot

echo "🚀 Launching Node 2 (Peer)..."
./target/release/node --port 9001 --rpc-port 8001 --datadir data_2 --bootnodes 127.0.0.1:9000 > node_2.log 2>&1 &
echo "Node 2 launched"

echo "🚀 Launching Node 3 (Peer)..."
./target/release/node --port 9002 --rpc-port 8002 --datadir data_3 --bootnodes 127.0.0.1:9000 > node_3.log 2>&1 &
echo "Node 3 launched"

echo "🚀 Launching Node 4 (Peer)..."
./target/release/node --port 9003 --rpc-port 8003 --datadir data_4 --bootnodes 127.0.0.1:9000 > node_4.log 2>&1 &
echo "Node 4 launched"

echo "✅ Cluster launched with 4 validators!"
echo "📜 Logs: node_1.log, node_2.log, node_3.log, node_4.log"
echo "💰 Monitor rewards with: ./watch_mining.sh data_2/node_identity.key"
