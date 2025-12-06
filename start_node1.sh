#!/bin/bash
# AINCORE - Start Node Script untuk Komputer 1

echo "🚀 Starting AINCORE Node (Komputer 1 - Bootnode)"
echo "================================================"
echo ""

# Check if node is already running
if ps aux | grep "target/release/node.*9000" | grep -v grep > /dev/null; then
    echo "⚠️  Node already running!"
    echo ""
    echo "To stop it:"
    echo "  pkill -f 'target/release/node'"
    echo ""
    echo "To restart:"
    echo "  pkill -f 'target/release/node' && ./start_node1.sh"
    exit 1
fi

# Get IP address
IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
echo "📍 Your IP Address: $IP"
echo ""

# Start node in background
echo "🔨 Starting node..."
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1 > node1.log 2>&1 &
NODE_PID=$!

echo "✅ Node started with PID: $NODE_PID"
echo ""

# Wait for node to start
echo "⏳ Waiting for node to initialize..."
sleep 5

# Check if node is running
if ps -p $NODE_PID > /dev/null; then
    echo "✅ Node is running!"
    echo ""
    
    # Get block height
    HEIGHT=$(curl -s http://localhost:8000 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"aincore_getBlockHeight","params":[],"id":1}' \
        | grep -o '"result":[0-9]*' | grep -o '[0-9]*')
    
    if [ ! -z "$HEIGHT" ]; then
        echo "📊 Current Block Height: $HEIGHT"
    fi
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ KOMPUTER 1 READY!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📍 Your IP: $IP"
    echo "🔌 P2P Port: 9000"
    echo "🌐 RPC Port: 8000"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📋 UNTUK KOMPUTER 2 (Copy command ini):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "./target/release/node \\"
    echo "  --port 9000 \\"
    echo "  --rpc-port 8000 \\"
    echo "  --datadir data_node2 \\"
    echo "  --bootnodes /ip4/$IP/tcp/9000"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📝 Useful Commands:"
    echo "  - View logs: tail -f node1.log"
    echo "  - Check peers: curl http://localhost:8000 -X POST -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"aincore_getPeers\",\"params\":[],\"id\":1}'"
    echo "  - Stop node: pkill -f 'target/release/node'"
    echo ""
else
    echo "❌ Node failed to start!"
    echo "Check logs: tail -f node1.log"
    exit 1
fi
