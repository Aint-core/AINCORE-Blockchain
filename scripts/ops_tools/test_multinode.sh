#!/bin/bash
# AINCORE - Test Multi-Node P2P Connection

echo "🧪 AINCORE Multi-Node P2P Test"
echo "=============================="
echo ""

# Get IP
IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
echo "📍 Your IP: $IP"
echo ""

# Stop any running nodes
echo "🛑 Stopping any running nodes..."
pkill -f 'target/release/node'
sleep 2

# Start Node 1
echo "🚀 Starting Node 1 (Bootnode)..."
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1 > node1_test.log 2>&1 &
NODE1_PID=$!
echo "✅ Node 1 started (PID: $NODE1_PID)"
sleep 8

# Check Node 1
echo ""
echo "📊 Node 1 Status:"
tail -5 node1_test.log | grep -E "(Listening|Consensus|Block)" || echo "Waiting for initialization..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ NODE 1 READY!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 FOR NODE 2 (Mac Mini), run:"
echo ""
echo "./target/release/node \\"
echo "  --port 9001 \\"
echo "  --rpc-port 8001 \\"
echo "  --datadir data_node2 \\"
echo "  --bootnodes /ip4/$IP/tcp/9000"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📝 Monitoring Node 1 logs..."
echo "   Press Ctrl+C to stop"
echo ""
tail -f node1_test.log
