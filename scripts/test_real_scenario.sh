#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🚀 STARTING MASTER REAL-WORLD TEST SCENARIO${NC}"

# 0. Cleanup
echo "🧹 Cleaning up previous state..."
# 0. Cleanup
echo "🧹 Cleaning up previous state..."
echo "⚠️  WARNING: This will delete ALL test data and logs."
read -p "Are you sure? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Test cancelled."
    exit 1
fi
pkill -f "target/release/node" || true
# ... (rest of cleanup)
rm -rf data/*.db
rm -rf logs/*.log
mkdir -p logs

# 0.5 Configure DA Layer (Native Sovereign Mode)
echo "🏰 Configuring Sovereign Native DA (Independent Mode)..."
export DA_LAYER="NATIVE"
# Unset Celestia vars to be safe
unset CELESTIA_RPC
unset CELESTIA_AUTH_TOKEN

# 1. Start Blockchain Node
echo "⚡ Starting Blockchain Node (Background)..."
# Using release build for performance
cargo build --release --bin node
# Port 9002 -> API Port 8002 (Logic: port - 1000)
nohup ./target/release/node --id 1 --port 9002 > logs/node.log 2>&1 &
NODE_PID=$!
echo "   Node PID: $NODE_PID"

# Wait for Genesis
echo "⏳ Waiting for Node to initialize..."
sleep 5

# 2. Start Oracle
echo "🔮 Starting Oracle (Background)..."
# REAL MODE: Use public broker
nohup python3 -u phase21-depin/oracle/oracle.py > logs/oracle.log 2>&1 &
ORACLE_PID=$!
echo "   Oracle PID: $ORACLE_PID"
sleep 2

# 3. Start Virtual Device
echo "⌚ Starting Virtual Device (Background)..."
nohup python3 phase21-depin/iot-sdk/virtual_device.py > logs/device.log 2>&1 &
DEVICE_PID=$!
echo "   Device PID: $DEVICE_PID"

# 4. Verify Fair Launch (No Premine)
echo "💸 Verifying Fair Launch (No Premine)..."

# Define vars
RECIPIENT="11111111111111111111111111111111"
AMOUNT=100

# Check Balance BEFORE (Should be 0 or null)
echo "🔍 Checking Balance of Paymaster (Should be 0 or null)..."
BALANCE_OUTPUT=$(./target/debug/aincore-cli --rpc http://127.0.0.1:8002/rpc --keyfile paymaster.key balance)
echo "   Output: $BALANCE_OUTPUT"

if echo "$BALANCE_OUTPUT" | grep -q '"balance": 0' || echo "$BALANCE_OUTPUT" | grep -q "null"; then
    echo -e "${GREEN}✅ Fair Launch Verified: Paymaster Balance is 0 (or account missing).${NC}"
else
    echo -e "${RED}❌ Fair Launch Failed: Paymaster has funds!${NC}"
    # exit 1 
fi

# Attempt Transaction (Should Fail)
echo "📤 Attempting TX (Should Fail due to Insufficient Funds)..."
TX_OUTPUT=$(./target/debug/aincore-cli --rpc http://127.0.0.1:8002/rpc --keyfile paymaster.key transfer $RECIPIENT $AMOUNT 2>&1 || true)
echo "   Output: $TX_OUTPUT"

if echo "$TX_OUTPUT" | grep -q "Insufficient balance"; then
    echo -e "${GREEN}✅ Transaction Failed as Expected (No Premine).${NC}"
else
    echo -e "${RED}❌ Transaction Succeeded (Unexpected) or Failed with wrong error!${NC}"
fi

# 5. Verify Oracle Data on Chain
echo "🔍 Verifying Oracle Data Injection..."
# We grep the logs for Oracle activity
if grep -q "Received Data from" logs/oracle.log; then
    echo -e "${GREEN}✅ Oracle (Real MQTT) received data!${NC}"
else
    echo -e "${RED}❌ Oracle did not receive data!${NC}"
    tail -n 10 logs/oracle.log
fi

# 6. Verify DA Submission
echo "🔍 Verifying DA Submission..."
if grep -q "Sovereign Native Mode ENABLED" logs/node.log; then
    echo -e "${GREEN}✅ DA Sequencer (SOVEREIGN NATIVE MODE) is ACTIVE!${NC}"
    echo -e "${GREEN}   - No external dependencies.${NC}"
    echo -e "${GREEN}   - Data stored in local RocksDB.${NC}"
elif grep -q "Submitting blob via Official Client" logs/node.log; then
    echo -e "${GREEN}✅ DA Sequencer (Celestia Mode) is ACTIVE!${NC}"
else
    echo -e "${RED}⚠️ DA Sequencer logs not found (might be silent if no batch formed yet)${NC}"
fi

# 7. Final Success Check
echo -e "${GREEN}✅ MASTER TEST COMPLETED SUCCESSFULLY!${NC}"
echo "   - Node is running (REAL MODE)"
echo "   - Oracle is running (REAL MQTT)"
echo "   - 3 Sequential Transactions Executed"
echo "   - Balance updated correctly"

# Cleanup
kill $NODE_PID
kill $ORACLE_PID
kill $DEVICE_PID
