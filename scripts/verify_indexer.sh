#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🔍 Starting Indexer Verification...${NC}"

# 1. Cleanup
echo "🧹 Cleaning up previous processes and data..."
# Use more specific patterns to avoid killing IDE/System node processes
pkill -f "target/debug/node" || true
pkill -f "target/debug/indexer" || true
rm -rf data/*.db
rm -f indexer.db

# 2. Start Node (Port 9002 -> API 8002)
echo -e "${GREEN}🚀 Starting AINCORE Node on port 9002 (API 8002)...${NC}"
# Use nohup to keep it running
nohup cargo run -q -p node --bin node -- --port 9002 > node.log 2>&1 &
NODE_PID=$!
echo "Node PID: $NODE_PID"

# Wait for node startup
echo "⏳ Waiting for node to initialize..."
sleep 5

# 3. Send Transaction
# We need a valid signature. I'll use a pre-signed mock or generate one via a small python script helper if needed.
# Converting the hardcoded test payload from verify_governance.sh or verify_api.sh
# Let's use a simple transfer transaction.
# We'll construct a simple JSON payload.
# Since we don't have a CLI tool handy for proper signing in bash easily without external deps,
# I will use the `aincore_sendTransaction` with a raw object if the node allows invalid sigs in debug,
# OR I'll rely on the hardcoded test transaction from `verify_api.sh` if available.
# Actually, the node checks signatures.
# Let's verify if `verify_api.sh` exists and steal a valid TX from there?
# Or better, let's use the Python script `test_chain_id.py` if it exists, as it generates valid TXs.
# I see `test_chain_id.py` in the open files list! I can use that to generate/send a TX.

echo "⚙️  Generating Valid Transaction..."
TX_JSON=$(cargo run -q -p aincore-cli --bin gen_test_tx 2>/dev/null)
if [ -z "$TX_JSON" ]; then
    echo -e "${RED}❌ Failed to generate transaction via aincore-cli${NC}"
    exit 1
fi
echo "Generate TX: $TX_JSON"

echo "📤 Sending to Node..."
# Using raw socket like test_chain_id.py (TX:{json}) or API?
# Node main.rs: "if msg.starts_with("TX:") ... mp.add_transaction(msg);"
# Also "if msg.starts_with('{') ... mp.add_transaction(msg);" (line 226 in main.rs view)
# But API `aincore_sendTransaction` is cleaner.
# Let's use API if available on 8002.
# API handler: aincore_sendTransaction params: [tx_string] or object
# curl -d '{"method":"aincore_sendTransaction", "params": [$TX_JSON], ...}'
# Note: TX_JSON is a string-ified JSON? No, the generator prints a JSON object.
# The API expects either a string OR an object.
RESP=$(curl -s -X POST -H "Content-Type: application/json" -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"aincore_sendTransaction\",
    \"params\": [$TX_JSON],
    \"id\": 1
}" "http://localhost:8002/rpc")

echo "Send Response: $RESP"

# Extract Sender for verification
SENDER=$(echo $TX_JSON | grep -o '"sender":"[^"]*"' | cut -d'"' -f4)
echo "Expected Sender: $SENDER"

# 4. Start Indexer
echo -e "${GREEN}🕵️ Starting Indexer...${NC}"
# Indexer defaults to http://localhost:8002/rpc which matches our node api port.
nohup cargo run -q -p indexer > indexer.log 2>&1 &
INDEXER_PID=$!
echo "Indexer PID: $INDEXER_PID"

echo "⏳ Waiting for Indexer to sync (10s)..."
sleep 10

# 5. Verify Data via API
# We expect the transaction sender to be in the history.
# The sender in `test_chain_id.py` (which I assume works) needs to be known.
# Viewing `test_chain_id.py` content would be useful, but I can assume it sends *something*.
# Let's just query the indexer for *any* transaction or the specific one.
# If I don't know the address, I can't query /history/{address}.
# The indexer logs "Indexing Block...". I can grep that.

if grep -q "Indexing Block" indexer.log; then
    echo -e "${GREEN}✅ Indexer is processing blocks!${NC}"
else
    echo -e "${RED}❌ Indexer did not index any blocks.${NC}"
    cat indexer.log
    # Don't fail yet, maybe it's just slow/empty.
fi

# Check specific sender address history
echo "🔍 Querying Indexer for Sender: $SENDER"
RESPONSE=$(curl -s "http://localhost:3001/history/$SENDER")
echo "API Response: $RESPONSE"

if [[ "$RESPONSE" == *"$SENDER"* ]] && [[ "$RESPONSE" == *"hash"* ]]; then
     echo -e "${GREEN}✅ Indexer Verified! Transaction found for $SENDER.${NC}"
else
     echo -e "${RED}⚠️ Indexer API response missing expected data for $SENDER.${NC}"
     echo "Logs:"
     tail -n 10 indexer.log
     # Optional: don't fail immediately, but mark as warning
     exit 1
fi

# Cleanup
kill $NODE_PID
kill $INDEXER_PID
echo -e "${GREEN}✅ Verification Complete.${NC}"
