#!/bin/bash
KEYFILE=$1

# Default to node_identity.key if not provided
if [ -z "$KEYFILE" ]; then
  if [ -f "data/node_identity.key" ]; then
    KEYFILE="data/node_identity.key"
  else
    echo "Usage: ./watch_mining.sh <keyfile>"
    echo "Example: ./watch_mining.sh validator_1.key"
    exit 1
  fi
fi

# Check if CLI exists (Release or Debug)
if [ -f "./target/release/aincore-cli" ]; then
    CLI="./target/release/aincore-cli"
elif [ -f "./target/debug/aincore-cli" ]; then
    CLI="./target/debug/aincore-cli"
    echo "⚠️  Using DEBUG binary (slower but works)."
else
    echo "❌ Error: aincore-cli not found in target/release/ or target/debug/"
    echo "Please run: cargo build --release --bin aincore-cli"
    exit 1
fi

# Get Address
ADDRESS_OUTPUT=$($CLI --keyfile "$KEYFILE" keygen 2>&1)
ADDRESS=$(echo "$ADDRESS_OUTPUT" | grep "Address" | cut -d ' ' -f 3)

clear
echo "==================================================="
echo "⛏️  AINCORE MINING MONITOR (Live)"
echo "==================================================="
echo "👤 Miner Address : $ADDRESS"
echo "🔑 Key File      : $KEYFILE"
echo "📡 Network       : Local Cluster (Port 9000)"
echo "---------------------------------------------------"
echo "Waiting for next block (Epoch)..."
echo ""

RPC_PORT=$2
if [ -z "$RPC_PORT" ]; then
    RPC_PORT=8000
fi

while true; do
  TIMESTAMP=$(date +"%H:%M:%S")
  
  # Fetch Balance (Targeting Port 8000 for Node 9000)
  # The CLI command now returns a JSON object with 'data' field
  BALANCE_OUTPUT=$($CLI --rpc http://127.0.0.1:$RPC_PORT/rpc --keyfile "$KEYFILE" balance 2>&1)
  
  # Check for connection errors first
  if echo "$BALANCE_OUTPUT" | grep -q "error trying to connect"; then
      echo -ne "\033[2K\r[$TIMESTAMP] ❌ API Unreachable - Blockchain is running, check logs"
  else
      # Filter for lines starting with { (JSON)
      JSON_PART=$(echo "$BALANCE_OUTPUT" | grep "^{")
      
      DATA=$(echo "$JSON_PART" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin)))" 2>/dev/null)
      if [ -z "$DATA" ] || [ "$DATA" == "null" ]; then



          echo -ne "\033[2K\r[$TIMESTAMP] 💰 Balance: 0 AIN | Status: ⏳ Connecting..."
      else
          # Extract fields using python one-liner for reliable parsing
          BALANCE=$(echo "$DATA" | python3 -c "import sys, json; print(json.load(sys.stdin).get('balance', 0))")
          BTC_BALANCE=$(echo "$DATA" | python3 -c "import sys, json; print(json.load(sys.stdin).get('btc_balance', 0))")
          
          # Convert BTC to nicer format (Sats -> BTC)
          # Use 'bc -l' for floating point arithmetic
          BTC_DISPLAY=$(echo "scale=8; $BTC_BALANCE / 100000000" | bc -l)
          
          echo -ne "\033[2K\r[$TIMESTAMP] 💰 Balance: $BALANCE AIN | ₿ BTC: $BTC_BALANCE Sats ($BTC_DISPLAY BTC) | Status: 🔨 Mining..."
      fi
  fi

  # Get Current Time
  TIME=$(date '+%H:%M:%S')

  # Print Status Line (Overwriting previous line)
  # Clear line first
  echo -ne "\033[2K\r[$TIME] 💰 Balance: $BALANCE | Status: $STATUS "
  
  sleep 5
done
