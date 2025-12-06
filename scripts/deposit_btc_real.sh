#!/bin/bash

AMOUNT=$1
RECIPIENT_AIN=$2

if [ -z "$AMOUNT" ] || [ -z "$RECIPIENT_AIN" ]; then
    echo "Usage: ./scripts/deposit_btc_real.sh <AMOUNT_BTC> <AIN_RECIPIENT_HEX>"
    echo "Example: ./scripts/deposit_btc_real.sh 1.5 e1d895a946252a40acb29b6d05c41f8f"
    exit 1
fi

VAULT_ADDR=$(cat vault_address.txt)
if [ -z "$VAULT_ADDR" ]; then
    echo "❌ vault_address.txt not found. Run start_bitcoin_regtest.sh first."
    exit 1
fi

echo "🏦 Sending $AMOUNT BTC to Vault ($VAULT_ADDR) with OP_RETURN metadata..."

# Construct JSON for sendmany
# Note: "data" key creates OP_RETURN with hex payload
JSON="{\"$VAULT_ADDR\": $AMOUNT, \"data\": \"$RECIPIENT_AIN\"}"

echo "📝 Payload: $JSON"

TXID=$(bitcoin-cli -regtest -datadir=./bitcoin_data -rpcuser=user -rpcpassword=pass -rpcport=18443 -rpcwallet="vault" sendmany "" "$JSON")

if [ $? -ne 0 ]; then
    echo "❌ Transaction Failed."
    exit 1
fi

echo "✅ Transaction Sent! TXID: $TXID"

echo "⛏️  Mining 1 block to confirm..."
bitcoin-cli -regtest -datadir=./bitcoin_data -rpcuser=user -rpcpassword=pass -rpcport=18443 -rpcwallet="vault" generatetoaddress 1 $VAULT_ADDR > /dev/null

echo "✅ Block Mined. Watcher should detect it now."
