#!/bin/bash

# Configuration
BITCOIN_DIR="./bitcoin_data"
RPC_USER="user"
RPC_PASS="pass"
RPC_PORT=18443
RPC_URL="http://$RPC_USER:$RPC_PASS@127.0.0.1:$RPC_PORT"

# Clean previous run (optional, maybe keep for persistence?)
# rm -rf $BITCOIN_DIR

mkdir -p $BITCOIN_DIR

echo "🚀 Starting Bitcoin Core (Regtest)..."
bitcoind -regtest -datadir=$BITCOIN_DIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT -server -daemon -fallbackfee=0.00001

echo "⏳ Waiting for Bitcoin to start..."
sleep 5

# Check status
bitcoin-cli -regtest -datadir=$BITCOIN_DIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT getblockchaininfo

if [ $? -ne 0 ]; then
    echo "❌ Failed to start Bitcoin Core"
    exit 1
fi

echo "✅ Bitcoin Core (Regtest) is running!"

# Setup Wallet
echo "💼 Setting up Vault Wallet..."
bitcoin-cli -regtest -datadir=$BITCOIN_DIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT createwallet "vault" > /dev/null 2>&1
bitcoin-cli -regtest -datadir=$BITCOIN_DIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT loadwallet "vault" > /dev/null 2>&1

# Generate Address
VAULT_ADDR=$(bitcoin-cli -regtest -datadir=$BITCOIN_DIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT -rpcwallet="vault" getnewaddress)

echo "🏦 Vault Address: $VAULT_ADDR"
echo $VAULT_ADDR > vault_address.txt

# Mine 101 blocks to unlock Coinbase funds (if fresh)
HEIGHT=$(bitcoin-cli -regtest -datadir=$BITCOIN_DIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT getblockcount)
if [ "$HEIGHT" -lt 101 ]; then
    echo "⛏️  Mining 101 blocks to mature coinbase..."
    bitcoin-cli -regtest -datadir=$BITCOIN_DIR -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcport=$RPC_PORT -rpcwallet="vault" generatetoaddress 101 $VAULT_ADDR > /dev/null
fi

echo "✅ Vault Setup Complete. Funds (Immature/Available) ready."
echo "📜 Vault Address saved to 'vault_address.txt'"
