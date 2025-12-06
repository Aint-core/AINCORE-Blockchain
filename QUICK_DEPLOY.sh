#!/bin/bash
# AINCORE Quick Deploy Script untuk Komputer Baru

echo "🚀 AINCORE Quick Deploy"
echo "======================="
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "✅ Rust already installed"
fi

# Check OS and install dependencies
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "📦 Installing Linux dependencies..."
    sudo apt update
    sudo apt install -y build-essential pkg-config libssl-dev git
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📦 Installing macOS dependencies..."
    brew install openssl pkg-config || true
fi

echo ""
echo "🔨 Building AINCORE..."
cargo build --release --bin node --bin aincore-cli

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ BUILD SUCCESS!"
    echo ""
    echo "📍 Binary locations:"
    echo "   - Node: ./target/release/node"
    echo "   - CLI:  ./target/release/aincore-cli"
    echo ""
    echo "🚀 To start node:"
    echo "   ./target/release/node --port 9000 --rpc-port 8000 --datadir data"
    echo ""
    echo "🌐 To connect to existing network:"
    echo "   ./target/release/node --port 9000 --rpc-port 8000 --datadir data --bootnodes /ip4/<BOOTNODE_IP>/tcp/9000"
    echo ""
else
    echo "❌ Build failed. Check errors above."
    exit 1
fi
