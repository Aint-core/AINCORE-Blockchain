#!/bin/bash
set -e

echo "🚀 Welcome to the AINCORE Node Installer"
echo "========================================="

OS="$(uname -s)"
ARCH="$(uname -m)"

echo "Detected OS: $OS"
echo "Detected Arch: $ARCH"

# Determine binary name based on OS/Arch
if [ "$OS" = "Linux" ]; then
    if [ "$ARCH" = "x86_64" ]; then
        TARGET="x86_64-unknown-linux-gnu"
    elif [ "$ARCH" = "aarch64" ]; then
        TARGET="aarch64-unknown-linux-gnu"
    else
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
    fi
elif [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "x86_64" ]; then
        TARGET="x86_64-apple-darwin"
    elif [ "$ARCH" = "arm64" ]; then
        TARGET="aarch64-apple-darwin"
    else
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
    fi
else
    echo "❌ Unsupported OS: $OS"
    exit 1
fi

BIN_URL="https://github.com/Aint-core/AINCORE-Blockchain/releases/latest/download/aincore-node-$TARGET.tar.gz"

echo "📥 Downloading AINCORE Node..."
curl -sSL "$BIN_URL" -o aincore-node.tar.gz || {
    echo "⚠️ Release not found. Please compile from source or wait for the official release."
    echo "To compile from source:"
    echo "  git clone https://github.com/Aint-core/AINCORE-Blockchain.git"
    echo "  cd AINCORE-Blockchain && cargo build --release -p node"
    exit 1
}

tar -xzf aincore-node.tar.gz
chmod +x aincore-node
sudo mv aincore-node /usr/local/bin/aincore-node
rm aincore-node.tar.gz

echo "✅ AINCORE Node installed successfully!"
echo ""
echo "To start your node, run:"
echo "  aincore-node --enable-mdns --enable-nat"
echo ""
echo "Happy mining! ⛏️"
