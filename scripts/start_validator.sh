#!/bin/bash
set -e

# AINCORE VALIDATOR START SCRIPT
# This script ensures your validator is set up correctly before launching.

# CONFIGURATION
DATA_DIR="./data"
DB_PATH="$DATA_DIR/validator.db"
GENESIS_ADDR="00000000000000000000000000000001"
KEYSTORE_DIR="./secrets"

echo "🚀 AINCORE Validator Launcher"

# 1. Check binaries
if [ ! -f "./target/release/node" ]; then
    echo "⚠️  Node binary not found. Building release..."
    cargo build --release --bin node
    cargo build --release --bin genesis-tool
fi

# 1.1 Build Ecosystem Components
if [ ! -f "./target/release/monitor" ]; then
    echo "🛠️  Building Monitor Dashboard..."
    cargo build --release --bin monitor
fi

if [ ! -f "./target/release/bridge-service" ]; then
    echo "🌉 Building Bridge Service..."
    # Assuming bridge-rust is part of workspace or needs explicit path.
    # Safe bet: explicit path build if workspace structure is complex
    cargo build --release --manifest-path depin/bridge-rust/Cargo.toml
fi

# 2. Check Data Dir
mkdir -p "$DATA_DIR"
mkdir -p "$KEYSTORE_DIR"

# 3. Check Genesis
if [ ! -d "$DB_PATH" ]; then
    echo "⚡ Initializing Genesis..."
    ./target/release/genesis-tool --db-path "$DB_PATH" --genesis-addr "$GENESIS_ADDR"
else
    echo "✅ Genesis DB found."
fi

# 4. Check Keystore
if [ -z "$(ls -A $KEYSTORE_DIR)" ]; then
    echo "⚠️  No keys found in $KEYSTORE_DIR."
    echo "   Please create a key: cargo run --bin aincore-cli keys new"
    # In pro script we might exit, but for UX we proceed (Node might fail or use dev key if allowed)
    # But we want to fail fast if no key passed in production mode.
    # For now, we assume user provides password file in CLI args or environment.
    echo "   Continuing... (Ensure you have your keys ready)"
fi

# 5. Launch Node
echo "🌍 Starting Node..."
# Adjust flags as needed. Using defaults for now.
./target/release/node --db-path "$DB_PATH"

