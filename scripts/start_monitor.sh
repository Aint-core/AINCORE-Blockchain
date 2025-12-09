#!/bin/bash
set -e

echo "📊 Starting AINCORE Cluster Monitor..."

# 1. Check Binary
if [ ! -f "./target/release/monitor" ]; then
    echo "⚠️  Monitor binary not found. Building..."
    cargo build --release --bin monitor
fi

# 2. Run
./target/release/monitor
