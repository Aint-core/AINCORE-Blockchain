#!/bin/bash
echo "🛑 Stopping all running nodes..."
pkill -f "target/release/node"
echo "✅ All nodes stopped!"
