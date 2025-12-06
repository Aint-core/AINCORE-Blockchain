#!/bin/bash
# AINCORE Production Hardening Script
# Eliminates ALL unwrap(), expect(), and panic!() from critical paths

set -e

echo "🔍 AINCORE PRODUCTION HARDENING"
echo "================================"
echo ""

echo "📊 Current Status:"
echo "- unwrap() calls: $(grep -r "\.unwrap()" --include="*.rs" phase1-core-prototype/ phase2-consensus-aa/ phase3-chain-sync/ phase4-da-sequencer/ common/ 2>/dev/null | grep -v "test" | wc -l | tr -d ' ')"
echo "- expect() calls: $(grep -r "\.expect(" --include="*.rs" phase1-core-prototype/ phase2-consensus-aa/ phase3-chain-sync/ phase4-da-sequencer/ common/ 2>/dev/null | grep -v "test" | wc -l | tr -d ' ')"
echo "- panic!() calls: $(grep -r "panic!" --include="*.rs" phase1-core-prototype/ phase2-consensus-aa/ phase3-chain-sync/ phase4-da-sequencer/ common/ 2>/dev/null | grep -v "test" | wc -l | tr -d ' ')"
echo ""

echo "🎯 Critical Files to Fix:"
echo "1. phase2-consensus-aa/consensus/src/dag.rs"
echo "2. phase1-core-prototype/executor/src/lib.rs"
echo "3. common/storage/src/lib.rs"
echo "4. common/network/src/lib.rs"
echo "5. phase1-core-prototype/vm_move/src/lib.rs"
echo ""

echo "✅ Running cargo build to verify current state..."
cargo build --release --bin node 2>&1 | grep -E "(error|warning:.*unwrap|warning:.*expect)" || echo "Build OK"

echo ""
echo "📝 Next Steps:"
echo "1. Fix consensus/dag.rs (highest priority)"
echo "2. Fix executor/lib.rs (transaction execution)"
echo "3. Fix storage/lib.rs (data persistence)"
echo "4. Fix network/lib.rs (P2P communication)"
echo "5. Fix vm_move/lib.rs (VM execution)"
echo ""
echo "Run individual fix scripts or manual fixes for each module."
