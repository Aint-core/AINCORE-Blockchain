#!/bin/bash
# AINCORE Complete System Verification
# Tests all critical features after production hardening

set -e

echo "🧪 AINCORE COMPLETE SYSTEM VERIFICATION"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        ((PASSED++))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        ((FAILED++))
    fi
}

echo "1️⃣  Testing Build System..."
cargo build --release --bin node --bin aincore-cli > /dev/null 2>&1
test_result $? "Build compilation"

echo ""
echo "2️⃣  Testing Node Startup..."
timeout 5s ./target/release/node --port 9998 --rpc-port 8998 --datadir data_verify_test > /tmp/node_test.log 2>&1 &
NODE_PID=$!
sleep 2
if ps -p $NODE_PID > /dev/null; then
    test_result 0 "Node startup and initialization"
    kill $NODE_PID 2>/dev/null || true
else
    test_result 1 "Node startup and initialization"
fi

echo ""
echo "3️⃣  Testing Consensus Module..."
cargo test --release --lib -p consensus > /dev/null 2>&1
test_result $? "Consensus DAG tests"

echo ""
echo "4️⃣  Testing VM Module..."
cargo test --release --lib -p vm_move > /dev/null 2>&1
test_result $? "Move VM and PQC tests"

echo ""
echo "5️⃣  Testing Executor Module..."
cargo test --release --lib -p executor > /dev/null 2>&1
test_result $? "Transaction executor tests"

echo ""
echo "6️⃣  Testing Storage Module..."
cargo test --release --lib -p storage > /dev/null 2>&1
test_result $? "RocksDB storage tests"

echo ""
echo "7️⃣  Testing Mempool Module..."
cargo test --release --lib -p mempool > /dev/null 2>&1
test_result $? "Mempool transaction pool tests"

echo ""
echo "8️⃣  Testing AA Module..."
cargo test --release --lib -p aa > /dev/null 2>&1
test_result $? "Account Abstraction tests"

echo ""
echo "9️⃣  Checking Critical Files..."
FILES=(
    "phase1-core-prototype/vm_move/stdlib/sources/staking.move"
    "phase1-core-prototype/vm_move/stdlib/sources/governance.move"
    "phase1-core-prototype/vm_move/stdlib/sources/universal_mining.move"
    "phase1-core-prototype/vm_move/stdlib/sources/coin.move"
    "phase2-consensus-aa/consensus/src/dag.rs"
    "phase2-consensus-aa/consensus/src/ordering.rs"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        test_result 0 "File exists: $(basename $file)"
    else
        test_result 1 "File exists: $(basename $file)"
    fi
done

echo ""
echo "🔟  Checking PQC Implementation..."
if grep -q "pqcrypto_dilithium" phase1-core-prototype/vm_move/src/lib.rs; then
    test_result 0 "Post-Quantum Cryptography (Dilithium5)"
else
    test_result 1 "Post-Quantum Cryptography (Dilithium5)"
fi

echo ""
echo "========================================"
echo -e "📊 FINAL RESULTS:"
echo -e "${GREEN}✅ Passed: $PASSED${NC}"
echo -e "${RED}❌ Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! SYSTEM READY FOR PRODUCTION!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests failed. Review above for details.${NC}"
    exit 1
fi
