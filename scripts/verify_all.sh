#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}       AINCORE BLOCKCHAIN - FINAL SYSTEM VERIFICATION      ${NC}"
echo -e "${BLUE}=========================================================${NC}"

# 1. Static Analysis & Compilation (Zero-Warning Policy)
echo -e "\n${BLUE}[1/4] Checking Compilation & Warnings...${NC}"
if cargo check --workspace --all-targets --all-features; then
    echo -e "${GREEN}✅ Compilation Successful (Zero Errors)${NC}"
else
    echo -e "${RED}❌ Compilation Failed${NC}"
    exit 1
fi

# 2. Unit & Integration Tests
echo -e "\n${BLUE}[2/4] Running Workspace Unit Tests...${NC}"
if cargo test --workspace; then
    echo -e "${GREEN}✅ All Unit Tests Passed${NC}"
else
    echo -e "${RED}❌ Unit Tests Failed${NC}"
    exit 1
fi

# 3. Governance Module Verification
echo -e "\n${BLUE}[3/4] Verifying Governance Module...${NC}"
chmod +x scripts/verify_governance.sh
if ./scripts/verify_governance.sh; then
    echo -e "${GREEN}✅ Governance Module Verified${NC}"
else
    echo -e "${RED}❌ Governance Verification Failed${NC}"
    exit 1
fi

# 4. Indexer Module Verification
echo -e "\n${BLUE}[4/4] Verifying Indexer Module...${NC}"
chmod +x scripts/verify_indexer.sh
if ./scripts/verify_indexer.sh; then
    echo -e "${GREEN}✅ Indexer Module Verified${NC}"
else
    echo -e "${RED}❌ Indexer Verification Failed${NC}"
    exit 1
fi

echo -e "\n${BLUE}=========================================================${NC}"
echo -e "${GREEN}   🎉 ALL SYSTEMS GO! MAXIMUM VERIFICATION COMPLETE.   ${NC}"
echo -e "${BLUE}=========================================================${NC}"
