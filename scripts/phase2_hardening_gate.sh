#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== AINCORE Phase 2 Hardening Gate =="

echo "[1/6] Compile critical packages"
cargo check -p vm_move -p executor -p consensus -p chain_sync -p node -p governance -p indexer

echo "[2/6] Consensus adversarial/unit tests"
cargo test -p consensus -- --nocapture

echo "[3/6] Sync/reorg/finality tests"
cargo test -p chain_sync -- --nocapture

echo "[4/6] Genesis integrity tests"
cargo test -p node genesis::tests -- --nocapture

echo "[5/6] Executor economics/runtime tests"
cargo test -p executor -- --nocapture

echo "[6/6] Governance + indexer compatibility tests"
cargo test -p governance -- --nocapture
cargo test -p indexer -- --nocapture

echo ""
echo "Phase 2 hardening gate PASSED."
echo "Next: run soak plan (7-30 days) before mainnet claim."
