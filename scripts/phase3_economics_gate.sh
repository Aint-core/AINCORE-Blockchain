#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== AINCORE Phase 3 Economics/Staking Gate =="

echo "[1/6] Compile Move stdlib bytecode"
cargo run --release -p move_compiler_tool -- \
  -s core/vm_move/stdlib/sources/*.move \
  -o core/vm_move/stdlib/bytecode

echo "[2/6] Compile critical economics packages"
cargo check -p vm_move -p executor -p node -p governance

echo "[3/6] Move VM stdlib/runtime tests"
cargo test -p vm_move -- --nocapture

echo "[4/6] Executor fee, gas, burn, and slashing tests"
cargo test -p executor -- --nocapture

echo "[5/6] Genesis economics resource integrity tests"
cargo test -p node genesis::tests -- --nocapture

echo "[6/6] API supply/faucet and governance economics tests"
cargo test -p node api_local::tests -- --nocapture
cargo test -p governance -- --nocapture

echo ""
echo "Phase 3 economics/staking gate PASSED."
