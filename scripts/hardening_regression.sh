#!/usr/bin/env bash
# Run only in an isolated checkout. Resource limits belong to the job runner.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ -n "$(git status --porcelain)" ]]; then
    printf 'Refusing a dirty source tree\n' >&2
    exit 2
fi
mkdir -p target
out="target/hardening-regression-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir "$out"
stage=metadata
finish() {
    code=$?
    trap - EXIT
    # An interrupted/incomplete run must never publish a successful result.
    if [[ "$code" -eq 0 && "$stage" != complete ]]; then
        code=1
    fi
    printf 'stage=%s\nexit_code=%s\n' "$stage" "$code" > "$out/result.tmp"
    mv "$out/result.tmp" "$out/result.txt"
    printf 'Result: %s (exit %s, stage %s)\n' "$out/result.txt" "$code" "$stage"
    exit "$code"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
git rev-parse HEAD > "$out/source.txt"
rustc --version >> "$out/source.txt"
cargo --version >> "$out/source.txt"
run_stage() {
    stage=$1
    shift
    printf '%s\n' "$stage" > "$out/current-stage.txt"
    printf 'Stage %s:' "$stage"
    printf ' %q' "$@"
    printf '\n'
    "$@" > "$out/$stage.log" 2>&1
}
run_stage gate-controls python3 -m unittest discover -s scripts/tests -p test_release_security_gate.py -v
run_stage runner-controls python3 -m unittest discover -s scripts/tests -p test_hardening_runner.py -v
packages=(-p blockchain -p chain_sync -p consensus -p executor -p network -p node -p storage -p vm_move -p state_commit)
run_stage regression cargo test --locked --offline "${packages[@]}" -- --test-threads=1
run_stage witnesses python3 scripts/release_security_gate.py --offline --report "$out/security-gate.json"
run_stage identity-vectors node scripts/tests/block_identity_v2_vectors.mjs
run_stage clippy cargo clippy --locked --offline "${packages[@]}" --all-targets -- -D warnings
run_stage release cargo build --locked --offline --release -p node -p indexer -p aincore-cli -p genesis-tool --bins
stage=complete
