#!/usr/bin/env bash
# Run only in an isolated checkout. Resource limits belong to the job runner.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
requested_out=
probe_genesis=
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|--probe-genesis)
            [[ $# -ge 2 && -n "$2" ]] || { printf 'Missing argument for %s\n' "$1" >&2; exit 2; }
            if [[ "$1" == --output ]]; then requested_out=$2; else probe_genesis=$2; fi
            shift 2 ;;
        *) printf 'Usage: %s [--output NEW_REPORT_DIRECTORY] [--probe-genesis TEST_GENESIS]\n' "$0" >&2; exit 2 ;;
    esac
done
if [[ -n "$probe_genesis" ]]; then
    [[ -f "$probe_genesis" ]] || { printf 'Missing probe genesis\n' >&2; exit 2; }
    probe_genesis="$(cd "$(dirname "$probe_genesis")" && pwd -P)/$(basename "$probe_genesis")"
fi
if [[ -n "$(git status --porcelain)" ]]; then
    printf 'Refusing a dirty source tree\n' >&2
    exit 2
fi
mkdir -p target
out="${requested_out:-$PWD/target/hardening-regression-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
mkdir "$out"
out="$(cd "$out" && pwd -P)"
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
# Cargo mtime fingerprints can reuse another checkout's workspace artifacts.
# Keep download caches, but never inherit compiled output or compiler wrappers.
export CARGO_TARGET_DIR="$out/build"
export CARGO_BUILD_BUILD_DIR="$CARGO_TARGET_DIR"
export RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER=
export CARGO_BUILD_RUSTC_WRAPPER= CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=
mkdir "$CARGO_TARGET_DIR"
printf '%s\n' "$CARGO_TARGET_DIR" > "$out/build-target.txt"
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
run_stage process-exit-controls python3 -m unittest discover -s scripts/tests -p test_node_exit_probe.py -v
run_stage steady-state-controls python3 -m unittest discover -s scripts/tests -p test_two_host_check.py -v
run_stage backup-controls python3 -m unittest discover -s scripts/tests -p test_backup_safety.py -v
run_stage restore-controls python3 -m unittest discover -s scripts/tests -p test_restore_safety.py -v
run_stage observer-dr-controls python3 -m unittest discover -s scripts/tests -p test_observer_backup_probe.py -v
run_stage package-controls python3 -m unittest discover -s scripts/tests -p test_release_package.py -v
run_stage package-smoke-controls python3 -m unittest discover -s scripts/tests -p test_release_package_smoke.py -v
# Check the deployable binary first, before spending time on the full test build.
run_stage release cargo build --locked --offline --release -p node -p indexer -p aincore-cli -p genesis-tool --bins
if [[ -n "$probe_genesis" ]]; then
    run_stage process-exits python3 scripts/node_exit_probe.py \
        --binary "$CARGO_TARGET_DIR/release/node" --genesis "$probe_genesis" \
        --source "$PWD" --output "$out/process-exits"
fi
packages=(-p blockchain -p chain_sync -p consensus -p executor -p network -p node -p storage -p vm_move -p state_commit)
run_stage regression cargo test --locked --offline "${packages[@]}" -- --test-threads=1
run_stage witnesses python3 scripts/release_security_gate.py --offline --report "$out/security-gate.json"
run_stage identity-vectors node scripts/tests/block_identity_v2_vectors.mjs
run_stage clippy cargo clippy --locked --offline "${packages[@]}" --all-targets -- -D warnings
stage=source-integrity
printf '%s\n' "$stage" > "$out/current-stage.txt"
if [[ -n "$(git status --porcelain)" || "$(git rev-parse HEAD)" != "$(head -n 1 "$out/source.txt")" ]]; then
    printf 'Source changed during the gate; result is not attributable\n' >&2
    exit 2
fi
stage=complete
printf '%s\n' "$stage" > "$out/current-stage.txt"
