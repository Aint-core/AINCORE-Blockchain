#!/usr/bin/env python3
"""Create fresh, disposable fixtures on NAS; never reuse a live genesis/key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.output.resolve()
    source = args.source.resolve()
    binaries = args.binaries.resolve()
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"]):
        raise RuntimeError("source must be clean")
    root.mkdir(mode=0o700, exist_ok=False)
    specs = []
    for i in range(4):
        directory = root / f"data-{i}"
        directory.mkdir()
        seed = secrets.token_bytes(32)
        (directory / "node.key").write_bytes(seed)
        specs.append(seed.hex() + ":1000000")
    seeds = root / "test-seeds.txt"
    seeds.write_text("\n".join(specs))
    chain = "AINCORE-LAB-" + secrets.token_hex(8).upper()
    shutil.copytree(source / "core/vm_move/stdlib/bytecode",
                    root / "core/vm_move/stdlib/bytecode")
    # Synthetic timing for functional tests, not measured production settings.
    subprocess.run([
        str(binaries / "genesis-tool"), "gen-multi",
        "--seeds-file", str(seeds), "--chain-id", chain,
        "--block-time-ms", "3000", "--clock-cap-secs", "9",
        "--out", str(root / "genesis.json"),
    ], cwd=source, check=True)
    manifest = {
        "chain_id": chain,
        "source_commit": subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip(),
        "genesis_sha256": hashlib.sha256((root / "genesis.json").read_bytes()).hexdigest(),
        "scope": "disposable two-host four-validator test, not mainnet",
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
