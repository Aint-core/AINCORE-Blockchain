#!/usr/bin/env python3
"""Reproduce cross-checkout mtime cache reuse with tiny disposable Rust crates.

Run on the NAS, not the Mac. No dependency download or blockchain build. Source
B already exists before A is compiled, like two pre-staged release checkouts.
Only a new --output directory is written. Never clean an existing target.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def run(root):
    root.mkdir(mode=0o700)
    manifest = '[package]\nname="cache_probe"\nversion="0.1.0"\nedition="2024"\n'
    report = {"reproduced": False, "isolated_control_passed": False, "builds": []}
    env = {k: v for k, v in os.environ.items()
           if k not in {"CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR", "RUSTC_WRAPPER",
                        "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}}
    env.update(CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0")
    try:
        for name, code in (("a", 0), ("b", 17)):
            source = root / name
            (source / "src").mkdir(parents=True)
            (source / "Cargo.toml").write_text(manifest)
            main = source / "src/main.rs"
            main.write_text(f"fn main() {{ std::process::exit({code}); }}\n")
            # Both inputs predate the first build; no future clock skew needed.
            old = time.time() - 10
            os.utime(main, (old, old))
        report["rustc"] = subprocess.check_output(["rustc", "-Vv"], env=env, text=True)
        report["cargo"] = subprocess.check_output(["cargo", "-V"], env=env, text=True)
        for label, checkout, target in (("a_shared", "a", "shared"),
                                        ("b_shared", "b", "shared"),
                                        ("b_isolated", "b", "isolated-b")):
            command = ["cargo", "build", "--offline", "--release", "--verbose",
                       "--manifest-path", str(root / checkout / "Cargo.toml"),
                       "--target-dir", str(root / target)]
            result = subprocess.run(command, cwd=root / checkout, env=env,
                                    capture_output=True, text=True, timeout=60)
            (root / f"{label}.log").write_text(result.stdout + result.stderr)
            record = {"label": label, "command": command, "build_exit": result.returncode}
            report["builds"].append(record)
            if result.returncode:
                raise RuntimeError(f"{label} compilation failed")
            binary = root / target / "release/cache_probe"
            record["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            record["source_sha256"] = hashlib.sha256(
                (root / checkout / "src/main.rs").read_bytes()).hexdigest()
            record["process_exit"] = subprocess.run([str(binary)], timeout=5).returncode
        a, b, isolated = report["builds"]
        report["reproduced"] = (a["process_exit"] == b["process_exit"] == 0
                                and a["source_sha256"] != b["source_sha256"]
                                and a["binary_sha256"] == b["binary_sha256"])
        report["isolated_control_passed"] = isolated["process_exit"] == 17
    except Exception as error:
        report["error"] = str(error)
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["reproduced"] and report["isolated_control_passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.output.absolute()))
