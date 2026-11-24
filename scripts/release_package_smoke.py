#!/usr/bin/env python3
"""Boot a freshly extracted release without borrowing runtime files from source.

Use only a disposable extraction and a test genesis. The observer has no P2P
listener or bootnodes. Its generated database/key remain in that extraction;
publish only the result JSON and log, never the whole test directory.
"""
import argparse
import json
from pathlib import Path

from node_exit_probe import run_case, sha256


def smoke(runtime, genesis):
    runtime = runtime.resolve(strict=True)
    genesis = genesis.resolve(strict=True)
    result = runtime / "release-smoke.json"
    if any(path.exists() or path.is_symlink() for path in (
            result, runtime / "clean_shutdown", runtime / "clean_shutdown.log")):
        raise ValueError("refusing to overwrite an earlier smoke run")
    binary = runtime / "node"
    chain = json.loads(genesis.read_text())["chain_id"]
    report = {"passed": False, "chain_id": chain,
              "scope": "fresh extracted release: observer startup and clean shutdown only",
              "genesis_sha256": sha256(genesis), "binary_sha256": sha256(binary)}
    try:
        report["case"] = run_case(binary, genesis, chain, runtime, "clean_shutdown")
        report["passed"] = (report["case"]["passed"]
                            and sha256(genesis) == report["genesis_sha256"]
                            and sha256(binary) == report["binary_sha256"])
    except Exception as error:
        report["error"] = str(error)
    finally:
        with result.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    args = parser.parse_args()
    report = smoke(args.runtime, args.genesis)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
