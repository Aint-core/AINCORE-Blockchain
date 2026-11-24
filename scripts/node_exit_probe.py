#!/usr/bin/env python3
"""Probe real process exits on Linux using fresh observer data, never live data.

Run as an unprivileged user under an externally resource-limited job. A supplied
genesis is read-only; all generated keys, databases and logs stay under a new
output directory. Permission injection changes only that run's own database.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verdict(scenario, code, log, forced_cleanup=False):
    if forced_cleanup:
        return False
    if scenario == "p2p_busy":
        return code == 1 and "Failed to start P2P" in log
    if scenario == "flush_denied":
        return (code == 1 and "storage flush failed" in log
                and "Shutdown drain completed" not in log)
    if scenario == "clean_shutdown":
        return (code == 0 and "storage flushed to disk" in log
                and "storage flush failed" not in log)
    raise ValueError(f"unknown scenario {scenario}")


def wait_ready(process, port, deadline):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited before readiness: {process.returncode}")
        try:
            with opener.open(f"http://127.0.0.1:{port}/health", timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.25)
    raise TimeoutError("RPC readiness timeout")


def run_case(binary, genesis, chain, root, scenario):
    datadir = root / scenario
    datadir.mkdir()
    log_path = root / f"{scenario}.log"
    record = {"scenario": scenario, "passed": False, "log": str(log_path)}
    process = None
    db = None
    mode = None
    # The P2P listener's base port is 100 below the actual bound port.
    with socket.socket() as occupied, socket.socket() as rpc_port:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1] - 100
        rpc_port.bind(("127.0.0.1", 0))
        rpc = rpc_port.getsockname()[1]
        rpc_port.close()
        environment = {k: v for k, v in os.environ.items()
                       if not k.startswith("AINCORE_")}
        environment.update({"AINCORE_GENESIS_PATH": str(genesis),
                            "AINCORE_CHAIN_ID": chain,
                            "AINCORE_GUARD_ORIGIN_INIT": "0",
                            "AINCORE_RPC_BIND": "127.0.0.1",
                            "AINCORE_P2P_LISTEN": "1" if scenario == "p2p_busy" else "0",
                            "TOKIO_WORKER_THREADS": "2", "RAYON_NUM_THREADS": "1"})
        command = [str(binary), "--port", str(port), "--rpc-port", str(rpc),
                   "--datadir", str(datadir)]
        record["command"] = command
        started = time.monotonic()
        try:
            with log_path.open("x") as log:
                process = subprocess.Popen(command, env=environment, cwd=root,
                                           stdout=log, stderr=subprocess.STDOUT)
                if scenario != "p2p_busy":
                    wait_ready(process, rpc, time.monotonic() + 180)
                    if scenario == "flush_denied":
                        db = datadir / f"validator_{port}.db"
                        mode = db.stat().st_mode & 0o777
                        db.chmod(0o500)
                        record["injected_fault"] = "own fresh database directory mode 0500"
                    process.send_signal(signal.SIGTERM)
                record["exit_code"] = process.wait(timeout=60)
        except Exception as error:
            record["error"] = str(error)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                record["forced_cleanup"] = True
            if db is not None and mode is not None:
                db.chmod(mode)
            record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        log = log_path.read_text(errors="replace")
        record["passed"] = ("error" not in record and verdict(
            scenario, record.get("exit_code"), log, record.get("forced_cleanup", False)))
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True,
                        help="source checkout containing the matching stdlib bytecode")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("permission injection must run unprivileged")
    binary, genesis = args.binary.resolve(strict=True), args.genesis.resolve(strict=True)
    chain = json.loads(genesis.read_text())["chain_id"]
    root = args.output.absolute()
    root.mkdir(mode=0o700)  # Refuse existing directories, especially live data.
    bytecode = args.source.resolve(strict=True) / "core/vm_move/stdlib/bytecode"
    shutil.copytree(bytecode, root / "core/vm_move/stdlib/bytecode")
    report = {"passed": False, "stage": "running", "chain_id": chain,
              "binary_sha256": sha256(binary), "genesis_sha256": sha256(genesis),
              "scope": "fresh isolated observer process exits; not validator recovery",
              "cases": []}
    output = root / "result.json"
    try:
        for scenario in ("p2p_busy", "clean_shutdown", "flush_denied"):
            record = run_case(binary, genesis, chain, root, scenario)
            report["cases"].append(record)
            print(json.dumps(record), flush=True)
        report["passed"] = (all(case["passed"] for case in report["cases"])
                            and sha256(genesis) == report["genesis_sha256"]
                            and sha256(binary) == report["binary_sha256"])
        report["stage"] = "complete"
    except Exception as error:
        report["error"] = str(error)
    finally:
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Report: {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
