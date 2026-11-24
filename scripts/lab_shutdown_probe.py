#!/usr/bin/env python3
"""Five process exits against the existing disposable Pi lab data, never live data."""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

from isolated_multivalidator_gate import certified_identity
from lab_transaction_gate import rejection

ROOT = Path("/home/pi/aincore-lab-20261020")
BINARY = Path("/home/pi/aincore-shutdown-fix-20261021/node-aarch64")
CHAIN = "AINCORE-LAB-646F5C8B4FEBB6A2"
TX_HASH = "0af9daa4bafa15cdee8be766bb7c3219f7fd18bb92fe0869df2d618df8dde86f"
GENESIS_SHA = "fb8479b39650654f608b6b159821764e9de31d9da7a1340afddfd26282cde61d"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rpc(method, params=None, raw=False):
    request = urllib.request.Request("http://127.0.0.1:8503/rpc",
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": params or []}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=8) as response:
        body = json.load(response)
    if raw:
        return body
    if body.get("error") is not None:
        raise ValueError(body["error"])
    return body["result"]


def snapshot():
    tx = rpc("aincore_getTransaction", [TX_HASH])
    if tx["chain_id"] != CHAIN:
        raise ValueError("wrong transaction chain")
    receipt = rpc("aincore_getTransactionReceipt", [TX_HASH])
    if receipt["block_height"] != 1263 or receipt["execution_receipt"]["status"] != "success":
        raise ValueError("historical successful receipt missing")
    return {
        "certificate": certified_identity(rpc("aincore_getQuorumCert", [1263]), CHAIN),
        "tip": certified_identity(rpc("aincore_getQuorumCert"), CHAIN),
        "nonce": rpc("aincore_getAccountNonce", [tx["sender"]]),
        "balance": rpc("aincore_getBalance", [
            "37d9a6e9265914f530e5381d36af5d0183927d7c6b9c10f8dc0630f861540ae7"]),
    }, tx


def main():
    report = {"passed": False, "scope": "Pi lab process shutdown/replay; RPC QC verification",
              "chain_id": CHAIN, "cycles": []}
    process = None
    run_id = str(time.time_ns())
    output = ROOT / f"shutdown-probe-{run_id}.json"
    try:
        if digest(ROOT / "genesis.json") != GENESIS_SHA:
            raise ValueError("unexpected lab genesis")
        key_sha = digest(ROOT / "data-2/node.key")
        report["binary_sha256"] = digest(BINARY)
        report["genesis_sha256"] = GENESIS_SHA
        for port in (8503, 9503, 9603):
            with socket.socket() as probe:
                probe.bind(("0.0.0.0", port))
        environment = {**os.environ, "AINCORE_CHAIN_ID": CHAIN,
            "AINCORE_GENESIS_PATH": str(ROOT / "genesis.json"), "AINCORE_GUARD_ORIGIN_INIT": "0",
            "TOKIO_WORKER_THREADS": "2", "RAYON_NUM_THREADS": "1"}
        baseline = None
        for cycle in range(5):
            log_path = ROOT / f"shutdown-probe-{run_id}-{cycle}.log"
            with log_path.open("x") as log:
                process = subprocess.Popen([str(BINARY), "--port", "9503", "--datadir",
                    str(ROOT / "data-2"), "--bootnodes",
                    "/ip4/192.168.18.202/tcp/9501,/ip4/192.168.18.202/tcp/9502,/ip4/192.168.18.66/tcp/9504"],
                    cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 180
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"node exited before ready: {process.returncode}")
                    try:
                        with urllib.request.urlopen("http://127.0.0.1:8503/health", timeout=2) as r:
                            if r.status == 200:
                                break
                    except (urllib.error.URLError, TimeoutError):
                        pass
                    if time.monotonic() > deadline:
                        raise TimeoutError("RPC did not become ready")
                    time.sleep(1)
                before, tx = snapshot()
                replay = rejection(rpc("aincore_sendTransaction", [tx], raw=True),
                                   ("duplicate transaction", "nonce", "sequence"))
                after, _ = snapshot()
                for key in ("certificate", "balance", "nonce"):
                    if before[key] != after[key] or (baseline and before[key] != baseline[key]):
                        raise ValueError(f"{key} changed after restart or replay")
                if baseline and before["tip"][0] < baseline["tip"][0]:
                    raise ValueError("tip regressed after restart")
                baseline = after
                time.sleep(5)
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=60)
                record = {"cycle": cycle + 1, "exit_code": code, "tip": after["tip"][0],
                          "replay": replay, "log": str(log_path)}
                report["cycles"].append(record)
                print(json.dumps(record), flush=True)
                if code != 0:
                    raise RuntimeError(f"unclean process exit {code}")
                process = None
            text = log_path.read_text()
            if any(word in text for word in ("pthread lock", "panicked at", "storage flush failed")):
                raise RuntimeError("shutdown log contains a fatal/storage error")
        if digest(ROOT / "data-2/node.key") != key_sha or digest(ROOT / "genesis.json") != GENESIS_SHA:
            raise ValueError("identity/genesis changed")
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                report["forced_cleanup"] = True
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(output), **report}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
