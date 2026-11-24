#!/usr/bin/env python3
"""Real stopped-observer RocksDB roundtrip, optionally on the named disposable lab.

Run unprivileged under external resource limits. Only new test-owned directories
and child processes are used; no validator key or live database is copied.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time
import urllib.request

from node_exit_probe import sha256, wait_ready
from isolated_multivalidator_gate import certified_identity

LAB_GENESIS = "fb8479b39650654f608b6b159821764e9de31d9da7a1340afddfd26282cde61d"
LAB_TX = "0af9daa4bafa15cdee8be766bb7c3219f7fd18bb92fe0869df2d618df8dde86f"
LAB_RECIPIENT = "37d9a6e9265914f530e5381d36af5d0183927d7c6b9c10f8dc0630f861540ae7"


def request(port, method=None, params=None):
    url = f"http://127.0.0.1:{port}"
    if method is None:
        query = urllib.request.Request(url + "/get_network_info")
    else:
        query = urllib.request.Request(url + "/rpc", data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params or [],
        }).encode(), headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(query, timeout=8) as response:
        value = json.load(response)
    if method is None:
        return value
    if value.get("error"):
        raise RuntimeError(value["error"])
    return value["result"]


def identity_status(port, expected_identity=None):
    deadline = time.monotonic() + 30
    while True:
        status = request(port, "aincore_getStatus")
        if status.get("node_id") is not None:
            if expected_identity is not None and status["node_id"] != expected_identity:
                raise RuntimeError("RPC identity differs from this child process")
            return status
        # This RPC deliberately avoids waiting on the consensus lock. Retry
        # only its documented busy/null result, never an unknown identity.
        if not status.get("consensus_busy"):
            raise RuntimeError("missing node identity without a busy indication")
        if expected_identity is not None:
            return {**status, "node_id": expected_identity,
                    "identity_source": "local child startup log; RPC consensus_busy=true"}
        if time.monotonic() >= deadline:
            raise TimeoutError("node identity remained busy for 30 seconds")
        time.sleep(0.2)


def snapshot(port, genesis, reference_height=None, expected_identity=None):
    info = request(port)
    if info["network"] != genesis["chain_id"]:
        raise RuntimeError("wrong chain")
    status = identity_status(port, expected_identity)
    if status["node_id"] in {v["address"] for v in genesis["validators"]}:
        raise RuntimeError("refusing validator backup")
    if reference_height is not None:
        if status["node_id"] is None:
            raise RuntimeError("missing observer identity")
        tx = request(port, "aincore_getTransaction", [LAB_TX])
        receipt = request(port, "aincore_getTransactionReceipt", [LAB_TX])
        if tx["chain_id"] != genesis["chain_id"] or receipt["block_height"] != 1263:
            raise RuntimeError("wrong historical transaction")
        if receipt["execution_receipt"]["status"] != "success":
            raise RuntimeError("historical transaction did not execute successfully")
        tip = certified_identity(request(port, "aincore_getQuorumCert"), genesis["chain_id"])
        if tip[0] < reference_height:
            raise RuntimeError("observer has not caught up to reference")
        history = {str(height): certified_identity(
            request(port, "aincore_getQuorumCert", [height]), genesis["chain_id"])
            for height in (1263, reference_height)}
        balance = request(port, "aincore_getBalance", [LAB_RECIPIENT])
        if int(balance["move_balance"]) != 10**18:
            raise RuntimeError("wrong historical recipient balance")
        return {"node_id": status["node_id"], "chain_id": info["network"],
                "identity_source": status.get("identity_source", "RPC"),
                "certified_tip": tip[0], "history": history,
                "receipt": {key: receipt[key] for key in ("block_height", "block_hash", "execution_receipt")},
                "nonce": request(port, "aincore_getAccountNonce", [tx["sender"]]),
                "balance": balance}
    if status["node_id"] is None or int(status["latest_height"]) != 0:
        raise RuntimeError("expected an isolated genesis-only observer")
    return {"node_id": status["node_id"], "chain_id": info["network"],
            "status": {key: status[key] for key in (
                "latest_height", "finalized_round", "last_anchor_round", "finality_digest")},
            "balances": {v["address"]: request(port, "aincore_getBalance", [v["address"]])
                         for v in genesis["validators"]}}


def files(path):
    return {str(p.relative_to(path)): sha256(p) for p in sorted(path.rglob("*")) if p.is_file()}


def run(args):
    if os.geteuid() == 0:
        raise ValueError("run as an unprivileged user")
    binary = args.binary.resolve(strict=True)
    genesis_path = args.genesis.resolve(strict=True)
    genesis = json.loads(genesis_path.read_text())
    if args.lab_history and sha256(genesis_path) != LAB_GENESIS:
        raise ValueError("history mode is restricted to the pinned disposable lab")
    root = args.output.absolute()
    root.mkdir(mode=0o700)  # Never reuse a failed probe's data or evidence.
    shutil.copytree(args.source.resolve(strict=True) / "core/vm_move/stdlib/bytecode",
                    root / "core/vm_move/stdlib/bytecode")
    report = {"passed": False, "stage": "running", "started_at": time.time(),
              "scope": "real RocksDB observer roundtrip at genesis; no certified-chain replay, "
                       "transaction history or validator recovery claim",
              "binary_sha256": sha256(binary), "genesis_sha256": sha256(genesis_path),
              "script_sha256": {name: sha256(Path(__file__).parent / name) for name in (
                  "backup_node.sh", "restore_node.sh", "observer_backup_probe.py", "node_exit_probe.py")},
              "steps": []}
    process = None
    handles = []
    try:
        reference = None
        reference_height = None
        if args.lab_history:
            reference_height = certified_identity(request(8503, "aincore_getQuorumCert"),
                                                  genesis["chain_id"])[0]
            if reference_height < 1263:
                raise RuntimeError("reference lab has no known transaction history")
            # The reference is a validator: read its history but not through the
            # observer-only snapshot guard.
            reference = {str(height): certified_identity(
                request(8503, "aincore_getQuorumCert", [height]), genesis["chain_id"])
                for height in (1263, reference_height)}
            report.update(scope="real disposable lab observer sync/backup/restore, historical "
                          "receipt/balance/nonce and RPC-verified QC checks; not validator recovery "
                          "or independent cryptographic verification", reference=reference,
                          reference_height=reference_height)
        with socket.socket() as base, socket.socket() as rpc_socket:
            base.bind(("127.0.0.1", 0))
            rpc_socket.bind(("127.0.0.1", 0))
            port, rpc_port = base.getsockname()[1], rpc_socket.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if not k.startswith("AINCORE_")}
        env.update(AINCORE_GENESIS_PATH=str(genesis_path), AINCORE_CHAIN_ID=genesis["chain_id"],
                   AINCORE_GUARD_ORIGIN_INIT="0", AINCORE_P2P_LISTEN="0",
                   AINCORE_RPC_BIND="127.0.0.1", TOKIO_WORKER_THREADS="2", RAYON_NUM_THREADS="1")

        def start(datadir, name):
            log = (root / f"{name}.log").open("x")
            handles.append(log)
            command = [str(binary), "--port", str(port), "--rpc-port", str(rpc_port),
                       "--datadir", str(datadir)]
            if args.lab_history:
                command.extend(["--bootnodes", "/ip4/192.168.18.202/tcp/9501,"
                                "/ip4/192.168.18.202/tcp/9502,/ip4/192.168.18.66/tcp/9503,"
                                "/ip4/192.168.18.66/tcp/9504"])
            child = subprocess.Popen(command, cwd=root, env=env,
                                     stdout=log, stderr=subprocess.STDOUT)
            return child

        def capture(child, name):
            if reference_height is not None:
                deadline = time.monotonic() + 600
                while int(request(rpc_port, "aincore_getStatus")["latest_height"]) < reference_height:
                    if child.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("observer catch-up failed or timed out")
                    time.sleep(3)
            # The process under test owns this new log. Its startup identity is
            # available even while replay holds the consensus lock; never use
            # arbitrary remote log text or substitute an unknown/null identity.
            matches = re.findall(r"AINCORE node ([0-9a-f]{64}) running on port ([0-9]+)",
                                 (root / f"{name}.log").read_text(errors="replace"))
            if len(matches) != 1 or int(matches[0][1]) != port:
                raise RuntimeError("missing or ambiguous local child startup identity")
            value = snapshot(rpc_port, genesis, reference_height, matches[0][0])
            if reference is not None and value["history"] != reference:
                raise RuntimeError("observer certified history differs from reference")
            return value

        def stop(child, name):
            child.send_signal(signal.SIGTERM)
            code = child.wait(timeout=60)
            log = (root / f"{name}.log").read_text(errors="replace")
            if code != 0 or "storage flushed to disk" not in log or "storage flush failed" in log:
                raise RuntimeError(f"{name} shutdown failed: exit {code}")
            report["steps"].append({"step": name + "_shutdown", "exit_code": code})

        data = root / "original"
        data.mkdir(mode=0o700)
        process = start(data, "original")
        wait_ready(process, rpc_port, time.monotonic() + 180)
        before = capture(process, "original")
        report["before"] = before
        backup_cmd = ["bash", str(Path(__file__).parent / "backup_node.sh"),
                      "--datadir", str(data), "--port", str(port), "--not-a-validator",
                      "--assume-stopped", "--genesis", str(genesis_path)]
        live_out = root / "refused-live-backup"
        busy = subprocess.run(backup_cmd + ["--out-dir", str(live_out)], capture_output=True,
                              text=True, timeout=30)
        (root / "live-backup.log").write_text(busy.stdout + busy.stderr)
        if busy.returncode != 3 or list(live_out.glob("*.tar.gz")):
            raise RuntimeError("active RocksDB was not rejected before archive creation")
        report["steps"].append({"step": "live_lock_refused", "exit_code": busy.returncode})
        stop(process, "original")
        process = None
        db_name = f"validator_{port}.db"
        original_files = files(data / db_name)
        backups = root / "backups"
        stopped = subprocess.run(backup_cmd + ["--out-dir", str(backups)], capture_output=True,
                                 text=True, timeout=60)
        (root / "stopped-backup.log").write_text(stopped.stdout + stopped.stderr)
        if stopped.returncode != 0:
            raise RuntimeError(f"stopped backup failed: {stopped.returncode}")
        archives = list(backups.glob("*.tar.gz"))
        if len(archives) != 1:
            raise RuntimeError("expected exactly one archive")
        restored = root / "restored"
        restored_genesis = root / "restored-genesis.json"
        restore = subprocess.run([
            "bash", str(Path(__file__).parent / "restore_node.sh"), "--backup", str(archives[0]),
            "--datadir", str(restored), "--port", str(port), "--not-a-validator",
            "--genesis-out", str(restored_genesis)], capture_output=True, text=True, timeout=60)
        (root / "restore.log").write_text(restore.stdout + restore.stderr)
        if restore.returncode != 0 or (restored / "node.key").exists():
            raise RuntimeError("restore failed or copied identity")
        if files(restored / db_name) != original_files or files(data / db_name) != original_files:
            raise RuntimeError("database bytes changed across backup/restore")
        if sha256(restored_genesis) != report["genesis_sha256"]:
            raise RuntimeError("restored genesis differs")
        report["steps"].append({"step": "stopped_backup_restore", "database_files": len(original_files),
                                "archive_sha256": sha256(archives[0]), "key_not_restored": True})
        env["AINCORE_GENESIS_PATH"] = str(restored_genesis)
        process = start(restored, "restored")
        wait_ready(process, rpc_port, time.monotonic() + 180)
        after = capture(process, "restored")
        report["after"] = after
        if before["node_id"] == after["node_id"]:
            raise RuntimeError("restore reused observer identity")
        fields = ("chain_id", "history", "receipt", "nonce", "balance") if args.lab_history else (
            "chain_id", "status", "balances")
        if any(before[key] != after[key] for key in fields):
            raise RuntimeError("restored state differs")
        if args.lab_history and after["certified_tip"] < before["certified_tip"]:
            raise RuntimeError("restored certified tip regressed")
        stop(process, "restored")
        process = None
        if sha256(binary) != report["binary_sha256"] or sha256(genesis_path) != report["genesis_sha256"]:
            raise RuntimeError("input identity changed")
        report.update(passed=True, stage="complete")
    except Exception as error:
        report.update(stage="failed", error=f"{type(error).__name__}: {error}")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            report.update(passed=False, forced_cleanup=True)
        for handle in handles:
            handle.close()
        report["finished_at"] = time.time()
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lab-history", action="store_true",
                        help="Pi-only: sync from the pinned October 20 disposable lab")
    raise SystemExit(run(parser.parse_args()))
