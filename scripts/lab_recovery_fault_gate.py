#!/usr/bin/env python3
"""Recovery/replay/quorum test restricted to the disposable NAS/Pi lab."""
import json
from pathlib import Path
import shlex
import subprocess
import time

from check_two_host_test import NODES, CHAIN, rpc
from isolated_multivalidator_gate import certified_identity
from lab_transaction_gate import rejection
from recover_two_host_lab import launch_args, UNIT_PREFIX, BINARY_SHA

TX_HASH = "0af9daa4bafa15cdee8be766bb7c3219f7fd18bb92fe0869df2d618df8dde86f"
RECIPIENT = "37d9a6e9265914f530e5381d36af5d0183927d7c6b9c10f8dc0630f861540ae7"


def unit(index, action):
    if index not in (2, 3) or action not in ("stop", "start"):
        raise ValueError("only owned Pi recovery units may be controlled")
    name = f"{UNIT_PREFIX}-{index}.service"
    args = ["systemctl", "--user", action, name]
    if action == "start":
        state = subprocess.check_output(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", NODES[index][0],
             shlex.join(["systemctl", "--user", "show", name, "-p", "LoadState", "--value"])],
            text=True, timeout=20).strip()
        # Successful transient services can be garbage-collected after stop.
        if state == "not-found":
            args = launch_args(index)
        else:
            status = stopped_status(index)
            if status.get("SubState") == "running":
                return
            args = ["systemctl", "--user", "restart", name]
    else:
        # RemainAfterExit retains exit evidence. SIGTERM ends the owned main
        # process without garbage-collecting its transient unit metadata.
        args = ["systemctl", "--user", "kill", "--kill-whom=main", "--signal=SIGTERM", name]
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                    NODES[index][0], shlex.join(args)],
                   check=True, timeout=130)
    if action == "stop":
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            status = stopped_status(index)
            if status.get("MainPID") == "0" and status.get("SubState") in ("exited", "failed", "dead"):
                return
            time.sleep(1)
        raise TimeoutError(f"lab validator {index} did not stop")


def heights(indices):
    return [certified_identity(rpc(NODES[i], "aincore_getQuorumCert"), CHAIN)[0]
            for i in indices]


def stopped_status(index):
    command = shlex.join(["systemctl", "--user", "show",
                          f"{UNIT_PREFIX}-{index}.service",
                          "-p", "Result", "-p", "ExecMainStatus", "-p", "ExecMainCode",
                          "-p", "MainPID", "-p", "SubState"])
    output = subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", NODES[index][0], command],
        text=True, timeout=20)
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def clean_stop(status):
    return (status.get("Result") == "success" and status.get("ExecMainStatus") == "0"
            and status.get("ExecMainCode") == "1")


def progress(indices, minimum):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            values = heights(indices)
        except subprocess.CalledProcessError as error:
            # Only curl connection refusal is expected during RPC startup.
            # Bad certificates, JSON errors and SSH failures remain failures.
            if error.returncode != 7:
                raise
            time.sleep(5)
            continue
        if min(values) >= minimum:
            return values
        time.sleep(5)
    raise TimeoutError(f"no certified progress to {minimum}")


def main():
    report = {"passed": False, "chain_id": CHAIN, "scope": "lab only; node RPC QC verification",
              "candidate_binary_sha256": BINARY_SHA}
    restore = set()
    try:
        for i, node in enumerate(NODES):
            pid = subprocess.check_output(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", node[0],
                 shlex.join(["systemctl", "--user", "show", f"{UNIT_PREFIX}-{i}.service",
                             "-p", "MainPID", "--value"])], text=True, timeout=20).strip()
            if not pid.isdecimal() or int(pid) == 0:
                raise ValueError(f"candidate validator {i} is not running")
            actual = subprocess.check_output(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", node[0],
                 shlex.join(["sha256sum", f"/proc/{pid}/exe"])], text=True, timeout=20).split()[0]
            if actual != BINARY_SHA[node[0]]:
                raise ValueError(f"validator {i} is not running the candidate binary")
        tx = rpc(NODES[0], "aincore_getTransaction", [TX_HASH])
        if tx["chain_id"] != CHAIN:
            raise ValueError("wrong chain")
        old = rpc(NODES[0], "aincore_getTransactionReceipt", [TX_HASH])
        if old["block_height"] != 1263 or old["execution_receipt"]["status"] != "success":
            raise ValueError("historical execution missing after restart")
        balance = int(rpc(NODES[0], "aincore_getBalance", [RECIPIENT])["move_balance"])
        nonce = rpc(NODES[0], "aincore_getAccountNonce", [tx["sender"]])["sequence_number"]
        payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                              "method": "aincore_sendTransaction", "params": [tx]})
        command = shlex.join(["curl", "-fsS", "--max-time", "8",
                             "http://127.0.0.1:8501/rpc", "-H",
                             "Content-Type: application/json", "-d", payload])
        reply = json.loads(subprocess.check_output(
            ["ssh", "-o", "BatchMode=yes", NODES[0][0], command], text=True, timeout=20))
        report["replay_after_restart"] = rejection(reply, ("duplicate transaction", "nonce", "sequence"))
        start = heights(range(4))
        progressed = progress(range(4), max(start) + 3)
        for node in NODES:
            if int(rpc(node, "aincore_getBalance", [RECIPIENT])["move_balance"]) != balance:
                raise ValueError("recipient balance changed/diverged after replay")
            if rpc(node, "aincore_getAccountNonce", [tx["sender"]])["sequence_number"] != nonce:
                raise ValueError("sender nonce changed/diverged after replay")
        report["post_replay_heights"] = progressed
        print("Replay after restart PASS; removing two lab validators", flush=True)
        for i in (2, 3):
            restore.add(i)
            unit(i, "stop")
            report.setdefault("shutdown_status", {})[str(i)] = stopped_status(i)
        time.sleep(30)
        before = heights((0, 1))
        time.sleep(30)
        after = heights((0, 1))
        if before != after:
            raise ValueError(f"certified progress without quorum: {before} -> {after}")
        report["no_quorum"] = {"before": before, "after": after, "observation_seconds": 30,
                               "settle_seconds": 30}
        for i in sorted(restore):
            unit(i, "start")
        time.sleep(5)
        healed = progress(range(4), max(after + progressed) + 3)
        common = min(healed)
        checked = sorted({1263, min(after), common})
        for height in checked:
            identities = [certified_identity(rpc(n, "aincore_getQuorumCert", [height]), CHAIN)
                          for n in NODES]
            if any(value != identities[0] or value[0] != height for value in identities):
                raise ValueError(f"conflicting certificate at {height}")
        report.update(healed_heights=healed, checked_heights=checked)
        restore.clear()
        if not all(clean_stop(s) for s in report["shutdown_status"].values()):
            raise RuntimeError("recovery succeeded, but a validator did not exit cleanly")
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
    finally:
        for i in sorted(restore):
            try:
                unit(i, "start")
            except Exception as error:
                report["passed"] = False
                report.setdefault("restore_errors", []).append(str(error))
        output = Path("/tmp") / f"aincore-recovery-fault-{time.time_ns()}.json"
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report_path": str(output), **report}, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
