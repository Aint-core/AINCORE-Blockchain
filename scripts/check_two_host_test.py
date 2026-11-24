#!/usr/bin/env python3
"""Read-only, sampled steady-state checks of the named disposable NAS/Pi lab.

This is not a transaction workload, an independent QC verifier or G6 clearance.
Fault-injection windows deliberately do not satisfy steady-state liveness.
"""
import argparse
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from isolated_multivalidator_gate import certified_identity

CHAIN = "AINCORE-LAB-646F5C8B4FEBB6A2"
NODES = [("alpha@192.168.18.202", 8501), ("alpha@192.168.18.202", 8502),
         ("pi@192.168.18.66", 8503), ("pi@192.168.18.66", 8504)]


def rpc(node, method, params=None):
    host, port = node
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params or []})
    command = shlex.join(["curl", "-fsS", "--max-time", "8",
                         f"http://127.0.0.1:{port}/rpc",
                         "-H", "Content-Type: application/json", "-d", payload])
    result = json.loads(subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, command],
        text=True, timeout=20))
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--recovery-height", type=int, default=0)
    parser.add_argument("--samples", type=int, default=2)
    parser.add_argument("--interval", type=float, default=20)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.samples < 2 or not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("at least two samples and a finite positive interval are required")
    if args.recovery_height < 0:
        parser.error("recovery height must be nonnegative")
    report = {"passed": False, "stage": "sampling", "chain_id": CHAIN,
              "scope": "sampled two-host steady state; node RPC verifies QC, not independent verifier; "
                       "no transaction load, independent operators or continuous-uptime claim",
              "started_at": time.time(), "requested_samples": args.samples,
              "interval_seconds": args.interval, "nodes": NODES, "samples": []}
    output = None
    observed = {}
    code = 1
    try:
        # Refuse to overwrite prior evidence, including a failed run.
        if args.report:
            output = args.report.open("x")
            persist(output, report)
        for index in range(args.samples):
            if index:
                time.sleep(args.interval)
            sample = {"started_at": time.time(), "complete": False}
            report["samples"].append(sample)
            started = time.monotonic()
            status = [rpc(node, "aincore_getStatus") for node in NODES]
            sample["status"] = status
            for value in status:
                if int(value["latest_height"]) < 1 or int(value["finalized_round"]) < 1:
                    raise RuntimeError("no finalized progress")
                if value["committee_sessions"] != len(NODES) - 1:
                    raise RuntimeError("missing committee session")
            latest = [certified_identity(rpc(node, "aincore_getQuorumCert"), CHAIN)[0]
                      for node in NODES]
            sample["certified_heights"] = latest
            common = min(latest)
            if common < 1:
                raise RuntimeError("no certified blocks")
            if args.recovery_height and common <= args.recovery_height:
                raise RuntimeError("has not advanced beyond pre-restart height")
            previous = report["samples"][index - 1] if index else None
            if previous:
                for a, b, old_qc, new_qc in zip(previous["status"], status,
                                                previous["certified_heights"], latest):
                    if int(b["latest_height"]) <= int(a["latest_height"]):
                        raise RuntimeError("height did not advance")
                    if int(b["finalized_round"]) <= int(a["finalized_round"]):
                        raise RuntimeError("finality did not advance")
                    if new_qc <= old_qc:
                        raise RuntimeError("certified height did not advance")
            # Bounded samples, including the prior common tip to detect rewriting
            # agreed history. Never imply that every intervening height was checked.
            heights = set(range(1, min(common, 18) + 1)) | {common}
            if previous:
                heights.add(min(previous["certified_heights"]))
            if args.recovery_height:
                heights.update([args.recovery_height, args.recovery_height + 1])
            sample["checked_commitments"] = {}
            for height in sorted(heights):
                identities = [certified_identity(rpc(node, "aincore_getQuorumCert", [height]), CHAIN)
                              for node in NODES]
                if any(value != identities[0] or value[0] != height for value in identities):
                    raise RuntimeError(f"certified commitments differ at {height}")
                if observed.setdefault(height, identities[0]) != identities[0]:
                    raise RuntimeError(f"previously certified history changed at {height}")
                sample["checked_commitments"][str(height)] = identities[0][1]
            sample.update(complete=True, finished_at=time.time(),
                          elapsed_seconds=time.monotonic() - started)
            if output:
                persist(output, report)
        report.update(passed=True, stage="complete",
                      before=report["samples"][0]["status"], after=report["samples"][-1]["status"],
                      checked_certified_heights=sorted(observed))
        code = 0
    except (Exception, KeyboardInterrupt) as error:
        report.update(stage="failed", error=f"{type(error).__name__}: {error}")
    finally:
        report["finished_at"] = time.time()
        if output:
            try:
                persist(output, report)
            finally:
                output.close()
    print(json.dumps(report, indent=2))
    return code


def persist(output, report):
    output.seek(0)
    json.dump(report, output, indent=2)
    output.write("\n")
    output.truncate()
    output.flush()
    os.fsync(output.fileno())


if __name__ == "__main__":
    sys.exit(main())
