#!/usr/bin/env python3
"""Fail closed on missing, skipped or failing release witnesses. No live operations."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/release_security_witnesses.json"
PACKAGES = {"chain_sync", "consensus", "executor"}
NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)+")


def run(command, timeout=1800):
    record = {"command": command, "timeout": False}
    try:
        process = subprocess.Popen(
            command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", start_new_session=True,
            env={**os.environ, "CARGO_TERM_COLOR": "never"},
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the cargo process group, including test/compiler children.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            record["timeout"] = True
        record.update(returncode=process.returncode, stdout=stdout, stderr=stderr)
    except OSError as error:
        record.update(returncode=-1, stdout="", stderr=str(error))
    return record


def successful(record):
    return record["returncode"] == 0 and not record["timeout"]


def validate_manifest(manifest):
    if (not isinstance(manifest, dict) or manifest.get("version") != 1
            or not isinstance(manifest.get("packages"), dict)
            or set(manifest["packages"]) != PACKAGES):
        raise ValueError("Manifest must classify all three critical packages")
    for package, policy in manifest["packages"].items():
        if not isinstance(policy, dict):
            raise ValueError(f"{package}: policy must be an object")
        required = policy.get("required")
        excluded = policy.get("excluded_ignored")
        if not isinstance(required, list) or not required or not isinstance(excluded, dict):
            raise ValueError(f"{package}: nonempty required list and exclusion map needed")
        if any(not isinstance(n, str) or not NAME.fullmatch(n) for n in required):
            raise ValueError(f"{package}: invalid required test name")
        if len(required) != len(set(required)) or set(required) & set(excluded):
            raise ValueError(f"{package}: duplicate or overlapping classification")
        if any(not NAME.fullmatch(n) or not isinstance(reason, str) or not reason.strip()
               for n, reason in excluded.items()):
            raise ValueError(f"{package}: exclusion needs a test name and reason")


def inventory(record):
    if not successful(record):
        raise ValueError("Test inventory command failed or timed out")
    names = re.findall(r"^([^\s]+): test$", record["stdout"], re.MULTILINE)
    totals = re.findall(r"^(\d+) tests?, (\d+) benchmarks?$", record["stdout"], re.MULTILINE)
    if len(totals) != 1 or int(totals[0][0]) != len(names) or len(set(names)) != len(names):
        raise ValueError("Missing, duplicate or inconsistent libtest inventory")
    return set(names)


def one_pass(record, name):
    summaries = re.findall(
        r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
        record["stdout"], re.MULTILINE,
    )
    return (successful(record) and summaries == [("ok", "1", "0", "0")]
            and f"test {name} ... ok" in record["stdout"].splitlines())


def evaluate(manifest, execute=run, offline=False):
    validate_manifest(manifest)
    report = {"manifest": manifest, "commands": [], "errors": [], "witnesses": []}

    def capture(command):
        result = execute(command)
        report["commands"].append(result)
        return result

    for package, policy in manifest["packages"].items():
        base = ["cargo", "test", "--locked"] + (["--offline"] if offline else [])
        base += ["-p", package, "--lib"]
        try:
            all_tests = inventory(capture(base + ["--", "--list"]))
            ignored = inventory(capture(base + ["--", "--list", "--ignored"]))
            required, excluded = set(policy["required"]), set(policy["excluded_ignored"])
            checks = {
                "missing required tests": required - all_tests,
                "unclassified ignored tests": ignored - required - excluded,
                "stale exclusions": excluded - ignored,
                "inconsistent ignored inventory": ignored - all_tests,
            }
            for label, names in checks.items():
                if names:
                    report["errors"].append(f"{package}: {label}: {sorted(names)}")
        except ValueError as error:
            report["errors"].append(f"{package}: {error}")
            continue
        # Continue after a red witness so the report retains every blocker.
        for name in policy["required"]:
            if name not in all_tests:
                continue
            result = capture(base + [name, "--", "--exact", "--include-ignored",
                                     "--test-threads=1", "--format=pretty"])
            passed = one_pass(result, name)
            report["witnesses"].append({"package": package, "name": name, "passed": passed})
            if not passed:
                report["errors"].append(f"{package}: witness did not pass exactly once: {name}")
    report["passed"] = not report["errors"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=ROOT / "target/release-security-gate.json")
    args = parser.parse_args()
    metadata = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_note": "HEAD alone does not identify a dirty worktree's compiled contents.",
        "environment": [run(command, timeout=30) for command in (
            ["rustc", "--version"], ["cargo", "--version"],
            ["git", "rev-parse", "HEAD"], ["git", "status", "--porcelain"],
        )],
    }
    try:
        report = evaluate(json.loads(MANIFEST.read_text()), offline=args.offline)
    except (ValueError, OSError, TypeError) as error:
        report = {"passed": False, "errors": [str(error)]}
    if not all(successful(item) for item in metadata["environment"]):
        report["passed"] = False
        report["errors"].append("Could not collect complete source/toolchain metadata")
    report.update(metadata)
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("Release witness gate: " + ("PASS" if report["passed"] else "FAIL"))
    for error in report["errors"]:
        print(error)
    print(f"Report: {args.report}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
