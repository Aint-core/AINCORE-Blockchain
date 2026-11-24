#!/usr/bin/env python3
"""Fail closed on missing, skipped or failing release witnesses. No live operations."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/release_security_witnesses.json"
PACKAGES = {
    "blockchain", "chain_sync", "consensus", "executor", "node", "state_commit", "storage",
    "vm_move", "network", "mempool",
}
NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)+")


class GateInterrupted(BaseException):
    def __init__(self, signum):
        self.signum = signum
        super().__init__(f"interrupted by signal {signum}")


def stop_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return process.communicate()


def run(command, timeout=1800, cwd=None):
    record = {"command": command, "timeout": False}
    try:
        process = subprocess.Popen(
            command, cwd=ROOT if cwd is None else cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", start_new_session=True,
            env={**os.environ, "CARGO_TERM_COLOR": "never"},
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the cargo process group, including test/compiler children.
            stdout, stderr = stop_process_group(process)
            record["timeout"] = True
        except BaseException:
            # The child session must not survive a canceled gate.
            stop_process_group(process)
            raise
        record.update(returncode=process.returncode, stdout=stdout, stderr=stderr)
    except OSError as error:
        record.update(returncode=-1, stdout="", stderr=str(error))
    return record


def atomic_report(path, report):
    """Replace one snapshot only after flushing it; retain the old one on error."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as output:
            temporary = Path(output.name)
            json.dump(report, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def successful(record):
    return record["returncode"] == 0 and not record["timeout"]


def validate_manifest(manifest):
    if (not isinstance(manifest, dict) or manifest.get("version") != 1
            or not isinstance(manifest.get("packages"), dict)
            or set(manifest["packages"]) != PACKAGES):
        raise ValueError("Manifest must classify every critical package")
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


def evaluate(manifest, execute=run, offline=False, checkpoint=None):
    validate_manifest(manifest)
    report = {"manifest": manifest, "commands": [], "errors": [], "witnesses": [],
              "complete": False, "passed": False, "active_command": None,
              "required_count": sum(len(p["required"]) for p in manifest["packages"].values())}

    def publish():
        if checkpoint is not None:
            checkpoint(report)

    publish()

    def capture(command):
        report["active_command"] = command
        publish()
        result = execute(command)
        report["commands"].append(result)
        report["active_command"] = None
        publish()
        return result

    # Unit tests and workspace feature unification can hide cfg(test) helpers
    # accidentally called by production code. Build this library in isolation.
    normal_build = ["cargo", "build", "--locked"] + (["--offline"] if offline else [])
    normal_build += ["-p", "executor", "--lib", "--no-default-features"]
    if not successful(capture(normal_build)):
        report["errors"].append("executor: normal library build failed or timed out")

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
            publish()
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
            publish()
    if len(report["witnesses"]) != report["required_count"]:
        report["errors"].append("Not all required witnesses completed")
    report["complete"] = True
    report["passed"] = not report["errors"]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, help="New report path; never overwrite a prior run")
    parser.add_argument("--source-root", type=Path, default=ROOT,
                        help="Isolated candidate root; defaults to this script's checkout")
    args = parser.parse_args(argv)
    root = args.source_root.resolve()
    manifest_path = root / "scripts/release_security_witnesses.json"
    path = args.report or root / "target/release-security-gate.json"
    metadata = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_root": str(root),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_note": "HEAD alone does not identify a dirty worktree's compiled contents.",
        "environment": [],
    }
    latest = {"passed": False, "complete": False, "errors": [], "commands": [],
              "witnesses": [], "active_command": None}
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x") as output:
            json.dump({**latest, **metadata}, output)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        parser.error(f"Refusing to overwrite existing report: {path}")

    def checkpoint(report):
        nonlocal latest
        latest = {**report, **metadata}
        latest["updated_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        atomic_report(path, latest)
        if report["active_command"] is not None:
            print(f"Witnesses {len(report['witnesses'])}/{report['required_count']}: "
                  + " ".join(report["active_command"]), flush=True)

    def interrupt(signum, frame):
        raise GateInterrupted(signum)

    handlers = {s: signal.signal(s, interrupt) for s in
                (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    code = 1
    try:
        manifest_bytes = manifest_path.read_bytes()
        metadata["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        metadata["environment"] = [run(command, timeout=30, cwd=root) for command in (
            ["rustc", "--version"], ["cargo", "--version"],
            ["git", "rev-parse", "HEAD"], ["git", "status", "--porcelain"],
        )]
        if not all(successful(item) for item in metadata["environment"]):
            raise ValueError("Could not collect complete source/toolchain metadata")
        if metadata["environment"][-1]["stdout"].strip():
            raise ValueError("Refusing a dirty candidate source tree")
        report = evaluate(json.loads(manifest_bytes),
                          execute=lambda command: run(command, cwd=root),
                          offline=args.offline, checkpoint=checkpoint)
        after = [run(command, timeout=30, cwd=root) for command in (
            ["git", "rev-parse", "HEAD"], ["git", "status", "--porcelain"],
        )]
        metadata["source_after"] = after
        if (not all(successful(item) for item in after)
                or after[0]["stdout"] != metadata["environment"][-2]["stdout"]
                or after[1]["stdout"].strip()
                or manifest_path.read_bytes() != manifest_bytes):
            report["errors"].append("Source changed during the gate; result is not attributable")
            report["passed"] = False
        code = 0 if report["passed"] else 1
    except (ValueError, OSError, TypeError, GateInterrupted, KeyboardInterrupt) as error:
        report = {**latest, "complete": False, "passed": False,
                  "errors": [*latest["errors"], str(error) or "interrupted"]}
        code = 128 + error.signum if isinstance(error, GateInterrupted) else 1
        if isinstance(error, KeyboardInterrupt):
            code = 130
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    report.update(metadata)
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    atomic_report(path, report)
    print("Release witness gate: " + ("PASS" if report["passed"] else "FAIL"))
    for error in report["errors"]:
        print(error)
    print(f"Report: {path}")
    return code


if __name__ == "__main__":
    sys.exit(main())
