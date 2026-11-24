import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "release_security_gate", Path(__file__).resolve().parents[1] / "release_security_gate.py"
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def result(command, stdout, returncode=0, timeout=False):
    return dict(command=command, stdout=stdout, stderr="", returncode=returncode, timeout=timeout)


class GateTests(unittest.TestCase):
    def required_count(self):
        return sum(len(p["required"]) for p in self.manifest["packages"].values())

    def setUp(self):
        self.manifest = json.loads(gate.MANIFEST.read_text())
        self.calls = []

    def fake(self, command):
        self.calls.append(command)
        if command[1] == "build":
            return result(command, "")
        package = command[command.index("-p") + 1]
        policy = self.manifest["packages"][package]
        if "--list" in command:
            names = list(policy["excluded_ignored"])
            if "--ignored" not in command:
                names += policy["required"]
            output = "".join(f"{name}: test\n" for name in names)
            return result(command, output + f"\n{len(names)} tests, 0 benchmarks\n")
        name = command[command.index("--lib") + 1]
        return result(command, f"test {name} ... ok\n"
                      "test result: ok. 1 passed; 0 failed; 0 ignored; 8 filtered out;\n")

    def test_exact_witnesses_and_offline_locked(self):
        report = gate.evaluate(self.manifest, self.fake, offline=True)
        self.assertTrue(report["passed"])
        self.assertEqual(len(report["witnesses"]), self.required_count())
        for command in self.calls:
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
            if command[1] == "build":
                self.assertEqual(command, ["cargo", "build", "--locked", "--offline",
                                          "-p", "executor", "--lib", "--no-default-features"])
            elif "--list" not in command:
                for flag in ("--exact", "--include-ignored", "--test-threads=1"):
                    self.assertIn(flag, command)

    def test_normal_build_failure_is_not_masked_by_green_tests(self):
        for code, timed_out in ((101, False), (-9, True)):
            def fail_build(command):
                record = self.fake(command)
                if command[1] == "build":
                    record.update(returncode=code, timeout=timed_out)
                return record

            with self.subTest(code=code, timeout=timed_out):
                report = gate.evaluate(self.manifest, fail_build)
                self.assertFalse(report["passed"])
                self.assertEqual(report["errors"],
                                 ["executor: normal library build failed or timed out"])
                self.assertEqual(len(report["witnesses"]), self.required_count())
                self.assertTrue(all(w["passed"] for w in report["witnesses"]))

    def test_network_deadlines_are_required_and_fail_closed(self):
        required = self.manifest["packages"]["network"]["required"]
        self.assertIn("tests::full_queues_timeout_without_enqueuing_expired_work", required)
        self.assertIn("tests::queue_admission_does_not_restart_reply_deadline", required)
        self.assertIn("tests::queued_requests_succeed_within_shared_deadline", required)
        for name in required:
            def failed_network(command):
                record = self.fake(command)
                if "network" in command and name in command:
                    record.update(returncode=101, stdout="test result: FAILED. 0 passed; 1 failed;")
                return record

            with self.subTest(witness=name):
                report = gate.evaluate(self.manifest, failed_network)
                self.assertFalse(report["passed"])
                self.assertEqual(sum(not w["passed"] for w in report["witnesses"]), 1)

    def test_missing_name_and_new_ignored_fail_closed(self):
        policy = copy.deepcopy(self.manifest)
        policy["packages"]["executor"]["required"][0] = "tests::renamed_or_missing"
        self.assertFalse(gate.evaluate(policy, self.fake)["passed"])
        self.manifest["packages"]["executor"]["excluded_ignored"]["tests::new_ignored"] = "new"
        report = gate.evaluate(policy, self.fake)
        self.assertTrue(any("unclassified ignored" in error for error in report["errors"]))

    def test_stale_exclusion_fails(self):
        policy = copy.deepcopy(self.manifest)
        policy["packages"]["executor"]["excluded_ignored"]["tests::gone"] = "not there"
        self.assertFalse(gate.evaluate(policy, self.fake)["passed"])

    def test_missing_stack_witness_is_not_masked_by_passing_vm_tests(self):
        name = "gas::tests::a_value_at_the_depth_bound_fits_the_vm_stack"
        self.assertIn(name, self.manifest["packages"]["vm_move"]["required"])
        policy = copy.deepcopy(self.manifest)
        # Model the NAS run: other VM tests pass, but this witness is absent.
        self.manifest["packages"]["vm_move"]["required"].remove(name)
        report = gate.evaluate(policy, self.fake)
        self.assertFalse(report["passed"])
        self.assertTrue(any("missing required tests" in error and name in error
                            for error in report["errors"]))
        self.assertTrue(any(w["package"] == "vm_move" and w["passed"]
                            for w in report["witnesses"]))

    def test_zero_match_stack_witness_fails_even_when_inventory_lists_it(self):
        name = "gas::tests::a_value_at_the_depth_bound_fits_the_vm_stack"
        self.assertIn(name, self.manifest["packages"]["vm_move"]["required"])

        def zero_match(command):
            record = self.fake(command)
            if "--list" not in command and name in command:
                record["stdout"] = (
                    "test result: ok. 0 passed; 0 failed; 0 ignored; 9 filtered out;\n"
                )
            return record

        report = gate.evaluate(self.manifest, zero_match)
        self.assertFalse(report["passed"])
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn(name, report["errors"][0])

    def test_zero_tests_ignored_failure_and_timeout_never_pass(self):
        name = "tests::witness"
        for stdout, code, timed_out in (
            ("test result: ok. 0 passed; 0 failed; 0 ignored;", 0, False),
            ("test result: ok. 0 passed; 0 failed; 1 ignored;", 0, False),
            (f"test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;", 101, False),
            (f"test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;", 0, True),
            ("test tests::other ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;", 0, False),
        ):
            with self.subTest(stdout=stdout, code=code, timeout=timed_out):
                self.assertFalse(gate.one_pass(result([], stdout, code, timed_out), name))

    def test_failed_witness_does_not_hide_later_results(self):
        def fail_tests(command):
            record = self.fake(command)
            if command[1] == "test" and "--list" not in command:
                record["returncode"] = 101
            return record
        report = gate.evaluate(self.manifest, fail_tests)
        self.assertFalse(report["passed"])
        self.assertEqual(len(report["witnesses"]), self.required_count())
        self.assertEqual(len(report["errors"]), self.required_count())

    def test_bad_inventory_or_failed_build_never_passes(self):
        for stdout, code in (("", 0), ("2 tests, 0 benchmarks\n", 0),
                             ("0 tests, 0 benchmarks\n", 101),
                             ("tests::a: test\ntests::a: test\n2 tests, 0 benchmarks\n", 0)):
            with self.subTest(stdout=stdout, code=code):
                with self.assertRaises(ValueError):
                    gate.inventory(result([], stdout, code))

    def test_empty_or_ambiguous_manifest_is_rejected(self):
        for modification in ("empty", "duplicate", "overlap", "reason"):
            manifest = copy.deepcopy(self.manifest)
            policy = manifest["packages"]["executor"]
            if modification == "empty":
                policy["required"] = []
            elif modification == "duplicate":
                policy["required"] *= 2
            elif modification == "overlap":
                policy["excluded_ignored"][policy["required"][0]] = "overlap"
            else:
                policy["excluded_ignored"]["tests::excluded"] = " "
            with self.subTest(modification=modification), self.assertRaises(ValueError):
                gate.validate_manifest(manifest)
        with self.assertRaises(ValueError):
            gate.validate_manifest({"version": 1, "packages": {}})
        for manifest in (None, [], {"version": 1, "packages": None}):
            with self.assertRaises(ValueError):
                gate.validate_manifest(manifest)

    def test_real_subprocess_timeout_and_missing_tool(self):
        record = gate.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.1)
        self.assertTrue(record["timeout"])
        self.assertFalse(gate.successful(record))
        self.assertFalse(gate.successful(gate.run(["/not-an-aincore-tool"])))

    def test_checkpoint_precedes_command_and_never_claims_partial_success(self):
        snapshots = []

        def checkpoint(report):
            snapshots.append(copy.deepcopy(report))

        def execute(command):
            self.assertEqual(snapshots[-1]["active_command"], command)
            self.assertFalse(snapshots[-1]["complete"])
            self.assertFalse(snapshots[-1]["passed"])
            return self.fake(command)

        report = gate.evaluate(self.manifest, execute, checkpoint=checkpoint)
        self.assertTrue(report["passed"])
        self.assertTrue(report["complete"])
        self.assertTrue(all(not r["passed"] and not r["complete"] for r in snapshots))
        self.assertEqual(len(snapshots[-1]["witnesses"]), self.required_count())

    def test_checkpoint_failure_prevents_execution(self):
        def checkpoint(report):
            if report["active_command"] is not None:
                raise OSError("disk full")

        with self.assertRaises(OSError):
            gate.evaluate(self.manifest, self.fake, checkpoint=checkpoint)
        self.assertEqual(self.calls, [])

    def test_atomic_replace_failure_retains_previous_valid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            gate.atomic_report(path, {"passed": False, "witnesses": ["first"]})
            before = path.read_bytes()
            with patch.object(gate.os, "replace", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    gate.atomic_report(path, {"passed": True})
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def exercise_main(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts/release_security_witnesses.json").write_text(json.dumps(self.manifest))
            path = root / "report.json"
            git_revisions = 0
            witnesses = 0

            def execute(command, timeout=1800, cwd=None):
                nonlocal git_revisions, witnesses
                self.assertEqual(cwd, root)
                if command[0] == "git":
                    if command[1] == "rev-parse":
                        git_revisions += 1
                        return result(command, "changed\n" if mode == "revision" and git_revisions > 1
                                      else "candidate\n")
                    return result(command, " M Cargo.toml\n" if mode == "dirty" else "")
                if command[0] == "rustc" or command[1] == "--version":
                    return result(command, "version\n", returncode=1 if mode == "metadata" else 0)
                if command[1] == "test" and "--list" not in command:
                    witnesses += 1
                    if mode in ("interrupt", "disk-full") and witnesses == 3:
                        if mode == "interrupt":
                            raise gate.GateInterrupted(signal.SIGTERM)
                        raise OSError("disk full")
                return self.fake(command)

            with patch.object(gate, "run", side_effect=execute), contextlib.redirect_stdout(io.StringIO()):
                code = gate.main(["--source-root", str(root), "--report", str(path), "--offline"])
            report = json.loads(path.read_text())
            self.assertEqual(report["source_root"], str(root))
            self.assertEqual(len(report["runner_sha256"]), 64)
            before = path.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                gate.main(["--source-root", str(root), "--report", str(path)])
            self.assertEqual(before, path.read_bytes())
            return code, report

    def test_main_complete_report_and_refusal_to_overwrite(self):
        code, report = self.exercise_main("success")
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"] and report["passed"])
        self.assertEqual(len(report["witnesses"]), self.required_count())
        self.assertEqual(len(report["manifest_sha256"]), 64)

    def test_main_interruption_and_io_error_preserve_completed_witnesses(self):
        for mode, expected in (("interrupt", 143), ("disk-full", 1)):
            with self.subTest(mode=mode):
                code, report = self.exercise_main(mode)
                self.assertEqual(code, expected)
                self.assertFalse(report["passed"])
                self.assertFalse(report["complete"])
                self.assertEqual(len(report["witnesses"]), 2)
                self.assertTrue(all(w["passed"] for w in report["witnesses"]))
                self.assertIsNotNone(report["active_command"])
                self.assertTrue(report["errors"])

    def test_main_dirty_changed_and_unidentified_source_cannot_pass(self):
        for mode in ("dirty", "revision", "metadata"):
            with self.subTest(mode=mode):
                code, report = self.exercise_main(mode)
                self.assertEqual(code, 1)
                self.assertFalse(report["passed"])
                self.assertTrue(report["errors"])
                if mode != "revision":
                    self.assertEqual(report["witnesses"], [])

    @unittest.skipUnless(sys.platform == "linux", "Linux process-group termination probe")
    def test_real_signal_kills_child_group_and_leaves_incomplete_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts/release_security_witnesses.json").write_text(json.dumps(self.manifest))
            tools = root / "bin"
            tools.mkdir()
            tool_body = (f"#!{sys.executable}\n"
                         "import os, pathlib, subprocess, sys, time\n"
                         "if pathlib.Path(sys.argv[0]).name == 'cargo' and sys.argv[1] == 'build':\n"
                         "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                         "    pathlib.Path('child.pid').write_text(str(child.pid))\n"
                         "    pathlib.Path('cargo.pid').write_text(str(os.getpid()))\n"
                         "    time.sleep(60)\n"
                         "elif sys.argv[1] != 'status':\n"
                         "    print('fixture-version')\n")
            for name in ("cargo", "git", "rustc"):
                tool = tools / name
                tool.write_text(tool_body)
                tool.chmod(0o755)
            path = root / "report.json"
            process = subprocess.Popen(
                [sys.executable, "-B", str(Path(gate.__file__)), "--source-root", str(root),
                 "--report", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}, text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while not (root / "cargo.pid").exists() and process.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("fixture child did not start")
                    time.sleep(0.02)
                self.assertIsNone(process.poll())
                process.send_signal(signal.SIGTERM)
                _, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 143, stderr)
                report = json.loads(path.read_text())
                self.assertFalse(report["passed"] or report["complete"])
                self.assertIn("build", report["active_command"])
                for name in ("cargo.pid", "child.pid"):
                    pid = int((root / name).read_text())
                    stat = Path(f"/proc/{pid}/stat")
                    if stat.exists():
                        # Orphaned descendants may await PID 1 reaping, but cannot run.
                        self.assertEqual(stat.read_text().split(")", 1)[1].split()[0], "Z")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
                for name in ("cargo.pid", "child.pid"):
                    if (root / name).exists():
                        try:
                            os.kill(int((root / name).read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
