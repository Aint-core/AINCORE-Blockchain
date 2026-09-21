import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "release_security_gate", Path(__file__).resolve().parents[1] / "release_security_gate.py"
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def result(command, stdout, returncode=0, timeout=False):
    return dict(command=command, stdout=stdout, stderr="", returncode=returncode, timeout=timeout)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(gate.MANIFEST.read_text())
        self.calls = []

    def fake(self, command):
        self.calls.append(command)
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
        self.assertEqual(len(report["witnesses"]), 14)
        for command in self.calls:
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
            if "--list" not in command:
                for flag in ("--exact", "--include-ignored", "--test-threads=1"):
                    self.assertIn(flag, command)

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
            if "--list" not in command:
                record["returncode"] = 101
            return record
        report = gate.evaluate(self.manifest, fail_tests)
        self.assertFalse(report["passed"])
        self.assertEqual(len(report["witnesses"]), 14)
        self.assertEqual(len(report["errors"]), 14)

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


if __name__ == "__main__":
    unittest.main()
