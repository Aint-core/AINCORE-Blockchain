"""Control the smoke gate without compiling or executing a node."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_package_smoke import smoke


class SmokeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / "node").write_bytes(b"fake binary")
        self.genesis = self.root / "fixture.json"
        self.genesis.write_text('{"chain_id":"SMOKE-ONLY"}')

    def test_uses_extraction_as_cwd_without_copying_source_files(self):
        with patch("release_package_smoke.run_case", return_value={"passed": True}) as run:
            self.assertTrue(smoke(self.root, self.genesis)["passed"])
        run.assert_called_once_with(self.root / "node", self.genesis, "SMOKE-ONLY",
                                    self.root, "clean_shutdown")
        self.assertFalse((self.root / "core").exists())

    def test_failed_boot_retained_as_failure(self):
        with patch("release_package_smoke.run_case", return_value={"passed": False}):
            self.assertFalse(smoke(self.root, self.genesis)["passed"])
        self.assertFalse(json.loads((self.root / "release-smoke.json").read_text())["passed"])

    def test_exception_retained_as_failure(self):
        with patch("release_package_smoke.run_case", side_effect=RuntimeError("fixture")):
            report = smoke(self.root, self.genesis)
        self.assertFalse(report["passed"])
        self.assertEqual(report["error"], "fixture")

    def test_changed_binary_is_not_pass(self):
        def change(*_args):
            (self.root / "node").write_bytes(b"different binary")
            return {"passed": True}
        with patch("release_package_smoke.run_case", side_effect=change):
            self.assertFalse(smoke(self.root, self.genesis)["passed"])

    def test_previous_result_never_overwritten(self):
        result = self.root / "release-smoke.json"
        result.write_text("retain failure")
        with patch("release_package_smoke.run_case") as run:
            with self.assertRaisesRegex(ValueError, "overwrite"):
                smoke(self.root, self.genesis)
        self.assertEqual(result.read_text(), "retain failure")
        run.assert_not_called()

    def test_previous_data_never_reused(self):
        (self.root / "clean_shutdown").mkdir()
        with self.assertRaisesRegex(ValueError, "overwrite"):
            smoke(self.root, self.genesis)


if __name__ == "__main__":
    unittest.main()
