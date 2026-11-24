"""Controls for the process-exit probe's verdicts; no node is launched here."""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "node_exit_probe", Path(__file__).resolve().parents[1] / "node_exit_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ExitProbeTests(unittest.TestCase):
    def test_error_log_with_success_exit_is_not_a_pass(self):
        self.assertFalse(probe.verdict("p2p_busy", 0, "Failed to start P2P"))
        self.assertFalse(probe.verdict("flush_denied", 0, "storage flush failed"))

    def test_expected_failure_needs_its_specific_cause(self):
        for scenario in ("p2p_busy", "flush_denied"):
            self.assertFalse(probe.verdict(scenario, 1, "unrelated startup failure"))
        self.assertTrue(probe.verdict("p2p_busy", 1, "Failed to start P2P"))
        self.assertTrue(probe.verdict("flush_denied", 1, "storage flush failed"))

    def test_forced_cleanup_and_abort_are_not_clean_failure(self):
        for scenario, log in (("p2p_busy", "Failed to start P2P"),
                              ("flush_denied", "storage flush failed")):
            self.assertFalse(probe.verdict(scenario, -6, log))
            self.assertFalse(probe.verdict(scenario, 1, log, forced_cleanup=True))

    def test_successful_shutdown_needs_the_flush_confirmation(self):
        self.assertTrue(probe.verdict("clean_shutdown", 0, "storage flushed to disk"))
        self.assertFalse(probe.verdict("clean_shutdown", 0, ""))
        self.assertFalse(probe.verdict("clean_shutdown", 1, "storage flushed to disk"))

    def test_failed_flush_cannot_claim_completed_drain(self):
        self.assertFalse(probe.verdict(
            "flush_denied", 1, "storage flush failed; Shutdown drain completed"))


if __name__ == "__main__":
    unittest.main()
