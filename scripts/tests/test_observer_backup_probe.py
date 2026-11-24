from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import observer_backup_probe as probe


class IdentityStatusTests(unittest.TestCase):
    def test_known_identity_returns_immediately(self):
        status = {"node_id": "observer", "consensus_busy": False}
        with patch.object(probe, "request", return_value=status) as request:
            self.assertEqual(probe.identity_status(1), status)
            request.assert_called_once()

    def test_explicit_busy_null_is_retried(self):
        ready = {"node_id": "observer", "consensus_busy": False}
        with patch.object(probe, "request", side_effect=[
                {"node_id": None, "consensus_busy": True}, ready]), \
                patch.object(probe.time, "sleep") as sleep:
            self.assertEqual(probe.identity_status(1), ready)
            sleep.assert_called_once_with(0.2)

    def test_unknown_null_is_not_treated_as_busy(self):
        with patch.object(probe, "request", return_value={"node_id": None}), \
                self.assertRaisesRegex(RuntimeError, "without a busy"):
            probe.identity_status(1)

    def test_busy_forever_times_out(self):
        with patch.object(probe, "request", return_value={"node_id": None, "consensus_busy": True}), \
                patch.object(probe.time, "monotonic", side_effect=[0, 31]), \
                self.assertRaises(TimeoutError):
            probe.identity_status(1)

    def test_rpc_error_is_not_hidden_by_retry(self):
        with patch.object(probe, "request", side_effect=RuntimeError("bad RPC")), \
                self.assertRaisesRegex(RuntimeError, "bad RPC"):
            probe.identity_status(1)

    def test_busy_can_use_identity_of_owned_child_with_explicit_source(self):
        with patch.object(probe, "request", return_value={"node_id": None, "consensus_busy": True}):
            status = probe.identity_status(1, "owned-observer")
            self.assertEqual(status["node_id"], "owned-observer")
            self.assertIn("local child startup log", status["identity_source"])

    def test_local_identity_does_not_hide_rpc_mismatch(self):
        with patch.object(probe, "request", return_value={"node_id": "other", "consensus_busy": False}), \
                self.assertRaisesRegex(RuntimeError, "differs"):
            probe.identity_status(1, "owned-observer")

    def test_local_identity_does_not_hide_unknown_null(self):
        with patch.object(probe, "request", return_value={"node_id": None}), \
                self.assertRaisesRegex(RuntimeError, "without a busy"):
            probe.identity_status(1, "owned-observer")


if __name__ == "__main__":
    unittest.main()
