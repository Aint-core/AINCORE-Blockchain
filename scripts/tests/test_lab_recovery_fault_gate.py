from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab_recovery_fault_gate as gate


class RecoveryGateTests(unittest.TestCase):
    def test_running_lab_is_not_restarted_during_cleanup(self):
        with patch.object(gate.subprocess, "check_output", return_value="loaded\n"), \
                patch.object(gate, "stopped_status", return_value={"SubState": "running"}), \
                patch.object(gate.subprocess, "run") as run:
            gate.unit(2, "start")
            run.assert_not_called()

    def test_signal_stop_retains_exit_metadata(self):
        with patch.object(gate, "stopped_status", return_value={"MainPID": "0", "SubState": "exited"}), \
                patch.object(gate.subprocess, "run") as run:
            gate.unit(2, "stop")
            self.assertIn("--signal=SIGTERM", run.call_args.args[0][-1])

    def test_exited_unit_is_restarted_not_merely_started(self):
        with patch.object(gate.subprocess, "check_output", return_value="loaded\n"), \
                patch.object(gate, "stopped_status", return_value={"SubState": "exited"}), \
                patch.object(gate.subprocess, "run") as run:
            gate.unit(2, "start")
            self.assertIn("restart", run.call_args.args[0][-1])

    def test_collected_lab_unit_is_recreated(self):
        with patch.object(gate.subprocess, "check_output", return_value="not-found\n"), \
                patch.object(gate.subprocess, "run") as run:
            gate.unit(2, "start")
            self.assertIn("systemd-run", run.call_args.args[0][-1])
            self.assertIn("data-2", run.call_args.args[0][-1])

    def test_other_services_cannot_be_controlled(self):
        with self.assertRaises(ValueError):
            gate.unit(0, "stop")

    def test_abort_and_missing_status_fail_closed(self):
        self.assertFalse(gate.clean_stop({}))
        self.assertFalse(gate.clean_stop({"Result": "signal", "ExecMainStatus": "6",
                                          "ExecMainCode": "2"}))
        self.assertTrue(gate.clean_stop({"Result": "success", "ExecMainStatus": "0",
                                         "ExecMainCode": "1"}))

    def test_startup_connection_failure_is_retried(self):
        with patch.object(gate, "heights", side_effect=[
                subprocess.CalledProcessError(7, "ssh"), [10, 10]]), \
                patch.object(gate.time, "sleep"):
            self.assertEqual(gate.progress((0, 1), 10), [10, 10])

    def test_invalid_certificate_is_not_retried(self):
        with patch.object(gate, "heights", side_effect=ValueError("bad QC")):
            with self.assertRaisesRegex(ValueError, "bad QC"):
                gate.progress((0, 1), 10)

    def test_ssh_failure_is_not_retried(self):
        with patch.object(gate, "heights", side_effect=subprocess.CalledProcessError(255, "ssh")):
            with self.assertRaises(subprocess.CalledProcessError):
                gate.progress((0, 1), 10)


if __name__ == "__main__":
    unittest.main()
