import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_two_host_test as gate


def certificate(height):
    return {"available": True, "verified": True, "height": height,
            "quorum_certificate": {
                "chain_id": gate.CHAIN, "block_height": height,
                "signed_stake": 3, "total_stake": 4,
                **{key: f"{key}-{height}" for key in
                   ("block_hash", "state_root", "receipts_root", "finality_digest")}}}


class Samples:
    def __init__(self, mutation=None):
        self.sample = -1
        self.mutation = mutation

    def rpc(self, node, method, params=None):
        index = gate.NODES.index(node)
        if method == "aincore_getStatus":
            if index == 0:
                self.sample += 1
            result = {"latest_height": str(100 + self.sample),
                      "finalized_round": str(200 + self.sample),
                      "committee_sessions": 3}
        else:
            result = certificate(params[0] if params else 100 + self.sample)
        if self.mutation:
            self.mutation(result, method, params, self.sample, index)
        return result


class SteadyStateChecks(unittest.TestCase):
    def run_check(self, mutation=None, extra_args=()):
        stream = io.StringIO()
        with patch.object(sys, "argv", ["check_two_host_test.py", *extra_args]), \
                patch.object(gate, "rpc", Samples(mutation).rpc), \
                patch.object(gate.time, "sleep"), contextlib.redirect_stdout(stream):
            code = gate.main()
        return code, json.loads(stream.getvalue())

    def test_advancing_status_cannot_hide_a_stale_certificate(self):
        def stale(result, method, params, sample, index):
            if method == "aincore_getQuorumCert" and not params:
                result.update(certificate(50))
        code, report = self.run_check(stale)
        self.assertEqual(code, 1)
        self.assertIs(report["passed"], False)
        self.assertIn("certified height did not advance", report["error"])

    def test_matching_progress_passes_with_exact_sampled_commitments(self):
        code, report = self.run_check(extra_args=("--samples", "3"))
        self.assertEqual(code, 0)
        self.assertIs(report["passed"], True)
        self.assertEqual(len(report["samples"]), 3)
        self.assertEqual(report["samples"][-1]["certified_heights"], [102] * 4)
        self.assertEqual(report["checked_certified_heights"], list(range(1, 19)) + [100, 101, 102])
        self.assertTrue(all(sample["complete"] for sample in report["samples"]))

    def test_each_node_must_advance_height_and_finality(self):
        for field, initial in (("latest_height", "100"), ("finalized_round", "200")):
            def stalled(result, method, params, sample, index):
                if method == "aincore_getStatus" and index == 3:
                    result[field] = initial
            with self.subTest(field=field):
                code, report = self.run_check(stalled)
                self.assertEqual(code, 1)
                self.assertIs(report["passed"], False)

    def test_missing_session_fails_even_in_initial_sample(self):
        def disconnected(result, method, params, sample, index):
            if method == "aincore_getStatus" and sample == 0 and index == 2:
                result["committee_sessions"] = 2
        code, report = self.run_check(disconnected)
        self.assertEqual(code, 1)
        self.assertIn("missing committee session", report["error"])

    def test_different_committed_roots_fail(self):
        def conflict(result, method, params, sample, index):
            if method == "aincore_getQuorumCert" and params and index == 2:
                result["quorum_certificate"]["state_root"] = "different"
        code, report = self.run_check(conflict)
        self.assertEqual(code, 1)
        self.assertIn("commitments differ", report["error"])

    def test_even_agreement_cannot_rewrite_previous_common_tip(self):
        def rewrite(result, method, params, sample, index):
            if method == "aincore_getQuorumCert" and params == [100] and sample > 0:
                result["quorum_certificate"]["receipts_root"] = "rewritten-on-all-nodes"
        code, report = self.run_check(rewrite)
        self.assertEqual(code, 1)
        self.assertIn("history changed at 100", report["error"])

    def test_wrong_requested_height_fails(self):
        def wrong_height(result, method, params, sample, index):
            if method == "aincore_getQuorumCert" and params:
                result.update(certificate(params[0] + 1))
        code, report = self.run_check(wrong_height)
        self.assertEqual(code, 1)
        self.assertIn("commitments differ", report["error"])

    def test_unverified_wrong_chain_or_insufficient_quorum_fail(self):
        for field, value in (("verified", False), ("chain_id", "OTHER"), ("signed_stake", 2)):
            def invalid(result, method, params, sample, index):
                if method == "aincore_getQuorumCert":
                    target = result if field == "verified" else result["quorum_certificate"]
                    target[field] = value
            with self.subTest(field=field):
                code, report = self.run_check(invalid)
                self.assertEqual(code, 1)
                self.assertIs(report["passed"], False)

    def test_recovery_requires_progress_past_retained_height(self):
        code, report = self.run_check(extra_args=("--recovery-height", "100"))
        self.assertEqual(code, 1)
        self.assertIn("pre-restart height", report["error"])

    def test_requested_recovery_heights_are_checked(self):
        code, report = self.run_check(extra_args=("--recovery-height", "50"))
        self.assertEqual(code, 0)
        self.assertIn(50, report["checked_certified_heights"])
        self.assertIn(51, report["checked_certified_heights"])

    def test_later_failure_keeps_earlier_samples_but_is_not_a_pass(self):
        def interrupted(result, method, params, sample, index):
            if sample == 2:
                raise TimeoutError("test RPC timeout")
        code, report = self.run_check(interrupted, ("--samples", "3"))
        self.assertEqual(code, 1)
        self.assertEqual([sample["complete"] for sample in report["samples"]], [True, True, False])
        self.assertIs(report["passed"], False)
        self.assertIn("TimeoutError", report["error"])

    def test_report_is_saved_and_previous_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            code, report = self.run_check(extra_args=("--report", str(path)))
            self.assertEqual(code, 0)
            original = path.read_bytes()
            self.assertEqual(json.loads(original), report)
            code, report = self.run_check(extra_args=("--report", str(path)))
            self.assertEqual(code, 1)
            self.assertIn("FileExistsError", report["error"])
            self.assertEqual(path.read_bytes(), original)

    def test_failed_run_also_saves_report(self):
        def unavailable(*args):
            raise ConnectionError("test host unreachable")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            code, report = self.run_check(unavailable, ("--report", str(path)))
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertIs(report["passed"], False)

    def test_invalid_observation_options_are_refused_before_rpc(self):
        for args in (("--samples", "1"), ("--interval", "0"), ("--interval", "nan"),
                     ("--interval", "inf"), ("--recovery-height", "-1")):
            with self.subTest(args=args), patch.object(gate, "rpc") as rpc, \
                    patch.object(sys, "argv", ["check_two_host_test.py", *args]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                try:
                    gate.main()
                finally:
                    rpc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
