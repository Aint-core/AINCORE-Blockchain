import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "transactions", Path(__file__).resolve().parents[1] / "lab_transaction_gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class RejectionEvidenceTests(unittest.TestCase):
    def test_explicit_signature_rejection(self):
        reply = {"error": {"code": -32010, "message": "Invalid signature: Ed25519 does not verify"}}
        self.assertEqual(gate.rejection(reply, ("invalid signature",)), reply["error"])

    def test_busy_or_unrelated_error_is_not_security_success(self):
        for reply in [
            {"error": {"code": -32005, "message": "busy"}},
            {"error": {"code": -32010, "message": "insufficient balance"}},
            {"result": {"status": "sent"}},
            {"error": None},
        ]:
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                gate.rejection(reply, ("duplicate transaction", "nonce", "sequence"))

    def test_duplicate_is_explicit_replay_rejection(self):
        reply = {"error": {"code": -32010, "message": "Duplicate transaction: abc"}}
        self.assertEqual(gate.rejection(reply, ("duplicate transaction",)), reply["error"])
