import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "isolated_gate", Path(__file__).resolve().parents[1] / "isolated_multivalidator_gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CertificateChecks(unittest.TestCase):
    def setUp(self):
        self.reply = {"available": True, "verified": True, "height": 1,
                      "quorum_certificate": {"chain_id": "TEST", "block_height": 1,
                      "signed_stake": 3, "total_stake": 4, "block_hash": "a",
                      "state_root": "b", "receipts_root": "c", "finality_digest": "d"}}

    def test_valid_three_of_four(self):
        self.assertEqual(gate.certified_identity(self.reply, "TEST"), (1, ("a", "b", "c", "d")))

    def test_unverified_or_unavailable_never_passes(self):
        for field in ("available", "verified"):
            for value in (False, None):
                reply = copy.deepcopy(self.reply)
                reply[field] = value
                with self.assertRaises(ValueError):
                    gate.certified_identity(reply, "TEST")

    def test_bad_domain_height_and_quorum_fail(self):
        for field, value in (("chain_id", "OTHER"), ("block_height", 2),
                             ("signed_stake", 2), ("signed_stake", 5),
                             ("total_stake", 0), ("state_root", "")):
            reply = copy.deepcopy(self.reply)
            reply["quorum_certificate"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                gate.certified_identity(reply, "TEST")
