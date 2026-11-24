import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab_shutdown_probe as probe


class ShutdownProbeTests(unittest.TestCase):
    def reply(self, body):
        return patch.object(probe.urllib.request, "urlopen",
                            return_value=io.BytesIO(json.dumps(body).encode()))

    def test_null_error_is_a_success(self):
        with self.reply({"error": None, "result": {"height": 9}}):
            self.assertEqual(probe.rpc("read"), {"height": 9})

    def test_real_error_still_fails(self):
        with self.reply({"error": {"code": -32010}, "result": None}):
            with self.assertRaises(ValueError):
                probe.rpc("read")

    def test_raw_replay_reply_keeps_rejection(self):
        body = {"error": {"code": -32010, "message": "Sequence already used"}}
        with self.reply(body):
            self.assertEqual(probe.rpc("send", raw=True), body)

    def test_missing_result_does_not_pass(self):
        with self.reply({"error": None}):
            with self.assertRaises(KeyError):
                probe.rpc("read")
