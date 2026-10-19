"""Exercise runner bookkeeping with fake commands, never build or touch live nodes."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "hardening_regression.sh"


class RunnerTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copyfile(RUNNER, root / "scripts/hardening_regression.sh")
            tools = root / "bin"
            tools.mkdir()
            commands = {
                "git": '#!/bin/sh\n[ "$1" = status ] && exit 0\necho fixture-commit\n',
                "rustc": '#!/bin/sh\necho fixture-rustc\n',
                "cargo": '#!/bin/sh\nexit 0\n',
                "node": '#!/bin/sh\nexit 0\n',
                "python3": '#!/bin/sh\ncase "$RUNNER_MODE" in\n'
                           'failure) exit 17 ;;\n'
                           'TERM|INT|HUP) kill -s "$RUNNER_MODE" "$PPID" ;;\n'
                           'esac\nexit 0\n',
            }
            for name, body in commands.items():
                path = tools / name
                path.write_text(body)
                path.chmod(0o755)
            result = subprocess.run(
                ["bash", str(root / "scripts/hardening_regression.sh")],
                env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                     "RUNNER_MODE": mode},
                capture_output=True, text=True, timeout=10,
            )
            reports = list((root / "target").glob("*/result.txt"))
            self.assertEqual(len(reports), 1, result.stderr)
            report = dict(line.split("=", 1) for line in reports[0].read_text().splitlines())
            return result.returncode, report

    def test_only_complete_run_reports_success(self):
        code, report = self.exercise("success")
        self.assertEqual(code, 0)
        self.assertEqual(report, {"stage": "complete", "exit_code": "0"})

    def test_stage_failure_preserves_exit_code(self):
        code, report = self.exercise("failure")
        self.assertEqual(code, 17)
        self.assertEqual(report, {"stage": "gate-controls", "exit_code": "17"})

    def test_interruption_cannot_report_success(self):
        for signal, expected in (("TERM", 143), ("INT", 130), ("HUP", 129)):
            with self.subTest(signal=signal):
                code, report = self.exercise(signal)
                self.assertEqual(code, expected)
                self.assertEqual(report, {"stage": "gate-controls", "exit_code": str(expected)})
