"""Exercise runner bookkeeping with fake commands, never build or touch live nodes."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "hardening_regression.sh"


class RunnerTests(unittest.TestCase):
    def exercise(self, mode, explicit_output=False, repeat=False, probe=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copyfile(RUNNER, root / "scripts/hardening_regression.sh")
            tools = root / "bin"
            tools.mkdir()
            shared = root / "previous-build"
            shared.mkdir()
            sentinel = shared / "old-binary"
            sentinel.write_text("do not modify")
            commands = {
                "git": '#!/bin/sh\n'
                       'if test "$1" = status; then\n'
                       '  if test "$RUNNER_MODE" = source-change && test -f "$OBSERVED_TARGETS"; then echo dirty; fi\n'
                       '  exit 0\n'
                       'fi\n'
                       'if test "$RUNNER_MODE" = revision-change && test -f "$OBSERVED_TARGETS"; then echo changed; else echo fixture-commit; fi\n',
                "rustc": '#!/bin/sh\necho fixture-rustc\n',
                "cargo": '#!/bin/sh\n'
                         'test "$CARGO_TARGET_DIR" = "$CARGO_BUILD_BUILD_DIR" || exit 41\n'
                         'test "$CARGO_TARGET_DIR" != "$OLD_TARGET" || exit 42\n'
                         'test -z "$RUSTC_WRAPPER$RUSTC_WORKSPACE_WRAPPER" || exit 43\n'
                         'test -z "$CARGO_BUILD_RUSTC_WRAPPER$CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER" || exit 44\n'
                         'test -d "$CARGO_TARGET_DIR" || exit 45\n'
                         'if test "$1" = --version; then\n'
                         '  test -z "$(ls -A "$CARGO_TARGET_DIR")" || exit 46\n'
                         'fi\n'
                         'printf "%s\\n" "$CARGO_TARGET_DIR" >> "$OBSERVED_TARGETS"\n'
                         'touch "$CARGO_TARGET_DIR/fixture-artifact"\n',
                "node": '#!/bin/sh\nexit 0\n',
                "python3": '#!/bin/sh\n'
                           'if test "$1" = scripts/node_exit_probe.py; then\n'
                           '  test "$3" = "$CARGO_TARGET_DIR/release/node" || exit 47\n'
                           '  printf "%s\\n" "$@" > "$PROBE_ARGS"\n'
                           '  test "$RUNNER_MODE" != probe-failure || exit 19\n'
                           'fi\n'
                           'case "$RUNNER_MODE" in\n'
                           'failure) exit 17 ;;\n'
                           'TERM|INT|HUP) kill -s "$RUNNER_MODE" "$PPID" ;;\n'
                           'esac\nexit 0\n',
            }
            for name, body in commands.items():
                path = tools / name
                path.write_text(body)
                path.chmod(0o755)
            command = ["bash", str(root / "scripts/hardening_regression.sh")]
            if explicit_output:
                command += ["--output", str(root / "target/requested-report")]
            if probe:
                (root / "fixture-genesis.json").write_text("{}")
                command += ["--probe-genesis", str(root / "fixture-genesis.json")]
            env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                   "RUNNER_MODE": mode, "OLD_TARGET": str(shared),
                   "CARGO_TARGET_DIR": str(shared), "CARGO_BUILD_BUILD_DIR": str(shared),
                   "RUSTC_WRAPPER": "stale-wrapper", "RUSTC_WORKSPACE_WRAPPER": "stale-wrapper",
                   "CARGO_BUILD_RUSTC_WRAPPER": "stale-wrapper",
                   "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "stale-wrapper",
                   "OBSERVED_TARGETS": str(root / "observed-targets.txt"),
                   "PROBE_ARGS": str(root / "probe-args.txt")}
            result = subprocess.run(
                command, env=env,
                capture_output=True, text=True, timeout=10,
            )
            reports = list((root / "target").glob("*/result.txt"))
            self.assertEqual(len(reports), 1, result.stderr)
            report = dict(line.split("=", 1) for line in reports[0].read_text().splitlines())
            target = (reports[0].parent / "build-target.txt").read_text().strip()
            self.assertEqual(Path(target), reports[0].parent / "build")
            self.assertEqual(set((root / "observed-targets.txt").read_text().splitlines()), {target})
            self.assertEqual(sentinel.read_text(), "do not modify")
            self.assertEqual(list(shared.iterdir()), [sentinel])
            if probe:
                args = (root / "probe-args.txt").read_text().splitlines()
                self.assertEqual(args[2], f"{target}/release/node")
                self.assertEqual(args[-1], str(reports[0].parent / "process-exits"))
                self.assertLess(result.stdout.index("Stage release:"), result.stdout.index("Stage process-exits:"))
            if repeat:
                before = reports[0].read_bytes()
                again = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
                if explicit_output:
                    self.assertNotEqual(again.returncode, 0)
                    self.assertEqual(reports[0].read_bytes(), before)
                else:
                    self.assertEqual(again.returncode, 0, again.stderr)
                    paths = list((root / "target").glob("*/build-target.txt"))
                    self.assertEqual(len(paths), 2)
                    self.assertEqual(len({path.read_text() for path in paths}), 2)
            return result.returncode, report

    def test_only_complete_run_reports_success(self):
        code, report = self.exercise("success")
        self.assertEqual(code, 0)
        self.assertEqual(report, {"stage": "complete", "exit_code": "0"})

    def test_stage_failure_preserves_exit_code(self):
        code, report = self.exercise("failure")
        self.assertEqual(code, 17)
        self.assertEqual(report, {"stage": "gate-controls", "exit_code": "17"})

    def test_explicit_report_is_the_artifact_handoff(self):
        code, report = self.exercise("success", explicit_output=True)
        self.assertEqual(code, 0)
        self.assertEqual(report["stage"], "complete")

    def test_existing_report_and_artifacts_are_not_reused(self):
        self.exercise("success", explicit_output=True, repeat=True)

    def test_each_default_run_gets_a_fresh_build_directory(self):
        self.exercise("success", repeat=True)

    def test_real_process_probe_receives_this_runs_binary(self):
        code, _ = self.exercise("success", probe=True)
        self.assertEqual(code, 0)

    def test_probe_failure_cannot_be_overridden_by_later_stages(self):
        code, report = self.exercise("probe-failure", probe=True)
        self.assertEqual(code, 19)
        self.assertEqual(report, {"stage": "process-exits", "exit_code": "19"})

    def test_source_mutation_cannot_report_success(self):
        for mode in ("source-change", "revision-change"):
            with self.subTest(mode=mode):
                code, report = self.exercise(mode)
                self.assertEqual(code, 2)
                self.assertEqual(report, {"stage": "source-integrity", "exit_code": "2"})

    def test_interruption_cannot_report_success(self):
        for signal, expected in (("TERM", 143), ("INT", 130), ("HUP", 129)):
            with self.subTest(signal=signal):
                code, report = self.exercise(signal)
                self.assertEqual(code, expected)
                self.assertEqual(report, {"stage": "gate-controls", "exit_code": str(expected)})
