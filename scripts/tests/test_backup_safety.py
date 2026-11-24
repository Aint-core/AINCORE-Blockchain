"""Backup guards on fabricated files; real RocksDB reopening is a separate drill."""
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BACKUP = ROOT / "scripts/backup_node.sh"


class BackupSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "data/validator_9001.db"
        self.db.mkdir(parents=True)
        (self.db / "LOCK").touch()
        (self.db / "CURRENT").write_text("MANIFEST-000001\n")
        (self.db / "MANIFEST-000001").write_text("fixture, not a real database\n")
        self.out = self.root / "backups"

    def backup(self, *flags, env=None):
        return subprocess.run([
            "bash", str(BACKUP), "--datadir", str(self.db.parent), "--port", "9001",
            "--out-dir", str(self.out), "--not-a-validator", *flags,
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=15, env=env)

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("Backup ready:", result.stdout)
        self.assertEqual(list(self.out.glob("*.tar.gz")), [])

    def test_hot_copy_refused_even_if_stopped_flag_follows(self):
        for flags in (("--hot",), ("--hot", "--assume-stopped"),
                      ("--assume-stopped", "--hot")):
            with self.subTest(flags=flags):
                self.assert_refused(self.backup(*flags))

    def test_explicit_stopped_acknowledgement_required(self):
        self.assert_refused(self.backup())

    def test_live_posix_lock_refused(self):
        with (self.db / "LOCK").open("r+b") as lock:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_refused(self.backup("--assume-stopped"))

    def test_missing_lock_refused_without_creating_it(self):
        (self.db / "LOCK").unlink()
        self.assert_refused(self.backup("--assume-stopped"))
        self.assertFalse((self.db / "LOCK").exists())

    def test_symlink_lock_refused(self):
        other = self.root / "other-lock"
        other.write_text("unchanged")
        (self.db / "LOCK").unlink()
        (self.db / "LOCK").symlink_to(other)
        self.assert_refused(self.backup("--assume-stopped"))
        self.assertEqual(other.read_text(), "unchanged")

    def test_stopped_backup_succeeds_and_releases_lock(self):
        result = self.backup("--assume-stopped")
        self.assertEqual(result.returncode, 0, result.stdout)
        archives = list(self.out.glob("*.tar.gz"))
        self.assertEqual(len(archives), 1)
        self.assertTrue(Path(str(archives[0]) + ".sha256").is_file())
        with (self.db / "LOCK").open("r+b") as lock:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_lock_held_during_entire_copy(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        tar = bin_dir / "tar"
        tar.write_text("""#!/usr/bin/env python3
import fcntl, os, sys
with open(os.environ['BACKUP_TEST_LOCK'], 'r+b') as lock:
    try:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.stdout.buffer.write(b'copy fixture: protected')
        sys.exit(0)
sys.exit(51)
""")
        tar.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                   BACKUP_TEST_LOCK=str(self.db / "LOCK"))
        result = self.backup("--assume-stopped", env=env)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_failed_copy_leaves_no_usable_archive(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        tar = bin_dir / "tar"
        tar.write_text("#!/bin/sh\nprintf 'partial'\nexit 42\n")
        tar.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
        self.assert_refused(self.backup("--assume-stopped", env=env))
        with (self.db / "LOCK").open("r+b") as lock:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)


if __name__ == "__main__":
    unittest.main()
