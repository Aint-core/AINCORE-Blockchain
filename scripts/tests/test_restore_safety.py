"""Observer restore preconditions using disposable archive fixtures, never live DBs."""
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


RESTORE = Path(__file__).resolve().parents[1] / "restore_node.sh"


class RestoreSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.datadir = self.root / "destination"
        self.db = self.datadir / "validator_9001.db"
        self.db.mkdir(parents=True)
        self.archive = self.root / "backup.tar.gz"

    def make_archive(self, ports):
        with tarfile.open(self.archive, "w:gz") as archive:
            for port in ports:
                source = self.root / f"validator_{port}.db"
                source.mkdir()
                (source / "CURRENT").write_text(f"restored-{port}")
                archive.add(source, arcname=source.name)

    def restore(self, *flags):
        checksum = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        return subprocess.run([
            "bash", str(RESTORE), "--backup", str(self.archive),
            "--datadir", str(self.datadir), "--port", "9001", "--sha256", checksum,
            "--not-a-validator", *flags,
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)

    def assert_original_untouched(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.db / "CURRENT").read_text(), "original")
        self.assertEqual(list(self.datadir.glob("*.pre-restore.*")), [])

    def test_invalid_archive_with_valid_hash_does_not_move_old_db(self):
        (self.db / "CURRENT").write_text("original")
        self.archive.write_bytes(b"not a tar archive")
        self.assert_original_untouched(self.restore("--force"))

    def test_missing_db_in_archive_does_not_move_old_db(self):
        (self.db / "CURRENT").write_text("original")
        self.make_archive([])
        self.assert_original_untouched(self.restore("--force"))

    def test_ambiguous_archive_does_not_pick_first_db(self):
        (self.db / "CURRENT").write_text("original")
        self.make_archive([9002, 9003])
        self.assert_original_untouched(self.restore("--force"))

    def test_empty_existing_destination_not_nested(self):
        self.make_archive([9002])
        result = self.restore()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.db / "CURRENT").read_text(), "restored-9002")
        self.assertFalse((self.db / "validator_9002.db").exists())

    def test_force_retains_old_db_when_archive_valid(self):
        (self.db / "CURRENT").write_text("original")
        self.make_archive([9002])
        result = self.restore("--force")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.db / "CURRENT").read_text(), "restored-9002")
        old = list(self.datadir.glob("*.pre-restore.*"))
        self.assertEqual(len(old), 1)
        self.assertEqual((old[0] / "CURRENT").read_text(), "original")

    def test_destination_symlink_refused(self):
        self.make_archive([9002])
        self.db.rmdir()
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        self.db.symlink_to(unrelated, target_is_directory=True)
        result = self.restore("--force")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.db.is_symlink())
        self.assertEqual(list(unrelated.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
