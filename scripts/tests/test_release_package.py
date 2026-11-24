"""Packaging contents and fail-closed checks; fake binaries, no local Rust builds."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/package_node_release.sh", self.root / "scripts/package_node_release.sh")
        (self.root / "docs").mkdir()
        (self.root / "docs/RELEASE_PACKAGE.md").write_text("fixture instructions")
        (self.root / "LICENSE").write_text("fixture license")
        self.modules = self.root / "core/vm_move/stdlib/bytecode"
        self.modules.mkdir(parents=True)
        (self.modules / "coin.mv").write_bytes(b"fixture module")
        self.binary = self.root / "input-node"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)
        self.out = self.root / "node.tar.gz"

    def package(self):
        return subprocess.run(["bash", str(self.root / "scripts/package_node_release.sh"),
                               str(self.binary), str(self.out)], capture_output=True,
                              text=True, timeout=15)

    def test_runtime_files_and_hashes_without_unrelated_secrets(self):
        (self.root / "node.key").write_text("never package this")
        (self.root / ".env").write_text("never package this")
        (self.modules / "unexpected.key").write_text("never package this")
        result = self.package()
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.out) as archive:
            names = {entry.name for entry in archive.getmembers() if entry.isfile()}
            self.assertEqual(names, {"node", "LICENSE", "README.md", "SHA256SUMS",
                                     "core/vm_move/stdlib/bytecode/coin.mv"})
            manifest = archive.extractfile("SHA256SUMS").read().decode().splitlines()
            for line in manifest:
                expected, name = line.split(maxsplit=1)
                self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(), expected)
            self.assertEqual(archive.getmember("node").mode & 0o111, 0o111)
        expected = Path(str(self.out) + ".sha256").read_text().split()[0]
        self.assertEqual(hashlib.sha256(self.out.read_bytes()).hexdigest(), expected)

    def test_existing_artifact_is_not_overwritten(self):
        self.out.write_bytes(b"retain earlier evidence")
        self.assertNotEqual(self.package().returncode, 0)
        self.assertEqual(self.out.read_bytes(), b"retain earlier evidence")

    def test_missing_stdlib_refused(self):
        (self.modules / "coin.mv").unlink()
        self.assertNotEqual(self.package().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_symlinked_module_refused(self):
        (self.modules / "coin.mv").unlink()
        (self.modules / "coin.mv").symlink_to(self.binary)
        self.assertNotEqual(self.package().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_non_executable_input_refused(self):
        self.binary.chmod(0o644)
        self.assertNotEqual(self.package().returncode, 0)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
