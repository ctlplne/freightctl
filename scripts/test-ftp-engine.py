#!/usr/bin/env python3
"""Real temporary-file source-pin refusal checks; no protocol qualification."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("engine", ROOT / "scripts/check-ftp-engine.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class EngineSourceContracts(unittest.TestCase):
    def fixture(self):
        tmp = tempfile.TemporaryDirectory(prefix="freightctl-engine-pin-")
        self.addCleanup(tmp.cleanup)
        target = Path(tmp.name) / "engine"
        shutil.copytree(engine.DIRECTORY, target)
        return target

    def test_current_source_pin(self):
        engine.verify()

    def test_modified_runtime_bytes_refuse(self):
        target = self.fixture()
        with (target / "transfer_pasv.go").open("a") as f:
            f.write("\n// unexpected source mutation\n")
        with self.assertRaises(ValueError):
            engine.verify(target)

    def test_missing_license_and_unlisted_files_refuse(self):
        for mutation in ("license", "additional"):
            with self.subTest(mutation=mutation):
                target = self.fixture()
                if mutation == "license":
                    (target / "license.txt").unlink()
                else:
                    (target / "unrecorded.go").write_text("package ftpserver\n")
                with self.assertRaises(ValueError):
                    engine.verify(target)

    def test_source_symlink_refuses(self):
        target = self.fixture()
        (target / "driver.go").unlink()
        (target / "driver.go").symlink_to(engine.DIRECTORY / "driver.go")
        with self.assertRaises(ValueError):
            engine.verify(target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
