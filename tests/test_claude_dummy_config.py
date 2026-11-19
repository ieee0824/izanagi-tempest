import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "integration/check_claude_dummy_config.py"


class ClaudeDummyConfigTests(unittest.TestCase):
    def test_requires_owned_private_empty_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Path(directory) / "settings.json"
            settings.write_text("{}")
            settings.chmod(0o600)

            def check(uid=os.getuid()):
                return subprocess.run(
                    [sys.executable, str(SCRIPT), directory, "--owner-uid", str(uid)],
                    capture_output=True,
                    timeout=5,
                )

            self.assertEqual(check().returncode, 0)
            self.assertIn(b"fixture owner", check(os.getuid() + 1).stderr)
            settings.chmod(0o644)
            self.assertIn(b"mode 0600", check().stderr)
            settings.chmod(0o600)
            settings.write_text('{"unknown":true}')
            self.assertIn(b"empty object", check().stderr)
            settings.unlink()
            settings.symlink_to("/dev/null")
            self.assertEqual(check().returncode, 1)

    def test_initialization_and_metadata_audit(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / "fixture"
            uid = os.geteuid()
            args = [sys.executable, str(SCRIPT), str(directory), "--owner-uid", str(uid)]
            result = subprocess.run(
                args + ["--initialize", "--audit"], capture_output=True, check=True, timeout=5
            )
            self.assertEqual(json.loads(result.stdout), {
                "root": {"kind": "directory", "uid": uid, "mode": "0700"},
                "settings.json": {"kind": "regular", "uid": uid, "mode": "0600"},
            })
            settings = directory / "settings.json"
            before = settings.stat()
            repeat = subprocess.run(args + ["--initialize"], capture_output=True, timeout=5)
            self.assertEqual(repeat.returncode, 1)
            self.assertEqual(settings.stat().st_ino, before.st_ino)
            self.assertEqual(settings.read_bytes(), b"{}\n")
            (directory / "unexpected").write_text("dummy")
            rejected = subprocess.run(args + ["--audit"], capture_output=True, timeout=5)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(rejected.stdout, b"")
