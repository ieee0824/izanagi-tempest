from pathlib import Path
import subprocess
import tempfile
import unittest


class GuestAllowlistTests(unittest.TestCase):
    def configuration_block(self):
        script = Path(__file__).with_name("guest-bootstrap.sh").read_text()
        start = script.index("test -d /etc/conf.d\n")
        end = script.index("chown root:root /etc/conf.d/izanagi-agent", start)
        # Execute the actual guard/write block in a fixture directory. Ownership
        # is checked separately when the real guest artifact is provisioned.
        return "set -eu\n" + script[start:end].replace("/etc/conf.d", '"$1"')

    def test_export_reaches_child_with_only_fixed_absolute_command(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["/bin/sh", "-c", self.configuration_block(), "sh", directory],
                                    env={}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            config = Path(directory) / "izanagi-agent"
            result = subprocess.run(["/bin/sh", "-c", '. "$1"; exec /usr/bin/env', "sh", str(config)],
                                    env={}, capture_output=True, text=True, check=True)
            environment = dict(line.split("=", 1) for line in result.stdout.splitlines())
            self.assertEqual(environment["IZANAGI_ALLOWED_COMMANDS"], "/usr/bin/id")
            self.assertNotIn("IZANAGI_ALLOW_ALL_COMMANDS", environment)

    def test_existing_regular_or_dangling_config_is_rejected(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "izanagi-agent"
                if symlink:
                    path.symlink_to("missing-config")
                else:
                    path.write_text("unexpected-existing-setting\n")
                result = subprocess.run(["/bin/sh", "-c", self.configuration_block(), "sh", directory],
                                        env={}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                if symlink:
                    self.assertTrue(path.is_symlink())
                    self.assertFalse((Path(directory) / "missing-config").exists())
                else:
                    self.assertEqual(path.read_text(), "unexpected-existing-setting\n")


if __name__ == "__main__":
    unittest.main()
