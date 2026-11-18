from pathlib import Path
import re
import subprocess
import unittest


class LockedIdentityTests(unittest.TestCase):
    def test_actual_guest_predicate_requires_one_locked_account(self):
        script = Path(__file__).with_name("guest-bootstrap.sh").read_text()
        predicate = re.search(r"awk -F: '([^']+)' /etc/shadow", script).group(1)
        fixtures = [
            ("izanagi:!:1000:0:99999:7:::\n", True),
            ("izanagi:!locked:1000:0:99999:7:::\n", True),
            ("izanagi:*:1000:0:99999:7:::\n", True),
            ("izanagi::1000:0:99999:7:::\n", False),
            ("izanagi:unlocked:1000:0:99999:7:::\n", False),
            ("other:!:1000:0:99999:7:::\n", False),
            ("izanagi:!:::::::\nizanagi:!:::::::\n", False),
        ]
        for fixture, accepted in fixtures:
            with self.subTest(accepted=accepted, fixture=fixture):
                result = subprocess.run(["awk", "-F:", predicate], input=fixture,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
