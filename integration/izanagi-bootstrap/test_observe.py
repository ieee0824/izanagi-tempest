import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from observe import loopback, main, sample


class ListenerBoundaryTests(unittest.TestCase):
    def test_attempt002_rejects_attempt001_control_group(self):
        with patch("observe.command", return_value=(
            "ControlGroup=/system.slice/tempest-izanagi-bootstrap-build-001.service\n"
            "InvocationID=old-attempt\n"
        )) as call:
            with self.assertRaisesRegex(RuntimeError, "unexpected control group"):
                sample("tempest-izanagi-bootstrap-build-002.service")
            self.assertEqual(call.call_args.args[0][2],
                             "tempest-izanagi-bootstrap-build-002.service")

    def test_loopback_ipv4_and_ipv6(self):
        for endpoint in ("127.0.0.1:18081", "[::1]:5901"):
            with self.subTest(endpoint=endpoint):
                self.assertTrue(loopback(endpoint))

    def test_wildcard_external_and_unparseable_are_not_loopback(self):
        for endpoint in ("0.0.0.0:22221", "[::]:22221", "*:5901",
                         "10.0.2.2:18081", "192.0.2.1:18081", "localhost:18081"):
            with self.subTest(endpoint=endpoint):
                self.assertFalse(loopback(endpoint))


class AttemptBindingTests(unittest.TestCase):
    def test_second_attempt_cli_observes_only_second_unit(self):
        row = {
            "unit": {"InvocationID": "second-invocation", "ActiveState": "inactive"},
            "cgroup_pids": [],
            "external_listener_observed": False,
        }
        with TemporaryDirectory() as directory:
            output = Path(directory) / "observation.jsonl"
            with patch("sys.argv", ["observe", "--attempt", "002", "--output", str(output)]), \
                 patch("observe.os.geteuid", return_value=0), \
                 patch("observe.sample", return_value=row) as read_sample:
                main()
            read_sample.assert_called_once_with("tempest-izanagi-bootstrap-build-002.service")
            self.assertTrue(output.is_file())

if __name__ == "__main__":
    unittest.main()
