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
    def test_boot_cli_is_bound_to_boot_unit(self):
        row = {"unit": {"InvocationID": "boot-invocation", "ActiveState": "inactive", "LoadState": "loaded"},
               "cgroup_pids": [], "external_listener_observed": False}
        for attempt in ("001", "002"):
            with self.subTest(attempt=attempt), TemporaryDirectory() as directory:
                output = Path(directory) / "boot.jsonl"
                with patch("sys.argv", ["observe", "--phase", "boot", "--attempt", attempt, "--output", str(output)]), \
                     patch("observe.os.geteuid", return_value=0), \
                     patch("observe.sample", return_value=row) as read_sample:
                    main()
                read_sample.assert_called_once_with(f"tempest-izanagi-bootstrap-boot-{attempt}.service")

    def test_explicit_attempt_cli_observes_only_selected_unit(self):
        row = {
            "unit": {"InvocationID": "second-invocation", "ActiveState": "inactive", "LoadState": "loaded"},
            "cgroup_pids": [],
            "external_listener_observed": False,
        }
        for attempt in ("002", "003", "004"):
            with self.subTest(attempt=attempt), TemporaryDirectory() as directory:
                output = Path(directory) / "observation.jsonl"
                with patch("sys.argv", ["observe", "--attempt", attempt, "--output", str(output)]), \
                     patch("observe.os.geteuid", return_value=0), \
                     patch("observe.sample", return_value=row) as read_sample:
                    main()
                read_sample.assert_called_once_with(f"tempest-izanagi-bootstrap-build-{attempt}.service")
                self.assertTrue(output.is_file())

    def test_unit_gc_is_not_same_invocation_terminal_proof(self):
        rows = [
            {"unit": {"InvocationID": "observed", "ActiveState": "active", "LoadState": "loaded"},
             "cgroup_pids": [123], "external_listener_observed": False},
            {"unit": {"InvocationID": "", "ActiveState": "inactive", "LoadState": "not-found"},
             "cgroup_pids": [], "external_listener_observed": False},
        ]
        with TemporaryDirectory() as directory:
            output = Path(directory) / "observation.jsonl"
            with patch("sys.argv", ["observe", "--attempt", "003", "--output", str(output)]), \
                 patch("observe.os.geteuid", return_value=0), \
                 patch("observe.sample", side_effect=rows), \
                 patch("observe.time.sleep"):
                with self.assertRaisesRegex(SystemExit, "terminal attributes not captured"):
                    main()

    def test_terminal_record_from_other_invocation_is_rejected(self):
        rows = [
            {"unit": {"InvocationID": "current", "ActiveState": "active", "LoadState": "loaded"},
             "cgroup_pids": [123], "external_listener_observed": False},
            {"unit": {"InvocationID": "old", "ActiveState": "inactive", "LoadState": "loaded"},
             "cgroup_pids": [], "external_listener_observed": False},
        ]
        with TemporaryDirectory() as directory:
            output = Path(directory) / "observation.jsonl"
            with patch("sys.argv", ["observe", "--attempt", "003", "--output", str(output)]), \
                 patch("observe.os.geteuid", return_value=0), \
                 patch("observe.sample", side_effect=rows), \
                 patch("observe.time.sleep"):
                with self.assertRaisesRegex(RuntimeError, "unit invocation changed"):
                    main()

if __name__ == "__main__":
    unittest.main()
