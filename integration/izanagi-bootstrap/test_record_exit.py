import subprocess
import unittest
from unittest.mock import patch

from record_exit import OUTPUT, collect


class ExitSnapshotTests(unittest.TestCase):
    def test_records_same_invocation_without_treating_deactivating_as_terminal(self):
        invocation = "a" * 32
        env = {"INVOCATION_ID": invocation, "SERVICE_RESULT": "success",
               "EXIT_CODE": "exited", "EXIT_STATUS": "0", "PRIVATE_CANARY": "omit"}
        response = subprocess.CompletedProcess([], 0, stdout=(
            f"InvocationID={invocation}\nExecMainCode=1\nExecMainStatus=0\n"
            "ActiveState=deactivating\nSubState=stop-post\nResult=success\n"
        ))
        with patch.dict("os.environ", env, clear=True), \
             patch("record_exit.subprocess.run", return_value=response) as read_state:
            row = collect()
        self.assertEqual(read_state.call_args.args[0][2], "tempest-izanagi-bootstrap-boot-002.service")
        self.assertEqual(OUTPUT, "/run/tempest-izanagi-bootstrap-002/evidence/exit-status.json")
        self.assertEqual(row["unit"]["ActiveState"], "deactivating")
        self.assertEqual(row["exit_status"], "0")
        self.assertNotIn("PRIVATE_CANARY", str(row))

    def test_stale_invocation_is_rejected(self):
        response = subprocess.CompletedProcess([], 0, stdout="InvocationID=" + "b" * 32 + "\n")
        with patch.dict("os.environ", {"INVOCATION_ID": "a" * 32}, clear=True), \
             patch("record_exit.subprocess.run", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "invocation mismatch"):
                collect()


if __name__ == "__main__":
    unittest.main()
