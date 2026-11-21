"""Exercise a synthetic host permit ledger and guest receipt across processes."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


PERMIT = {"permit_id": "permit-1", "target_id": "target-1", "generation": 1}
COMMITTED = {**PERMIT, "state": "consumed"}
ACK_LOST = 23


def write_record(path, record):
    temporary = path.with_suffix(".pending")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_record(path):
    return json.loads(path.read_text(encoding="utf-8"))


def host_consume(ledger, witness, fault):
    # A separate record closes the permit before committing the ledger. A crash
    # between writes leaves a mismatch that also refuses further consumption.
    try:
        current = read_record(ledger)
        if current != read_record(witness):
            print("rollback or incomplete commit")
            return 1
        if current != {**PERMIT, "state": "issued"}:
            print("permit already consumed or invalid")
            return 1
        write_record(witness, COMMITTED)
        write_record(ledger, COMMITTED)
    except (OSError, ValueError):
        print("permit state unavailable")
        return 1
    if fault == "drop-ack":
        os._exit(ACK_LOST)
    print(json.dumps(COMMITTED), flush=True)
    return 0


def guest_request(ledger, witness, guest, fault):
    host = worker("host", ledger, witness, fault)
    if host.returncode != 0:
        print(host.stdout.strip() or "no commit acknowledgement")
        return host.returncode
    if json.loads(host.stdout) != COMMITTED:
        return 1
    write_record(guest, COMMITTED)
    return 0


def worker(*args):
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker", *map(str, args)],
        capture_output=True, text=True, timeout=10,
    )


class LedgerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.ledger = root / "host" / "ledger.json"
        self.witness = root / "independent" / "commit.json"
        self.guest = root / "guest" / "launch-ready.json"
        self.backup = root / "issued-backup.json"
        for record in (self.ledger, self.witness, self.guest):
            record.parent.mkdir()
        for record in (self.ledger, self.witness, self.backup):
            write_record(record, {**PERMIT, "state": "issued"})

    def guest_request(self, fault="none"):
        return worker("guest", self.ledger, self.witness, self.guest, fault)

    def assert_refused(self, reason):
        result = self.guest_request()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout.strip(), reason)
        self.assertFalse(self.guest.exists())

    def test_acknowledged_commit_leaves_matching_guest_record(self):
        result = self.guest_request()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(read_record(self.guest), COMMITTED)

    def test_lost_commit_ack_refuses_guest_and_retry_in_fresh_processes(self):
        result = self.guest_request("drop-ack")
        self.assertEqual(result.returncode, ACK_LOST, result.stderr)
        self.assertEqual(result.stdout.strip(), "no commit acknowledgement")
        self.assertFalse(self.guest.exists())
        self.assertEqual(read_record(self.ledger), COMMITTED)
        self.assertEqual(read_record(self.witness), COMMITTED)
        self.assert_refused("permit already consumed or invalid")

    def test_restored_issued_ledger_conflicts_with_independent_commit(self):
        self.assertEqual(self.guest_request("drop-ack").returncode, ACK_LOST)
        shutil.copyfile(self.backup, self.ledger)
        self.assertEqual(read_record(self.ledger)["state"], "issued")
        self.assert_refused("rollback or incomplete commit")
        self.assertEqual(read_record(self.witness), COMMITTED)
        self.assertEqual(read_record(self.ledger)["state"], "issued")

    def test_missing_ledger_does_not_get_initialized(self):
        self.ledger.unlink()
        self.assert_refused("permit state unavailable")
        self.assertFalse(self.ledger.exists())


if __name__ == "__main__":
    if sys.argv[1:2] == ["--worker"]:
        mode, ledger, witness, *arguments = sys.argv[2:]
        if mode == "host":
            raise SystemExit(host_consume(Path(ledger), Path(witness), *arguments))
        if mode == "guest":
            guest, fault = arguments
            raise SystemExit(guest_request(Path(ledger), Path(witness), Path(guest), fault))
        raise SystemExit(2)
    unittest.main()
