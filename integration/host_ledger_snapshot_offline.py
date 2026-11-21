"""Exercise the host ledger reader with an offline SQLite database."""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools/host_ledger"
sys.path.insert(0, str(TOOLS))
from read_snapshot import canonical_json, read_committed_snapshot


class HostLedgerSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / "ledger.sqlite3"
        self.scope = {"target_id": "target-fixture", "permit_id": "permit-fixture", "generation": 7}
        self.record = {"ledger_id": "ledger-fixture", "scope": self.scope,
                       "sequence": 3, "state": "consumed"}
        self.checkpoint = {
            "sequence": 3, "digest": sha256(canonical_json(self.record)).hexdigest(),
        }
        with closing(sqlite3.connect(self.database)) as db, db:
            db.executescript((TOOLS / "schema.sql").read_text())
            db.executemany("INSERT INTO permit_commits VALUES (?, ?, ?, ?, ?, ?)", [
                (1, "ledger-fixture", "target-fixture", "permit-fixture", 7, "issued"),
                (3, "ledger-fixture", "target-fixture", "permit-fixture", 7, "consumed"),
            ])

    def read(self, scope=None, checkpoint=None):
        return read_committed_snapshot(self.database, scope or self.scope, checkpoint or self.checkpoint)

    def test_exact_checkpoint_and_scope(self):
        before = self.database.read_bytes()
        self.assertEqual(self.read(), self.record)
        self.assertEqual(self.database.read_bytes(), before)

    def test_missing_database_is_not_created(self):
        self.database.unlink()
        with self.assertRaises(FileNotFoundError):
            self.read()
        self.assertFalse(self.database.exists())

    def test_wal_database_is_refused_without_creating_sidecars(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("PRAGMA journal_mode=WAL")
        with self.assertRaises(ValueError):
            self.read()
        self.assertEqual(list(self.database.parent.iterdir()), [self.database])

    def test_rollback_does_not_match_checkpoint(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("DELETE FROM permit_commits WHERE sequence = 3")
        with self.assertRaises(ValueError):
            self.read()

    def test_newer_revocation_does_not_fall_back_to_consumption(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("INSERT INTO permit_commits VALUES (?, ?, ?, ?, ?, ?)",
                       (4, "ledger-fixture", "target-fixture", "permit-fixture", 7, "revoked"))
        with self.assertRaises(ValueError):
            self.read()

    def test_changed_scope_or_digest_is_refused(self):
        with self.assertRaises(ValueError):
            self.read(scope={**self.scope, "generation": 8})
        with self.assertRaises(ValueError):
            self.read(checkpoint={**self.checkpoint, "digest": "0" * 64})


if __name__ == "__main__":
    unittest.main()
