"""Read one committed diagnostic record from the host management ledger."""

from contextlib import closing
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys


MANAGEMENT = Path("/var/lib/izanagi-tempest")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]+")
DIGEST = re.compile(r"[a-f0-9]{64}")


def canonical_json(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def read_committed_snapshot(database, scope, checkpoint, allowed_states=("consumed",)):
    """Caller holds the host management lock across this read and its inputs."""
    with database.open("rb") as stream:
        header = stream.read(20)
    if header[:16] != b"SQLite format 3\0" or header[18:20] != b"\x01\x01":
        raise ValueError("ledger is not a rollback-journal SQLite database")
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=0)) as db:
        db.execute("PRAGMA query_only = ON")
        db.execute("BEGIN")
        if db.execute("PRAGMA user_version").fetchone() != (1,):
            raise ValueError("unrecognized ledger schema")
        row = db.execute(
            """SELECT ledger_id, target_id, permit_id, generation, sequence, state
               FROM permit_commits WHERE permit_id = ? ORDER BY sequence DESC LIMIT 1""",
            (scope["permit_id"],),
        ).fetchone()
        if row is None:
            raise ValueError("permit is missing")
        ledger, target, permit, generation, sequence, state = row
        if (not isinstance(ledger, str) or not IDENTIFIER.fullmatch(ledger)
                or type(sequence) is not int or sequence <= 0
                or type(generation) is not int or generation <= 0):
            raise ValueError("invalid ledger record")
        record = {
            "ledger_id": ledger, "scope": {
                "target_id": target, "permit_id": permit, "generation": generation,
            }, "sequence": sequence, "state": state,
        }
        if (state not in allowed_states or record["scope"] != scope
                or sequence != checkpoint["sequence"]
                or sha256(canonical_json(record)).hexdigest() != checkpoint["digest"]):
            raise ValueError("commit does not match the independent checkpoint")
        return record


def check_directory(path, mode=None):
    info = path.lstat()
    permissions = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or permissions & 0o022 or (mode is not None and permissions != mode)):
        raise PermissionError("invalid management directory")


def check_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise PermissionError("invalid management file")


def read_json(path):
    check_file(path)
    with path.open("rb") as stream:
        data = stream.read(1025)
    if len(data) > 1024:
        raise ValueError("management input too large")
    return json.loads(data)


def read_management_snapshot(root, allowed_states=("consumed",)):
    for ancestor in reversed(root.parents):
        check_directory(ancestor)
    check_directory(root, 0o700)
    authority, recovery, ledger, publication = (
        root / name for name in ("host-login-authority", "host-login-recovery",
                                 "host-login-ledger-source", "host-login-ledger")
    )
    for directory in (authority, recovery, ledger, publication):
        check_directory(directory, 0o700)
    lock = publication / "lock"
    check_file(lock)
    with lock.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
        scope = read_json(authority / "scope.json")
        checkpoint = read_json(recovery / "checkpoint.json")
        if (not isinstance(scope, dict) or set(scope) != {"target_id", "permit_id", "generation"}
                or type(scope["generation"]) is not int or scope["generation"] <= 0
                or not all(isinstance(scope[key], str) and IDENTIFIER.fullmatch(scope[key])
                           for key in ("target_id", "permit_id"))):
            raise ValueError("invalid scope")
        if (not isinstance(checkpoint, dict) or set(checkpoint) != {"sequence", "digest"}
                or type(checkpoint["sequence"]) is not int or checkpoint["sequence"] <= 0
                or not isinstance(checkpoint["digest"], str)
                or not DIGEST.fullmatch(checkpoint["digest"])):
            raise ValueError("invalid checkpoint")
        database = ledger / "ledger.sqlite3"
        check_file(database)
        return read_committed_snapshot(database, scope, checkpoint, allowed_states)


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        return 1
    try:
        record = read_management_snapshot(MANAGEMENT)
        print(canonical_json(record).decode("ascii"))
    except (OSError, ValueError, sqlite3.Error):
        print("host ledger snapshot refused", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
