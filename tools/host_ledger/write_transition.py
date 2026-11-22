"""Advance the fixed host permit and its independent checkpoint under one lock."""

from contextlib import closing
import fcntl
from hashlib import sha256
import os
import sqlite3
import sys

from read_snapshot import (
    IDENTIFIER, MANAGEMENT, canonical_json, check_directory, check_file, read_json,
)


TRANSITIONS = {
    "issue": {"empty": "issued"},
    "consume": {"issued": "consumed"},
    "revoke": {"issued": "revoked", "consumed": "revoked"},
}


def checkpoint_for(record):
    return {"sequence": record["sequence"], "digest": sha256(canonical_json(record)).hexdigest()}


def replace_checkpoint(path, checkpoint):
    pending = path.with_name("checkpoint.new")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical_json(checkpoint))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def advance(root, operation, expected_scope=None):
    for ancestor in reversed(root.parents):
        check_directory(ancestor)
    check_directory(root, 0o700)
    authority = root / "host-login-authority"
    recovery = root / "host-login-recovery"
    ledger = root / "host-login-ledger-source"
    publication = root / "host-login-ledger"
    for directory in (authority, recovery, ledger, publication):
        check_directory(directory, 0o700)
    lock = publication / "lock"
    check_file(lock)
    with lock.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if expected_scope is not None and read_json(authority / "scope.json") != expected_scope:
            raise ValueError("requested ledger scope mismatch")
        advance_locked(authority, recovery, ledger, operation)


def advance_locked(authority, recovery, ledger, operation):
    scope = read_json(authority / "scope.json")
    ledger_id = read_json(authority / "ledger-id.json")
    if (not isinstance(scope, dict) or set(scope) != {"target_id", "permit_id", "generation"}
            or type(scope["generation"]) is not int or not 0 < scope["generation"] < 2**63
            or not all(isinstance(value, str) and IDENTIFIER.fullmatch(value)
                       for value in (ledger_id, scope["target_id"], scope["permit_id"]))):
        raise ValueError("invalid fixed ledger scope")
    checkpoint_path = recovery / "checkpoint.json"
    checkpoint = read_json(checkpoint_path)
    if (not isinstance(checkpoint, dict) or set(checkpoint) != {"sequence", "digest"}
            or type(checkpoint["sequence"]) is not int):
        raise ValueError("invalid independent checkpoint")
    if os.path.lexists(recovery / "checkpoint.new"):
        raise ValueError("checkpoint update pending")
    database = ledger / "ledger.sqlite3"
    check_file(database)
    with database.open("rb") as stream:
        header = stream.read(20)
    if header[:16] != b"SQLite format 3\0" or header[18:20] != b"\x01\x01":
        raise ValueError("invalid rollback-journal ledger")
    with closing(sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=0)) as db, db:
        db.execute("PRAGMA synchronous = EXTRA")
        db.execute("BEGIN IMMEDIATE")
        if db.execute("PRAGMA user_version").fetchone() != (1,):
            raise ValueError("unrecognized ledger schema")
        current = db.execute(
            """SELECT sequence, ledger_id, target_id, permit_id, generation, state
               FROM permit_commits ORDER BY sequence DESC LIMIT 1""",
        ).fetchone()
        sequence, state = 0, "empty"
        if current is not None:
            sequence, identity, target, permit, generation, state = current
            if ((identity, target, permit, generation)
                    != (ledger_id, scope["target_id"], scope["permit_id"], scope["generation"])):
                raise ValueError("ledger scope mismatch")
        record = {"ledger_id": ledger_id, "scope": scope, "sequence": sequence, "state": state}
        if checkpoint_for(record) != checkpoint:
            raise ValueError("ledger and independent checkpoint differ")
        next_state = TRANSITIONS[operation].get(state)
        if next_state is None or sequence == 2**63 - 1:
            raise ValueError("permit transition refused")
        record.update(sequence=sequence + 1, state=next_state)
        db.execute(
            "INSERT INTO permit_commits VALUES (?, ?, ?, ?, ?, ?)",
            (record["sequence"], ledger_id, scope["target_id"], scope["permit_id"],
             scope["generation"], next_state),
        )
    # A crash here leaves a mismatch. Readers and later transitions refuse it.
    replace_checkpoint(checkpoint_path, checkpoint_for(record))


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in TRANSITIONS or os.geteuid() != 0:
        return 1
    try:
        advance(MANAGEMENT, sys.argv[1])
    except (OSError, ValueError, sqlite3.Error):
        print("host ledger transition refused", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
