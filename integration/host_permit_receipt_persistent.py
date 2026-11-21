"""Test a QEMU fixture's committed ledger against an independent host checkpoint."""

from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from host_permit_ledger_offline import write_record
from host_permit_receipt import Checkpoint, Commit, ReceiptVerifier, Scope, receipt_bytes


def read_commit(ledger, permit):
    with closing(sqlite3.connect(ledger.as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute("SELECT state FROM permits WHERE id=?", (permit,)).fetchone()
    if row is None:
        raise ValueError("fixed permit not found")
    sequence = {"issued": 1, "consumed": 2}[row[0]]
    return Commit("qemu-fixture-ledger", sequence, Scope("qemu-fixture-target", permit, 1), row[0])


def persist_checkpoint(ledger, checkpoint, permit):
    commit = read_commit(ledger, permit)
    if commit.state != "consumed":
        raise ValueError("fixture permit has not been consumed")
    write_record(checkpoint, {"sequence": commit.sequence, "digest": commit.digest().hex()})


def check_receipt(ledger, checkpoint_path, permit, previous):
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    verifier = ReceiptVerifier(signer.public_key(), Scope("qemu-fixture-target", permit, 1))
    try:
        statement = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if (not isinstance(statement, dict) or set(statement) != {"sequence", "digest"}
                or type(statement["sequence"]) is not int
                or not isinstance(statement["digest"], str)):
            raise ValueError("invalid checkpoint format")
        digest = bytes.fromhex(statement["digest"])
        if len(digest) != 32:
            raise ValueError("invalid checkpoint digest length")
        checkpoint = Checkpoint(statement["sequence"], digest)
        commit = read_commit(ledger, permit)
        if previous:
            challenge = bytes.fromhex(previous["challenge"])
            signature = bytes.fromhex(previous["signature"])
        else:
            challenge = verifier.challenge
            signature = signer.sign(receipt_bytes(challenge, commit))
    except (OSError, sqlite3.Error, ValueError, KeyError):
        return "unavailable", None
    if not verifier.verify(challenge, commit, signature, checkpoint):
        return "mismatch", None
    return "verified", {"challenge": challenge.hex(), "signature": signature.hex()}


def verify_in_fresh_processes(ledger, checkpoint, issued_backup, permit):
    def check(expected, previous=None):
        worker = subprocess.run([
            sys.executable, str(Path(__file__).resolve()), str(ledger), str(checkpoint), permit,
        ], input=json.dumps(previous), text=True, capture_output=True, check=True, timeout=10)
        result, response = json.loads(worker.stdout)
        if result != expected:
            raise RuntimeError(f"host subprocess returned {result}, expected {expected}")
        return response

    accepted = check("verified")
    check("mismatch", accepted)
    saved_checkpoint = checkpoint.read_bytes()
    checkpoint.unlink()
    check("unavailable")
    checkpoint.write_text("broken fixture checkpoint", encoding="utf-8")
    check("unavailable")
    checkpoint.write_bytes(saved_checkpoint)
    shutil.copyfile(issued_backup, ledger)
    check("mismatch")
    print("PASS: fresh host processes reject replay, missing/corrupt checkpoint and ledger rollback")


if __name__ == "__main__":
    database_path, commit_path, permit_id = sys.argv[1:]
    print(json.dumps(check_receipt(Path(database_path), Path(commit_path), permit_id, json.load(sys.stdin))))
