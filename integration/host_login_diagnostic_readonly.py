"""Check the dedicated host management reader in isolated mount and network namespaces."""

from contextlib import closing
from dataclasses import asdict, replace
import fcntl
import json
import os
from pathlib import Path
import select
import sqlite3
import subprocess
import sys
import tempfile


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from host_permit_receipt import Commit, Scope, receipt_bytes


VERIFIED_INPUTS = "receipt verified; launch disabled"
INVALID_RECEIPT = "receipt unavailable or invalid"
INVALID_INPUTS = "management inputs unavailable or invalid"


def exercise(binary, root, responder=None, publisher=None, writer=None):
    parent = root / "izanagi-tempest"
    authority = parent / "host-login-authority"
    recovery = parent / "host-login-recovery"
    for directory in (parent, authority, recovery):
        directory.mkdir(mode=0o700)
    key = authority / "verification-key"
    key.write_bytes(bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))
    key.chmod(0o600)
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    scope = Scope("qemu-fixture-target", "permit-fixture", 1)
    commit = Commit("host-fixture-ledger", 2, scope, "consumed")
    scope_path = authority / "scope.json"
    scope_path.write_text(json.dumps(asdict(scope)), encoding="ascii")
    scope_path.chmod(0o600)
    checkpoint = recovery / "checkpoint.json"

    def write_checkpoint(value):
        checkpoint.write_text(json.dumps({
            "sequence": value.sequence, "digest": value.digest().hex(),
        }), encoding="ascii")
        checkpoint.chmod(0o600)

    def sign(challenge, value, signing_key=signer):
        signature = signing_key.sign(receipt_bytes(bytes.fromhex(challenge), value))
        return {"challenge": challenge, "commit": asdict(value), "signature": signature.hex()}

    write_checkpoint(commit)
    subprocess.run(["mount", "--bind", str(root), "/var/lib"], check=True)
    subprocess.run(["mount", "-o", "remount,bind,ro", "/var/lib"], check=True)
    try:
        def check(expected, *arguments, reply=None):
            trace = root / "syscalls"
            with subprocess.Popen(
                ["strace", "-f", "-qq", "-o", str(trace), "-e", "trace=%network,%process",
                 binary, *arguments],
                env={"HOME": str(root), "TEMPEST_HOST_LOGIN_DIRECTORY": str(root)},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ) as process:
                response = None
                try:
                    if reply is not None:
                        if not select.select([process.stdout], [], [], 10)[0]:
                            raise RuntimeError("missing host challenge")
                        challenge = process.stdout.readline().strip()
                        if len(challenge) != 64 or len(bytes.fromhex(challenge)) != 32:
                            raise RuntimeError(f"invalid host challenge: {challenge!r}")
                        response = reply(challenge)
                    _, stderr = process.communicate(
                        "" if response is None else json.dumps(response) + "\n", timeout=10,
                    )
                finally:
                    if process.poll() is None:
                        process.kill()
            calls = trace.read_text(encoding="utf-8").splitlines()
            if process.returncode != 1 or expected not in stderr:
                raise RuntimeError(f"unexpected diagnostic result: {stderr}")
            # The initial exec and the diagnostic's own exit are the only traced calls.
            if len(calls) != 2 or "execve(" not in calls[0] or "exit_group(1)" not in calls[1]:
                raise RuntimeError(f"unexpected child or network activity: {calls}")
            return response

        initial = checkpoint.read_bytes()
        accepted = check(VERIFIED_INPUTS, reply=lambda challenge: sign(challenge, commit))
        check(INVALID_RECEIPT, reply=lambda _: accepted)
        with subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) as silent:
            try:
                if not select.select([silent.stdout], [], [], 3)[0]:
                    raise RuntimeError("missing standalone diagnostic challenge")
                challenge = silent.stdout.readline().strip()
                if len(challenge) != 64 or silent.wait(timeout=7) != 1:
                    raise RuntimeError("standalone diagnostic did not bound the open pipe")
                if INVALID_RECEIPT not in silent.stderr.read():
                    raise RuntimeError("standalone diagnostic did not reject the missing response")
            finally:
                if silent.poll() is None:
                    silent.kill()
        check(INVALID_RECEIPT)
        other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, commit, other_key))
        check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, replace(commit, sequence=3)))
        check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, replace(commit, ledger_id="other")))
        for wrong in (replace(scope, target_id="other"), replace(scope, permit_id="other"),
                      replace(scope, generation=2)):
            wrong_commit = replace(commit, scope=wrong)
            write_checkpoint(wrong_commit)
            check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, wrong_commit))
        write_checkpoint(commit)
        check("dedicated administrator entry required", str(root))
        if checkpoint.read_bytes() != initial:
            raise RuntimeError("diagnostic changed the checkpoint")
        checkpoint.unlink()
        check(INVALID_INPUTS)
        checkpoint.write_bytes(b"broken")
        checkpoint.chmod(0o600)
        check(INVALID_INPUTS)
        checkpoint.write_bytes(initial)
        key.rename(authority / "test-key")
        check(INVALID_INPUTS)
        key.symlink_to("test-key")
        check(INVALID_INPUTS)
        if responder is not None:
            key.unlink()
            (authority / "test-key").rename(key)
            ledger = parent / "host-login-ledger"
            signer_directory = parent / "host-login-signer"
            ledger.mkdir(mode=0o700)
            lock = ledger / "lock"
            lock.touch(mode=0o600)
            source = parent / "host-login-ledger-source"
            source.mkdir(mode=0o700)
            database = source / "ledger.sqlite3"
            schema = Path(__file__).resolve().parents[1] / "tools/host_ledger/schema.sql"

            def write_source(value):
                if not database.exists():
                    with closing(sqlite3.connect(database)) as db, db:
                        db.executescript(schema.read_text(encoding="ascii"))
                    database.chmod(0o600)
                with closing(sqlite3.connect(database)) as db, db:
                    db.execute("DELETE FROM permit_commits")
                    db.execute("INSERT INTO permit_commits VALUES (?, ?, ?, ?, ?, ?)", (
                        value.sequence, value.ledger_id, value.scope.target_id,
                        value.scope.permit_id, value.scope.generation, value.state,
                    ))
            signer_directory.mkdir(mode=0o700)
            seed = signer_directory / "signing-seed"
            seed.write_bytes(bytes(range(32)))
            seed.chmod(0o600)
            record = ledger / "record.json"

            def write_record(value, path=record):
                path.write_text(json.dumps(asdict(value)), encoding="ascii")
                path.chmod(0o600)

            def request(challenge, status):
                trace = root / "responder-syscalls"
                before = record.read_bytes(), checkpoint.read_bytes()
                result = subprocess.run(
                    ["strace", "-f", "-qq", "-o", str(trace), "-e", "trace=%network,%process",
                     responder], input=challenge + "\n", capture_output=True, text=True, timeout=10,
                )
                calls = trace.read_text(encoding="utf-8").splitlines()
                if (result.returncode != status or len(calls) != 2 or "execve(" not in calls[0]
                        or f"exit_group({status})" not in calls[1]):
                    raise RuntimeError(f"unexpected responder result: {result}, {calls}")
                if before != (record.read_bytes(), checkpoint.read_bytes()):
                    raise RuntimeError("responder changed the management records")
                if status:
                    if result.stdout:
                        raise RuntimeError("refusal emitted a response")
                    return None
                return json.loads(result.stdout)

            def lose_response(challenge):
                request(challenge, 0)
                return None

            write_source(commit)
            if publisher is None:
                write_record(commit)
            else:
                def publish(status, wrapper=()):
                    subprocess.run(["mount", "-o", "remount,bind,rw", "/var/lib"], check=True)
                    try:
                        result = subprocess.run([*wrapper, publisher], capture_output=True, timeout=10)
                        if result.returncode != status:
                            raise RuntimeError(f"unexpected publication result: {result}")
                    finally:
                        subprocess.run(["mount", "-o", "remount,bind,ro", "/var/lib"], check=True)

                publish(0)
            check(VERIFIED_INPUTS, reply=lambda challenge: request(challenge, 0))
            if publisher is not None:
                # Model the ledger manager holding the shared contract's exclusive lock.
                with lock.open("rb") as updating:
                    fcntl.flock(updating, fcntl.LOCK_EX)
                    publish(1)
                    check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
                check(VERIFIED_INPUTS, reply=lambda challenge: request(challenge, 0))
                with lock.open("rb") as updating:
                    fcntl.flock(updating, fcntl.LOCK_EX)
                    with closing(sqlite3.connect(database)) as db, db:
                        db.execute("INSERT INTO permit_commits VALUES (?, ?, ?, ?, ?, ?)", (
                            commit.sequence + 1, commit.ledger_id, scope.target_id,
                            scope.permit_id, scope.generation, "revoked",
                        ))
                # Keep both the old checkpoint and public record. The live DB must veto signing.
                check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
                publish(1)
                pending_source = replace(commit, state="issued")
                write_source(pending_source)
                write_checkpoint(pending_source)
                publish(1)
                check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
                write_checkpoint(commit)
                database.unlink()
                publish(1)
                check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
                write_source(replace(commit, sequence=1))
                publish(1)
                check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
                write_source(commit)
                pending = ledger / "pending"
                publish(1, ("strace", "-qq", "-e", "trace=rename,renameat,renameat2",
                            "-e", "inject=rename,renameat,renameat2:error=EIO"))
                if not pending.exists() or not (ledger / "record.new").exists():
                    raise RuntimeError("injected rename failure did not leave pending publication")
                publish(1)
                check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
                (ledger / "record.new").unlink()
                pending.unlink()
                print("PASS: publication, writer contention, missing/pending/rolled-back source and interrupted-publication refusal")
            if writer is not None:
                ledger_id = authority / "ledger-id.json"
                ledger_id.write_text(json.dumps(commit.ledger_id), encoding="ascii")
                ledger_id.chmod(0o600)

                def reset_writer_fixture():
                    database.unlink()
                    with closing(sqlite3.connect(database)) as db, db:
                        db.executescript(schema.read_text(encoding="ascii"))
                    database.chmod(0o600)
                    write_checkpoint(replace(commit, sequence=0, state="empty"))

                def transition(action, expected, wrapper=()):
                    subprocess.run(["mount", "-o", "remount,bind,rw", "/var/lib"], check=True)
                    try:
                        result = subprocess.run(
                            [*wrapper, sys.executable, writer, action],
                            capture_output=True, timeout=10,
                        )
                        if result.returncode != expected:
                            raise RuntimeError(f"unexpected transition {action}: {result}")
                    finally:
                        subprocess.run(["mount", "-o", "remount,bind,ro", "/var/lib"], check=True)

                reset_writer_fixture()
                transition("issue", 0)
                transition("revoke", 0)
                revoked = database.read_bytes(), checkpoint.read_bytes()
                transition("consume", 1)
                if revoked != (database.read_bytes(), checkpoint.read_bytes()):
                    raise RuntimeError("refused consumption changed the records")

                reset_writer_fixture()
                transition("issue", 0)
                transition("consume", 0)
                consumed = database.read_bytes(), checkpoint.read_bytes()
                transition("consume", 1)
                if consumed != (database.read_bytes(), checkpoint.read_bytes()):
                    raise RuntimeError("duplicate consumption changed the records")
                publish(0)
                check(VERIFIED_INPUTS, reply=lambda challenge: request(challenge, 0))
                transition("revoke", 0)
                publish(1)
                check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))

                reset_writer_fixture()
                transition("issue", 0)
                transition("consume", 0)
                publish(0)
                before_checkpoint = checkpoint.read_bytes()
                transition("revoke", 1, ("strace", "-qq", "-e", "trace=rename,renameat,renameat2",
                                         "-e", "inject=rename,renameat,renameat2:error=EIO"))
                with closing(sqlite3.connect(database)) as db:
                    latest = db.execute(
                        "SELECT sequence, state FROM permit_commits ORDER BY sequence DESC LIMIT 1"
                    ).fetchone()
                if latest != (3, "revoked") or checkpoint.read_bytes() != before_checkpoint:
                    raise RuntimeError("expected a committed revocation and old checkpoint")
                publish(1)
                check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
                (recovery / "checkpoint.new").unlink()
                transition("revoke", 1)
                write_source(commit)
                write_checkpoint(commit)
                print("PASS: fixed ledger transitions and interrupted checkpoint update refused")
            check(INVALID_RECEIPT, reply=lose_response)
            pending = replace(commit, state="pending")
            write_record(pending)
            write_checkpoint(pending)
            check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
            write_checkpoint(commit)
            write_record(replace(commit, sequence=1))
            check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
            print("PASS: real responder connected, pending/rollback/dropped response refused")
        print("PASS: isolated signature verification, scope/checkpoint/replay refusal, no child/network activity")
    finally:
        subprocess.run(["umount", "/var/lib"], check=True)


def main():
    if sys.argv[1:2] != ["--isolated"]:
        if len(sys.argv) not in (2, 3, 4, 5):
            return 2
        binaries = [str(Path(path).resolve(strict=True)) for path in sys.argv[1:]]
        return subprocess.call([
            "unshare", "--mount", "--net", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()), "--isolated", *binaries,
        ])
    if len(sys.argv) not in (3, 4, 5, 6) or os.geteuid() != 0:
        return 2
    with tempfile.TemporaryDirectory(prefix="tempest-host-diagnostic-") as directory:
        exercise(sys.argv[2], Path(directory), *sys.argv[3:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
