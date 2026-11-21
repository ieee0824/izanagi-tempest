"""Exercise both real read-only login verifiers on one administrator PTY."""

from contextlib import closing
from dataclasses import asdict, replace
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import sqlite3
import subprocess
import sys
import tempfile
import termios

from claude_manual_login_refusal import FIXED_CLI, check_signed_publication
from host_permit_receipt import Commit, Scope


MATCH = b"host and PTY inputs match"
HANDOFF = b"manual login verified inputs handed off"


def write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def exercise(root, binary, responder, publisher):
    config = root / "etc/tempest"
    config.mkdir(parents=True, mode=0o700)
    local_ledger = config / "claude-login-diagnostic-ledger"
    local_ledger.mkdir(mode=0o700)
    host = root / "lib/izanagi-tempest"
    host.mkdir(parents=True, mode=0o700)
    source, published, authority, recovery, signer = [
        host / name for name in ("host-login-ledger-source", "host-login-ledger",
                                 "host-login-authority", "host-login-recovery", "host-login-signer")
    ]
    for directory in (source, published, authority, recovery, signer):
        directory.mkdir(mode=0o700)
    write(authority / "verification-key",
          bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))
    write(signer / "signing-seed", bytes(range(32)))
    write(published / "lock", b"")
    database = source / "ledger.sqlite3"
    schema = Path(__file__).resolve().parents[1] / "tools/host_ledger/schema.sql"
    with closing(sqlite3.connect(database)) as db, db:
        db.executescript(schema.read_text())
    database.chmod(0o600)
    scope = Scope("synthetic-diagnostic-target", f"{1:032x}", 1)

    def prepare(value):
        write(authority / "scope.json", json.dumps(asdict(value.scope)).encode())
        write(recovery / "checkpoint.json", json.dumps({
            "sequence": value.sequence, "digest": value.digest().hex(),
        }).encode())
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("DELETE FROM permit_commits")
            db.execute("INSERT INTO permit_commits VALUES (?, ?, ?, ?, ?, ?)", (
                value.sequence, value.ledger_id, value.scope.target_id, value.scope.permit_id,
                value.scope.generation, value.state,
            ))

    def run_case(label, value, expected, lose_response=False, revoke_after_response=False):
        prepare(value)
        publication = subprocess.run([publisher], capture_output=True, timeout=5)
        if publication.returncode != (0 if value.state == "consumed" else 1):
            raise RuntimeError(f"{label}: unexpected publication {publication}")
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        trace = root / "trace"
        protected = (database, published / "record.json", recovery / "checkpoint.json")
        before = tuple(path.read_bytes() for path in protected)
        output = b""
        try:
            with subprocess.Popen(
                ["strace", "-f", "-qq", "-o", trace, "-e", "trace=%network,%process,%file",
                 binary], stdin=slave, stdout=slave, stderr=slave,
            ) as diagnostic:
                try:
                    while not (match := re.search(rb"(?:^|\n)([a-f0-9]{64})\r?\n", output)):
                        if not select.select([master], [], [], 10)[0]:
                            raise RuntimeError(f"{label}: no challenge in {output!r}")
                        output += os.read(master, 4096)
                    response = subprocess.run(
                        [responder], input=match[1] + b"\n", capture_output=True, timeout=5,
                    )
                    if response.returncode != (0 if value.state == "consumed" else 1):
                        raise RuntimeError(f"{label}: unexpected responder result {response}")
                    if revoke_after_response:
                        with (published / "lock").open("rb") as held:
                            fcntl.flock(held, fcntl.LOCK_EX)
                            with closing(sqlite3.connect(database)) as db, db:
                                db.execute("INSERT INTO permit_commits VALUES (?, ?, ?, ?, ?, ?)", (
                                    value.sequence + 1, value.ledger_id, value.scope.target_id,
                                    value.scope.permit_id, value.scope.generation, "revoked",
                                ))
                        before = tuple(path.read_bytes() for path in protected)
                    os.write(master, response.stdout if response.stdout and not lose_response else b"\x04")
                    if diagnostic.wait(timeout=10) != 1:
                        raise RuntimeError(f"{label}: diagnostic did not refuse")
                finally:
                    if diagnostic.poll() is None:
                        diagnostic.kill()
            while select.select([master], [], [], 0)[0]:
                output += os.read(master, 4096)
        finally:
            os.close(slave)
            os.close(master)
        if (MATCH in output) != expected or (HANDOFF in output) != expected:
            raise RuntimeError(f"{label}: unexpected diagnostic output {output!r}")
        if tuple(path.read_bytes() for path in protected) != before or any(local_ledger.iterdir()):
            raise RuntimeError(f"{label}: diagnostic mutated the ledger")
        allowed = {"execve", "openat", "access", "newfstatat", "statx", "readlink", "exit_group"}
        calls = [line.split(maxsplit=1)[1] for line in trace.read_text().splitlines()]
        if (sum(line.startswith("execve(") for line in calls) != 1
                or any(line.split("(", 1)[0] not in allowed
                       or any(flag in line for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"))
                       for line in calls)):
            raise RuntimeError(f"{label}: unexpected child, network or writing syscall: {calls}")
        print(f"{label}: exit 1, no child, network or ledger mutation")

    def signed_fixture(refresh_publication):
        commit = Commit("fixture-ledger", 1, scope, "consumed")
        scenarios = [
            ("matching host and PTY", commit, True, {}),
            ("target mismatch", replace(commit, scope=replace(scope, target_id="other")), False, {}),
            ("permit mismatch", replace(commit, scope=replace(scope, permit_id="other")), False, {}),
            ("generation mismatch", replace(commit, scope=replace(scope, generation=2)), False, {}),
            ("response lost", commit, False, {"lose_response": True}),
            ("unconfirmed consumption", replace(commit, state="issued"), False, {}),
            ("revoked after signing", commit, False, {"revoke_after_response": True}),
        ]
        for label, value, expected, options in scenarios:
            refresh_publication()
            run_case(label, value, expected, **options)

    check_signed_publication(config, local_ledger, None, combined_check=signed_fixture)


def main():
    if sys.argv[1:2] != ["--isolated"]:
        if len(sys.argv) != 4 or os.geteuid() != 0:
            return 2
        binaries = [str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:]]
        return subprocess.call(["unshare", "-mn", "--propagation", "private", sys.executable,
                                str(Path(__file__).resolve()), "--isolated",
                                os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/self/ns/net"),
                                *binaries])
    if len(sys.argv) != 7 or os.geteuid() != 0 or any(
        os.readlink(f"/proc/self/ns/{kind}") == original
        for kind, original in zip(("mnt", "net"), sys.argv[2:4])
    ):
        return 2
    with tempfile.TemporaryDirectory(prefix="tempest-combined-") as directory:
        root = Path(directory)
        (root / "etc").mkdir()
        synthetic_cli = root / "lib/tempest-claude-offline/claude"
        synthetic_cli.parent.mkdir(parents=True)
        synthetic_cli.touch()
        original = root / "original-lib"
        original.mkdir()
        subprocess.run(["mount", "--bind", "/var/lib", original], check=True)
        subprocess.run(["mount", "--bind", root / "etc", "/etc"], check=True)
        subprocess.run(["mount", "--bind", root / "lib", "/var/lib"], check=True)
        subprocess.run(["mount", "--bind", original / "tempest-claude-offline/claude", FIXED_CLI],
                       check=True)
        try:
            subprocess.run(["mount", "-o", "remount,bind,ro,noexec", FIXED_CLI], check=True)
            exercise(root, *sys.argv[4:])
        finally:
            for path in (FIXED_CLI, "/var/lib", "/etc", original):
                subprocess.run(["umount", path], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
