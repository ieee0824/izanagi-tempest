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
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import termios
import time

from claude_manual_login_refusal import FIXED_CLI, check_signed_publication
from host_permit_receipt import Commit, Scope
from claude_local_auth_pty_smoke import check_signed_permits
from claude_supervised_pty_smoke import WORK
from claude_writable_pty_smoke import CONFIG


MATCH = b"host and PTY inputs match"
HANDOFF = b"manual login verified inputs handed off"


def write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def exercise(root, binary, responder, publisher, dummy=None, *, staging_test=False):
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

    def run_case(label, value, expected, lose_response=False, revoke_after_response=False, stage=None, stall=None):
        prepare(value)
        publication = subprocess.run([publisher], capture_output=True, timeout=5)
        if publication.returncode != (0 if value.state == "consumed" else 1):
            raise RuntimeError(f"{label}: unexpected publication {publication}")
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        if stall == "partial":
            attrs[3] &= ~termios.ICANON
            attrs[6][termios.VMIN] = 1
            attrs[6][termios.VTIME] = 0
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        trace = root / "trace"
        protected = (database, published / "record.json", recovery / "checkpoint.json")
        before = tuple(path.read_bytes() for path in protected)
        output = b""
        filters = "%network,%process,%file" if stage is None else "%network,%process"
        command = ["strace", "-f", "-qq", "-o", trace, "-e", f"trace={filters}", binary]
        environment = None
        if stage is not None:
            command += ["--ignored", "--nocapture", "stage_combined_diagnostic_descriptors"]
            environment = {"TEMPEST_STAGE_CASE": stage}
        try:
            with subprocess.Popen(
                command, stdin=slave, stdout=slave, stderr=slave, env=environment,
            ) as diagnostic:
                try:
                    while not (match := re.search(rb"(?:^|\n)([a-f0-9]{64})\r?\n", output)):
                        if not select.select([master], [], [], 10)[0]:
                            raise RuntimeError(f"{label}: no challenge in {output!r}")
                        output += os.read(master, 4096)
                    if stall is None:
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
                    else:
                        lock_path = config / "claude-login-publication/lock"
                        lock = ["flock", "-n", "-x", lock_path, "true"]
                        if subprocess.run(lock, timeout=5).returncode != 1:
                            raise RuntimeError(f"{label}: shared publication lock was not held")
                        if stall == "partial":
                            os.write(master, b'{"challenge":')
                        state = config / "claude-login-authority/revocation-state"
                        deadline = json.loads(state.read_bytes().split(b"\0", 1)[1])["expires_unix_seconds"]
                    if diagnostic.wait(timeout=25) != (1 if stage is None else 0):
                        raise RuntimeError(f"{label}: unexpected diagnostic status")
                    if stall is not None:
                        if time.time() > deadline + 1:
                            raise RuntimeError(f"{label}: diagnostic exceeded the signed deadline")
                        subprocess.run(lock, check=True, timeout=5)
                finally:
                    if diagnostic.poll() is None:
                        diagnostic.kill()
            while select.select([master], [], [], 0)[0]:
                output += os.read(master, 4096)
        finally:
            os.close(slave)
            os.close(master)
        if stage is not None:
            marker = f"staging case {stage}: expected outcome, mounts detached and generation removed"
            if marker.encode() not in output or any(CONFIG.iterdir()):
                raise RuntimeError(f"{label}: unexpected staging output {output!r}")
            expected_work = {WORK / "staging-source"}
            if set(WORK.iterdir()) != expected_work:
                raise RuntimeError(f"{label}: staging retained work unexpectedly")
            calls = [line.split(maxsplit=1)[1] for line in trace.read_text().splitlines()]
            # The offline route check uses only the kernel's local rtnetlink socket.
            allowed = {"execve", "exit_group", "exit", "clone", "clone3", "socket",
                       "bind", "getsockname", "sendto", "recvmsg"}
            if sum(line.startswith("execve(") for line in calls) != 1 or any(
                line.split("(", 1)[0] not in allowed
                or (line.startswith("socket(") and "AF_NETLINK" not in line)
                or (line.startswith(("clone(", "clone3(")) and "CLONE_THREAD" not in line)
                for line in calls
            ):
                raise RuntimeError(f"{label}: unexpected execution or network call: {calls}")
            if tuple(path.read_bytes() for path in protected) != before:
                raise RuntimeError(f"{label}: staging changed the ledger")
            print(marker)
            return True
        if stall is not None and b"host receipt deadline expired" not in output:
            raise RuntimeError(f"{label}: expected an absolute-deadline refusal, got {output!r}")
        if (MATCH in output) != expected or (HANDOFF in output) != expected:
            raise RuntimeError(f"{label}: unexpected diagnostic output {output!r}")
        if tuple(path.read_bytes() for path in protected) != before or any(local_ledger.iterdir()):
            raise RuntimeError(f"{label}: diagnostic mutated the ledger")
        allowed = {"execve", "openat", "access", "newfstatat", "statx", "readlink", "exit_group"}
        calls = [line.split(maxsplit=1)[1] for line in trace.read_text().splitlines()]
        if (sum(line.startswith("execve(") for line in calls) != 1
                or any(line.split("(", 1)[0] not in allowed
                       or any(flag in line for flag in ("O_RDWR", "O_CREAT", "O_TRUNC"))
                       or ("O_WRONLY" in line and not (
                           "O_NONBLOCK" in line and any(f'"/proc/self/fd/{fd}"' in line for fd in (1, 2))
                       ))
                       for line in calls)):
            raise RuntimeError(f"{label}: unexpected child, network or writing syscall: {calls}")
        print(f"{label}: exit 1, no child, network or ledger mutation")
        return MATCH in output and HANDOFF in output

    def check_blocked_output(commit, after_receipt=False):
        prepare(commit)
        subprocess.run([publisher], check=True, timeout=5)
        master, slave = pty.openpty()
        trace = root / "blocked-output-trace"
        lock = ["flock", "-n", "-x", config / "claude-login-publication/lock", "true"]
        try:
            def fill_queue():
                filler = os.open(os.ttyname(slave), os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
                try:
                    # Let already queued bytes move into the master buffer without draining it.
                    for _ in range(8):
                        try:
                            while True:
                                os.write(filler, b"x" * 4096)
                        except BlockingIOError:
                            time.sleep(0.025)
                    try:
                        os.write(filler, b"x" * 65)
                    except BlockingIOError:
                        pass
                    else:
                        raise RuntimeError("PTY output queue still accepts a challenge")
                finally:
                    os.close(filler)

            if not after_receipt:
                fill_queue()
            with subprocess.Popen(
                ["strace", "-f", "-qq", "-o", trace, "-e", "trace=poll,write,%process,%network", "-s", "150",
                 binary], stdin=slave, stdout=slave, stderr=slave,
            ) as diagnostic:
                try:
                    started = time.monotonic() + 5
                    while subprocess.run(lock, timeout=3).returncode != 1:
                        if diagnostic.poll() is not None or time.monotonic() >= started:
                            raise RuntimeError("combined diagnostic did not hold publication lock")
                        time.sleep(0.025)
                    if after_receipt:
                        output = b""
                        while not (match := re.search(rb"(?:^|\n)([a-f0-9]{64})\r?\n", output)):
                            if not select.select([master], [], [], 10)[0]:
                                raise RuntimeError("missing challenge before filling the output queue")
                            output += os.read(master, 4096)
                        response = subprocess.run(
                            [responder], input=match[1] + b"\n", capture_output=True,
                            check=True, timeout=5,
                        )
                        fill_queue()
                        os.write(master, response.stdout)
                    state = config / "claude-login-authority/revocation-state"
                    deadline = json.loads(state.read_bytes().split(b"\0", 1)[1])["expires_unix_seconds"]
                    if diagnostic.wait(timeout=27) != 1 or time.time() > deadline + 1:
                        raise RuntimeError("blocked challenge did not refuse by the signed deadline")
                    subprocess.run(lock, check=True, timeout=3)
                finally:
                    if diagnostic.poll() is None:
                        diagnostic.kill()
            calls = trace.read_text().splitlines()
            if after_receipt:
                blocked = any("host and PTY inputs match" in line and "EAGAIN" in line
                              for line in calls)
                label = "output full after signature acceptance"
            else:
                blocked = any("events=POLLOUT" in line and "(Timeout)" in line for line in calls)
                label = "output full before challenge"
            if (not blocked or sum("execve(" in line for line in calls) != 1
                    or any("socket(" in line or "connect(" in line for line in calls)):
                raise RuntimeError(f"{label}: unexpected output trace {calls!r}")
            print(f"{label}: refused and exclusive publication lock recovered")
        finally:
            os.close(slave)
            os.close(master)

    def signed_fixture(refresh_publication):
        if staging_test:
            commit = Commit("fixture-ledger", 1, scope, "consumed")
            for mode in ("replace", "missing", "generation", "modify"):
                refresh_publication()
                run_case(mode, commit, False, stage=mode)
            return
        if dummy is not None:
            def verify_dummy(record, payload):
                _, pair = payload.read_bytes().split(b"\0", 1)
                handoff = json.loads(pair)
                expected = Scope(handoff["target_id"], handoff["permit_id"], 1)
                if expected.permit_id != record.name:
                    raise RuntimeError("fixture handoff does not match the intended permit and generation")
                commit = Commit("fixture-ledger", 1, expected, "consumed")
                refresh_publication(expected.permit_id, expected.target_id)
                wrong = replace(commit, scope=replace(expected, generation=2))
                if run_case("dummy prevented on generation mismatch", wrong, False):
                    raise RuntimeError("mismatch reached the dummy gate")
                if any(WORK.iterdir()) or record.exists():
                    raise RuntimeError("mismatch started the dummy or consumed its local permit")
                refresh_publication(expected.permit_id, expected.target_id)
                if not run_case("matched dummy gate", commit, True):
                    raise RuntimeError("matched diagnostic failed to reach the dummy gate")

            check_signed_permits(dummy, integration_gate=verify_dummy)
            return
        commit = Commit("fixture-ledger", 1, scope, "consumed")
        scenarios = [
            ("matching host and PTY", commit, True, {}),
            ("target mismatch", replace(commit, scope=replace(scope, target_id="other")), False, {}),
            ("permit mismatch", replace(commit, scope=replace(scope, permit_id="other")), False, {}),
            ("generation mismatch", replace(commit, scope=replace(scope, generation=2)), False, {}),
            ("response lost", commit, False, {"lose_response": True}),
            ("unconfirmed consumption", replace(commit, state="issued"), False, {}),
            ("revoked after signing", commit, False, {"revoke_after_response": True}),
            ("open PTY with no response", commit, False, {"stall": "silent"}),
            ("open PTY with partial response", commit, False, {"stall": "partial"}),
        ]
        for label, value, expected, options in scenarios:
            refresh_publication()
            run_case(label, value, expected, **options)
        refresh_publication()
        check_blocked_output(commit)
        refresh_publication()
        check_blocked_output(commit, after_receipt=True)

    check_signed_publication(config, local_ledger, None, combined_check=signed_fixture)


def main():
    staging_test = sys.argv[-1:] == ["--staging-test"]
    if staging_test:
        sys.argv.pop()
    if sys.argv[1:2] != ["--isolated"]:
        if len(sys.argv) not in (4, 5) or os.geteuid() != 0:
            return 2
        binaries = [str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:]]
        return subprocess.call(["unshare", "-mn", "--propagation", "private", sys.executable,
                                str(Path(__file__).resolve()), "--isolated",
                                os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/self/ns/net"),
                                *binaries, *(["--staging-test"] if staging_test else [])])
    if len(sys.argv) not in (7, 8) or os.geteuid() != 0 or any(
        os.readlink(f"/proc/self/ns/{kind}") == original
        for kind, original in zip(("mnt", "net"), sys.argv[2:4])
    ):
        return 2
    with tempfile.TemporaryDirectory(prefix="tempest-combined-") as directory:
        root = Path(directory)
        (root / "etc").mkdir()
        if len(sys.argv) == 8:
            # nft renders protocol names from the local system databases.
            for name in ("protocols", "services", "ethertypes"):
                shutil.copyfile(Path("/etc") / name, root / "etc" / name)
        synthetic_cli = root / "lib/tempest-claude-offline/claude"
        synthetic_cli.parent.mkdir(parents=True)
        synthetic_cli.touch()
        original = root / "original-lib"
        original.mkdir()
        subprocess.run(["mount", "--bind", "/var/lib", original], check=True)
        subprocess.run(["mount", "--bind", root / "etc", "/etc"], check=True)
        subprocess.run(["mount", "--bind", root / "lib", "/var/lib"], check=True)
        try:
            if len(sys.argv) == 8 or staging_test:
                if any(subprocess.check_output(["ip", family, "route", "show"]).strip()
                       for family in ("-4", "-6")):
                    raise RuntimeError("external route in test namespace")
                if not staging_test:
                    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
                for path in (WORK, CONFIG):
                    path.mkdir(mode=0o700)
                    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0700,size=1024m",
                                    "tmpfs", path], check=True)
            artifact = original / "tempest-claude-offline/claude"
            if staging_test:
                copy = WORK / "staging-source"
                shutil.copyfile(artifact, copy)
                copy.chmod(0o755)
                artifact = copy
            subprocess.run(["mount", "--bind", artifact, FIXED_CLI], check=True)
            subprocess.run(["mount", "-o", "remount,bind,ro,noexec", FIXED_CLI], check=True)
            exercise(root, *sys.argv[4:], staging_test=staging_test)
        finally:
            if os.path.ismount(FIXED_CLI) or any(
                    row.split()[4] == FIXED_CLI
                    for row in Path("/proc/self/mountinfo").read_text().splitlines()):
                subprocess.run(["umount", FIXED_CLI], check=True)
            if len(sys.argv) == 8 or staging_test:
                for path in (CONFIG, WORK):
                    if path.is_mount():
                        subprocess.run(["umount", path], check=True)
            for path in ("/var/lib", "/etc", original):
                subprocess.run(["umount", path], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
