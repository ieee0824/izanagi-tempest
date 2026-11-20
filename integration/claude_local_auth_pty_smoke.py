"""Exercise the integrated synthetic local-auth PTY and the pre-grant failures."""

import errno
import json
import time
import os
from pathlib import Path
import pty
import subprocess
import sys

from claude_supervised_pty_smoke import WORK, fixture
from claude_writable_pty_smoke import CONFIG, REMOVED

POSITIVE = (
    b"local auth: tunnel accepted, other host refused, three direct ports denied; "
    b"listeners and policy closed\n"
)
NEGATIVE = b"local auth: accepts=0,0,0,0 denied=0; listeners and policy closed\n"
FAILURES = {
    "missing-namespace": b"fixed login namespace missing or mismatched",
    "wrong-namespace": b"fixed login namespace missing or mismatched",
    "missing-policy": b"fixed login policy or loopback inspection failed",
    "wrong-policy": b"fixed login policy or loopback inspection failed",
    "missing-gateway": b"fixed gateway unavailable",
    "empty-resolution": b"fixed gateway upstream unavailable or unapproved",
    "unapproved-resolution": b"fixed gateway upstream unavailable or unapproved",
    "expired-permit": b"synthetic permit expired",
    "wrong-permit-scope": b"synthetic permit scope mismatch",
    "wrong-permit-arguments": b"synthetic permit scope mismatch",
    "wrong-permit-authority": b"synthetic permit scope mismatch",
}


def assert_empty():
    if any(WORK.iterdir()) or any(CONFIG.iterdir()):
        raise RuntimeError("trial or configuration generation remains")


def check_pre_grant_denial(binary, case, reason):
    master, slave = pty.openpty()
    try:
        with subprocess.Popen(
            [binary, case], stdin=slave, stdout=slave, stderr=subprocess.PIPE, env={}
        ) as process:
            os.close(slave)
            slave = -1
            _, result = process.communicate(timeout=8)
            if (
                process.returncode != 1
                or NEGATIVE not in result
                or b"work removed" not in result
                or reason not in result
            ):
                raise RuntimeError(f"{case}: pre-grant refusal or recovery failed: {result!r}")
        # The master queue is empty once the slave side has exited.
        try:
            output = os.read(master, 1024)
        except OSError as error:
            if error.errno != errno.EIO:  # Linux PTY hangup.
                raise
        else:
            if output:
                raise RuntimeError(f"{case}: fixed child emitted output before grant")
    finally:
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)
    assert_empty()


def check_terminal_refusals(binary):
    master, slave = pty.openpty()
    other_master, other_slave = pty.openpty()
    try:
        for input_fd, output_fd in (
            (subprocess.DEVNULL, slave),
            (slave, subprocess.PIPE),
            (slave, other_slave),
            (master, master),
        ):
            result = subprocess.run(
                [binary, "match"], stdin=input_fd, stdout=output_fd,
                stderr=subprocess.PIPE, env={}, timeout=5,
            )
            if result.returncode != 1 or result.stdout or result.stderr:
                raise RuntimeError("invalid login terminal was not refused before staging")
            assert_empty()
    finally:
        for fd in (master, slave, other_master, other_slave):
            os.close(fd)


def check_concurrent_refusal(binary):
    original = (set(WORK.iterdir()), set(CONFIG.iterdir()))
    master, slave = pty.openpty()
    try:
        result = subprocess.run(
            [binary, "match"], stdin=slave, stdout=slave,
            stderr=subprocess.PIPE, env={}, timeout=2,
        )
        if result.returncode != 1 or b"dedicated PTY work area already in use" not in result.stderr:
            raise RuntimeError(f"concurrent login was not refused by the lock: {result.stderr!r}")
        os.close(slave)
        slave = -1
        try:
            output = os.read(master, 1024)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
        else:
            if output:
                raise RuntimeError("concurrent login emitted PTY output")
        if (set(WORK.iterdir()), set(CONFIG.iterdir())) != original:
            raise RuntimeError("concurrent login changed an active generation")
    finally:
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)


def check_permit_replay(binary):
    marker = CONFIG / ".used-synthetic-login-permit"
    policy = CONFIG / ".synthetic-login-policy.json"
    assert_empty()

    def write_settings(expires):
        with os.fdopen(os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as out:
            json.dump({
                "policy": {"version": 1, "authority": "platform.claude.com:443"},
                "expires_unix_seconds": expires,
            }, out)

    def check_refusal(reason, expected):
        master, slave = pty.openpty()
        try:
            result = subprocess.run(
                [binary, "single-use-permit"], stdin=slave, stdout=slave,
                stderr=subprocess.PIPE, env={}, timeout=2,
            )
            if result.returncode != 1 or reason not in result.stderr:
                raise RuntimeError(f"synthetic permit refusal failed: {result.stderr!r}")
            if any(WORK.iterdir()) or set(CONFIG.iterdir()) != expected:
                raise RuntimeError("rejected permit staged a new generation")
        finally:
            os.close(slave)
            os.close(master)

    try:
        check_refusal(b"No such file or directory", set())
        write_settings(int(time.time()) - 1)
        check_refusal(b"synthetic permit expired", {policy})
        write_settings(int(time.time()) + 45)
        fixture(
            [binary, "single-use-permit"], {},
            complete_probe=True, success=POSITIVE + REMOVED,
        )
        if set(CONFIG.iterdir()) != {marker, policy} or not marker.is_file() or marker.stat().st_size:
            raise RuntimeError("unexpected settings or permit artifacts after cleanup")
        check_refusal(b"synthetic login permit already used", {marker, policy})
    finally:
        marker.unlink(missing_ok=True)
        policy.unlink(missing_ok=True)
    assert_empty()


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
        return 2
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    assert_empty()
    check_terminal_refusals(binary)
    print("invalid terminals: redirected, split and master endpoints refused before staging")
    for case, reason in FAILURES.items():
        check_pre_grant_denial(binary, case, reason)
        print(f"{case}: no launch, no traffic, recovered")
    fixture(
        [binary, "match"],
        {"HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": "*"},
        complete_probe=True,
        success=POSITIVE + REMOVED,
        startup_timeout=20,
        before_probe=lambda: check_concurrent_refusal(binary),
    )
    assert_empty()
    check_permit_replay(binary)
    print("configured permit: missing, expired and replayed settings refused; first use recovered")
    print("concurrent launch: refused before staging")
    print("match: auth accepted, other host and three direct ports denied; disconnect reaped, active tunnel and listeners closed, generation removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
