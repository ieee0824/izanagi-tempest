"""Exercise the integrated synthetic local-auth PTY and the pre-grant failures."""

import errno
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
    )
    assert_empty()
    print("match: auth accepted, other host and three direct ports denied; disconnect reaped, active tunnel and listeners closed, generation removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
