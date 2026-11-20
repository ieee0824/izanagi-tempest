"""Exercise the integrated synthetic local-auth PTY and the pre-grant failures."""

import errno
import os
from pathlib import Path
import pty
import subprocess
import sys

from claude_supervised_pty_smoke import WORK, fixture
from claude_writable_pty_smoke import CONFIG, REMOVED

POSITIVE = b"local auth: accepts=1,0,0,0 denied=3; listeners and policy closed\n"
NEGATIVE = b"local auth: accepts=0,0,0,0 denied=0; listeners and policy closed\n"
FAILURES = {
    "missing-namespace": b"fixed login namespace missing or mismatched",
    "wrong-namespace": b"fixed login namespace missing or mismatched",
    "missing-policy": b"fixed login policy or loopback inspection failed",
    "wrong-policy": b"fixed login policy or loopback inspection failed",
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
                or not result.startswith(NEGATIVE)
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


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
        return 2
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    assert_empty()
    for case, reason in FAILURES.items():
        check_pre_grant_denial(binary, case, reason)
        print(f"{case}: no launch, no traffic, recovered")
    fixture([binary, "match"], {}, complete_probe=True, success=POSITIVE + REMOVED)
    assert_empty()
    print("match: auth accepted, three denied; disconnect reaped, listeners closed, generation removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
