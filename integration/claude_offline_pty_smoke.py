"""Exercise a fixed local PTY command and verify disconnect cleanup on Linux."""

import errno
import os
from pathlib import Path
import pty
import select
import signal
import sys
import tempfile
import time

FIXTURE = """
from pathlib import Path
Path("started").touch()
print("fixture-ready", flush=True)
if input() == "probe":
    print("fixture-response", flush=True)
input()
"""


def read_until(fd: int, marker: bytes) -> None:
    deadline = time.monotonic() + 3
    output = bytearray()
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError("PTY response missing")
        data = os.read(fd, 1024)
        if not data or len(output) + len(data) > 4096:
            raise RuntimeError("invalid PTY response")
        output.extend(data)


def reap_after_disconnect(pid: int) -> int:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        reaped, status = os.waitpid(pid, os.WNOHANG)
        if reaped:
            return status
        time.sleep(0.02)
    raise TimeoutError("PTY disconnect did not stop the child")


def run_fixture(work: Path) -> None:
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.chdir(work)
            os.execve(sys.executable, [sys.executable, "-I", "-c", FIXTURE], {"LC_ALL": "C"})
        finally:
            os._exit(125)
    try:
        read_until(master, b"fixture-ready")
        os.write(master, b"probe\n")
        read_until(master, b"fixture-response")
        if not (work / "started").is_file():
            raise RuntimeError("fixed command marker missing")
        os.close(master)
        master = -1
        status = reap_after_disconnect(pid)
        pid = 0
        if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGHUP:
            raise RuntimeError("child did not terminate from the PTY hangup")
    finally:
        if master >= 0:
            os.close(master)
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError as error:
                if error.errno != errno.ESRCH:
                    raise
            os.waitpid(pid, 0)


def main() -> int:
    if sys.platform != "linux" or len(sys.argv) != 1:
        print("usage: python3 integration/claude_offline_pty_smoke.py", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="tempest-offline-pty-") as directory:
        work = Path(directory)
        run_fixture(work)
    if work.exists():
        raise RuntimeError("fixture directory remains after cleanup")
    print("fixed-command=ok pty-roundtrip=ok disconnect-sighup=ok reaped=ok cleanup=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
