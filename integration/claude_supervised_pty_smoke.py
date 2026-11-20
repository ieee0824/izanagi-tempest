"""Verify the fixed supervised PTY fixture on a dedicated Linux host."""

import os
from pathlib import Path
import pty
import subprocess
import sys

from claude_offline_pty_smoke import read_until

WORK = Path("/var/lib/tempest-claude-version-work")
SUCCESS = b"offline PTY: supervisor stopped and reaped namespace; cleanup complete\n"


def fixture(command: list[str], complete_probe: bool) -> None:
    master, slave = pty.openpty()
    try:
        with subprocess.Popen(
            command, stdin=slave, stdout=slave, stderr=subprocess.PIPE
        ) as child:
            os.close(slave)
            slave = -1
            try:
                read_until(master, b"fixture-ready")
                if complete_probe:
                    os.write(master, b"probe\n")
                    read_until(master, b"fixture-response")
            finally:
                os.close(master)
                master = -1
                _, result = child.communicate(timeout=20)
        if complete_probe:
            if child.returncode != 0 or result != SUCCESS:
                raise RuntimeError(f"disconnect and recovery failed: {result!r}")
        elif child.returncode != 1 or SUCCESS in result:
            raise RuntimeError(f"early disconnect was not rejected: {result!r}")
        if any(WORK.iterdir()):
            raise RuntimeError("supervised work area remains after disconnect")
    finally:
        for fd in (master, slave):
            if fd != -1:
                os.close(fd)


def main() -> int:
    if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
        print("usage: sudo python3 integration/claude_supervised_pty_smoke.py /path/to/fixture", file=sys.stderr)
        return 2
    if any(WORK.iterdir()):
        raise RuntimeError("the dedicated work area must start empty")
    command = [str(Path(sys.argv[1]).resolve(strict=True))]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    if result.returncode != 1 or any(WORK.iterdir()):
        raise RuntimeError("non-PTY launch was not rejected before staging")
    fixture(command, complete_probe=False)
    fixture(command, complete_probe=True)
    print("non-pty=rejected early-disconnect=rejected probe=ok disconnect=reaped cleanup=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
